"""
Taint Tracking Analyzer - v0.13.0

Provides function-level taint analysis for enhanced AGENT-034 detection precision.

This module implements:
1. SourceClassifier - Identifies taint sources (function params, env vars, user input)
2. DataFlowBuilder - Builds intra-function data flow graph
3. SanitizationDetector - Detects validation/sanitization operations
4. SinkReachabilityChecker - Checks if tainted data reaches dangerous sinks
5. TaintTracker - Main orchestrator combining all components

Key design decisions:
- AST-only: Uses Python stdlib `ast` module, no external dependencies
- Function-scoped: Tracks data flow within a single function (intra-procedural)
- Conservative: When uncertain, assumes data is tainted (safe default)
- Performance: Target <10ms per function analysis
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TaintSource(Enum):
    """Classification of taint sources."""

    FUNCTION_PARAM = "function_param"  # Function parameter (from LLM/user)
    USER_INPUT = "user_input"  # request.json(), input(), etc.
    ENV_VAR = "env_var"  # os.getenv(), os.environ[]
    NETWORK = "network"  # HTTP requests, sockets
    FILE_READ = "file_read"  # File reads
    LLM_OUTPUT = "llm_output"  # LLM completion results
    HARDCODED = "hardcoded"  # String/number literals (NOT tainted)
    DERIVED = "derived"  # Derived from tainted variable
    UNKNOWN = "unknown"  # Cannot determine source


class SinkType(Enum):
    """Classification of dangerous sinks."""

    SHELL_EXEC = "shell_exec"  # subprocess, os.system, etc.
    CODE_EXEC = "code_exec"  # eval, exec, compile
    SQL_EXEC = "sql_exec"  # cursor.execute, raw SQL
    FILE_WRITE = "file_write"  # File writes with tainted path/content
    NETWORK_REQ = "network_req"  # Network requests with tainted URL/data
    MEMORY_WRITE = "memory_write"  # Agent memory operations


class SanitizationType(Enum):
    """Classification of sanitization operations."""

    TYPE_CHECK = "type_check"  # isinstance, type()
    STRING_CHECK = "string_check"  # startswith, endswith, isalnum, etc.
    LENGTH_CHECK = "length_check"  # len() comparison
    ALLOWLIST_CHECK = "allowlist_check"  # x in ALLOWED, x not in BLOCKED
    EXPLICIT_VALIDATION = "explicit_validation"  # validate(), sanitize(), etc.
    ESCAPE_TRANSFORM = "escape_transform"  # escape(), quote(), html.escape()


@dataclass
class TaintedValue:
    """Represents a value with taint information."""

    name: str
    source: TaintSource
    line: int
    original_param: Optional[str] = None  # Original param if derived
    is_sanitized: bool = False
    sanitization_type: Optional[SanitizationType] = None
    sanitization_line: Optional[int] = None


@dataclass
class DataFlowEdge:
    """Represents a data flow edge in the flow graph."""

    source: str  # Source variable/expression
    target: str  # Target variable/expression
    edge_type: str  # 'assign', 'call_arg', 'format', 'concat', 'attribute'
    line: int


@dataclass
class SinkReach:
    """Represents a tainted value reaching a dangerous sink."""

    tainted_var: str
    sink_function: str
    sink_type: SinkType
    line: int
    is_sanitized: bool
    flow_path: List[str]  # Variable chain from source to sink
    source: TaintSource
    confidence: float


@dataclass
class TaintAnalysisResult:
    """Result of taint analysis for a function."""

    function_name: str
    tainted_params: List[str]
    dangerous_flows: List[SinkReach]
    sanitization_points: Dict[str, Tuple[SanitizationType, int]]
    has_unsanitized_flow: bool
    confidence: float
    analysis_notes: List[str] = field(default_factory=list)

    def to_metadata_dict(self) -> Dict[str, Any]:
        """
        Export taint analysis as metadata dict for engine.py.

        v0.14.0: Returns format expected by oracle_eval.validates_taint_flow():
        {
            'dangerous_flows': [
                {
                    'var': str,
                    'sink': str,
                    'sink_type': str,  # 'eval', 'code_execution', 'shell_execution'
                    'source': str,     # 'user_input', 'llm_output', 'config'
                    'line': int,
                    'path': List[str],
                    'confidence': float,
                }
            ],
            'sanitization_points': [...]
        }
        """
        # Map internal sink types to oracle-compatible types
        # Oracle expects: 'eval', 'code_execution', 'shell_execution', 'sql_execution'
        sink_type_map = {
            SinkType.CODE_EXEC: 'code_execution',
            SinkType.SHELL_EXEC: 'shell_execution',
            SinkType.SQL_EXEC: 'sql_execution',
            SinkType.FILE_WRITE: 'file_write',
            SinkType.NETWORK_REQ: 'http_request',
            SinkType.MEMORY_WRITE: 'memory_write',
        }

        # Map internal source types to oracle-compatible types
        # Oracle expects: 'user_input', 'llm_output', 'config'
        source_type_map = {
            TaintSource.FUNCTION_PARAM: 'user_input',
            TaintSource.ENV_VAR: 'config',
            TaintSource.USER_INPUT: 'user_input',
            TaintSource.LLM_OUTPUT: 'llm_output',
            TaintSource.NETWORK: 'user_input',
            TaintSource.FILE_READ: 'user_input',
            TaintSource.DERIVED: 'user_input',
            TaintSource.UNKNOWN: 'user_input',
        }

        exported_flows = []
        for flow in self.dangerous_flows:
            # v0.14.0: Map sink functions to oracle-compatible types
            # Oracle expects 'code_execution' for eval/exec, 'shell_execution' for subprocess
            sink_func = flow.sink_function
            if sink_func in ('eval', 'exec', 'compile'):
                sink_type_str = 'code_execution'
            elif sink_func.startswith('subprocess.') or sink_func in ('os.system', 'os.popen'):
                sink_type_str = 'shell_execution'
            else:
                sink_type_str = sink_type_map.get(flow.sink_type, str(flow.sink_type.value))

            exported_flows.append({
                'var': flow.tainted_var,
                'sink': flow.sink_function,
                'sink_type': sink_type_str,
                'source': source_type_map.get(flow.source, 'user_input'),
                'line': flow.line,
                'path': flow.flow_path,
                'confidence': flow.confidence,
            })

        # Export sanitization points
        exported_sanitization = []
        for var_name, (san_type, line) in self.sanitization_points.items():
            exported_sanitization.append({
                'var': var_name,
                'type': san_type.value,
                'line': line,
            })

        return {
            'dangerous_flows': exported_flows,
            'sanitization_points': exported_sanitization,
        }

    @property
    def has_dangerous_flows(self) -> bool:
        """Check if there are any unsanitized dangerous flows."""
        return self.has_unsanitized_flow


# === Dangerous Sink Patterns ===

DANGEROUS_SINKS: Dict[str, SinkType] = {
    # Shell execution
    "subprocess.run": SinkType.SHELL_EXEC,
    "subprocess.Popen": SinkType.SHELL_EXEC,
    "subprocess.call": SinkType.SHELL_EXEC,
    "subprocess.check_output": SinkType.SHELL_EXEC,
    "subprocess.check_call": SinkType.SHELL_EXEC,
    "os.system": SinkType.SHELL_EXEC,
    "os.popen": SinkType.SHELL_EXEC,
    "os.spawn": SinkType.SHELL_EXEC,
    "os.spawnl": SinkType.SHELL_EXEC,
    "os.spawnle": SinkType.SHELL_EXEC,
    "os.spawnlp": SinkType.SHELL_EXEC,
    "os.spawnlpe": SinkType.SHELL_EXEC,
    "os.spawnv": SinkType.SHELL_EXEC,
    "os.spawnve": SinkType.SHELL_EXEC,
    "os.spawnvp": SinkType.SHELL_EXEC,
    "os.spawnvpe": SinkType.SHELL_EXEC,
    "os.execl": SinkType.SHELL_EXEC,
    "os.execle": SinkType.SHELL_EXEC,
    "os.execlp": SinkType.SHELL_EXEC,
    "os.execlpe": SinkType.SHELL_EXEC,
    "os.execv": SinkType.SHELL_EXEC,
    "os.execve": SinkType.SHELL_EXEC,
    "os.execvp": SinkType.SHELL_EXEC,
    "os.execvpe": SinkType.SHELL_EXEC,
    # Code execution
    "eval": SinkType.CODE_EXEC,
    "exec": SinkType.CODE_EXEC,
    "compile": SinkType.CODE_EXEC,
    "__import__": SinkType.CODE_EXEC,
    "importlib.import_module": SinkType.CODE_EXEC,
    # SQL execution
    "cursor.execute": SinkType.SQL_EXEC,
    "cursor.executemany": SinkType.SQL_EXEC,
    "connection.execute": SinkType.SQL_EXEC,
    "session.execute": SinkType.SQL_EXEC,
    "engine.execute": SinkType.SQL_EXEC,
    "db.execute": SinkType.SQL_EXEC,
}

# Patterns for env var access
ENV_VAR_PATTERNS: Set[str] = {
    "os.getenv",
    "os.environ.get",
    "os.environ",
    "environ.get",
    "dotenv.get_key",
}

# Patterns for user input
USER_INPUT_PATTERNS: Set[str] = {
    "input",
    "request.json",
    "request.form",
    "request.args",
    "request.data",
    "request.get_json",
    "request.values",
    "flask.request.json",
    "fastapi.Request",
    "sys.stdin.read",
    "sys.stdin.readline",
}

# Patterns for LLM output
LLM_OUTPUT_PATTERNS: Set[str] = {
    "completion.choices",
    "response.content",
    "response.text",
    "chat.completions.create",
    "messages.create",
    "llm.invoke",
    "llm.predict",
    "chain.invoke",
    "chain.run",
    "agent.run",
    "agent.invoke",
}

# Sanitization function patterns
SANITIZATION_PATTERNS: Dict[str, SanitizationType] = {
    # Type checks
    "isinstance": SanitizationType.TYPE_CHECK,
    "type": SanitizationType.TYPE_CHECK,
    # String checks
    "startswith": SanitizationType.STRING_CHECK,
    "endswith": SanitizationType.STRING_CHECK,
    "isalnum": SanitizationType.STRING_CHECK,
    "isalpha": SanitizationType.STRING_CHECK,
    "isdigit": SanitizationType.STRING_CHECK,
    "isnumeric": SanitizationType.STRING_CHECK,
    "isidentifier": SanitizationType.STRING_CHECK,
    "match": SanitizationType.STRING_CHECK,
    "fullmatch": SanitizationType.STRING_CHECK,
    "search": SanitizationType.STRING_CHECK,
    # Length checks
    "len": SanitizationType.LENGTH_CHECK,
    # Explicit validation
    "validate": SanitizationType.EXPLICIT_VALIDATION,
    "sanitize": SanitizationType.EXPLICIT_VALIDATION,
    "check": SanitizationType.EXPLICIT_VALIDATION,
    "verify": SanitizationType.EXPLICIT_VALIDATION,
    "is_valid": SanitizationType.EXPLICIT_VALIDATION,
    "is_safe": SanitizationType.EXPLICIT_VALIDATION,
    # Escape/transform
    "escape": SanitizationType.ESCAPE_TRANSFORM,
    "quote": SanitizationType.ESCAPE_TRANSFORM,
    "html.escape": SanitizationType.ESCAPE_TRANSFORM,
    "shlex.quote": SanitizationType.ESCAPE_TRANSFORM,
    "urllib.parse.quote": SanitizationType.ESCAPE_TRANSFORM,
    "markupsafe.escape": SanitizationType.ESCAPE_TRANSFORM,
    "bleach.clean": SanitizationType.ESCAPE_TRANSFORM,
}


class SourceClassifier(ast.NodeVisitor):
    """
    Phase 1: Classify taint sources within a function.

    Identifies:
    - Function parameters (FUNCTION_PARAM)
    - Environment variable access (ENV_VAR)
    - User input calls (USER_INPUT)
    - LLM output (LLM_OUTPUT)
    - Hardcoded values (HARDCODED - NOT tainted)
    """

    def __init__(self, func_node: ast.FunctionDef) -> None:
        self.func_node = func_node
        self.tainted_values: Dict[str, TaintedValue] = {}
        self._classify_params()

    def _classify_params(self) -> None:
        """Mark function parameters as tainted (from LLM/user input)."""
        for arg in self.func_node.args.args:
            param_name = arg.arg
            # Skip 'self' and 'cls'
            if param_name in ("self", "cls"):
                continue
            self.tainted_values[param_name] = TaintedValue(
                name=param_name,
                source=TaintSource.FUNCTION_PARAM,
                line=arg.lineno if hasattr(arg, "lineno") else self.func_node.lineno,
                original_param=param_name,
            )

    def classify(self) -> Dict[str, TaintedValue]:
        """Run classification and return tainted values."""
        self.visit(self.func_node)
        return self.tainted_values

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments that introduce new taint sources."""
        source_type = self._classify_value_source(node.value)

        if source_type != TaintSource.HARDCODED:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Check if derived from existing tainted variable
                    original_param = self._get_original_param(node.value)
                    self.tainted_values[var_name] = TaintedValue(
                        name=var_name,
                        source=source_type,
                        line=node.lineno,
                        original_param=original_param,
                    )
                elif isinstance(target, ast.Tuple):
                    # Handle tuple unpacking
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_values[elt.id] = TaintedValue(
                                name=elt.id,
                                source=source_type,
                                line=node.lineno,
                            )

        self.generic_visit(node)

    def _classify_value_source(self, node: ast.expr) -> TaintSource:
        """Classify the taint source of an expression."""
        # Hardcoded constants
        if isinstance(node, ast.Constant):
            return TaintSource.HARDCODED

        # Variable reference - check if already tainted
        # v0.14.0: Propagate original source type (e.g., LLM_OUTPUT) through derivations
        if isinstance(node, ast.Name):
            if node.id in self.tainted_values:
                original_source = self.tainted_values[node.id].source
                # Preserve semantically important source types
                if original_source in (TaintSource.LLM_OUTPUT, TaintSource.USER_INPUT,
                                       TaintSource.ENV_VAR, TaintSource.NETWORK):
                    return original_source
                return TaintSource.DERIVED
            return TaintSource.UNKNOWN

        # Function call - check for taint-introducing patterns
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                # Check env var patterns
                for pattern in ENV_VAR_PATTERNS:
                    if pattern in func_name or func_name.endswith(pattern.split(".")[-1]):
                        return TaintSource.ENV_VAR

                # Check user input patterns
                for pattern in USER_INPUT_PATTERNS:
                    if pattern in func_name or func_name.endswith(pattern.split(".")[-1]):
                        return TaintSource.USER_INPUT

                # Check LLM output patterns
                for pattern in LLM_OUTPUT_PATTERNS:
                    if pattern in func_name or func_name.endswith(pattern.split(".")[-1]):
                        return TaintSource.LLM_OUTPUT

            # Check if any argument is tainted
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_values:
                    return TaintSource.DERIVED

            # Check if method call on tainted object (e.g., cmd.strip())
            # v0.14.0: Propagate original source type through method chains
            if isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and receiver.id in self.tainted_values:
                    original_source = self.tainted_values[receiver.id].source
                    if original_source in (TaintSource.LLM_OUTPUT, TaintSource.USER_INPUT,
                                           TaintSource.ENV_VAR, TaintSource.NETWORK):
                        return original_source
                    return TaintSource.DERIVED
                # Handle chained calls (e.g., cmd.strip().lower())
                if isinstance(receiver, ast.Call):
                    receiver_source = self._classify_value_source(receiver)
                    if receiver_source != TaintSource.HARDCODED:
                        return receiver_source
                # v0.14.0: Handle subscript receivers (e.g., expression[6:].strip())
                if isinstance(receiver, ast.Subscript):
                    if isinstance(receiver.value, ast.Name) and receiver.value.id in self.tainted_values:
                        original_source = self.tainted_values[receiver.value.id].source
                        if original_source in (TaintSource.LLM_OUTPUT, TaintSource.USER_INPUT,
                                               TaintSource.ENV_VAR, TaintSource.NETWORK):
                            return original_source
                        return TaintSource.DERIVED

        # String operations that propagate taint
        # v0.14.0: Preserve original source type through concatenations
        if isinstance(node, ast.BinOp):
            left_source = self._classify_value_source(node.left)
            right_source = self._classify_value_source(node.right)
            # Prioritize semantically important source types
            for source in (left_source, right_source):
                if source in (TaintSource.LLM_OUTPUT, TaintSource.USER_INPUT,
                              TaintSource.ENV_VAR, TaintSource.NETWORK):
                    return source
            if left_source != TaintSource.HARDCODED:
                return left_source
            if right_source != TaintSource.HARDCODED:
                return right_source
            return TaintSource.HARDCODED

        # F-string - check formatted values
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    source = self._classify_value_source(value.value)
                    if source != TaintSource.HARDCODED:
                        return source
            return TaintSource.HARDCODED

        # Subscript (e.g., dict[key], list[idx])
        # v0.14.0: Preserve original source type through subscripts
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                if node.value.id in self.tainted_values:
                    original_source = self.tainted_values[node.value.id].source
                    if original_source in (TaintSource.LLM_OUTPUT, TaintSource.USER_INPUT,
                                           TaintSource.ENV_VAR, TaintSource.NETWORK):
                        return original_source
                    return TaintSource.DERIVED
            # Check for os.environ["KEY"]
            if isinstance(node.value, ast.Attribute):
                attr_name = self._get_attribute_chain(node.value)
                if "os.environ" in attr_name:
                    return TaintSource.ENV_VAR

        # Attribute access
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id in self.tainted_values:
                    return TaintSource.DERIVED

        return TaintSource.UNKNOWN

    def _get_original_param(self, node: ast.expr) -> Optional[str]:
        """Get the original function parameter if this is derived."""
        if isinstance(node, ast.Name):
            if node.id in self.tainted_values:
                tv = self.tainted_values[node.id]
                return tv.original_param or tv.name
        if isinstance(node, ast.BinOp):
            left_param = self._get_original_param(node.left)
            if left_param:
                return left_param
            return self._get_original_param(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    param = self._get_original_param(value.value)
                    if param:
                        return param
        return None

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._get_attribute_chain(node.func)
        return None

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain like 'os.environ.get'."""
        parts: List[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))


class DataFlowBuilder(ast.NodeVisitor):
    """
    Phase 2: Build intra-function data flow graph.

    Tracks data flow through:
    - Assignments: x = y
    - Call arguments: func(x)
    - String formatting: f"{x}", x.format(y), x + y
    - Attribute access: x.attr
    """

    def __init__(self, func_node: ast.FunctionDef) -> None:
        self.func_node = func_node
        self.edges: List[DataFlowEdge] = []
        self._call_counter = 0

    def build(self) -> List[DataFlowEdge]:
        """Build and return data flow edges."""
        self.visit(self.func_node)
        return self.edges

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignment data flow."""
        sources = self._extract_sources(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id
                for source in sources:
                    self.edges.append(
                        DataFlowEdge(
                            source=source,
                            target=target_name,
                            edge_type="assign",
                            line=node.lineno,
                        )
                    )
            elif isinstance(target, ast.Tuple):
                # Tuple unpacking - approximate by connecting all sources
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        for source in sources:
                            self.edges.append(
                                DataFlowEdge(
                                    source=source,
                                    target=elt.id,
                                    edge_type="assign",
                                    line=node.lineno,
                                )
                            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Track data flow into function calls."""
        func_name = self._get_call_name(node)
        if not func_name:
            func_name = "_unknown"

        self._call_counter += 1
        call_id = f"_call_{func_name}_{self._call_counter}"

        # Track positional arguments
        for i, arg in enumerate(node.args):
            sources = self._extract_sources(arg)
            for source in sources:
                self.edges.append(
                    DataFlowEdge(
                        source=source,
                        target=f"{call_id}_arg{i}",
                        edge_type="call_arg",
                        line=node.lineno,
                    )
                )

        # Track keyword arguments
        for kw in node.keywords:
            sources = self._extract_sources(kw.value)
            kw_name = kw.arg if kw.arg else "_kwargs"
            for source in sources:
                self.edges.append(
                    DataFlowEdge(
                        source=source,
                        target=f"{call_id}_{kw_name}",
                        edge_type="call_arg",
                        line=node.lineno,
                    )
                )

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Track f-string data flow."""
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                sources = self._extract_sources(value.value)
                for source in sources:
                    self.edges.append(
                        DataFlowEdge(
                            source=source,
                            target="_fstring_result",
                            edge_type="format",
                            line=node.lineno,
                        )
                    )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Track binary operation data flow (string concatenation, etc.)."""
        if isinstance(node.op, ast.Add):
            # Could be string concatenation
            left_sources = self._extract_sources(node.left)
            right_sources = self._extract_sources(node.right)
            for source in left_sources + right_sources:
                self.edges.append(
                    DataFlowEdge(
                        source=source,
                        target="_concat_result",
                        edge_type="concat",
                        line=node.lineno,
                    )
                )

        self.generic_visit(node)

    def _extract_sources(self, node: ast.expr) -> List[str]:
        """Extract variable names from an expression."""
        sources: List[str] = []

        if isinstance(node, ast.Name):
            sources.append(node.id)
        elif isinstance(node, ast.Attribute):
            # Track base object
            if isinstance(node.value, ast.Name):
                sources.append(node.value.id)
        elif isinstance(node, ast.BinOp):
            sources.extend(self._extract_sources(node.left))
            sources.extend(self._extract_sources(node.right))
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sources.extend(self._extract_sources(value.value))
        elif isinstance(node, ast.Call):
            for arg in node.args:
                sources.extend(self._extract_sources(arg))
            for kw in node.keywords:
                sources.extend(self._extract_sources(kw.value))
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                sources.append(node.value.id)

        return sources

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._get_attribute_chain(node.func)
        return None

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain."""
        parts: List[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))


class SanitizationDetector(ast.NodeVisitor):
    """
    Phase 3: Detect sanitization and validation operations.

    Identifies:
    - Conditional checks: if validate(x): use(x)
    - Assignment transforms: x = sanitize(x)
    - Type guards: if isinstance(x, str): use(x)
    - Allowlist checks: if x in ALLOWED: use(x)
    """

    def __init__(self, func_node: ast.FunctionDef) -> None:
        self.func_node = func_node
        self.sanitized_vars: Dict[str, Tuple[SanitizationType, int, Optional[int]]] = {}
        # Maps variable -> (sanitization_type, line, scope_end_line)
        self._current_scope_end: Optional[int] = None

    def detect(self) -> Dict[str, Tuple[SanitizationType, int, Optional[int]]]:
        """Run detection and return sanitized variables."""
        self.visit(self.func_node)
        return self.sanitized_vars

    def visit_If(self, node: ast.If) -> None:
        """Detect sanitization in if conditions."""
        sanitized = self._analyze_condition(node.test)

        if sanitized:
            # Check for guard pattern: if (not) condition: raise/return
            # Guard patterns sanitize for the REST of the function, not just the if body
            is_guard_pattern = self._is_guard_pattern(node)

            if is_guard_pattern:
                # Guard patterns extend sanitization to end of function
                scope_end = None
            else:
                # Normal patterns: sanitized within the if body only
                scope_end = self._get_block_end_line(node.body)

            for var_name, san_type in sanitized:
                self.sanitized_vars[var_name] = (san_type, node.lineno, scope_end)

        # Continue visiting
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)

    def _is_guard_pattern(self, node: ast.If) -> bool:
        """
        Check if the if statement is a guard pattern.

        Guard patterns are: if (not) condition: raise/return
        These validate and then bail out if invalid, meaning the code
        AFTER the if block is safe.
        """
        # Check if body is a single statement that exits (raise/return)
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, (ast.Raise, ast.Return)):
                return True
            # Handle: raise ValueError(...) or return None
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_name = self._get_call_name(stmt.value)
                if call_name and call_name in ("raise", "return"):
                    return True

        # Check for negative condition (if not ...: raise)
        if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
            if len(node.body) == 1 and isinstance(node.body[0], (ast.Raise, ast.Return)):
                return True

        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect sanitization via assignment."""
        if isinstance(node.value, ast.Call):
            func_name = self._get_call_name(node.value)
            if func_name:
                san_type = self._get_sanitization_type(func_name)
                if san_type:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Sanitization applies from this line onward
                            self.sanitized_vars[target.id] = (san_type, node.lineno, None)

        self.generic_visit(node)

    def _analyze_condition(
        self, node: ast.expr
    ) -> List[Tuple[str, SanitizationType]]:
        """Analyze a condition for sanitization patterns."""
        result: List[Tuple[str, SanitizationType]] = []

        # isinstance(x, ...)
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name == "isinstance" and len(node.args) >= 1:
                if isinstance(node.args[0], ast.Name):
                    result.append((node.args[0].id, SanitizationType.TYPE_CHECK))
            elif func_name:
                san_type = self._get_sanitization_type(func_name)
                if san_type:
                    # Extract variables from arguments
                    for arg in node.args:
                        if isinstance(arg, ast.Name):
                            result.append((arg.id, san_type))

                # Special handling for re.match, re.search, re.fullmatch
                # where the pattern is first arg and the string to validate is second
                if func_name in ("re.match", "re.search", "re.fullmatch", "match", "search", "fullmatch"):
                    if len(node.args) >= 2:
                        if isinstance(node.args[1], ast.Name):
                            result.append((node.args[1].id, SanitizationType.STRING_CHECK))
                    # Also check keyword args
                    for kw in node.keywords:
                        if kw.arg == "string" and isinstance(kw.value, ast.Name):
                            result.append((kw.value.id, SanitizationType.STRING_CHECK))

        # x in ALLOWED / x not in BLOCKED
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    if isinstance(node.left, ast.Name):
                        result.append(
                            (node.left.id, SanitizationType.ALLOWLIST_CHECK)
                        )

        # x.startswith(...), x.endswith(...), etc.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            if method_name in SANITIZATION_PATTERNS:
                if isinstance(node.func.value, ast.Name):
                    result.append(
                        (node.func.value.id, SANITIZATION_PATTERNS[method_name])
                    )

        # Boolean operations (and/or)
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                result.extend(self._analyze_condition(value))

        # Negation (not x)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            result.extend(self._analyze_condition(node.operand))

        return result

    def _get_sanitization_type(self, func_name: str) -> Optional[SanitizationType]:
        """Check if function name matches a sanitization pattern."""
        # Direct match
        if func_name in SANITIZATION_PATTERNS:
            return SANITIZATION_PATTERNS[func_name]

        # Partial match (e.g., validate_input, is_valid_email)
        simple_name = func_name.split(".")[-1].lower()
        for pattern, san_type in SANITIZATION_PATTERNS.items():
            if pattern in simple_name:
                return san_type

        return None

    def _get_block_end_line(self, body: List[ast.stmt]) -> Optional[int]:
        """Get the last line number of a code block."""
        if not body:
            return None
        last_stmt = body[-1]
        if hasattr(last_stmt, "end_lineno"):
            return last_stmt.end_lineno
        return last_stmt.lineno

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._get_attribute_chain(node.func)
        return None

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain."""
        parts: List[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))


class SinkReachabilityChecker:
    """
    Phase 4: Check if tainted values reach dangerous sinks.

    Uses BFS to propagate taint through data flow edges,
    checking for sanitization along the path.
    """

    def __init__(
        self,
        func_node: ast.FunctionDef,
        tainted_values: Dict[str, TaintedValue],
        data_flow_edges: List[DataFlowEdge],
        sanitized_vars: Dict[str, Tuple[SanitizationType, int, Optional[int]]],
    ) -> None:
        self.func_node = func_node
        self.tainted_values = tainted_values
        self.data_flow_edges = data_flow_edges
        self.sanitized_vars = sanitized_vars
        self._sink_calls: List[Tuple[str, str, int]] = []  # (func_name, sink_type, line)
        self._find_sink_calls()

    def _find_sink_calls(self) -> None:
        """Find all dangerous sink calls in the function."""
        for node in ast.walk(self.func_node):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name:
                    sink_type = self._get_sink_type(func_name)
                    if sink_type:
                        self._sink_calls.append((func_name, sink_type, node.lineno))

    def check(self) -> List[SinkReach]:
        """Check for tainted data reaching sinks."""
        results: List[SinkReach] = []

        # Build adjacency list from edges
        flow_graph: Dict[str, List[Tuple[str, int]]] = {}
        for edge in self.data_flow_edges:
            if edge.source not in flow_graph:
                flow_graph[edge.source] = []
            flow_graph[edge.source].append((edge.target, edge.line))

        # For each tainted value, check if it reaches a sink
        for var_name, tainted in self.tainted_values.items():
            # Skip hardcoded values (not actually tainted)
            if tainted.source == TaintSource.HARDCODED:
                continue

            # BFS from this tainted variable
            visited: Set[str] = set()
            queue: List[Tuple[str, List[str], int]] = [(var_name, [var_name], tainted.line)]

            while queue:
                current, path, current_line = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                # Check if current reaches a sink call
                for sink_func, sink_type_name, sink_line in self._sink_calls:
                    sink_type = SinkType(sink_type_name)
                    # Check if current variable is used in this sink call
                    if self._var_used_in_call(current, sink_func, sink_line):
                        # Check sanitization
                        is_sanitized = self._is_sanitized_at_line(var_name, sink_line)

                        # Calculate confidence
                        confidence = self._calculate_confidence(
                            tainted.source, len(path), is_sanitized
                        )

                        results.append(
                            SinkReach(
                                tainted_var=var_name,
                                sink_function=sink_func,
                                sink_type=sink_type,
                                line=sink_line,
                                is_sanitized=is_sanitized,
                                flow_path=path.copy(),
                                source=tainted.source,
                                confidence=confidence,
                            )
                        )

                # Continue BFS through flow edges
                if current in flow_graph:
                    for next_var, edge_line in flow_graph[current]:
                        if next_var not in visited:
                            queue.append((next_var, path + [next_var], edge_line))

        return results

    def _var_used_in_call(self, var_name: str, func_name: str, line: int) -> bool:
        """Check if variable is used in a specific call."""
        # Check data flow edges for call_arg edges to this function
        for edge in self.data_flow_edges:
            if edge.line == line and edge.edge_type == "call_arg":
                if edge.source == var_name:
                    return True
                # Check if target is for this function
                if func_name.replace(".", "_") in edge.target or "_call_" in edge.target:
                    if edge.source == var_name:
                        return True

        # Also check direct variable usage (simple heuristic)
        for node in ast.walk(self.func_node):
            if isinstance(node, ast.Call) and node.lineno == line:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == var_name:
                        return True
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                        return True

        return False

    def _is_sanitized_at_line(self, var_name: str, line: int) -> bool:
        """Check if variable is sanitized at a given line."""
        if var_name not in self.sanitized_vars:
            return False

        san_type, san_line, scope_end = self.sanitized_vars[var_name]

        # Sanitization must occur before the sink
        if san_line > line:
            return False

        # If scope_end is set, check if sink is within scope
        if scope_end is not None and line > scope_end:
            return False

        return True

    def _calculate_confidence(
        self, source: TaintSource, path_length: int, is_sanitized: bool
    ) -> float:
        """Calculate confidence score for the finding."""
        # Base confidence by source type
        base_confidence = {
            TaintSource.FUNCTION_PARAM: 0.90,
            TaintSource.USER_INPUT: 0.95,
            TaintSource.ENV_VAR: 0.70,
            TaintSource.NETWORK: 0.85,
            TaintSource.FILE_READ: 0.75,
            TaintSource.LLM_OUTPUT: 0.90,
            TaintSource.DERIVED: 0.85,
            TaintSource.UNKNOWN: 0.50,
            TaintSource.HARDCODED: 0.10,
        }.get(source, 0.50)

        # Reduce confidence for longer paths
        path_penalty = max(0, (path_length - 1) * 0.05)
        confidence = base_confidence - path_penalty

        # Significantly reduce if sanitized
        if is_sanitized:
            confidence *= 0.20

        return max(0.10, min(0.99, confidence))

    def _get_sink_type(self, func_name: str) -> Optional[str]:
        """Get sink type for a function name."""
        # Direct match
        if func_name in DANGEROUS_SINKS:
            return DANGEROUS_SINKS[func_name].value

        # Partial match for generic patterns
        simple_name = func_name.split(".")[-1]
        for pattern, sink_type in DANGEROUS_SINKS.items():
            if pattern.endswith(simple_name):
                return sink_type.value

        return None

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._get_attribute_chain(node.func)
        return None

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain."""
        parts: List[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))


class TaintTracker:
    """
    Main orchestrator for taint analysis.

    Combines all phases:
    1. SourceClassifier - Identify taint sources
    2. DataFlowBuilder - Build data flow graph
    3. SanitizationDetector - Find sanitization points
    4. SinkReachabilityChecker - Check taint reaching sinks
    """

    def __init__(self, func_node: ast.FunctionDef) -> None:
        self.func_node = func_node

    def analyze(self) -> TaintAnalysisResult:
        """Run full taint analysis on the function."""
        notes: List[str] = []

        # Phase 1: Classify sources
        classifier = SourceClassifier(self.func_node)
        tainted_values = classifier.classify()
        notes.append(f"Found {len(tainted_values)} tainted values")

        # Phase 2: Build data flow
        flow_builder = DataFlowBuilder(self.func_node)
        data_flow_edges = flow_builder.build()
        notes.append(f"Built {len(data_flow_edges)} data flow edges")

        # Phase 3: Detect sanitization
        san_detector = SanitizationDetector(self.func_node)
        sanitized_vars = san_detector.detect()
        notes.append(f"Found {len(sanitized_vars)} sanitization points")

        # Phase 4: Check sink reachability
        sink_checker = SinkReachabilityChecker(
            self.func_node, tainted_values, data_flow_edges, sanitized_vars
        )
        dangerous_flows = sink_checker.check()
        notes.append(f"Found {len(dangerous_flows)} flows to sinks")

        # Determine if there are unsanitized flows
        unsanitized_flows = [f for f in dangerous_flows if not f.is_sanitized]
        has_unsanitized = len(unsanitized_flows) > 0

        # Calculate overall confidence
        if unsanitized_flows:
            confidence = max(f.confidence for f in unsanitized_flows)
        elif dangerous_flows:
            confidence = max(f.confidence for f in dangerous_flows) * 0.30
        else:
            confidence = 0.0

        # Extract tainted parameter names
        tainted_params = [
            name
            for name, tv in tainted_values.items()
            if tv.source == TaintSource.FUNCTION_PARAM
        ]

        # Convert sanitization info
        sanitization_points = {
            var: (san_type, line)
            for var, (san_type, line, _) in sanitized_vars.items()
        }

        return TaintAnalysisResult(
            function_name=self.func_node.name,
            tainted_params=tainted_params,
            dangerous_flows=dangerous_flows,
            sanitization_points=sanitization_points,
            has_unsanitized_flow=has_unsanitized,
            confidence=confidence,
            analysis_notes=notes,
        )
