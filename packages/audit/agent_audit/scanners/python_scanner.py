"""Python AST scanner for detecting dangerous patterns in agent code."""

import ast
import fnmatch
import logging
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field

from agent_audit.scanners.base import BaseScanner, ScanResult
from agent_audit.models.tool import ToolDefinition, PermissionType, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class PythonScanResult(ScanResult):
    """Python scan result with extracted tools and patterns."""
    tools: List[ToolDefinition] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    function_calls: List[Dict[str, Any]] = field(default_factory=list)
    dangerous_patterns: List[Dict[str, Any]] = field(default_factory=list)


class PythonScanner(BaseScanner):
    """
    Python code scanner using the built-in ast module.

    Detects:
    - Dangerous function calls (os.system, subprocess with shell=True, eval, exec)
    - @tool decorators and BaseTool subclasses
    - Tainted input flowing to dangerous functions
    - Import aliases for tracking function origins
    """

    name = "Python Scanner"

    # Dangerous function mapping to permission types
    DANGEROUS_FUNCTIONS = {
        'os.system': PermissionType.SHELL_EXEC,
        'os.popen': PermissionType.SHELL_EXEC,
        'subprocess.run': PermissionType.SHELL_EXEC,
        'subprocess.Popen': PermissionType.SHELL_EXEC,
        'subprocess.call': PermissionType.SHELL_EXEC,
        'subprocess.check_output': PermissionType.SHELL_EXEC,
        'subprocess.check_call': PermissionType.SHELL_EXEC,
        'eval': PermissionType.SHELL_EXEC,
        'exec': PermissionType.SHELL_EXEC,
        'open': PermissionType.FILE_READ,
        'os.remove': PermissionType.FILE_DELETE,
        'os.unlink': PermissionType.FILE_DELETE,
        'os.rmdir': PermissionType.FILE_DELETE,
        'shutil.rmtree': PermissionType.FILE_DELETE,
        'shutil.move': PermissionType.FILE_WRITE,
        'shutil.copy': PermissionType.FILE_WRITE,
        'requests.get': PermissionType.NETWORK_OUTBOUND,
        'requests.post': PermissionType.NETWORK_OUTBOUND,
        'requests.put': PermissionType.NETWORK_OUTBOUND,
        'requests.delete': PermissionType.NETWORK_OUTBOUND,
        'httpx.get': PermissionType.NETWORK_OUTBOUND,
        'httpx.post': PermissionType.NETWORK_OUTBOUND,
        'aiohttp.ClientSession': PermissionType.NETWORK_OUTBOUND,
        'urllib.request.urlopen': PermissionType.NETWORK_OUTBOUND,
    }

    # Tool decorator names to detect
    TOOL_DECORATORS = {'tool', 'langchain.tools.tool', 'langchain_core.tools.tool'}

    # Base classes for tool detection
    TOOL_BASE_CLASSES = {'BaseTool', 'StructuredTool'}

    def __init__(
        self,
        exclude_patterns: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None  # Backward compatibility alias
    ):
        """
        Initialize the Python scanner.

        Args:
            exclude_patterns: Glob patterns to exclude from scanning (e.g., "tests/**")
            exclude_paths: Deprecated alias for exclude_patterns (backward compatibility)
        """
        # Support both parameter names for backward compatibility
        self.exclude_patterns = exclude_patterns or exclude_paths or []

    def scan(self, path: Path) -> List[PythonScanResult]:
        """
        Scan a path for Python files and analyze them.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results
        """
        results = []
        python_files = self._find_python_files(path)

        for py_file in python_files:
            result = self._scan_file(py_file)
            if result:
                results.append(result)

        return results

    def _find_python_files(self, path: Path) -> List[Path]:
        """Find all Python files to scan."""
        if path.is_file():
            return [path] if path.suffix == '.py' else []

        python_files = []
        for py_file in path.rglob('*.py'):
            rel_path = str(py_file.relative_to(path))

            # Skip excluded paths using glob patterns
            if self._should_exclude(rel_path):
                continue

            # Skip common non-source directories
            skip_dirs = {'.git', 'venv', '.venv', '__pycache__', 'dist',
                        'build', 'node_modules', '.tox', '.pytest_cache'}
            if any(part in skip_dirs for part in py_file.parts):
                continue

            # Skip hidden directories (but not . or ..)
            if any(part.startswith('.') and part not in {'.', '..'}
                  for part in py_file.parts):
                continue

            python_files.append(py_file)

        return python_files

    def _should_exclude(self, rel_path: str) -> bool:
        """Check if a relative path matches any exclude pattern."""
        # Normalize path separators
        normalized_path = rel_path.replace('\\', '/')

        for pattern in self.exclude_patterns:
            normalized_pattern = pattern.replace('\\', '/')

            # Simple substring matching (backward compatibility)
            if normalized_pattern in normalized_path:
                return True

            # Direct fnmatch for glob patterns
            if fnmatch.fnmatch(normalized_path, normalized_pattern):
                return True

            # Handle "tests/**" style patterns
            if normalized_pattern.endswith('/**'):
                prefix = normalized_pattern[:-3]
                if normalized_path.startswith(prefix + '/') or normalized_path == prefix:
                    return True

            # Handle "**/test_*" style patterns
            if normalized_pattern.startswith('**/'):
                suffix_pattern = normalized_pattern[3:]
                # Match against filename
                filename = Path(normalized_path).name
                if fnmatch.fnmatch(filename, suffix_pattern):
                    return True
                # Match against any path segment
                for part in Path(normalized_path).parts:
                    if fnmatch.fnmatch(part, suffix_pattern):
                        return True

        return False

    def _scan_file(self, file_path: Path) -> Optional[PythonScanResult]:
        """Scan a single Python file."""
        try:
            source = file_path.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return None
        except UnicodeDecodeError as e:
            logger.warning(f"Encoding error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

        visitor = PythonASTVisitor(file_path, source)
        visitor.visit(tree)

        return PythonScanResult(
            source_file=str(file_path),
            tools=visitor.tools,
            imports=visitor.imports,
            function_calls=visitor.function_calls,
            dangerous_patterns=visitor.dangerous_patterns
        )


class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor that extracts security-relevant information."""

    # Prompt-related function names for ASI-01 detection
    PROMPT_FUNCTIONS: Set[str] = {
        'SystemMessage', 'HumanMessage', 'AIMessage',
        'ChatPromptTemplate', 'PromptTemplate',
        'SystemMessagePromptTemplate',
        'from_messages', 'from_template',
    }

    # Variable names that typically hold system prompts
    SYSTEM_PROMPT_VARNAMES: Set[str] = {
        'system_prompt', 'system_message', 'instructions',
        'system_instructions', 'agent_prompt', 'system_content',
        'sys_prompt', 'base_prompt',
    }

    # Memory write functions for ASI-06 detection
    MEMORY_WRITE_FUNCTIONS: Set[str] = {
        'add_documents', 'add_texts', 'upsert', 'insert',
        'persist', 'save_context', 'add_message', 'add_memory',
        'store', 'put', 'set',
    }

    # Unbounded memory classes for ASI-06 detection
    UNBOUNDED_MEMORY_CLASSES: Set[str] = {
        'ConversationBufferMemory',
        'ConversationSummaryMemory',
        'ChatMessageHistory',
    }

    # Agent constructor functions for ASI-08/10 detection
    AGENT_CONSTRUCTORS: Set[str] = {
        'AgentExecutor', 'initialize_agent', 'create_react_agent',
        'create_openai_functions_agent', 'Crew',
    }

    # Auto-approval keywords for ASI-03 detection
    AUTO_APPROVAL_KEYWORDS: Set[str] = {
        'trust_all_tools', 'auto_approve', 'no_confirm',
        'skip_approval', 'dangerously_skip_permissions',
        'no_interactive', 'trust_all',
    }

    # Multi-agent classes for ASI-07 detection
    MULTI_AGENT_CLASSES: Set[str] = {
        'GroupChat', 'GroupChatManager', 'ConversableAgent',
        'Crew', 'Agent',
    }

    # Authentication-related keyword arguments for ASI-07 detection
    AUTH_KEYWORDS: Set[str] = {
        'authentication', 'tls', 'verify', 'auth',
        'secure_channel', 'ssl', 'https',
    }

    # Agent communication context keywords for ASI-07 detection
    AGENT_COMM_KEYWORDS: Set[str] = {
        'agent', 'delegate', 'handoff', 'message',
        'endpoint', 'server', 'worker', 'peer',
    }

    # Transparency-related keyword arguments for ASI-09 detection
    TRANSPARENCY_KEYWORDS: Set[str] = {
        'return_intermediate_steps', 'verbose',
        'return_source_documents', 'include_reasoning',
    }

    # External call functions for ASI-08 tool error handling detection
    EXTERNAL_CALL_FUNCTIONS: Set[str] = {
        'requests.get', 'requests.post', 'requests.put', 'requests.delete',
        'httpx.get', 'httpx.post', 'httpx.put', 'httpx.delete',
        'urllib.request.urlopen', 'aiohttp.ClientSession',
        'subprocess.run', 'subprocess.Popen', 'subprocess.call',
        'os.system', 'os.popen',
        'open',
    }

    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()

        self.tools: List[ToolDefinition] = []
        self.imports: List[str] = []
        self.function_calls: List[Dict[str, Any]] = []
        self.dangerous_patterns: List[Dict[str, Any]] = []

        # Track import aliases (e.g., import subprocess as sp)
        self._imported_names: Dict[str, str] = {}
        # Track current function context for taint analysis
        self._current_function: Optional[str] = None
        self._current_function_params: Set[str] = set()
        # Track current class for tool detection
        self._current_class: Optional[str] = None
        # Track if inside @tool decorated function (ASI-05)
        self._in_tool_function: bool = False

    def visit_Import(self, node: ast.Import):
        """Track imports like 'import subprocess'."""
        for alias in node.names:
            self.imports.append(alias.name)
            name = alias.asname or alias.name
            self._imported_names[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track imports like 'from subprocess import run'."""
        module = node.module or ''
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full_name)
            name = alias.asname or alias.name
            self._imported_names[name] = full_name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definitions to detect BaseTool subclasses."""
        old_class = self._current_class
        self._current_class = node.name

        # Check if this class inherits from a tool base class
        is_tool_class = False
        for base in node.bases:
            base_name = self._get_name(base)
            if base_name and base_name in PythonScanner.TOOL_BASE_CLASSES:
                is_tool_class = True
                break

        if is_tool_class:
            tool = self._extract_tool_from_class(node)
            if tool:
                self.tools.append(tool)

        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definitions to detect @tool decorators."""
        old_func = self._current_function
        old_params = self._current_function_params
        old_in_tool = self._in_tool_function

        self._current_function = node.name
        self._current_function_params = {
            arg.arg for arg in node.args.args
        }

        # Check for @tool decorator
        is_tool = self._has_tool_decorator(node)
        self._in_tool_function = is_tool

        if is_tool:
            tool = self._extract_tool_from_function(node)
            if tool:
                self.tools.append(tool)

            # ASI-08: Check for tool without error handling
            err_finding = self._check_tool_without_error_handling(node)
            if err_finding:
                self.dangerous_patterns.append(err_finding)

        self.generic_visit(node)

        self._current_function = old_func
        self._current_function_params = old_params
        self._in_tool_function = old_in_tool

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async function definitions the same as regular functions."""
        # Reuse the same logic as FunctionDef - cast to satisfy type checker
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Assign(self, node: ast.Assign):
        """Visit assignment statements to detect system prompt concatenation."""
        # ASI-01: Check for system prompt constructed via string operations
        finding = self._check_system_prompt_concat(node)
        if finding:
            self.dangerous_patterns.append(finding)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit function calls to detect dangerous patterns."""
        func_name = self._get_call_name(node)

        if func_name:
            call_info = {
                'name': func_name,
                'line': node.lineno,
                'in_function': self._current_function,
                'in_class': self._current_class,
            }
            self.function_calls.append(call_info)

            # Check if this is a dangerous function
            if func_name in PythonScanner.DANGEROUS_FUNCTIONS:
                pattern = {
                    'type': 'dangerous_function_call',
                    'function': func_name,
                    'permission': PythonScanner.DANGEROUS_FUNCTIONS[func_name],
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'has_tainted_input': self._check_tainted_input(node),
                    'in_function': self._current_function,
                }
                self.dangerous_patterns.append(pattern)

            # Check for subprocess with shell=True
            if func_name in {'subprocess.run', 'subprocess.Popen',
                            'subprocess.call', 'subprocess.check_output',
                            'subprocess.check_call'}:
                if self._has_shell_true(node):
                    pattern = {
                        'type': 'shell_true',
                        'function': func_name,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'has_tainted_input': self._check_tainted_input(node),
                        'in_function': self._current_function,
                    }
                    self.dangerous_patterns.append(pattern)

            # === OWASP Agentic Top 10 detections ===

            # ASI-01: Prompt injection vector
            pi_finding = self._check_prompt_injection_vector(node)
            if pi_finding:
                self.dangerous_patterns.append(pi_finding)

            # ASI-03: Excessive tools / auto-approval
            et_finding = self._check_excessive_tools(node)
            if et_finding:
                self.dangerous_patterns.append(et_finding)

            # ASI-05: Unsandboxed code execution in tool context
            rce_finding = self._check_unsandboxed_code_exec(node)
            if rce_finding:
                self.dangerous_patterns.append(rce_finding)

            # ASI-06: Memory poisoning
            mem_finding = self._check_memory_poisoning(node)
            if mem_finding:
                self.dangerous_patterns.append(mem_finding)

            mem_unbound = self._check_unbounded_memory(node)
            if mem_unbound:
                self.dangerous_patterns.append(mem_unbound)

            # ASI-08: Missing circuit breaker
            cb_finding = self._check_missing_circuit_breaker(node)
            if cb_finding:
                self.dangerous_patterns.append(cb_finding)

            # ASI-10: Missing kill switch / observability
            ks_finding = self._check_missing_kill_switch(node)
            if ks_finding:
                self.dangerous_patterns.append(ks_finding)

            obs_finding = self._check_missing_observability(node)
            if obs_finding:
                self.dangerous_patterns.append(obs_finding)

            # ASI-07: Inter-agent communication without authentication
            ia_finding = self._check_multi_agent_no_auth(node)
            if ia_finding:
                self.dangerous_patterns.append(ia_finding)

            # ASI-07: Unencrypted agent communication
            tls_finding = self._check_agent_comm_no_tls(node)
            if tls_finding:
                self.dangerous_patterns.append(tls_finding)

            # ASI-09: Opaque agent output
            oa_finding = self._check_opaque_agent_output(node)
            if oa_finding:
                self.dangerous_patterns.append(oa_finding)

        self.generic_visit(node)

    def _has_tool_decorator(self, node: ast.FunctionDef) -> bool:
        """Check if a function has a tool decorator."""
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name and any(t in dec_name for t in PythonScanner.TOOL_DECORATORS):
                return True
        return False

    def _extract_tool_from_function(self, node: ast.FunctionDef) -> Optional[ToolDefinition]:
        """Extract a ToolDefinition from a @tool decorated function."""
        description = ast.get_docstring(node) or ""
        permissions = self._analyze_function_permissions(node)

        # Extract parameters from function signature
        parameters = []
        for arg in node.args.args:
            if arg.arg == 'self':
                continue
            param = ToolParameter(
                name=arg.arg,
                type=self._get_annotation_type(arg.annotation),
                required=True,  # Default to required
                allows_arbitrary_input=True,  # Conservative assumption
            )
            parameters.append(param)

        tool = ToolDefinition(
            name=node.name,
            description=description,
            source_file=str(self.file_path),
            source_line=node.lineno,
            permissions=permissions,
            parameters=parameters,
            has_input_validation=self._check_input_validation(node),
        )
        tool.update_capability_flags()
        tool.risk_level = tool.infer_risk_level()

        return tool

    def _extract_tool_from_class(self, node: ast.ClassDef) -> Optional[ToolDefinition]:
        """Extract a ToolDefinition from a BaseTool subclass."""
        description = ast.get_docstring(node) or ""

        # Find the _run method to analyze permissions
        permissions: Set[PermissionType] = set()
        has_validation = False

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in ('_run', '_arun', 'run', 'arun'):
                    permissions.update(self._analyze_function_permissions(item))  # type: ignore[arg-type]
                    has_validation = has_validation or self._check_input_validation(item)  # type: ignore[arg-type]

        tool = ToolDefinition(
            name=node.name,
            description=description,
            source_file=str(self.file_path),
            source_line=node.lineno,
            permissions=permissions,
            has_input_validation=has_validation,
        )
        tool.update_capability_flags()
        tool.risk_level = tool.infer_risk_level()

        return tool

    def _analyze_function_permissions(self, node: ast.FunctionDef) -> Set[PermissionType]:
        """Analyze a function body to infer required permissions."""
        permissions: Set[PermissionType] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_call_name(child)
                if func_name and func_name in PythonScanner.DANGEROUS_FUNCTIONS:
                    permissions.add(PythonScanner.DANGEROUS_FUNCTIONS[func_name])

        return permissions

    def _check_tainted_input(self, node: ast.Call) -> bool:
        """
        Check if a function call uses tainted (user-controlled) input.

        This is a simplified taint analysis that checks if any argument
        comes from function parameters.
        """
        if not self._current_function_params:
            return False

        for arg in node.args:
            if self._contains_tainted_var(arg):
                return True

        for keyword in node.keywords:
            if self._contains_tainted_var(keyword.value):
                return True

        return False

    def _contains_tainted_var(self, node: ast.expr) -> bool:
        """Check if an expression contains a tainted variable."""
        if isinstance(node, ast.Name):
            return node.id in self._current_function_params

        if isinstance(node, ast.JoinedStr):
            # f-strings might contain tainted variables
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self._contains_tainted_var(value.value):
                        return True
            return False

        if isinstance(node, ast.BinOp):
            # String concatenation
            return (self._contains_tainted_var(node.left) or
                   self._contains_tainted_var(node.right))

        if isinstance(node, ast.Call):
            # Check arguments of nested calls
            for arg in node.args:
                if self._contains_tainted_var(arg):
                    return True

        return False

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if a subprocess call has shell=True."""
        for keyword in node.keywords:
            if keyword.arg == 'shell':
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is True
                if isinstance(keyword.value, ast.NameConstant):  # Python 3.7 compat
                    return keyword.value.value is True
        return False

    def _check_input_validation(self, node: ast.FunctionDef) -> bool:
        """
        Check if a function has input validation.

        Looks for assert statements, raise statements, or type checking.
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                return True
            if isinstance(child, ast.Raise):
                return True
            if isinstance(child, ast.Call):
                func_name = self._get_call_name(child)
                if func_name and any(v in func_name.lower() for v in
                                    ['validate', 'check', 'verify', 'sanitize']):
                    return True

        return False

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the full name of a function being called."""
        if isinstance(node.func, ast.Name):
            name = node.func.id
            # Resolve import alias
            return self._imported_names.get(name, name)

        elif isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                parts.reverse()
                full_name = '.'.join(parts)

                # Check if base name is aliased
                base = parts[0]
                if base in self._imported_names:
                    parts[0] = self._imported_names[base]
                    return '.'.join(parts)

                return full_name

        return None

    def _get_name(self, node: ast.expr) -> Optional[str]:
        """Get the name from a Name or Attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _get_decorator_name(self, decorator: ast.expr) -> Optional[str]:
        """Get the name of a decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return None

    def _get_annotation_type(self, annotation: Optional[ast.expr]) -> str:
        """Convert an annotation to a type string."""
        if annotation is None:
            return "Any"
        if isinstance(annotation, ast.Name):
            return annotation.id
        if isinstance(annotation, ast.Constant):
            return str(annotation.value)
        if isinstance(annotation, ast.Subscript):
            # Handle generic types like List[str]
            return ast.unparse(annotation) if hasattr(ast, 'unparse') else "Generic"
        return "Any"

    def _get_line(self, lineno: int) -> str:
        """Get a source line by number."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    # =========================================================================
    # OWASP Agentic Top 10 Detection Methods
    # =========================================================================

    def _check_prompt_injection_vector(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-01: Detect prompt functions containing f-strings or format calls.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Check if this is a prompt-related function
        is_prompt_func = any(pf in func_name for pf in self.PROMPT_FUNCTIONS)
        if not is_prompt_func:
            return None

        # Check arguments for f-strings (JoinedStr)
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                return {
                    'type': 'prompt_injection_fstring',
                    'function': func_name,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'risk': 'User input may be interpolated into prompt via f-string',
                    'owasp_id': 'ASI-01',
                }

        # Check keyword arguments for f-strings
        for kw in node.keywords:
            if kw.arg in ('content', 'template', 'messages', 'system_message'):
                if isinstance(kw.value, ast.JoinedStr):
                    return {
                        'type': 'prompt_injection_fstring_kwarg',
                        'function': func_name,
                        'keyword': kw.arg,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-01',
                    }

        # Check for .format() calls in arguments
        for arg in node.args:
            if isinstance(arg, ast.Call):
                inner_name = self._get_call_name(arg)
                if inner_name and inner_name.endswith('.format'):
                    return {
                        'type': 'prompt_injection_format',
                        'function': func_name,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-01',
                    }

        return None

    def _check_system_prompt_concat(self, node: ast.Assign) -> Optional[Dict[str, Any]]:
        """
        ASI-01: Detect system_prompt variable constructed via string concatenation.

        Returns a finding dict if vulnerable, None otherwise.
        """
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            varname = target.id.lower()
            if varname not in self.SYSTEM_PROMPT_VARNAMES:
                continue

            # Check for f-string
            if isinstance(node.value, ast.JoinedStr):
                return {
                    'type': 'system_prompt_fstring',
                    'variable': target.id,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-01',
                }

            # Check for + concatenation
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                return {
                    'type': 'system_prompt_concat',
                    'variable': target.id,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-01',
                }

            # Check for .format() call
            if isinstance(node.value, ast.Call):
                call_name = self._get_call_name(node.value)
                if call_name and call_name.endswith('.format'):
                    return {
                        'type': 'system_prompt_format',
                        'variable': target.id,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-01',
                    }

        return None

    def _check_excessive_tools(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-03: Detect agents with too many tools or auto-approval mode.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if not any(ac in func_name for ac in self.AGENT_CONSTRUCTORS):
            return None

        # Check tools parameter for excessive count
        for kw in node.keywords:
            if kw.arg == 'tools':
                if isinstance(kw.value, ast.List) and len(kw.value.elts) > 10:
                    return {
                        'type': 'excessive_tools',
                        'function': func_name,
                        'tool_count': len(kw.value.elts),
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-03',
                    }

            # Check for auto-approval keywords
            if kw.arg:
                arg_lower = kw.arg.lower().replace('-', '_')
                if arg_lower in self.AUTO_APPROVAL_KEYWORDS:
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return {
                            'type': 'auto_approval',
                            'keyword': kw.arg,
                            'function': func_name,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-03',
                        }

        return None

    def _check_unsandboxed_code_exec(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-05: Detect eval/exec inside @tool decorated functions.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if func_name not in ('eval', 'exec', 'compile'):
            return None

        # Only flag if inside a tool function
        if self._in_tool_function:
            return {
                'type': 'unsandboxed_code_exec_in_tool',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-05',
            }

        return None

    def _check_memory_poisoning(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-06: Detect unsanitized writes to vector databases or memory stores.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Extract method name (last part after dot)
        method_name = func_name.split('.')[-1] if '.' in func_name else func_name

        if method_name not in self.MEMORY_WRITE_FUNCTIONS:
            return None

        # Check if arguments contain variable references (potential user input)
        has_variable_input = False
        for arg in node.args:
            if isinstance(arg, (ast.Name, ast.Subscript, ast.Attribute)):
                has_variable_input = True
                break
            if isinstance(arg, ast.List):
                for elt in arg.elts:
                    if isinstance(elt, (ast.Name, ast.Subscript, ast.Attribute)):
                        has_variable_input = True
                        break

        if has_variable_input:
            return {
                'type': 'unsanitized_memory_write',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-06',
            }

        return None

    def _check_unbounded_memory(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-06: Detect unbounded memory configurations.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if func_name not in self.UNBOUNDED_MEMORY_CLASSES:
            return None

        # Check if memory has bounds configured
        has_limit = False
        for kw in node.keywords:
            if kw.arg in ('k', 'max_token_limit', 'max_history', 'window_size'):
                has_limit = True
                break

        if not has_limit:
            return {
                'type': 'unbounded_memory',
                'class': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-06',
            }

        return None

    def _check_missing_circuit_breaker(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-08: Detect AgentExecutor without max_iterations or timeout.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if func_name not in self.AGENT_CONSTRUCTORS:
            return None

        has_limit = False
        for kw in node.keywords:
            if kw.arg in ('max_iterations', 'max_execution_time', 'max_steps', 'timeout'):
                has_limit = True
                break

        if not has_limit:
            return {
                'type': 'missing_circuit_breaker',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-08',
            }

        return None

    def _check_missing_kill_switch(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-10: Detect agent without kill switch (execution limits).

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if func_name not in self.AGENT_CONSTRUCTORS:
            return None

        kw_names = {kw.arg for kw in node.keywords if kw.arg}

        # Check for kill switch params
        kill_switch_params = {'max_iterations', 'max_execution_time', 'timeout', 'early_stopping_method'}
        has_kill_switch = bool(kw_names & kill_switch_params)

        if not has_kill_switch:
            return {
                'type': 'no_kill_switch',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-10',
            }

        return None

    def _check_missing_observability(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-10: Detect agent without observability (callbacks, verbose, logging).

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        if func_name not in self.AGENT_CONSTRUCTORS:
            return None

        kw_names = {kw.arg for kw in node.keywords if kw.arg}

        # Check for observability params
        observability_params = {'callbacks', 'callback_manager', 'verbose'}
        has_observability = bool(kw_names & observability_params)

        if not has_observability:
            return {
                'type': 'no_observability',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-10',
            }

        return None

    def _check_multi_agent_no_auth(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-07: Detect multi-agent classes without authentication configuration.

        Checks GroupChat, GroupChatManager, ConversableAgent (autogen) or
        Crew, Agent (crewai) instantiation for missing auth-related params.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Check if this is a multi-agent class
        if func_name not in self.MULTI_AGENT_CLASSES:
            return None

        # Check for authentication-related keyword arguments
        kw_names = {kw.arg.lower() for kw in node.keywords if kw.arg}
        has_auth = bool(kw_names & self.AUTH_KEYWORDS)

        if not has_auth:
            return {
                'type': 'multi_agent_no_auth',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-07',
            }

        return None

    def _check_agent_comm_no_tls(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-07: Detect agent communication over unencrypted HTTP.

        Checks for http:// string literals in contexts related to agent communication.

        Returns a finding dict if vulnerable, None otherwise.
        """
        # Check string arguments for http:// URLs
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith('http://'):
                    # Check if in agent communication context
                    func_name = self._get_call_name(node) or ''
                    in_agent_context = any(
                        kw in func_name.lower() for kw in self.AGENT_COMM_KEYWORDS
                    )
                    # Also check current function name
                    if self._current_function:
                        in_agent_context = in_agent_context or any(
                            kw in self._current_function.lower()
                            for kw in self.AGENT_COMM_KEYWORDS
                        )
                    # Check keyword argument names
                    for kw in node.keywords:
                        if kw.arg and any(
                            ak in kw.arg.lower() for ak in self.AGENT_COMM_KEYWORDS
                        ):
                            in_agent_context = True
                            break

                    if in_agent_context:
                        return {
                            'type': 'agent_comm_no_tls',
                            'url': arg.value,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-07',
                            'confidence': 0.6,  # Lower confidence
                        }

        # Also check keyword arguments
        for kw in node.keywords:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if kw.value.value.startswith('http://'):
                    if kw.arg and any(
                        ak in kw.arg.lower() for ak in self.AGENT_COMM_KEYWORDS
                    ):
                        return {
                            'type': 'agent_comm_no_tls',
                            'url': kw.value.value,
                            'keyword': kw.arg,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-07',
                            'confidence': 0.6,
                        }

        return None

    def _check_opaque_agent_output(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        ASI-09: Detect AgentExecutor without transparency configuration.

        Checks for missing return_intermediate_steps, verbose, or similar params.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Only check AgentExecutor specifically for transparency
        if func_name != 'AgentExecutor':
            return None

        # Check for transparency-related keyword arguments
        kw_names = {kw.arg for kw in node.keywords if kw.arg}
        has_transparency = bool(kw_names & self.TRANSPARENCY_KEYWORDS)

        if not has_transparency:
            return {
                'type': 'opaque_agent_output',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-09',
            }

        return None

    def _check_tool_without_error_handling(
        self, node: ast.FunctionDef
    ) -> Optional[Dict[str, Any]]:
        """
        ASI-08: Detect @tool decorated functions without try/except.

        Checks if a tool function calls external operations (network, file, subprocess)
        without proper error handling.

        Args:
            node: Function definition AST node

        Returns a finding dict if vulnerable, None otherwise.
        """
        # Must have @tool decorator
        if not self._has_tool_decorator(node):
            return None

        # Check if function calls external operations
        has_external_call = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    # Check full name or method name suffix
                    if call_name in self.EXTERNAL_CALL_FUNCTIONS or any(
                        call_name.endswith(f'.{fn.split(".")[-1]}')
                        for fn in self.EXTERNAL_CALL_FUNCTIONS
                    ):
                        has_external_call = True
                        break

        if not has_external_call:
            return None

        # Check if function has try/except
        has_try_except = False
        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                has_try_except = True
                break

        if not has_try_except:
            return {
                'type': 'tool_without_error_handling',
                'function': node.name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-08',
            }

        return None
