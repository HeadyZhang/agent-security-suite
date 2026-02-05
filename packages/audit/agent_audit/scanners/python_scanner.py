"""Python AST scanner for detecting dangerous patterns in agent code."""

import ast
import fnmatch
import logging
import re
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field

from agent_audit.scanners.base import BaseScanner, ScanResult
from agent_audit.models.tool import ToolDefinition, PermissionType, ToolParameter
from agent_audit.analyzers.memory_context import MemoryContextAnalyzer, MemoryOpContext
from agent_audit.analysis.dangerous_operation_analyzer import should_flag_tool_input
from agent_audit.analysis.rule_context_config import is_localhost_url

logger = logging.getLogger(__name__)

# Global memory context analyzer instance (lazy initialized)
_memory_analyzer: Optional[MemoryContextAnalyzer] = None


def _get_memory_analyzer() -> MemoryContextAnalyzer:
    """Get or create the global memory context analyzer."""
    global _memory_analyzer
    if _memory_analyzer is None:
        _memory_analyzer = MemoryContextAnalyzer()
    return _memory_analyzer


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

    # v0.5.0: Context confidence levels for tiered detection
    # Higher confidence = more likely to be a real vulnerability
    CONTEXT_CONFIDENCE: Dict[str, float] = {
        "tool_decorator": 0.90,      # @tool, @langchain.tool, create_tool()
        "agent_framework": 0.85,     # AgentExecutor, BaseTool, ToolNode
        "handler_function": 0.75,    # def handle_*, async def process_*
        "main_entry": 0.70,          # if __name__ == "__main__", app.run()
        "class_method": 0.60,        # Class method with dangerous calls
        "standalone_function": 0.55, # Standalone function with dangerous calls
        "module_level": 0.50,        # Module-level code
    }

    # v0.5.0: Expanded eval/exec patterns (AGENT-034 expansion)
    EVAL_EXEC_PATTERNS_PYTHON: Set[str] = {
        "eval", "exec", "compile",
        "os.system", "os.popen",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "__import__",
    }

    # v0.5.0: Safe eval alternatives (low confidence)
    SAFE_EVAL_PATTERNS: Set[str] = {
        "ast.literal_eval", "literal_eval",
        "json.loads", "json.load",
    }

    # v0.5.0: SSRF patterns for network requests (AGENT-026/037 expansion)
    SSRF_PATTERNS_PYTHON: Set[str] = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.head", "requests.patch", "requests.request",
        "urllib.request.urlopen", "urllib.request.Request",
        "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
        "httpx.AsyncClient", "httpx.Client",
        "aiohttp.ClientSession",
    }

    # v0.5.0: Agent framework indicators for context detection
    AGENT_FRAMEWORK_INDICATORS: Set[str] = {
        "AgentExecutor", "BaseTool", "ToolNode", "Agent",
        "LLMChain", "ConversationChain", "RetrievalQA",
        "ChatOpenAI", "ChatAnthropic", "Crew", "Task",
    }

    # v0.5.0: Handler function name patterns
    HANDLER_FUNCTION_PATTERNS: Set[str] = {
        "handle", "process", "execute", "run", "invoke",
        "call", "dispatch", "route", "serve",
    }

    # v0.5.0: Build/deploy script patterns (lower confidence for these)
    BUILD_DEPLOY_PATTERNS: Set[str] = {
        "setup", "install", "build", "deploy", "migrate",
        "seed", "init", "bootstrap", "configure",
    }

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
        'create_openai_functions_agent', 'create_structured_chat_agent',
        'create_tool_calling_agent', 'Crew',
    }

    # v0.3.0: LangChain AgentExecutor requiring safety params (AGENT-025)
    # Only AgentExecutor has max_iterations/max_execution_time params
    # create_*_agent functions create the agent runnable but don't have these params
    LANGCHAIN_AGENT_EXECUTOR_CLASSES: Set[str] = {
        'AgentExecutor',
    }

    # v0.3.1: Extended LangChain detection - legacy API support
    # These are old-style agent classes and factory functions
    LANGCHAIN_LEGACY_AGENT_CLASSES: Set[str] = {
        # Legacy Agent classes (from langchain.agents)
        'ConversationalChatAgent',
        'ConversationalAgent',
        'ZeroShotAgent',
        'ChatAgent',
        'StructuredChatAgent',
        'OpenAIFunctionsAgent',
        'OpenAIMultiFunctionsAgent',
        'XMLAgent',
        'ReActDocstoreAgent',
        'ReActTextWorldAgent',
        'SelfAskWithSearchAgent',
    }

    # Factory functions that RETURN AgentExecutor (support max_iterations)
    LANGCHAIN_EXECUTOR_FACTORY_FUNCTIONS: Set[str] = {
        'initialize_agent',  # Returns AgentExecutor with max_iterations support
    }

    # Factory functions that create agent RUNNABLES (not executors)
    # These don't support max_iterations directly - that's set on AgentExecutor
    LANGCHAIN_AGENT_FACTORY_FUNCTIONS: Set[str] = {
        'create_react_agent',
        'create_openai_functions_agent',
        'create_structured_chat_agent',
        'create_tool_calling_agent',
        'create_json_chat_agent',
        'create_xml_agent',
    }

    # Class methods that create AgentExecutor instances (support max_iterations)
    LANGCHAIN_EXECUTOR_FACTORY_METHODS: Set[str] = {
        'from_agent_and_tools',  # AgentExecutor.from_agent_and_tools()
    }

    # Class methods that create agent runnables (not executors)
    LANGCHAIN_AGENT_FACTORY_METHODS: Set[str] = {
        'from_llm_and_tools',  # ConversationalChatAgent.from_llm_and_tools()
    }

    # v0.3.0: Dangerous functions for tool input analysis (AGENT-026)
    DANGEROUS_TOOL_INPUT_SINKS: Dict[str, str] = {
        # File operations
        'open': 'file_access',
        'Path': 'file_access',
        'pathlib.Path': 'file_access',
        'os.path.join': 'file_access',
        'os.path.exists': 'file_access',
        'os.remove': 'file_delete',
        'os.unlink': 'file_delete',
        'shutil.rmtree': 'file_delete',
        # Command execution
        'subprocess.run': 'command_exec',
        'subprocess.Popen': 'command_exec',
        'subprocess.call': 'command_exec',
        'os.system': 'command_exec',
        'os.popen': 'command_exec',
        # Database
        'cursor.execute': 'sql_exec',
        'execute': 'sql_exec',
        'executemany': 'sql_exec',
        'engine.execute': 'sql_exec',
        # Network
        'requests.get': 'network',
        'requests.post': 'network',
        'httpx.get': 'network',
        'httpx.post': 'network',
        'urllib.request.urlopen': 'network',
    }

    # v0.3.0: Sanitization patterns (AGENT-026)
    SANITIZATION_PATTERNS: Set[str] = {
        'isinstance', 'type', 're.match', 're.search', 're.fullmatch',
        'validate', 'sanitize', 'clean', 'escape', 'quote',
        'shlex.quote', 'html.escape',
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

    # v0.3.0: Tool decorators for validation detection (AGENT-034)
    TOOL_DECORATORS_EXTENDED: Set[str] = {
        'tool', 'langchain.tools.tool', 'langchain_core.tools.tool',
        'function_tool', 'register_function', 'register_tool',
    }

    # v0.3.0: Input validation patterns (AGENT-034)
    INPUT_VALIDATION_PATTERNS: Set[str] = {
        'isinstance', 'type', 're.match', 're.search', 're.fullmatch',
        'validate', 'sanitize', 'clean', 'escape', 'check',
        'len', 'max', 'min',  # Bounds checking
        'Field',  # Pydantic
    }

    # v0.3.0: Unsafe execution functions (AGENT-035)
    UNSAFE_EXEC_FUNCTIONS: Set[str] = {
        'exec', 'eval', 'compile', '__import__',
        'os.system', 'os.popen',
    }

    # v0.3.0: Side effect tool name patterns (AGENT-037)
    SIDE_EFFECT_TOOL_PATTERNS: Set[str] = {
        'write', 'create', 'delete', 'save', 'remove', 'update',
        'insert', 'http', 'request', 'fetch', 'api', 'post',
        'shell', 'command', 'exec', 'run', 'execute',
    }

    # v0.3.0: Human approval evidence (AGENT-037)
    HUMAN_APPROVAL_EVIDENCE: Set[str] = {
        'HumanApprovalCallbackHandler', 'interrupt_before', 'interrupt_after',
        'human_input', 'confirm', 'approve', 'review',
    }

    # v0.3.0: Impersonation patterns (AGENT-038)
    IMPERSONATION_PATTERNS: List[str] = [
        r'pretend\s+you\s+are\s+a?\s*human',
        r'act\s+as\s+if\s+you\s+are\s+a?\s*real\s+person',
        r'never\s+reveal\s+you\s+are\s+an?\s*(AI|artificial)',
        r"don'?t\s+tell\s+.*(you\s+are\s+an?\s*(AI|bot|artificial))",
        r'impersonate',
    ]

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
        # v0.5.0: Track if inside agent framework class
        self._in_agent_framework_class: bool = False

    def _get_context_confidence(self) -> tuple:
        """
        v0.5.0: Determine the current execution context and its confidence level.
        v0.6.0: Added test file detection for FP reduction.

        Returns:
            Tuple of (context_type: str, confidence: float)
        """
        # v0.6.0: Check if in test file - significantly reduce confidence
        # Test files contain mocks, test fixtures, and intentionally unsafe code
        file_str = str(self.file_path).lower().replace("\\", "/")
        filename = file_str.split("/")[-1] if "/" in file_str else file_str
        is_test_file = (
            "/tests/" in file_str or
            "/test/" in file_str or
            filename.startswith("test_") or  # test_foo.py
            filename.endswith("_test.py") or  # foo_test.py
            "/fixtures/" in file_str or
            "/spec/" in file_str
        )
        if is_test_file:
            return ("test_file", 0.30)  # Very low confidence for test code

        # Highest priority: @tool decorator
        if self._in_tool_function:
            return ("tool_decorator", self.CONTEXT_CONFIDENCE["tool_decorator"])

        # Check if in agent framework class
        if self._in_agent_framework_class:
            return ("agent_framework", self.CONTEXT_CONFIDENCE["agent_framework"])

        # Check current class name
        if self._current_class:
            class_lower = self._current_class.lower()
            # Check for agent framework indicators in class name
            for indicator in self.AGENT_FRAMEWORK_INDICATORS:
                if indicator.lower() in class_lower:
                    return ("agent_framework", self.CONTEXT_CONFIDENCE["agent_framework"])
            # Check for tool-related class
            if "tool" in class_lower:
                return ("agent_framework", self.CONTEXT_CONFIDENCE["agent_framework"])

        # Check current function name
        if self._current_function:
            func_lower = self._current_function.lower()

            # Check for handler function patterns
            for pattern in self.HANDLER_FUNCTION_PATTERNS:
                if func_lower.startswith(pattern) or f"_{pattern}" in func_lower:
                    return ("handler_function", self.CONTEXT_CONFIDENCE["handler_function"])

            # Check for build/deploy scripts (lower confidence)
            for pattern in self.BUILD_DEPLOY_PATTERNS:
                if pattern in func_lower:
                    # Return lower confidence for build/deploy contexts
                    return ("build_script", 0.40)

            # Regular function in a class
            if self._current_class:
                return ("class_method", self.CONTEXT_CONFIDENCE["class_method"])

            # Standalone function
            return ("standalone_function", self.CONTEXT_CONFIDENCE["standalone_function"])

        # Module level code
        return ("module_level", self.CONTEXT_CONFIDENCE["module_level"])

    def _has_input_from_function_params(self, node: ast.Call) -> bool:
        """
        v0.5.0: Check if a call uses input from function parameters (tainted).

        Args:
            node: The call AST node

        Returns:
            True if call arguments come from function parameters
        """
        if not self._current_function_params:
            return False

        for arg in node.args:
            if self._contains_tainted_var(arg):
                return True
        for kw in node.keywords:
            if self._contains_tainted_var(kw.value):
                return True

        return False

    def _is_hardcoded_url(self, node: ast.Call) -> bool:
        """
        v0.5.0: Check if a network call uses a hardcoded URL.

        Args:
            node: The call AST node

        Returns:
            True if the URL argument is a string constant
        """
        if not node.args:
            return False

        first_arg = node.args[0]
        # Direct string constant
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            return True

        # Check url= keyword argument
        for kw in node.keywords:
            if kw.arg == "url":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    return True

        return False

    def _has_url_validation(self, node: ast.Call) -> bool:
        """
        v0.5.0: Check if URL validation exists before the network call.

        This is a heuristic check that looks for common validation patterns
        in the current function.

        Args:
            node: The call AST node

        Returns:
            True if URL validation pattern is detected
        """
        if not self._current_function:
            return False

        # Look for common URL validation patterns in source
        source_lower = self.source.lower()
        validation_patterns = [
            "urlparse", "urlvalidate", "validate_url",
            "allowed_domains", "allowlist", "whitelist",
            "parsed.netloc", "parsed.hostname",
        ]

        for pattern in validation_patterns:
            if pattern in source_lower:
                return True

        return False

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
        old_in_agent_framework = self._in_agent_framework_class
        self._current_class = node.name

        # Check if this class inherits from a tool base class
        is_tool_class = False
        for base in node.bases:
            base_name = self._get_name(base)
            if base_name and base_name in PythonScanner.TOOL_BASE_CLASSES:
                is_tool_class = True
                break

        # v0.5.0: Check if this class is an agent framework class
        is_agent_framework = is_tool_class
        if not is_agent_framework:
            for base in node.bases:
                base_name = self._get_name(base)
                if base_name and base_name in self.AGENT_FRAMEWORK_INDICATORS:
                    is_agent_framework = True
                    break
            # Also check class name
            if not is_agent_framework:
                class_lower = node.name.lower()
                if any(ind.lower() in class_lower for ind in self.AGENT_FRAMEWORK_INDICATORS):
                    is_agent_framework = True

        self._in_agent_framework_class = is_agent_framework

        if is_tool_class:
            tool = self._extract_tool_from_class(node)
            if tool:
                self.tools.append(tool)

        self.generic_visit(node)
        self._current_class = old_class
        self._in_agent_framework_class = old_in_agent_framework

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

            # v0.3.0 AGENT-026: Check for unsanitized tool input
            unsanitized_finding = self._check_langchain_tool_input_unsanitized(node)
            if unsanitized_finding:
                self.dangerous_patterns.append(unsanitized_finding)

            # v0.3.0 AGENT-034: Check for tool without input validation
            no_validation_finding = self._check_tool_no_input_validation(node)
            if no_validation_finding:
                self.dangerous_patterns.append(no_validation_finding)

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

            # v0.3.0: AGENT-025 - LangChain agent executor risk
            lc_exec_finding = self._check_langchain_agent_executor_risk(node)
            if lc_exec_finding:
                self.dangerous_patterns.append(lc_exec_finding)

            # v0.3.0: AGENT-027 - System prompt injection
            lc_prompt_finding = self._check_langchain_system_prompt_injectable(node)
            if lc_prompt_finding:
                self.dangerous_patterns.append(lc_prompt_finding)

            # v0.3.0: AGENT-028 - Unbounded iterations (cross-framework)
            unbounded_finding = self._check_agent_max_iterations_unbounded(node)
            if unbounded_finding:
                self.dangerous_patterns.append(unbounded_finding)

            # v0.3.0: AGENT-035 - Tool unrestricted execution
            unrestricted_finding = self._check_tool_unrestricted_execution(node)
            if unrestricted_finding:
                self.dangerous_patterns.append(unrestricted_finding)

            # v0.3.0: AGENT-037 - Missing human approval for side effects
            approval_finding = self._check_missing_human_approval(node)
            if approval_finding:
                self.dangerous_patterns.append(approval_finding)

            # v0.3.0: AGENT-038 - Agent impersonation risk
            impersonation_finding = self._check_agent_impersonation(node)
            if impersonation_finding:
                self.dangerous_patterns.append(impersonation_finding)

            # v0.3.0: AGENT-039 - Trust boundary violation
            trust_finding = self._check_trust_boundary_violation(node)
            if trust_finding:
                self.dangerous_patterns.append(trust_finding)

            # v0.3.2: AGENT-041 - SQL injection via f-string
            sql_finding = self._check_sql_fstring_injection(node)
            if sql_finding:
                self.dangerous_patterns.append(sql_finding)

            # v0.5.0: Expanded detection (outside @tool context)
            # AGENT-034 expansion - eval/exec in all contexts
            expanded_eval = self._check_expanded_eval_exec(node)
            if expanded_eval:
                self.dangerous_patterns.append(expanded_eval)

            # v0.5.0: AGENT-026/037 expansion - SSRF in all contexts
            expanded_ssrf = self._check_expanded_ssrf(node)
            if expanded_ssrf:
                self.dangerous_patterns.append(expanded_ssrf)

            # v0.5.0: AGENT-034/036 expansion - subprocess in all contexts
            expanded_subprocess = self._check_expanded_subprocess(node)
            if expanded_subprocess:
                self.dangerous_patterns.append(expanded_subprocess)

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

        Uses three-level filtering for false positive suppression:
        1. Framework allowlist - standard framework patterns get INFO severity
        2. Context analysis - determine data source and sanitization
        3. Confidence threshold - low confidence findings need review

        v0.3.2: Added framework internal path check to suppress framework tests/source.

        Returns a finding dict if vulnerable, None otherwise.
        """
        # v0.3.2: Skip framework internal code and test files
        file_path = str(self.file_path) if self.file_path else ''
        if self._is_framework_internal_path(file_path):
            return None

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

        if not has_variable_input:
            return None

        # v0.3.0: Apply context analysis for false positive suppression
        analyzer = _get_memory_analyzer()
        ctx: MemoryOpContext = analyzer.analyze(
            node=node,
            source_code=self.source,
            file_imports=self.imports,
        )

        # Build finding with context information
        finding: Dict[str, Any] = {
            'type': 'unsanitized_memory_write',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-06',
            # v0.3.0: Context analysis fields
            'confidence': ctx.confidence,
            'context': {
                'operation_type': ctx.operation_type.value,
                'data_source': ctx.data_source.value,
                'has_sanitization': ctx.has_sanitization,
                'framework_detected': ctx.framework_detected,
                'is_framework_standard': ctx.is_framework_standard,
            },
        }

        # Level 1: Framework allowlist - suppress standard framework patterns
        if ctx.is_framework_standard:
            finding['suppressed'] = True
            finding['suppression_reason'] = (
                f"Framework standard pattern: {ctx.framework_detected}"
            )
            finding['severity_override'] = 'INFO'

        # Level 2: Determine severity based on data source and sanitization
        elif ctx.data_source.value == 'user_input' and not ctx.has_sanitization:
            finding['severity_override'] = 'CRITICAL'
        elif ctx.data_source.value == 'llm_output' and not ctx.has_sanitization:
            finding['severity_override'] = 'HIGH'
        elif ctx.data_source.value == 'internal':
            finding['severity_override'] = 'LOW'
        elif ctx.has_sanitization:
            finding['severity_override'] = 'LOW'

        # Level 3: Mark low-confidence findings for review
        if ctx.confidence < 0.7 and ctx.confidence >= 0.3:
            finding['needs_review'] = True

        return finding

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

        v0.8.0: Added localhost URL detection for FP suppression.

        Returns a finding dict if vulnerable, None otherwise.
        """
        # Check string arguments for http:// URLs
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith('http://'):
                    url = arg.value

                    # v0.8.0: Suppress localhost URLs - they are almost always test/dev
                    if is_localhost_url(url):
                        # Return with very low confidence to effectively suppress
                        return {
                            'type': 'agent_comm_no_tls',
                            'url': url,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-07',
                            'confidence': 0.05,  # v0.8.0: Suppress localhost URLs
                            'localhost': True,
                        }

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
                            'url': url,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-07',
                            'confidence': 0.6,  # Lower confidence
                        }

        # Also check keyword arguments
        for kw in node.keywords:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if kw.value.value.startswith('http://'):
                    url = kw.value.value

                    # v0.8.0: Suppress localhost URLs
                    if is_localhost_url(url):
                        return {
                            'type': 'agent_comm_no_tls',
                            'url': url,
                            'keyword': kw.arg,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-07',
                            'confidence': 0.05,  # v0.8.0: Suppress localhost URLs
                            'localhost': True,
                        }

                    if kw.arg and any(
                        ak in kw.arg.lower() for ak in self.AGENT_COMM_KEYWORDS
                    ):
                        return {
                            'type': 'agent_comm_no_tls',
                            'url': url,
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

    # =========================================================================
    # v0.3.0: LangChain-Specific Detection Methods (AGENT-025~028)
    # =========================================================================

    def _check_langchain_agent_executor_risk(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-025: Detect AgentExecutor/create_react_agent without safety params.

        v0.3.1: Extended to detect legacy LangChain API patterns:
        - AgentExecutor.from_agent_and_tools()
        - XXXAgent.from_llm_and_tools()
        - initialize_agent()

        Checks for:
        - Missing max_iterations or value > 20
        - Missing max_execution_time
        - handle_parsing_errors not explicitly set to False

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Extract parts for analysis
        parts = func_name.split('.')
        simple_name = parts[-1]
        is_relevant = False
        detection_type = ''

        # Check 1: Direct AgentExecutor instantiation
        if simple_name in self.LANGCHAIN_AGENT_EXECUTOR_CLASSES:
            is_relevant = True
            detection_type = 'direct_instantiation'

        # Check 2: AgentExecutor.from_agent_and_tools() - creates executor with iteration support
        elif simple_name in self.LANGCHAIN_EXECUTOR_FACTORY_METHODS:
            if len(parts) >= 2:
                class_name = parts[-2]
                if class_name in self.LANGCHAIN_AGENT_EXECUTOR_CLASSES:
                    is_relevant = True
                    detection_type = f'{class_name}.{simple_name}'

        # Check 3: initialize_agent() - factory that returns AgentExecutor
        elif simple_name in self.LANGCHAIN_EXECUTOR_FACTORY_FUNCTIONS:
            is_relevant = True
            detection_type = f'factory:{simple_name}'

        # Note: create_react_agent, from_llm_and_tools etc. create agent runnables,
        # not executors. max_iterations is set on the executor, not the agent.
        # So we don't flag those directly.

        if not is_relevant:
            return None

        kw_names = {kw.arg for kw in node.keywords if kw.arg}
        issues: List[str] = []

        # Check max_iterations
        has_max_iter = False
        max_iter_value = None
        for kw in node.keywords:
            if kw.arg == 'max_iterations':
                has_max_iter = True
                if isinstance(kw.value, ast.Constant):
                    max_iter_value = kw.value.value

        if not has_max_iter:
            issues.append("missing max_iterations")
        elif max_iter_value is not None and isinstance(max_iter_value, int) and max_iter_value > 20:
            issues.append(f"max_iterations={max_iter_value} (>20)")

        # Check max_execution_time
        if 'max_execution_time' not in kw_names:
            issues.append("missing max_execution_time")

        # Only report if there are issues
        if issues:
            return {
                'type': 'langchain_agent_executor_risk',
                'function': func_name,
                'detection_type': detection_type,
                'issues': issues,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-01',
            }

        return None

    def _has_url_allowlist_validation(
        self, node: ast.FunctionDef, url_param: str
    ) -> bool:
        """
        Check if URL parameter has allowlist validation before network request.

        Detects patterns like:
            parsed = urlparse(url)
            if parsed.netloc not in ALLOWED_DOMAINS:
                raise/return ...

        Args:
            node: The function AST node
            url_param: The parameter name to check

        Returns:
            True if URL allowlist validation is detected
        """
        has_urlparse = False
        has_netloc_or_hostname = False
        has_in_or_not_in = False
        has_rejection = False  # raise or return in if block

        for child in ast.walk(node):
            # Check for urlparse call
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name and 'urlparse' in call_name:
                    # Check if it's called with our URL param
                    for arg in child.args:
                        if isinstance(arg, ast.Name) and arg.id == url_param:
                            has_urlparse = True
                            break

            # Check for .netloc or .hostname attribute access
            if isinstance(child, ast.Attribute):
                if child.attr in ('netloc', 'hostname', 'host'):
                    has_netloc_or_hostname = True

            # Check for 'in' or 'not in' comparison
            if isinstance(child, ast.Compare):
                for op in child.ops:
                    if isinstance(op, (ast.In, ast.NotIn)):
                        has_in_or_not_in = True
                        break

            # Check for If statements with raise/return
            if isinstance(child, ast.If):
                for stmt in child.body:
                    if isinstance(stmt, (ast.Raise, ast.Return)):
                        has_rejection = True
                        break
                for stmt in child.orelse:
                    if isinstance(stmt, (ast.Raise, ast.Return)):
                        has_rejection = True
                        break

        # All four elements must be present for URL allowlist validation
        return has_urlparse and has_netloc_or_hostname and has_in_or_not_in and has_rejection

    def _check_langchain_tool_input_unsanitized(
        self, node: ast.FunctionDef
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-026: Detect @tool functions with unsanitized parameter usage.

        Checks if parameters of type str/Any are passed directly to dangerous
        functions (file ops, command exec, SQL, network) without validation.

        v0.4.1: Recognizes URL allowlist validation as mitigation.

        Returns a finding dict if vulnerable, None otherwise.
        """
        if not self._has_tool_decorator(node):
            return None

        # Get string/Any parameters
        str_params: Set[str] = set()
        for arg in node.args.args:
            if arg.arg == 'self':
                continue
            # Check if parameter has annotation
            anno_type = self._get_annotation_type(arg.annotation)
            if anno_type in ('str', 'Any', 'Optional[str]', 'string'):
                str_params.add(arg.arg)
            elif anno_type == 'Any' or arg.annotation is None:
                # No annotation or Any type - conservative assumption
                str_params.add(arg.arg)

        if not str_params:
            return None

        # Track which params are validated
        validated_params: Set[str] = set()

        # First pass: find validation patterns
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    # Check if it's a sanitization function
                    is_sanitization = any(
                        san_pattern in call_name.lower()
                        for san_pattern in self.SANITIZATION_PATTERNS
                    )
                    if is_sanitization:
                        # Mark all params used in this call as validated
                        for call_arg in child.args:
                            if isinstance(call_arg, ast.Name) and call_arg.id in str_params:
                                validated_params.add(call_arg.id)

            # Check isinstance() calls
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name == 'isinstance' and len(child.args) >= 1:
                    if isinstance(child.args[0], ast.Name):
                        validated_params.add(child.args[0].id)

            # v0.5.0: Check for 'in' / 'not in' membership tests (allowlist checks)
            if isinstance(child, ast.Compare):
                for op in child.ops:
                    if isinstance(op, (ast.In, ast.NotIn)):
                        # If the left side is a param, mark it as validated
                        if isinstance(child.left, ast.Name) and child.left.id in str_params:
                            validated_params.add(child.left.id)
                        # Also check comparators
                        for comp in child.comparators:
                            if isinstance(comp, ast.Name) and comp.id in str_params:
                                validated_params.add(comp.id)

        unvalidated_params = str_params - validated_params

        if not unvalidated_params:
            return None

        # Second pass: check if unvalidated params flow to dangerous sinks
        dangerous_usages: List[Dict[str, Any]] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if not call_name:
                    continue

                # Check if this is a dangerous sink
                sink_type = None
                for sink, stype in self.DANGEROUS_TOOL_INPUT_SINKS.items():
                    if call_name == sink or call_name.endswith('.' + sink.split('.')[-1]):
                        sink_type = stype
                        break

                if sink_type:
                    # Check if any unvalidated param is used
                    for call_arg in child.args:
                        if isinstance(call_arg, ast.Name) and call_arg.id in unvalidated_params:
                            dangerous_usages.append({
                                'param': call_arg.id,
                                'sink': call_name,
                                'sink_type': sink_type,
                                'line': child.lineno,
                            })
                    for kw in child.keywords:
                        if isinstance(kw.value, ast.Name) and kw.value.id in unvalidated_params:
                            dangerous_usages.append({
                                'param': kw.value.id,
                                'sink': call_name,
                                'sink_type': sink_type,
                                'line': child.lineno,
                            })

        if dangerous_usages:
            # v0.4.1: Check for URL allowlist validation as mitigation
            confidence = 1.0
            mitigation_detected = None

            # Check if any network-related dangerous usage has URL validation
            for usage in dangerous_usages:
                if usage.get('sink_type') == 'network':
                    param = usage.get('param', '')
                    if self._has_url_allowlist_validation(node, param):
                        confidence = 0.20  # Suppress - URL validation detected
                        mitigation_detected = 'url_allowlist_validation'
                        break

            return {
                'type': 'langchain_tool_input_unsanitized',
                'function': node.name,
                'dangerous_usages': dangerous_usages,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-02',
                'confidence': confidence,
                'mitigation_detected': mitigation_detected,
            }

        return None

    def _check_langchain_system_prompt_injectable(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-027: Detect injectable system prompts in LangChain.

        Checks SystemMessage/HumanMessage/AIMessage for f-string or .format()
        in the content parameter.

        Also checks Prompt(template=...) and PromptTemplate(template=...) for
        templates containing user-controllable input_variables.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Target message classes
        message_classes = {'SystemMessage', 'HumanMessage', 'AIMessage'}
        # v0.3.2: Also check Prompt/PromptTemplate classes
        prompt_classes = {'Prompt', 'PromptTemplate', 'ChatPromptTemplate'}

        # Extract simple name for comparison (handle fully qualified names)
        simple_name = func_name.split('.')[-1]

        # v0.3.2: Check Prompt/PromptTemplate with user input_variables
        if simple_name in prompt_classes:
            # Check for template= kwarg with placeholders
            for kw in node.keywords:
                if kw.arg == 'template':
                    template_val = kw.value
                    # Case 1: template is a constant string with placeholders
                    if isinstance(template_val, ast.Constant) and isinstance(template_val.value, str):
                        template_str = template_val.value
                        injection_prone = any(
                            placeholder in template_str.lower()
                            for placeholder in ['{question}', '{input}', '{query}',
                                               '{user_input}', '{message}', '{text}']
                        )
                        if injection_prone:
                            return {
                                'type': 'langchain_system_prompt_injectable',
                                'function': func_name,
                                'injection_type': 'template_placeholder',
                                'line': node.lineno,
                                'snippet': self._get_line(node.lineno),
                                'owasp_id': 'ASI-01',
                                'note': 'Prompt template accepts user input without sanitization',
                            }
                    # Case 2: template is a variable - potential injection
                    elif isinstance(template_val, ast.Name):
                        return {
                            'type': 'langchain_system_prompt_injectable',
                            'function': func_name,
                            'injection_type': 'variable_template',
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-01',
                            'note': f'Prompt template from variable "{template_val.id}" may contain unvalidated input',
                        }

                # Also check input_variables containing user-controllable names
                if kw.arg == 'input_variables':
                    if isinstance(kw.value, ast.List):
                        var_names = []
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                var_names.append(elt.value.lower())
                        # Check for user-controllable variable names
                        risky_vars = ['question', 'input', 'query', 'user_input', 'message', 'text']
                        if any(rv in var_names for rv in risky_vars):
                            return {
                                'type': 'langchain_system_prompt_injectable',
                                'function': func_name,
                                'injection_type': 'risky_input_variables',
                                'line': node.lineno,
                                'snippet': self._get_line(node.lineno),
                                'owasp_id': 'ASI-01',
                                'note': 'Prompt accepts user-controllable input_variables',
                            }
            return None

        if simple_name not in message_classes:
            return None

        # Check first positional argument (content)
        if node.args:
            content_arg = node.args[0]
            if isinstance(content_arg, ast.JoinedStr):
                # f-string detected
                # Check if it contains non-literal values
                has_external = False
                for value in content_arg.values:
                    if isinstance(value, ast.FormattedValue):
                        # Check if the formatted value is a simple constant
                        if not isinstance(value.value, ast.Constant):
                            has_external = True
                            break

                if has_external:
                    return {
                        'type': 'langchain_system_prompt_injectable',
                        'function': func_name,
                        'injection_type': 'f-string',
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-01',
                    }

        # Check content keyword argument
        for kw in node.keywords:
            if kw.arg == 'content':
                if isinstance(kw.value, ast.JoinedStr):
                    has_external = False
                    for value in kw.value.values:
                        if isinstance(value, ast.FormattedValue):
                            if not isinstance(value.value, ast.Constant):
                                has_external = True
                                break

                    if has_external:
                        return {
                            'type': 'langchain_system_prompt_injectable',
                            'function': func_name,
                            'injection_type': 'f-string',
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-01',
                        }

                # Check for .format() call
                if isinstance(kw.value, ast.Call):
                    inner_name = self._get_call_name(kw.value)
                    if inner_name and inner_name.endswith('.format'):
                        return {
                            'type': 'langchain_system_prompt_injectable',
                            'function': func_name,
                            'injection_type': 'format',
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-01',
                        }

        return None

    def _check_agent_max_iterations_unbounded(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-028: Detect agents without max_iterations across frameworks.

        v0.3.1: Added framework allowlist to suppress findings for:
        - Framework internal code (src/, lib/)
        - Test files (tests/, test_*.py)

        Checks:
        - LangChain AgentExecutor: max_iterations missing or > 20
        - CrewAI Agent: max_iter missing
        - AutoGen: max_consecutive_auto_reply missing

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # v0.3.1: Skip framework internal code and test files
        file_path = str(self.file_path) if self.file_path else ''
        if self._is_framework_internal_path(file_path):
            return None

        # Extract simple name for comparison (handle fully qualified names)
        simple_name = func_name.split('.')[-1]
        kw_names = {kw.arg for kw in node.keywords if kw.arg}

        # Check by framework
        if simple_name in ('AgentExecutor', 'initialize_agent'):
            if 'max_iterations' not in kw_names:
                return {
                    'type': 'agent_max_iterations_unbounded',
                    'function': func_name,
                    'framework': 'langchain',
                    'missing_param': 'max_iterations',
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-08',
                }

        elif simple_name == 'Agent' and 'crewai' in ' '.join(self.imports).lower():
            if 'max_iter' not in kw_names:
                return {
                    'type': 'agent_max_iterations_unbounded',
                    'function': func_name,
                    'framework': 'crewai',
                    'missing_param': 'max_iter',
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-08',
                }

        elif simple_name in ('ConversableAgent', 'AssistantAgent', 'UserProxyAgent'):
            if 'max_consecutive_auto_reply' not in kw_names:
                return {
                    'type': 'agent_max_iterations_unbounded',
                    'function': func_name,
                    'framework': 'autogen',
                    'missing_param': 'max_consecutive_auto_reply',
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-08',
                }

        return None

    def _is_framework_internal_path(self, file_path: str) -> bool:
        """
        v0.3.1: Check if file is framework internal code.

        Returns True if the path matches framework source code patterns:
        - /src/crewai/, /lib/crewai/, etc.
        - /site-packages/
        - Framework test directories (only within framework repos)

        Note: We do NOT skip all test files - only framework internal tests.
        User project tests should still be scanned.
        """
        path_lower = file_path.lower()

        # Framework source patterns - these indicate we're scanning the framework itself
        framework_patterns = [
            # crewAI
            '/src/crewai/',
            '/lib/crewai/',
            '/crewai/crewai/',
            '/crewai/src/',
            '/crewai/lib/',
            # LangChain (includes langchain-core, langchain-community, etc.)
            '/src/langchain/',
            '/libs/langchain/',
            '/langchain/langchain/',
            '/libs/core/langchain_core/',  # v0.4.0: langchain-core source
            '/langchain_core/',  # v0.4.0: langchain_core package
            '/libs/community/langchain_community/',  # v0.4.0: langchain-community
            # AutoGen
            '/src/autogen/',
            '/autogen/autogen/',
            # AgentScope
            '/src/agentscope/',
            '/agentscope/src/',
            # DeepAgents
            '/src/deepagents/',
            '/deepagents/libs/',
            # OpenAI Agents SDK
            '/openai-agents-python/src/',  # v0.4.0: OpenAI agents
            # Google ADK
            '/adk-python/src/',  # v0.4.0: Google ADK
            # Installed packages
            '/site-packages/',
        ]

        for pattern in framework_patterns:
            if pattern in path_lower:
                return True

        # Also check if this looks like a framework's test directory
        # (e.g., crewAI/tests/, langchain/tests/)
        framework_test_patterns = [
            '/crewai/tests/',
            '/crewai/lib/crewai/tests/',
            '/langchain/tests/',
            '/autogen/tests/',
            '/autogen/python/packages/',  # v0.3.2: autogen monorepo packages
            '/agentscope/tests/',
            '/deepagents/tests/',
        ]
        for pattern in framework_test_patterns:
            if pattern in path_lower:
                return True

        # v0.3.2: Check for generic framework test patterns
        # (repos where we're scanning the framework itself, not user code)
        if '/repos/' in path_lower:
            # Check if this is a known framework repo with tests
            repo_test_patterns = [
                '/repos/autogen/',
                '/repos/langchain/',
                '/repos/crewai/',
                '/repos/agentscope/',
            ]
            for pattern in repo_test_patterns:
                if pattern in path_lower and '/tests/' in path_lower:
                    return True

        return False

    # =========================================================================
    # v0.3.0: ASI-02 / ASI-09 Coverage (AGENT-034~039)
    # =========================================================================

    def _has_safe_ast_evaluation(self, node: ast.FunctionDef) -> bool:
        """
        Check if function uses safe AST-based evaluation instead of eval/exec.

        Safe patterns:
        1. ast.literal_eval(x) - only evaluates literals
        2. ast.parse(x, mode='eval') without subsequent compile()/exec()
        3. ast.parse(x) + custom safe walker (no eval/exec)

        Args:
            node: The function AST node

        Returns:
            True if safe AST evaluation is detected (no eval/exec)
        """
        has_ast_parse = False
        has_ast_literal_eval = False
        has_eval_exec = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    simple_name = call_name.split('.')[-1]
                    # Check for ast.literal_eval - always safe
                    if simple_name == 'literal_eval' or call_name == 'ast.literal_eval':
                        has_ast_literal_eval = True
                    # Check for ast.parse - potentially safe
                    elif simple_name == 'parse' and 'ast' in call_name:
                        has_ast_parse = True
                    # Check for dangerous eval/exec
                    elif simple_name in ('eval', 'exec', 'compile'):
                        has_eval_exec = True

        # ast.literal_eval is always safe
        if has_ast_literal_eval:
            return True

        # ast.parse without eval/exec is safe (custom AST walker)
        if has_ast_parse and not has_eval_exec:
            return True

        return False

    def _has_parameterized_sql(self, node: ast.FunctionDef) -> bool:
        """
        Check if function uses parameterized SQL queries.

        Safe pattern:
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

        The key indicator is .execute() with 2+ arguments where:
        - First arg is NOT an f-string, .format(), % formatting, or + concatenation
        - Second arg exists (the parameters)

        Args:
            node: The function AST node

        Returns:
            True if parameterized SQL query is detected
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    simple_name = call_name.split('.')[-1]
                    if simple_name in ('execute', 'executemany'):
                        # Check if there are at least 2 arguments
                        if len(child.args) >= 2:
                            first_arg = child.args[0]
                            # Check that first arg is NOT unsafe string construction
                            is_safe_query = True
                            if isinstance(first_arg, ast.JoinedStr):
                                # f-string - NOT safe
                                is_safe_query = False
                            elif isinstance(first_arg, ast.BinOp):
                                # String concatenation - NOT safe
                                if isinstance(first_arg.op, (ast.Add, ast.Mod)):
                                    is_safe_query = False
                            elif isinstance(first_arg, ast.Call):
                                # Check for .format() - NOT safe
                                if isinstance(first_arg.func, ast.Attribute):
                                    if first_arg.func.attr == 'format':
                                        is_safe_query = False

                            if is_safe_query:
                                return True

        return False

    def _check_tool_no_input_validation(
        self, node: ast.FunctionDef
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-034: Detect tool functions without input validation.

        Checks if @tool decorated functions or tool-named functions accept
        str/Any parameters without validation in the function body.

        v0.4.1: Recognizes safe AST evaluation and parameterized SQL as mitigation.
        v0.6.0: Uses dangerous operation analyzer to avoid flagging safe tools.

        Returns a finding dict if vulnerable, None otherwise.
        """
        # Check if it's a tool function
        is_tool = self._has_tool_decorator(node) or 'tool' in node.name.lower()

        if not is_tool:
            return None

        # Get string/Any parameters
        str_params: Set[str] = set()
        for arg in node.args.args:
            if arg.arg == 'self':
                continue
            anno_type = self._get_annotation_type(arg.annotation)
            if anno_type in ('str', 'Any', 'Optional[str]', 'string') or arg.annotation is None:
                str_params.add(arg.arg)

        if not str_params:
            return None  # No string params, no validation needed

        # Check if function body has validation
        has_validation = False
        for child in ast.walk(node):
            if has_validation:
                break

            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    simple_name = call_name.split('.')[-1].lower()
                    # Check for validation function calls
                    if any(
                        val_pattern in simple_name
                        for val_pattern in self.INPUT_VALIDATION_PATTERNS
                    ):
                        has_validation = True
                    # Check for string method validation patterns
                    elif simple_name in ('startswith', 'endswith', 'isalnum', 'isdigit',
                                        'isalpha', 'isnumeric', 'isdecimal'):
                        has_validation = True

            # Check for isinstance/type checks
            elif isinstance(child, ast.Compare):
                # Check for membership tests (in / not in)
                for op in child.ops:
                    if isinstance(op, (ast.In, ast.NotIn)):
                        has_validation = True
                        break

                # Check for len() comparisons
                if isinstance(child.left, ast.Call):
                    cname = self._get_call_name(child.left)
                    if cname == 'len':
                        has_validation = True

                # Check for isinstance/type in comparators
                for comp in child.comparators:
                    if isinstance(comp, ast.Call):
                        cname = self._get_call_name(comp)
                        if cname in ('type', 'isinstance'):
                            has_validation = True

            # Check for Raise statements (validation error handling)
            elif isinstance(child, ast.Raise):
                # If there's a Raise inside an If, it's likely validation
                has_validation = True

        if not has_validation:
            # v0.4.1: Check for safe mitigations
            confidence = 1.0
            mitigation_detected = None

            # Check for safe AST evaluation (ast.literal_eval or ast.parse without eval/exec)
            if self._has_safe_ast_evaluation(node):
                confidence = 0.10  # Very low - AST evaluation is safe
                mitigation_detected = 'safe_ast_evaluation'

            # Check for parameterized SQL queries
            elif self._has_parameterized_sql(node):
                confidence = 0.10  # Very low - parameterized queries are safe
                mitigation_detected = 'parameterized_sql_query'

            # v0.6.0: Use dangerous operation analyzer for FP reduction
            # Only flag tools that actually have dangerous operations
            else:
                # Get function body text
                try:
                    func_body = ast.get_source_segment(self.source, node) or ''
                except Exception:
                    func_body = ''

                # Check if tool should be flagged based on dangerous operations
                should_flag, analyzer_confidence, reason = should_flag_tool_input(
                    func_name=node.name,
                    func_body=func_body,
                    param_names=list(str_params),
                    has_validation=False,
                )

                if not should_flag:
                    # Safe tool pattern - don't flag
                    return None

                # Use analyzer confidence if lower than default
                if analyzer_confidence < confidence:
                    confidence = analyzer_confidence
                    mitigation_detected = reason

            return {
                'type': 'tool_no_input_validation',
                'function': node.name,
                'unvalidated_params': list(str_params),
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-02',
                'confidence': confidence,
                'mitigation_detected': mitigation_detected,
            }

        return None

    def _check_tool_unrestricted_execution(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-035: Detect tools with unrestricted code execution.

        Checks for exec/eval/os.system etc in tool functions without
        sandboxing evidence.

        Returns a finding dict if vulnerable, None otherwise.
        """
        if not self._in_tool_function:
            return None

        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Check if it's an unsafe execution function
        simple_name = func_name.split('.')[-1]
        is_unsafe = (
            func_name in self.UNSAFE_EXEC_FUNCTIONS or
            simple_name in self.UNSAFE_EXEC_FUNCTIONS
        )

        if not is_unsafe:
            # Also check subprocess with shell=True
            if simple_name in ('run', 'Popen', 'call', 'check_output', 'check_call'):
                if self._has_shell_true(node):
                    is_unsafe = True

        if not is_unsafe:
            return None

        # Check for sandboxing evidence (docker, sandbox, jail in source)
        source_lower = self.source.lower()
        has_sandbox = any(
            pattern in source_lower
            for pattern in ['docker', 'sandbox', 'jail', 'container', 'isolated']
        )

        if has_sandbox:
            return None  # Has sandboxing evidence

        return {
            'type': 'tool_unrestricted_execution',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-02',
            'in_function': self._current_function,
        }

    def _check_missing_human_approval(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-037: Detect agent/chain with side-effect tools but no human approval.

        Checks AgentExecutor/Crew for tools with dangerous names and no
        HumanApprovalCallbackHandler or interrupt_before configuration.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        simple_name = func_name.split('.')[-1]
        if simple_name not in ('AgentExecutor', 'Crew', 'Agent', 'initialize_agent'):
            return None

        # Find tools parameter
        tools_names: List[str] = []
        has_side_effect_tool = False

        for kw in node.keywords:
            if kw.arg == 'tools':
                if isinstance(kw.value, ast.List):
                    for tool_elt in kw.value.elts:
                        tool_name = self._get_name(tool_elt)
                        if tool_name:
                            tools_names.append(tool_name)
                            # Check if it's a side effect tool
                            tool_lower = tool_name.lower()
                            if any(
                                pattern in tool_lower
                                for pattern in self.SIDE_EFFECT_TOOL_PATTERNS
                            ):
                                has_side_effect_tool = True

        if not has_side_effect_tool:
            return None

        # Check for human approval evidence
        has_approval = False
        kw_names = {kw.arg for kw in node.keywords if kw.arg}

        # Check keyword arguments
        for evidence in self.HUMAN_APPROVAL_EVIDENCE:
            if evidence in kw_names:
                has_approval = True
                break

        # Check callbacks for HumanApprovalCallbackHandler
        for kw in node.keywords:
            if kw.arg == 'callbacks':
                if isinstance(kw.value, ast.List):
                    for cb in kw.value.elts:
                        cb_name = None
                        # Handle direct name reference
                        if isinstance(cb, ast.Name):
                            cb_name = cb.id
                        # Handle function call like HumanApprovalCallbackHandler()
                        elif isinstance(cb, ast.Call):
                            cb_name = self._get_call_name(cb)
                        if cb_name and 'HumanApproval' in cb_name:
                            has_approval = True
                            break

        if has_approval:
            return None

        return {
            'type': 'missing_human_in_loop',
            'function': func_name,
            'side_effect_tools': [
                t for t in tools_names
                if any(p in t.lower() for p in self.SIDE_EFFECT_TOOL_PATTERNS)
            ],
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-09',
        }

    def _check_agent_impersonation(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-038: Detect system prompts that instruct impersonation.

        Checks string arguments for patterns like "pretend you are human",
        "never reveal you are an AI", etc.

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Check if this is a prompt-related function
        simple_name = func_name.split('.')[-1]
        is_prompt_related = simple_name in (
            'SystemMessage', 'HumanMessage', 'AIMessage',
            'PromptTemplate', 'ChatPromptTemplate',
        ) or 'prompt' in simple_name.lower()

        if not is_prompt_related:
            return None

        # Check string arguments for impersonation patterns
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                for pattern in self.IMPERSONATION_PATTERNS:
                    if re.search(pattern, arg.value, re.IGNORECASE):
                        return {
                            'type': 'agent_impersonation_risk',
                            'function': func_name,
                            'matched_pattern': pattern,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-09',
                            'owasp_id_secondary': 'ASI-03',  # v0.3.1: Also identity abuse
                        }

        # Check keyword arguments
        for kw in node.keywords:
            if kw.arg in ('content', 'template', 'system_message', 'system_prompt'):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    for pattern in self.IMPERSONATION_PATTERNS:
                        if re.search(pattern, kw.value.value, re.IGNORECASE):
                            return {
                                'type': 'agent_impersonation_risk',
                                'function': func_name,
                                'matched_pattern': pattern,
                                'line': node.lineno,
                                'snippet': self._get_line(node.lineno),
                                'owasp_id': 'ASI-09',
                                'owasp_id_secondary': 'ASI-03',  # v0.3.1: Also identity abuse
                            }

        return None

    def _check_trust_boundary_violation(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-039: Detect trust boundary violations in multi-agent systems.

        Checks multi-agent setups (CrewAI Crew, AutoGen GroupChat) for
        patterns where one agent can influence another's instructions.

        v0.3.2: Added framework allowlist to suppress findings for:
        - Framework internal code (src/, lib/)
        - Framework test directories

        Returns a finding dict if vulnerable, None otherwise.
        """
        # v0.3.2: Skip framework internal code and test files (same as AGENT-028)
        file_path = str(self.file_path) if self.file_path else ''
        if self._is_framework_internal_path(file_path):
            return None

        func_name = self._get_call_name(node)
        if not func_name:
            return None

        simple_name = func_name.split('.')[-1]
        if simple_name not in ('Crew', 'GroupChat', 'GroupChatManager'):
            return None

        # Check for agents parameter
        agents_present = False
        for kw in node.keywords:
            if kw.arg in ('agents', 'workers', 'participants'):
                if isinstance(kw.value, ast.List) and len(kw.value.elts) > 1:
                    agents_present = True
                    break

        # Also check positional args for Crew(agents=[...])
        for arg in node.args:
            if isinstance(arg, ast.List) and len(arg.elts) > 1:
                agents_present = True
                break

        if not agents_present:
            return None

        # Check for authentication/verification in keywords
        kw_names = {kw.arg.lower() for kw in node.keywords if kw.arg}
        has_auth = any(
            auth_kw in kw_names
            for auth_kw in ('authentication', 'verify', 'auth', 'signed')
        )

        if has_auth:
            return None

        # Multi-agent setup without explicit authentication
        return {
            'type': 'trust_boundary_violation',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-09',
            'note': 'Multi-agent setup without explicit authentication between agents',
        }

    def _check_sql_fstring_injection(
        self, node: ast.Call
    ) -> Optional[Dict[str, Any]]:
        """
        AGENT-041 (v0.4.0): Detect SQL injection via f-string interpolation.

        Detects patterns like:
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

        v0.4.0 improvements to reduce false positives:
        - Only trigger when caller looks like a database cursor/connection
        - Require the string to start with SQL keywords (SELECT, INSERT, UPDATE, etc.)
        - Distinguish safe parameterized queries from vulnerable string interpolation
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Check for SQL execution functions
        simple_name = func_name.split('.')[-1]
        sql_functions = {'execute', 'executemany', 'executescript', 'raw'}
        if simple_name not in sql_functions:
            return None

        # v0.4.0: Additional check - caller object should look like a database cursor
        # e.g., cursor.execute, conn.execute, db.execute, session.execute
        caller_hints = {
            'cursor', 'conn', 'connection', 'db', 'database', 'session',
            'engine', 'query', 'sql', 'sqlite', 'mysql', 'postgres', 'psycopg',
        }
        caller_name = func_name.rsplit('.', 1)[0] if '.' in func_name else ''
        caller_lower = caller_name.lower()

        # Skip if caller doesn't look like a database object
        if caller_lower and not any(hint in caller_lower for hint in caller_hints):
            # Also allow if the variable name contains 'sql' or 'query' hints
            pass  # Continue checking the query content

        # Check if first argument is an f-string (JoinedStr)
        if not node.args:
            return None

        first_arg = node.args[0]

        # Helper to check if a string constant starts with SQL keywords
        def looks_like_sql(s: str) -> bool:
            if not s:
                return False
            s_stripped = s.strip().upper()
            sql_keywords = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE',
                           'DROP', 'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE', 'WITH')
            return any(s_stripped.startswith(kw) for kw in sql_keywords)

        # Helper to extract string prefix from AST node
        def get_string_prefix(node: ast.AST) -> str:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value[:50]  # First 50 chars
            if isinstance(node, ast.JoinedStr) and node.values:
                first = node.values[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return first.value[:50]
            return ""

        # Direct f-string: cursor.execute(f"SELECT...")
        if isinstance(first_arg, ast.JoinedStr):
            # Check if the f-string contains variable interpolation
            has_interpolation = any(
                isinstance(value, ast.FormattedValue)
                for value in first_arg.values
            )
            if has_interpolation:
                # v0.4.0: Only flag if the string looks like SQL
                prefix = get_string_prefix(first_arg)
                if looks_like_sql(prefix):
                    return {
                        'type': 'sql_fstring_injection',
                        'function': func_name,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                        'owasp_id': 'ASI-02',
                        'note': 'SQL query constructed with f-string interpolation',
                    }

        # Also check for .format() calls on string
        # cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
        if isinstance(first_arg, ast.Call):
            # Check if this is a .format() call on a string literal
            if (isinstance(first_arg.func, ast.Attribute) and
                    first_arg.func.attr == 'format'):
                # v0.4.0: Check if the base string looks like SQL
                base_value = first_arg.func.value
                if isinstance(base_value, ast.Constant) and isinstance(base_value.value, str):
                    prefix = base_value.value[:50]
                    if looks_like_sql(prefix):
                        return {
                            'type': 'sql_format_injection',
                            'function': func_name,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-02',
                            'note': 'SQL query constructed with .format() interpolation',
                        }

        # Check for string concatenation with BinOp (+ operator)
        # cursor.execute("SELECT * FROM users WHERE id = " + user_id)
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            # v0.4.0: Check if the left operand looks like SQL
            left_prefix = get_string_prefix(first_arg.left)
            if looks_like_sql(left_prefix):
                # Check if any operand contains a variable (Name node)
                for operand in [first_arg.left, first_arg.right]:
                    if isinstance(operand, ast.Name):
                        return {
                            'type': 'sql_concat_injection',
                            'function': func_name,
                            'line': node.lineno,
                            'snippet': self._get_line(node.lineno),
                            'owasp_id': 'ASI-02',
                            'note': 'SQL query constructed with string concatenation',
                        }

        # v0.4.0: REMOVED sql_percent_injection check
        # Reason: "SELECT * FROM users WHERE id = %s" % user_id could be either:
        # - Vulnerable: cursor.execute("SELECT * WHERE id = %s" % user_id)
        # - Safe: cursor.execute("SELECT * WHERE id = %s", (user_id,))
        # Without context, we can't distinguish. The parameterized query form
        # (with tuple as second arg) is the standard safe pattern in Python DB-API.
        # Flagging this causes many false positives.

        return None

    # =========================================================================
    # v0.5.0: Expanded Detection (AGENT-034/026/037 Context-Aware Detection)
    # =========================================================================

    def _check_expanded_eval_exec(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        v0.5.0 AGENT-034 Expansion: Detect eval/exec in all contexts with confidence tiers.

        This expands detection beyond @tool decorator to catch vulnerabilities like:
        - KNOWN-001: LangChain LLMMathChain eval injection (CVE-2023-29374)
        - KNOWN-002: PythonREPLTool exec (CVE-2023-36258)
        - KNOWN-005: Auto-GPT shell execution
        - WILD-001: Calculator tool eval

        Confidence tiers:
        - @tool context     -> 0.90 (HIGH)
        - Agent framework   -> 0.85 (HIGH)
        - Handler function  -> 0.75 (MEDIUM)
        - Class method      -> 0.60 (MEDIUM)
        - Standalone func   -> 0.55 (LOW)
        - Build script      -> 0.40 (SUPPRESSED)

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Extract simple name
        simple_name = func_name.split('.')[-1]

        # Check if this is an eval/exec pattern
        is_eval_exec = (
            func_name in self.EVAL_EXEC_PATTERNS_PYTHON or
            simple_name in self.EVAL_EXEC_PATTERNS_PYTHON
        )

        if not is_eval_exec:
            return None

        # Check for safe alternatives (very low confidence)
        is_safe = (
            func_name in self.SAFE_EVAL_PATTERNS or
            simple_name in self.SAFE_EVAL_PATTERNS
        )

        if is_safe:
            # Still report but with very low confidence (INFO level)
            return {
                'type': 'eval_exec_expanded',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-05',
                'confidence': 0.10,
                'context_type': 'safe_alternative',
                'note': f'Safe alternative to eval/exec: {func_name}',
            }

        # Get context confidence
        context_type, base_confidence = self._get_context_confidence()

        # Adjust confidence based on input source
        confidence = base_confidence
        has_tainted_input = self._has_input_from_function_params(node)

        if has_tainted_input:
            # Higher confidence if input comes from function parameters
            confidence = min(confidence + 0.10, 0.95)
        else:
            # Lower confidence if using local/constant values
            confidence = max(confidence - 0.10, 0.30)

        # Skip if this is already detected by ASI-05 in tool context
        # (avoid duplicate findings)
        if self._in_tool_function and simple_name in ('eval', 'exec', 'compile'):
            return None  # Will be caught by _check_unsandboxed_code_exec

        # Skip subprocess patterns in @tool context (handled by existing checks)
        subprocess_patterns = {'run', 'Popen', 'call', 'check_output', 'check_call', 'system', 'popen'}
        if self._in_tool_function and simple_name in subprocess_patterns:
            return None  # Will be caught by dangerous_function_call or shell_true checks

        # Suppress findings with very low confidence (build scripts, etc.)
        if confidence < 0.45:
            return None

        return {
            'type': 'eval_exec_expanded',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-05',
            'confidence': confidence,
            'context_type': context_type,
            'has_tainted_input': has_tainted_input,
            'in_function': self._current_function,
            'in_class': self._current_class,
        }

    def _check_expanded_ssrf(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        v0.5.0 AGENT-026/037 Expansion: Detect SSRF patterns in all contexts.

        This expands detection beyond @tool decorator to catch:
        - WILD-002: Web fetcher SSRF with unvalidated URLs

        Confidence logic:
        - URL from function params, no validation -> context_base + 0.10
        - URL from function params, with validation -> 0.30 (INFO)
        - Hardcoded URL -> 0.20 (SUPPRESSED)

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Extract simple name and base module
        parts = func_name.split('.')
        simple_name = parts[-1]
        base_module = parts[0] if len(parts) > 1 else ''

        # Check if this is an SSRF-relevant function
        # Must match full name OR have known network module as base
        is_ssrf_func = func_name in self.SSRF_PATTERNS_PYTHON

        # Also check if base module is a known network library
        network_modules = {'requests', 'httpx', 'urllib', 'aiohttp', 'http', 'https'}
        if not is_ssrf_func and base_module in network_modules:
            # Check if the constructed name is a known SSRF pattern
            is_ssrf_func = (
                f"{base_module}.{simple_name}" in self.SSRF_PATTERNS_PYTHON or
                func_name in self.SSRF_PATTERNS_PYTHON
            )

        if not is_ssrf_func:
            return None

        # Check if URL is hardcoded (low risk)
        if self._is_hardcoded_url(node):
            return {
                'type': 'network_request_hardcoded_url',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'owasp_id': 'ASI-02',
                'confidence': 0.20,
                'context_type': 'hardcoded_url',
                'note': 'Network request with hardcoded URL (low risk)',
            }

        # Get context confidence
        context_type, base_confidence = self._get_context_confidence()

        # Check for tainted input
        has_tainted_input = self._has_input_from_function_params(node)

        # Check for URL validation
        has_validation = self._has_url_validation(node)

        # Calculate final confidence
        if has_tainted_input and not has_validation:
            confidence = min(base_confidence + 0.10, 0.95)
        elif has_tainted_input and has_validation:
            confidence = 0.30  # Validation detected
        else:
            confidence = max(base_confidence - 0.15, 0.30)

        # Skip if already detected by AGENT-026 in tool context
        if self._in_tool_function:
            return None  # Will be caught by _check_langchain_tool_input_unsanitized

        # Suppress very low confidence findings
        if confidence < 0.40:
            return None

        return {
            'type': 'ssrf_expanded',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-02',
            'confidence': confidence,
            'context_type': context_type,
            'has_tainted_input': has_tainted_input,
            'has_validation': has_validation,
            'in_function': self._current_function,
            'in_class': self._current_class,
        }

    def _check_expanded_subprocess(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        v0.5.0 AGENT-034/036 Expansion: Detect subprocess/shell calls in all contexts.

        This expands detection for:
        - KNOWN-005: Auto-GPT shell execution
        - General command injection patterns

        Returns a finding dict if vulnerable, None otherwise.
        """
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Extract simple name
        simple_name = func_name.split('.')[-1]

        # Check if this is a subprocess/shell function
        subprocess_funcs = {
            'run', 'Popen', 'call', 'check_output', 'check_call',
            'system', 'popen', 'spawn', 'spawnl', 'spawnle',
            'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe',
        }

        is_subprocess = (
            simple_name in subprocess_funcs or
            func_name in ('os.system', 'os.popen', 'subprocess.run',
                          'subprocess.Popen', 'subprocess.call')
        )

        if not is_subprocess:
            return None

        # Check for shell=True (higher risk)
        has_shell_true = self._has_shell_true(node)

        # Get context confidence
        context_type, base_confidence = self._get_context_confidence()

        # Check for tainted input
        has_tainted_input = self._has_input_from_function_params(node)

        # Calculate final confidence
        confidence = base_confidence
        if has_shell_true:
            confidence = min(confidence + 0.15, 0.95)
        if has_tainted_input:
            confidence = min(confidence + 0.10, 0.95)
        else:
            confidence = max(confidence - 0.10, 0.30)

        # Skip if already detected in tool context
        if self._in_tool_function:
            return None  # Will be caught by existing checks

        # Suppress very low confidence (build scripts, etc.)
        if confidence < 0.45:
            return None

        return {
            'type': 'subprocess_expanded',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-05',
            'confidence': confidence,
            'context_type': context_type,
            'has_shell_true': has_shell_true,
            'has_tainted_input': has_tainted_input,
            'in_function': self._current_function,
            'in_class': self._current_class,
        }
