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

        self._current_function = node.name
        self._current_function_params = {
            arg.arg for arg in node.args.args
        }

        # Check for @tool decorator
        if self._has_tool_decorator(node):
            tool = self._extract_tool_from_function(node)
            if tool:
                self.tools.append(tool)

        self.generic_visit(node)

        self._current_function = old_func
        self._current_function_params = old_params

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async function definitions the same as regular functions."""
        # Reuse the same logic as FunctionDef - cast to satisfy type checker
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

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
