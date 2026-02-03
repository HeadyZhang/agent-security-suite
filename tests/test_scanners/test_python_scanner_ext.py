"""Extended tests for Python AST scanner."""

import pytest
import tempfile
from pathlib import Path

from agent_audit.scanners.python_scanner import (
    PythonScanner,
    PythonScanResult,
    PythonASTVisitor,
)
from agent_core.models.tool import PermissionType


class TestPythonScannerBaseTool:
    """Tests for BaseTool subclass detection."""

    def test_detects_base_tool_subclass(self):
        """Should detect BaseTool subclasses as tools."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import BaseTool

class MyTool(BaseTool):
    """A custom tool."""
    name = "my_tool"
    description = "Does something"

    def _run(self, query: str):
        return f"Result: {query}"
'''
            file_path = Path(tmpdir) / "tool.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            assert len(results[0].tools) > 0
            assert any(t.name == "MyTool" for t in results[0].tools)

    def test_detects_structured_tool_subclass(self):
        """Should detect StructuredTool subclasses as tools."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import StructuredTool

class MyStructuredTool(StructuredTool):
    """A structured tool."""
    pass
'''
            file_path = Path(tmpdir) / "tool.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            assert any(t.name == "MyStructuredTool" for t in results[0].tools)


class TestPythonScannerImportAliases:
    """Tests for import alias tracking."""

    def test_tracks_import_aliases(self):
        """Should track import aliases correctly."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
import subprocess as sp

def run_command(cmd):
    sp.run(cmd, shell=True)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            # Should detect subprocess.run even with alias
            assert any(
                p["function"] == "subprocess.run"
                for p in results[0].dangerous_patterns
            )

    def test_tracks_from_import(self):
        """Should track from-import statements."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from os import system

def run_cmd(cmd):
    system(cmd)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            assert "os.system" in results[0].imports


class TestPythonScannerAsyncFunctions:
    """Tests for async function handling."""

    def test_detects_async_tool_decorator(self):
        """Should detect async functions with @tool decorator."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import tool

@tool
async def async_tool(query: str) -> str:
    """An async tool."""
    return query
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            assert any(t.name == "async_tool" for t in results[0].tools)


class TestPythonScannerInputValidation:
    """Tests for input validation detection."""

    def test_detects_assert_as_validation(self):
        """Should detect assert statements as validation."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import tool

@tool
def validated_tool(x: int) -> str:
    """Tool with validation."""
    assert x > 0
    return str(x)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            tool = next(t for t in results[0].tools if t.name == "validated_tool")
            assert tool.has_input_validation

    def test_detects_raise_as_validation(self):
        """Should detect raise statements as validation."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import tool

@tool
def validated_tool(x: int) -> str:
    """Tool with validation."""
    if x <= 0:
        raise ValueError("x must be positive")
    return str(x)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            tool = next(t for t in results[0].tools if t.name == "validated_tool")
            assert tool.has_input_validation

    def test_detects_validation_function_calls(self):
        """Should detect validation function calls."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
from langchain.tools import tool

def validate_input(x):
    pass

@tool
def validated_tool(x: int) -> str:
    """Tool with validation."""
    validate_input(x)
    return str(x)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            tool = next(t for t in results[0].tools if t.name == "validated_tool")
            assert tool.has_input_validation


class TestPythonScannerTaintedInput:
    """Tests for tainted input detection."""

    def test_detects_tainted_in_fstring(self):
        """Should detect tainted input in f-strings."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
import os

def dangerous(user_input):
    os.system(f"echo {user_input}")
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            patterns = results[0].dangerous_patterns
            assert any(p["has_tainted_input"] for p in patterns)

    def test_detects_tainted_in_concat(self):
        """Should detect tainted input in string concatenation."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            code = '''
import os

def dangerous(user_input):
    os.system("echo " + user_input)
'''
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text(code, encoding="utf-8")

            results = scanner.scan(file_path)

            assert len(results) == 1
            patterns = results[0].dangerous_patterns
            assert any(p["has_tainted_input"] for p in patterns)


class TestPythonScannerExcludePaths:
    """Tests for path exclusion."""

    def test_excludes_specified_paths(self):
        """Should exclude files matching exclude patterns."""
        scanner = PythonScanner(exclude_paths=["excluded/"])

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files in excluded and non-excluded directories
            excluded_dir = Path(tmpdir) / "excluded"
            excluded_dir.mkdir()
            (excluded_dir / "test.py").write_text("import os\nos.system('cmd')", encoding="utf-8")

            included_dir = Path(tmpdir) / "included"
            included_dir.mkdir()
            (included_dir / "test.py").write_text("print('hello')", encoding="utf-8")

            results = scanner.scan(Path(tmpdir))

            # Should only include files not in excluded directory
            source_files = [r.source_file for r in results]
            assert not any("excluded" in f for f in source_files)


class TestPythonScannerSkipDirectories:
    """Tests for skipping common non-source directories."""

    def test_skips_venv_directory(self):
        """Should skip venv directories."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            venv_dir = Path(tmpdir) / "venv"
            venv_dir.mkdir()
            (venv_dir / "test.py").write_text("import os", encoding="utf-8")

            results = scanner.scan(Path(tmpdir))

            assert not any("venv" in r.source_file for r in results)

    def test_skips_pycache_directory(self):
        """Should skip __pycache__ directories."""
        scanner = PythonScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "__pycache__"
            cache_dir.mkdir()
            (cache_dir / "test.py").write_text("import os", encoding="utf-8")

            results = scanner.scan(Path(tmpdir))

            assert not any("__pycache__" in r.source_file for r in results)


class TestPythonScanResult:
    """Tests for PythonScanResult dataclass."""

    def test_result_has_required_fields(self):
        """Result should have all required fields."""
        result = PythonScanResult(source_file="/test.py")

        assert result.source_file == "/test.py"
        assert result.tools == []
        assert result.imports == []
        assert result.function_calls == []
        assert result.dangerous_patterns == []
