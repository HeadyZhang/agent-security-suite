"""Tests for the Python scanner."""

import pytest
from pathlib import Path

from agent_audit.scanners.python_scanner import PythonScanner
from agent_core.models.tool import PermissionType


class TestPythonScanner:
    """Tests for PythonScanner."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    @pytest.fixture
    def fixtures_path(self):
        return Path(__file__).parent.parent / "fixtures" / "vulnerable_agents"

    @pytest.fixture
    def safe_fixtures_path(self):
        return Path(__file__).parent.parent / "fixtures" / "safe_agents"

    def test_detects_command_injection(self, scanner, fixtures_path):
        """Should detect command injection vulnerabilities."""
        results = scanner.scan(fixtures_path / "command_injection.py")

        assert len(results) == 1
        result = results[0]

        # Should find tools
        assert len(result.tools) >= 1

        # Should find dangerous patterns
        assert len(result.dangerous_patterns) > 0

        # Should find shell=True patterns
        shell_true_patterns = [
            p for p in result.dangerous_patterns
            if p['type'] == 'shell_true'
        ]
        assert len(shell_true_patterns) > 0

    def test_detects_subprocess_with_shell_true(self, scanner, fixtures_path):
        """Should detect subprocess.run(shell=True)."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        shell_patterns = [
            p for p in result.dangerous_patterns
            if p.get('type') == 'shell_true'
        ]
        assert len(shell_patterns) > 0
        assert any(p['function'] == 'subprocess.run' for p in shell_patterns)

    def test_detects_tool_decorators(self, scanner, fixtures_path):
        """Should detect @tool decorated functions."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        tool_names = [t.name for t in result.tools]
        assert 'execute_command' in tool_names
        assert 'read_file' in tool_names
        assert 'send_data' in tool_names

    def test_infers_permissions(self, scanner, fixtures_path):
        """Should correctly infer tool permissions."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        # Find execute_command tool
        exec_tool = next(
            (t for t in result.tools if t.name == 'execute_command'),
            None
        )
        assert exec_tool is not None
        assert PermissionType.SHELL_EXEC in exec_tool.permissions

        # Find read_file tool
        read_tool = next(
            (t for t in result.tools if t.name == 'read_file'),
            None
        )
        assert read_tool is not None
        assert PermissionType.FILE_READ in read_tool.permissions

        # Find send_data tool
        send_tool = next(
            (t for t in result.tools if t.name == 'send_data'),
            None
        )
        assert send_tool is not None
        assert PermissionType.NETWORK_OUTBOUND in send_tool.permissions

    def test_detects_tainted_input(self, scanner, fixtures_path):
        """Should detect tainted input in dangerous function calls."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        # subprocess.run call should be marked as having tainted input
        sub_patterns = [
            p for p in result.dangerous_patterns
            if 'subprocess' in p.get('function', '')
        ]
        assert any(p.get('has_tainted_input', False) for p in sub_patterns)

    def test_detects_os_system(self, scanner, fixtures_path):
        """Should detect os.system calls."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        os_system_patterns = [
            p for p in result.dangerous_patterns
            if p.get('function') == 'os.system'
        ]
        assert len(os_system_patterns) > 0

    def test_detects_eval(self, scanner, fixtures_path):
        """Should detect eval() calls."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        eval_patterns = [
            p for p in result.dangerous_patterns
            if p.get('function') == 'eval'
        ]
        assert len(eval_patterns) > 0

    def test_excludes_test_files(self, scanner):
        """Should respect exclude patterns."""
        scanner_with_exclude = PythonScanner(exclude_paths=['test_'])
        results = scanner_with_exclude.scan(Path(__file__).parent)

        # Should not scan test files
        scanned_files = [r.source_file for r in results]
        assert not any('test_python_scanner' in f for f in scanned_files)

    def test_tracks_imports(self, scanner, fixtures_path):
        """Should track imports for alias resolution."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        assert 'subprocess' in result.imports
        assert 'os' in result.imports

    def test_safe_agent_minimal_issues(self, scanner, safe_fixtures_path):
        """Safe agent should have minimal dangerous patterns."""
        results = scanner.scan(safe_fixtures_path / "basic_agent.py")

        if results:
            result = results[0]
            # Safe agent uses subprocess.run but without shell=True
            shell_true = [
                p for p in result.dangerous_patterns
                if p['type'] == 'shell_true'
            ]
            # Should have no shell=True patterns
            assert len(shell_true) == 0

    def test_handles_syntax_errors(self, scanner, tmp_path):
        """Should handle files with syntax errors gracefully."""
        bad_file = tmp_path / "bad_syntax.py"
        bad_file.write_text("def broken(\n")

        results = scanner.scan(bad_file)
        assert results == []  # Should return empty, not crash

    def test_handles_empty_files(self, scanner, tmp_path):
        """Should handle empty files."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        results = scanner.scan(empty_file)
        # Should not crash, may or may not return a result
        assert isinstance(results, list)

    def test_extracts_tool_parameters(self, scanner, fixtures_path):
        """Should extract tool parameter information."""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]

        exec_tool = next(
            (t for t in result.tools if t.name == 'execute_command'),
            None
        )
        assert exec_tool is not None
        assert len(exec_tool.parameters) > 0

        # Check parameter details
        cmd_param = next(
            (p for p in exec_tool.parameters if p.name == 'command'),
            None
        )
        assert cmd_param is not None
        assert cmd_param.type == 'str'
