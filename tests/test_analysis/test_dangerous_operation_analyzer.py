"""Tests for dangerous operation analyzer."""

import pytest
from agent_audit.analysis.dangerous_operation_analyzer import (
    analyze_tool_for_dangerous_operations,
    is_safe_tool_pattern,
    should_flag_tool_input,
    DangerousOperationType,
)


class TestSafeToolPatterns:
    """Test safe tool pattern detection."""

    @pytest.mark.parametrize("func_name,expected_safe", [
        # Safe patterns - read-only
        ("get_weather", True),
        ("fetch_data", True),
        ("list_files", True),
        ("search_documents", True),
        ("query_database", True),
        ("read_file", True),
        ("load_config", True),
        ("describe_item", True),
        ("lookup_user", True),
        ("check_status", True),
        # Safe patterns - validation/parsing
        ("validate_input", True),
        ("parse_json", True),
        ("format_output", True),
        ("convert_data", True),
        ("transform_result", True),
        # Safe patterns - computation
        ("calculate_total", True),
        ("compute_hash", True),
        ("count_items", True),
        # NOT safe - potentially dangerous
        ("run_command", False),
        ("execute_query", False),
        ("delete_file", False),
        ("write_data", False),
        ("send_request", False),
        ("update_record", False),
    ])
    def test_safe_tool_patterns(self, func_name: str, expected_safe: bool):
        """Test that safe tool patterns are correctly identified."""
        is_safe, reason = is_safe_tool_pattern(func_name)
        assert is_safe == expected_safe


class TestDangerousOperationAnalysis:
    """Test dangerous operation detection."""

    def test_safe_getter_tool_not_flagged(self):
        """Getter tools without dangerous ops should not trigger."""
        func_body = '''
def get_weather(location: str) -> str:
    """Get weather for location."""
    response = weather_api.get(location)
    return response.json()
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="get_weather",
            func_body=func_body,
            param_names=["location"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is False

    def test_exec_tool_flagged(self):
        """Tools with exec should trigger."""
        func_body = '''
def run_code(code: str) -> str:
    """Run arbitrary code."""
    result = exec(code)
    return str(result)
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="run_code",
            func_body=func_body,
            param_names=["code"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True
        assert result.operation_type == DangerousOperationType.CODE_EXECUTION
        assert result.confidence > 0.80

    def test_eval_tool_flagged(self):
        """Tools with eval should trigger."""
        func_body = '''
def evaluate(expression: str) -> str:
    """Evaluate expression."""
    return str(eval(expression))
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="evaluate",
            func_body=func_body,
            param_names=["expression"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True
        assert result.operation_type == DangerousOperationType.CODE_EXECUTION

    def test_subprocess_with_param_flagged(self):
        """Subprocess with param in command should trigger."""
        func_body = '''
def run_shell(command: str) -> str:
    """Run shell command."""
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="run_shell",
            func_body=func_body,
            param_names=["command"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True
        assert result.operation_type == DangerousOperationType.SHELL_EXECUTION

    def test_subprocess_hardcoded_not_flagged(self):
        """Subprocess with hardcoded command should not trigger."""
        func_body = '''
def list_files(directory: str) -> str:
    """List files in directory."""
    result = subprocess.run(["ls", "-la"], capture_output=True)
    return f"Files in {directory}: {result.stdout.decode()}"
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="list_files",
            func_body=func_body,
            param_names=["directory"],
            param_types=["str"]
        )
        # The param doesn't flow to subprocess, only to output string
        assert result.has_dangerous_operation is False

    def test_os_system_flagged(self):
        """os.system should trigger."""
        func_body = '''
def execute(cmd: str) -> int:
    """Execute command."""
    return os.system(cmd)
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="execute",
            func_body=func_body,
            param_names=["cmd"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True
        assert result.operation_type == DangerousOperationType.SHELL_EXECUTION

    def test_sql_fstring_flagged(self):
        """SQL with f-string interpolation should trigger."""
        func_body = '''
def execute_user_query(name: str) -> list:
    """Execute user query by name."""
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="execute_user_query",
            func_body=func_body,
            param_names=["name"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True
        assert result.operation_type == DangerousOperationType.SQL_OPERATION

    def test_sql_format_flagged(self):
        """SQL with .format() should trigger."""
        func_body = '''
def run_user_lookup(user_id: str) -> dict:
    """Run user lookup with unsafe query."""
    query = "SELECT * FROM users WHERE id = '{}'".format(user_id)
    cursor.execute(query)
    return cursor.fetchone()
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="run_user_lookup",
            func_body=func_body,
            param_names=["user_id"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is True

    def test_no_dangerous_operations(self):
        """Functions without dangerous operations should not trigger."""
        func_body = '''
def process_data(data: str) -> str:
    """Process data safely."""
    result = data.strip().upper()
    return json.dumps({"processed": result})
'''
        result = analyze_tool_for_dangerous_operations(
            func_name="process_data",
            func_body=func_body,
            param_names=["data"],
            param_types=["str"]
        )
        assert result.has_dangerous_operation is False


class TestShouldFlagToolInput:
    """Test the main entry point for AGENT-034 detection."""

    def test_dangerous_tool_flagged(self):
        """Dangerous tools should be flagged."""
        func_body = '''
def run_code(code: str) -> str:
    return str(exec(code))
'''
        should_flag, confidence, reason = should_flag_tool_input(
            func_name="run_code",
            func_body=func_body,
            param_names=["code"],
            has_validation=False,
        )
        assert should_flag is True
        assert confidence > 0.50

    def test_safe_tool_not_flagged(self):
        """Safe tools should not be flagged."""
        func_body = '''
def get_weather(location: str) -> str:
    return api.get(location)
'''
        should_flag, confidence, reason = should_flag_tool_input(
            func_name="get_weather",
            func_body=func_body,
            param_names=["location"],
            has_validation=False,
        )
        assert should_flag is False

    def test_validation_reduces_confidence(self):
        """Tools with validation should have reduced confidence."""
        func_body = '''
def run_code(code: str) -> str:
    return str(exec(code))
'''
        _, conf_no_validation, _ = should_flag_tool_input(
            func_name="run_code",
            func_body=func_body,
            param_names=["code"],
            has_validation=False,
        )
        _, conf_with_validation, _ = should_flag_tool_input(
            func_name="run_code",
            func_body=func_body,
            param_names=["code"],
            has_validation=True,
        )
        assert conf_with_validation < conf_no_validation
