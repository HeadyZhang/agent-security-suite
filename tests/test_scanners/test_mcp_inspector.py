"""Tests for MCP Inspector module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_audit.scanners.mcp_inspector import (
    MCPInspector,
    MCPInspectionResult,
)
from agent_audit.utils.mcp_client import TransportType
from agent_core.models.tool import PermissionType


class TestMCPInspector:
    """Tests for MCPInspector class."""

    def test_inspector_initialization(self):
        """Inspector should initialize with default timeout."""
        inspector = MCPInspector()
        assert inspector.timeout == 30

    def test_inspector_initialization_with_timeout(self):
        """Inspector should accept custom timeout."""
        inspector = MCPInspector(timeout=60)
        assert inspector.timeout == 60

    def test_high_risk_keywords_exist(self):
        """Inspector should have high risk keywords defined."""
        assert len(MCPInspector.HIGH_RISK_KEYWORDS) > 0
        assert 'exec' in MCPInspector.HIGH_RISK_KEYWORDS
        assert 'shell' in MCPInspector.HIGH_RISK_KEYWORDS

    def test_permission_keywords_exist(self):
        """Inspector should have permission keywords defined."""
        assert len(MCPInspector.PERMISSION_KEYWORDS) > 0
        assert PermissionType.SHELL_EXEC in MCPInspector.PERMISSION_KEYWORDS
        assert PermissionType.FILE_READ in MCPInspector.PERMISSION_KEYWORDS

    def test_sensitive_resource_patterns_exist(self):
        """Inspector should have sensitive resource patterns."""
        assert len(MCPInspector.SENSITIVE_RESOURCE_PATTERNS) > 0
        assert any('/etc/' in p for p in MCPInspector.SENSITIVE_RESOURCE_PATTERNS)
        assert any('.ssh/' in p for p in MCPInspector.SENSITIVE_RESOURCE_PATTERNS)


class TestMCPInspectorInferPermissions:
    """Tests for permission inference from tool names and descriptions."""

    def test_infer_shell_exec_permission(self):
        """Should infer SHELL_EXEC from exec-related keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("execute_command", "Execute shell command")
        assert PermissionType.SHELL_EXEC in permissions

    def test_infer_file_read_permission(self):
        """Should infer FILE_READ from read-related keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("read_file", "Read file contents")
        assert PermissionType.FILE_READ in permissions

    def test_infer_file_write_permission(self):
        """Should infer FILE_WRITE from write-related keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("write_file", "Write to file")
        assert PermissionType.FILE_WRITE in permissions

    def test_infer_network_permission(self):
        """Should infer NETWORK_OUTBOUND from network keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("fetch_url", "Make HTTP request")
        assert PermissionType.NETWORK_OUTBOUND in permissions

    def test_infer_database_permission(self):
        """Should infer DATABASE_READ from query keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("run_query", "Execute SQL query")
        assert PermissionType.DATABASE_READ in permissions

    def test_infer_secret_access_permission(self):
        """Should infer SECRET_ACCESS from credential keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("get_secret", "Access credentials")
        assert PermissionType.SECRET_ACCESS in permissions

    def test_infer_multiple_permissions(self):
        """Should infer multiple permissions from combined keywords."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions(
            "read_and_execute",
            "Read file and execute shell command"
        )
        assert PermissionType.FILE_READ in permissions
        assert PermissionType.SHELL_EXEC in permissions

    def test_no_permissions_for_safe_tool(self):
        """Should infer no dangerous permissions for safe tools."""
        inspector = MCPInspector()
        permissions = inspector._infer_permissions("calculate_sum", "Add two numbers")
        # Should be empty or have minimal permissions
        dangerous_perms = {
            PermissionType.SHELL_EXEC,
            PermissionType.FILE_DELETE,
            PermissionType.SECRET_ACCESS,
        }
        assert not permissions.intersection(dangerous_perms)


class TestMCPInspectorAnalyzeTool:
    """Tests for tool analysis."""

    def test_analyze_tool_basic(self):
        """Should analyze a basic tool definition."""
        inspector = MCPInspector()
        raw_tool = {
            "name": "test_tool",
            "description": "A test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "param1": {"type": "string"}
                },
                "required": ["param1"]
            }
        }

        tool = inspector._analyze_tool(raw_tool)

        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert len(tool.parameters) == 1

    def test_analyze_tool_with_dangerous_name(self):
        """Should identify tools with dangerous names."""
        inspector = MCPInspector()
        raw_tool = {
            "name": "execute_shell_command",
            "description": "Run system commands",
            "inputSchema": {}
        }

        tool = inspector._analyze_tool(raw_tool)

        assert PermissionType.SHELL_EXEC in tool.permissions

    def test_analyze_tool_with_validation(self):
        """Should detect input validation in schema."""
        inspector = MCPInspector()
        raw_tool = {
            "name": "safe_tool",
            "description": "A safe tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write"]
                    }
                }
            }
        }

        tool = inspector._analyze_tool(raw_tool)

        assert tool.has_input_validation


class TestMCPInspectorInputSchemaAnalysis:
    """Tests for input schema analysis."""

    def test_detects_enum_validation(self):
        """Should detect enum constraint as validation."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["a", "b"]}
            }
        }

        analysis = inspector._analyze_input_schema(schema)

        assert analysis["has_validation"]
        assert analysis["has_enum"]

    def test_detects_pattern_validation(self):
        """Should detect pattern constraint as validation."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "pattern": "^[a-z@.]+$"}
            }
        }

        analysis = inspector._analyze_input_schema(schema)

        assert analysis["has_validation"]
        assert analysis["has_pattern"]

    def test_detects_length_validation(self):
        """Should detect length constraints as validation."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 100}
            }
        }

        analysis = inspector._analyze_input_schema(schema)

        assert analysis["has_validation"]

    def test_detects_unconstrained_strings(self):
        """Should identify unconstrained string parameters."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "path": {"type": "string"}
            }
        }

        analysis = inspector._analyze_input_schema(schema)

        assert len(analysis["unconstrained_strings"]) == 2
        assert "command" in analysis["unconstrained_strings"]

    def test_numeric_range_validation(self):
        """Should detect numeric range constraints."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "minimum": 0, "maximum": 100}
            }
        }

        analysis = inspector._analyze_input_schema(schema)

        assert analysis["has_validation"]


class TestMCPInspectorRiskCalculation:
    """Tests for risk score calculation."""

    def test_calculate_risk_empty_result(self):
        """Should return 0 for disconnected result."""
        inspector = MCPInspector()
        result = MCPInspectionResult(
            server_name="test",
            connected=False
        )

        score = inspector._calculate_risk_score(result)

        assert score == 0.0

    def test_risk_increases_with_high_risk_tools(self):
        """Risk should increase with high-risk tool names."""
        inspector = MCPInspector()

        # Create a tool with high-risk name
        tool = MagicMock()
        tool.name = "execute_shell"
        tool.parameters = []
        tool.calculate_risk_score = MagicMock(return_value=5.0)

        result = MCPInspectionResult(
            server_name="test",
            connected=True,
            tools=[tool],
            tool_count=1
        )

        score = inspector._calculate_risk_score(result)

        assert score > 0

    def test_risk_capped_at_10(self):
        """Risk score should be capped at 10."""
        inspector = MCPInspector()

        # Create many high-risk tools
        tools = []
        for i in range(30):
            tool = MagicMock()
            tool.name = f"exec_command_{i}"
            tool.parameters = []
            tool.calculate_risk_score = MagicMock(return_value=10.0)
            tools.append(tool)

        result = MCPInspectionResult(
            server_name="test",
            connected=True,
            tools=tools,
            tool_count=30
        )

        score = inspector._calculate_risk_score(result)

        assert score <= 10.0


class TestMCPInspectorFindingsGeneration:
    """Tests for security findings generation."""

    def test_generates_findings_for_high_risk_tools(self):
        """Should generate findings for high-risk tool names."""
        inspector = MCPInspector()

        tool = MagicMock()
        tool.name = "execute_shell"
        tool.parameters = []
        tool.permissions = set()

        result = MCPInspectionResult(
            server_name="test",
            connected=True,
            tools=[tool],
            tool_count=1,
            resources=[]
        )

        findings = inspector._generate_findings(result)

        high_risk_findings = [
            f for f in findings
            if f["type"] == "high_risk_tool"
        ]
        assert len(high_risk_findings) > 0

    def test_generates_findings_for_sensitive_resources(self):
        """Should generate findings for sensitive resource paths."""
        inspector = MCPInspector()

        result = MCPInspectionResult(
            server_name="test",
            connected=True,
            tools=[],
            tool_count=0,
            resources=[
                {"uri": "file:///etc/passwd", "name": "passwd"}
            ]
        )

        findings = inspector._generate_findings(result)

        sensitive_findings = [
            f for f in findings
            if f["type"] == "sensitive_resource"
        ]
        assert len(sensitive_findings) > 0

    def test_generates_findings_for_dangerous_permission_combo(self):
        """Should warn about dangerous permission combinations."""
        inspector = MCPInspector()

        # Tool with secret access
        tool1 = MagicMock()
        tool1.name = "get_secret"
        tool1.parameters = []
        tool1.permissions = {PermissionType.SECRET_ACCESS}

        # Tool with network access
        tool2 = MagicMock()
        tool2.name = "send_request"
        tool2.parameters = []
        tool2.permissions = {PermissionType.NETWORK_OUTBOUND}

        result = MCPInspectionResult(
            server_name="test",
            connected=True,
            tools=[tool1, tool2],
            tool_count=2,
            resources=[]
        )

        findings = inspector._generate_findings(result)

        combo_findings = [
            f for f in findings
            if f["type"] == "dangerous_permission_combo"
        ]
        assert len(combo_findings) > 0


class TestMCPInspectionResult:
    """Tests for MCPInspectionResult dataclass."""

    def test_result_default_values(self):
        """Result should have sensible default values."""
        result = MCPInspectionResult(server_name="test")

        assert result.server_name == "test"
        assert result.server_version is None
        assert result.tools == []
        assert result.tool_count == 0
        assert result.resources == []
        assert result.resource_count == 0
        assert result.prompts == []
        assert result.prompt_count == 0
        assert result.risk_score == 0.0
        assert result.findings == []
        assert result.connected is False
        assert result.connection_error is None

    def test_result_with_connection_error(self):
        """Result should store connection errors."""
        result = MCPInspectionResult(
            server_name="test",
            connected=False,
            connection_error="Connection refused"
        )

        assert not result.connected
        assert result.connection_error == "Connection refused"


class TestMCPInspectorExtractParameters:
    """Tests for parameter extraction from schema."""

    def test_extracts_required_parameters(self):
        """Should mark required parameters correctly."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "required_param": {"type": "string"},
                "optional_param": {"type": "string"}
            },
            "required": ["required_param"]
        }

        params = inspector._extract_parameters(schema)

        required_param = next(p for p in params if p.name == "required_param")
        optional_param = next(p for p in params if p.name == "optional_param")

        assert required_param.required
        assert not optional_param.required

    def test_extracts_parameter_types(self):
        """Should extract parameter types correctly."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "string_param": {"type": "string"},
                "int_param": {"type": "integer"},
                "bool_param": {"type": "boolean"}
            }
        }

        params = inspector._extract_parameters(schema)

        string_param = next(p for p in params if p.name == "string_param")
        int_param = next(p for p in params if p.name == "int_param")
        bool_param = next(p for p in params if p.name == "bool_param")

        assert string_param.type == "string"
        assert int_param.type == "integer"
        assert bool_param.type == "boolean"

    def test_identifies_arbitrary_input_parameters(self):
        """Should identify parameters that allow arbitrary input."""
        inspector = MCPInspector()
        schema = {
            "type": "object",
            "properties": {
                "unconstrained": {"type": "string"},
                "constrained": {"type": "string", "enum": ["a", "b"]}
            }
        }

        params = inspector._extract_parameters(schema)

        unconstrained = next(p for p in params if p.name == "unconstrained")
        constrained = next(p for p in params if p.name == "constrained")

        assert unconstrained.allows_arbitrary_input
        assert not constrained.allows_arbitrary_input
