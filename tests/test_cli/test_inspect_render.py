"""Tests for inspect command rendering."""

import pytest
from unittest.mock import MagicMock

from agent_audit.cli.commands.inspect import (
    _render_terminal,
    _render_json,
)
from agent_audit.scanners.mcp_inspector import MCPInspectionResult
from agent_audit.utils.mcp_client import TransportType
from agent_core.models.tool import RiskLevel


class TestRenderTerminal:
    """Tests for terminal rendering."""

    def test_render_connected_server(self, capsys):
        """Should render connected server info."""
        result = MCPInspectionResult(
            server_name="test-server",
            server_version="1.0.0",
            connected=True,
            transport=TransportType.STDIO,
            tool_count=5,
            resource_count=2,
            prompt_count=1,
            risk_score=3.0,
            response_time_ms=150,
            capabilities_declared=["tools", "resources"],
            tools=[],
            resources=[],
            prompts=[],
            findings=[],
        )

        _render_terminal(result)
        # Should not crash

    def test_render_disconnected_server(self, capsys):
        """Should render disconnected server with error."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=False,
            connection_error="Connection timed out after 30s",
            response_time_ms=30000,
        )

        _render_terminal(result)
        # Should not crash

    def test_render_with_tools(self, capsys):
        """Should render tool information."""
        tool_mock = MagicMock()
        tool_mock.name = "execute_command"
        tool_mock.permissions = set()
        tool_mock.risk_level = MagicMock()
        tool_mock.risk_level.value = 3
        tool_mock.has_input_validation = False

        result = MCPInspectionResult(
            server_name="test-server",
            connected=True,
            tool_count=1,
            tools=[tool_mock],
            resources=[],
            prompts=[],
            findings=[],
            risk_score=5.0,
            response_time_ms=100,
            capabilities_declared=[],
        )

        _render_terminal(result)
        # Should not crash

    def test_render_with_resources(self, capsys):
        """Should render resource information."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=True,
            tool_count=0,
            tools=[],
            resource_count=3,
            resources=[
                {"uri": "file:///etc/passwd"},
                {"uri": "file:///home/user/.ssh/id_rsa"},
                {"uri": "file:///var/log/syslog"},
            ],
            prompts=[],
            findings=[],
            risk_score=5.0,
            response_time_ms=100,
            capabilities_declared=[],
        )

        _render_terminal(result)
        # Should not crash

    def test_render_with_prompts(self, capsys):
        """Should render prompt information."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=True,
            tool_count=0,
            tools=[],
            resource_count=0,
            resources=[],
            prompt_count=2,
            prompts=[
                {"name": "greeting"},
                {"name": "farewell"},
            ],
            findings=[],
            risk_score=1.0,
            response_time_ms=100,
            capabilities_declared=[],
        )

        _render_terminal(result)
        # Should not crash

    def test_render_with_findings(self, capsys):
        """Should render security findings."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=True,
            tool_count=0,
            tools=[],
            resource_count=0,
            resources=[],
            prompt_count=0,
            prompts=[],
            findings=[
                {"type": "high_risk_tool", "tool": "exec", "severity": "critical", "description": "Dangerous tool"},
                {"type": "sensitive_resource", "severity": "high", "description": "Sensitive path exposed"},
                {"type": "warning", "severity": "medium", "description": "Consider reviewing"},
                {"type": "info", "severity": "low", "description": "Information"},
            ],
            risk_score=8.0,
            response_time_ms=100,
            capabilities_declared=[],
        )

        _render_terminal(result)
        # Should not crash

    def test_render_high_risk_server(self, capsys):
        """Should render high risk server appropriately."""
        result = MCPInspectionResult(
            server_name="risky-server",
            connected=True,
            risk_score=9.5,
            response_time_ms=100,
            tools=[],
            resources=[],
            prompts=[],
            findings=[],
            capabilities_declared=[],
        )

        _render_terminal(result)
        # Should not crash


class TestRenderJSON:
    """Tests for JSON rendering."""

    def test_render_json_basic(self, capsys):
        """Should render basic result as JSON."""
        tool_mock = MagicMock()
        tool_mock.to_dict.return_value = {
            "name": "test_tool",
            "description": "A test tool",
        }

        result = MCPInspectionResult(
            server_name="test-server",
            server_version="1.0.0",
            connected=True,
            transport=TransportType.STDIO,
            tool_count=1,
            tools=[tool_mock],
            resource_count=0,
            resources=[],
            prompt_count=0,
            prompts=[],
            risk_score=2.0,
            response_time_ms=100,
            capabilities_declared=["tools"],
            findings=[],
        )

        _render_json(result)
        # Should not crash

    def test_render_json_with_error(self, capsys):
        """Should render error result as JSON."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=False,
            connection_error="Connection refused",
            response_time_ms=5000,
        )

        _render_json(result)
        # Should not crash
