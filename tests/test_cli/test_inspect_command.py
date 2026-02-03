"""Tests for the inspect CLI command."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner

from agent_audit.cli.commands.inspect import (
    inspect,
    render_inspection_result,
    run_inspect,
)
from agent_audit.scanners.mcp_inspector import MCPInspectionResult
from agent_audit.utils.mcp_client import TransportType
from agent_core.models.tool import RiskLevel


class TestInspectCommand:
    """Tests for the inspect CLI command."""

    def test_inspect_help(self):
        """Inspect command should show help."""
        runner = CliRunner()
        result = runner.invoke(inspect, ["--help"])

        assert result.exit_code == 0
        assert "Inspect a running MCP server" in result.output

    def test_inspect_requires_transport_type(self):
        """Inspect command should require transport type."""
        runner = CliRunner()
        result = runner.invoke(inspect, [])

        # Should fail without transport type
        assert result.exit_code != 0

    def test_inspect_requires_target(self):
        """Inspect command should require target."""
        runner = CliRunner()
        result = runner.invoke(inspect, ["stdio"])

        # Should fail without target
        assert result.exit_code != 0


class TestRenderInspectionResult:
    """Tests for rendering inspection results."""

    def test_render_terminal_connected(self, capsys):
        """Should render connected result in terminal format."""
        result = MCPInspectionResult(
            server_name="test-server",
            server_version="1.0.0",
            transport=TransportType.STDIO,
            connected=True,
            tool_count=2,
            resource_count=1,
            prompt_count=0,
            risk_score=3.5,
            response_time_ms=100,
            capabilities_declared=["tools"],
            tools=[],
            resources=[],
            prompts=[],
            findings=[],
        )

        render_inspection_result(result, "terminal")
        captured = capsys.readouterr()

        # Output goes to Rich console, check it doesn't crash
        assert True

    def test_render_terminal_disconnected(self, capsys):
        """Should render disconnected result in terminal format."""
        result = MCPInspectionResult(
            server_name="test-server",
            connected=False,
            connection_error="Connection refused",
            response_time_ms=50,
        )

        render_inspection_result(result, "terminal")
        # Should not crash
        assert True

    def test_render_json_format(self, capsys):
        """Should render result in JSON format."""
        tool_mock = MagicMock()
        tool_mock.to_dict.return_value = {"name": "test_tool"}

        result = MCPInspectionResult(
            server_name="test-server",
            server_version="1.0.0",
            transport=TransportType.STDIO,
            connected=True,
            tool_count=1,
            tools=[tool_mock],
            resource_count=0,
            resources=[],
            prompt_count=0,
            prompts=[],
            risk_score=2.0,
            response_time_ms=100,
            capabilities_declared=[],
            findings=[],
        )

        render_inspection_result(result, "json")
        # Should not crash
        assert True


class TestRunInspect:
    """Tests for run_inspect function."""

    @patch("agent_audit.cli.commands.inspect.MCPInspector")
    @patch("agent_audit.cli.commands.inspect.render_inspection_result")
    def test_run_inspect_success(self, mock_render, mock_inspector_class):
        """Should return 0 for successful low-risk inspection."""
        mock_inspector = MagicMock()
        mock_inspector.inspect = AsyncMock(return_value=MCPInspectionResult(
            server_name="test",
            connected=True,
            risk_score=2.0,
        ))
        mock_inspector_class.return_value = mock_inspector

        exit_code = run_inspect(
            target="python server.py",
            transport="stdio",
            timeout=30,
            output_format="terminal"
        )

        assert exit_code == 0

    @patch("agent_audit.cli.commands.inspect.MCPInspector")
    @patch("agent_audit.cli.commands.inspect.render_inspection_result")
    def test_run_inspect_high_risk(self, mock_render, mock_inspector_class):
        """Should return 1 for high-risk inspection."""
        mock_inspector = MagicMock()
        mock_inspector.inspect = AsyncMock(return_value=MCPInspectionResult(
            server_name="test",
            connected=True,
            risk_score=8.0,
        ))
        mock_inspector_class.return_value = mock_inspector

        exit_code = run_inspect(
            target="python server.py",
            transport="stdio",
            timeout=30,
            output_format="terminal"
        )

        assert exit_code == 1

    @patch("agent_audit.cli.commands.inspect.MCPInspector")
    @patch("agent_audit.cli.commands.inspect.render_inspection_result")
    def test_run_inspect_connection_failure(self, mock_render, mock_inspector_class):
        """Should return 2 for connection failure."""
        mock_inspector = MagicMock()
        mock_inspector.inspect = AsyncMock(return_value=MCPInspectionResult(
            server_name="test",
            connected=False,
            connection_error="Connection refused",
        ))
        mock_inspector_class.return_value = mock_inspector

        exit_code = run_inspect(
            target="python server.py",
            transport="stdio",
            timeout=30,
            output_format="terminal"
        )

        assert exit_code == 2


class TestInspectTransportTypes:
    """Tests for transport type handling."""

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_stdio_transport(self, mock_run):
        """Should handle stdio transport type."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "stdio", "--", "python", "server.py"
        ])

        # Verify the command was parsed correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["transport"] == "stdio"

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_sse_transport(self, mock_run):
        """Should handle sse transport type."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "sse", "https://example.com/sse"
        ])

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["transport"] == "sse"


class TestInspectOutputFormats:
    """Tests for output format options."""

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_terminal_output_format(self, mock_run):
        """Should use terminal output format by default."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "stdio", "--", "python", "server.py"
        ])

        call_args = mock_run.call_args
        assert call_args[1]["output_format"] == "terminal"

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_json_output_format(self, mock_run):
        """Should support JSON output format."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "stdio", "--format", "json", "--", "python", "server.py"
        ])

        call_args = mock_run.call_args
        assert call_args[1]["output_format"] == "json"


class TestInspectTimeout:
    """Tests for timeout option."""

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_default_timeout(self, mock_run):
        """Should use default timeout of 30 seconds."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "stdio", "--", "python", "server.py"
        ])

        call_args = mock_run.call_args
        assert call_args[1]["timeout"] == 30

    @patch("agent_audit.cli.commands.inspect.run_inspect")
    def test_custom_timeout(self, mock_run):
        """Should accept custom timeout."""
        mock_run.return_value = 0
        runner = CliRunner()

        result = runner.invoke(inspect, [
            "stdio", "--timeout", "60", "--", "python", "server.py"
        ])

        call_args = mock_run.call_args
        assert call_args[1]["timeout"] == 60
