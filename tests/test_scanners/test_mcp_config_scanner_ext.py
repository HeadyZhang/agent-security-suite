"""Extended tests for MCP configuration scanner."""

import json
import pytest
import tempfile
from pathlib import Path

import yaml

from agent_audit.scanners.mcp_config_scanner import (
    MCPConfigScanner,
    MCPServerConfig,
    MCPConfigScanResult,
)


class TestMCPConfigScannerDockerFormat:
    """Tests for Docker MCP configuration format."""

    def test_scans_docker_mcp_config(self):
        """Should scan Docker MCP gateway configuration."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "docker-mcp.json"
            config = {
                "gateway": {
                    "servers": [
                        {
                            "name": "test-server",
                            "image": "docker.io/test/server:latest"
                        }
                    ]
                }
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            assert results[0].config_type == "docker_mcp"
            assert len(results[0].servers) == 1

    def test_handles_standard_servers_format(self):
        """Should handle standard servers array format."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.yaml"
            config = {
                "servers": [
                    {"name": "server1", "url": "https://example.com"},
                    {"name": "server2", "command": "python", "args": ["server.py"]}
                ]
            }
            config_path.write_text(yaml.dump(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            assert results[0].config_type == "standard"
            assert len(results[0].servers) == 2

    def test_handles_servers_dict_format(self):
        """Should handle servers as dictionary format."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.json"
            config = {
                "servers": {
                    "my-server": {
                        "command": "python",
                        "args": ["server.py"]
                    }
                }
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            assert results[0].servers[0].name == "my-server"


class TestMCPConfigScannerVerification:
    """Tests for server source verification."""

    def test_verifies_anthropic_server(self):
        """Should mark Anthropic servers as verified."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.json"
            config = {
                "servers": [
                    {"name": "official", "url": "ghcr.io/anthropics/mcp-server"}
                ]
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert results[0].servers[0].verified

    def test_verifies_mcp_catalog_server(self):
        """Should mark MCP catalog servers as verified."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.json"
            config = {
                "servers": [
                    {"name": "catalog", "image": "docker.io/mcp-catalog/server"}
                ]
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert results[0].servers[0].verified

    def test_unverified_unknown_source(self):
        """Should mark unknown sources as unverified."""
        scanner = MCPConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.json"
            config = {
                "servers": [
                    {"name": "unknown", "url": "https://random-server.com/mcp"}
                ]
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert not results[0].servers[0].verified


class TestMCPConfigScannerDangerousEnv:
    """Tests for detecting dangerous environment variables."""

    def test_detects_hardcoded_api_key(self):
        """Should detect hardcoded API keys in env vars."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            env={"API_KEY": "sk-1234567890abcdef"}
        )

        dangerous = scanner.get_dangerous_env_vars(server)

        assert len(dangerous) > 0
        assert any(d["key"] == "API_KEY" for d in dangerous)

    def test_detects_hardcoded_secret(self):
        """Should detect hardcoded secrets in env vars."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            env={"SECRET_KEY": "super-secret-value-here"}
        )

        dangerous = scanner.get_dangerous_env_vars(server)

        assert len(dangerous) > 0

    def test_ignores_env_variable_references(self):
        """Should ignore environment variable references."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            env={"API_KEY": "${API_KEY}", "TOKEN": "$TOKEN"}
        )

        dangerous = scanner.get_dangerous_env_vars(server)

        assert len(dangerous) == 0

    def test_ignores_short_values(self):
        """Should ignore short values that are likely not secrets."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            env={"API_KEY": "default"}
        )

        dangerous = scanner.get_dangerous_env_vars(server)

        assert len(dangerous) == 0


class TestMCPConfigScannerFilesystemAccess:
    """Tests for filesystem access detection."""

    def test_detects_root_access(self):
        """Should detect root filesystem access."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            args=["/"]
        )

        result = scanner.check_filesystem_access(server)

        assert result["has_root_access"]
        assert result["risk_level"] == "critical"

    def test_detects_home_access(self):
        """Should detect home directory access."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            args=["/home/user"]
        )

        result = scanner.check_filesystem_access(server)

        assert result["has_home_access"]
        assert result["risk_level"] == "high"

    def test_detects_accessible_paths(self):
        """Should track other accessible paths."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            args=["/opt/data", "/var/log"]
        )

        result = scanner.check_filesystem_access(server)

        assert "/opt/data" in result["accessible_paths"]
        assert "/var/log" in result["accessible_paths"]

    def test_low_risk_for_no_paths(self):
        """Should report low risk for no filesystem access."""
        scanner = MCPConfigScanner()

        server = MCPServerConfig(
            name="test",
            args=["--port", "8080"]
        )

        result = scanner.check_filesystem_access(server)

        assert result["risk_level"] == "low"


class TestMCPServerConfig:
    """Tests for MCPServerConfig dataclass."""

    def test_config_creation(self):
        """Should create config with required fields."""
        config = MCPServerConfig(name="test")

        assert config.name == "test"
        assert config.command is None
        assert config.args == []
        assert config.url is None
        assert config.env == {}
        assert not config.verified

    def test_config_with_command(self):
        """Should store command and args."""
        config = MCPServerConfig(
            name="test",
            command="python",
            args=["server.py", "--port", "8080"]
        )

        assert config.command == "python"
        assert config.args == ["server.py", "--port", "8080"]

    def test_config_with_url(self):
        """Should store URL for remote servers."""
        config = MCPServerConfig(
            name="test",
            url="https://example.com/mcp"
        )

        assert config.url == "https://example.com/mcp"


class TestMCPConfigScanResult:
    """Tests for MCPConfigScanResult dataclass."""

    def test_result_creation(self):
        """Should create result with source file."""
        result = MCPConfigScanResult(source_file="/path/to/config.json")

        assert result.source_file == "/path/to/config.json"
        assert result.servers == []
        assert result.config_type == "unknown"

    def test_result_with_servers(self):
        """Should store server configurations."""
        server = MCPServerConfig(name="test")
        result = MCPConfigScanResult(
            source_file="/path/to/config.json",
            servers=[server],
            config_type="claude_desktop"
        )

        assert len(result.servers) == 1
        assert result.config_type == "claude_desktop"
