"""Tests for MCP config scanner."""

import pytest
import json
from pathlib import Path
from textwrap import dedent

from agent_audit.scanners.mcp_config_scanner import MCPConfigScanner


class TestMCPConfigScanner:
    """Tests for MCPConfigScanner."""

    @pytest.fixture
    def scanner(self):
        return MCPConfigScanner()

    @pytest.fixture
    def mcp_configs_path(self, tmp_path):
        """Create test MCP config files."""
        configs_dir = tmp_path / "mcp_configs"
        configs_dir.mkdir()
        return configs_dir

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner is not None

    def test_scans_json_config(self, scanner, mcp_configs_path):
        """Test scanning JSON MCP config."""
        config = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-test"],
                    "env": {"API_KEY": "test-key"}
                }
            }
        }
        config_file = mcp_configs_path / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)

        assert len(results) == 1
        assert len(results[0].servers) == 1
        assert results[0].servers[0].name == "test-server"

    def test_scans_yaml_config(self, scanner, mcp_configs_path):
        """Test scanning YAML MCP config."""
        yaml_content = dedent("""
            mcpServers:
              sqlite-server:
                command: uvx
                args:
                  - mcp-server-sqlite
                  - --db-path
                  - ./data.db
        """)
        config_file = mcp_configs_path / "mcp.yaml"
        config_file.write_text(yaml_content)

        results = scanner.scan(config_file)

        assert len(results) == 1
        assert len(results[0].servers) == 1
        assert results[0].servers[0].name == "sqlite-server"
        assert results[0].servers[0].command == "uvx"

    def test_handles_claude_desktop_config(self, scanner, mcp_configs_path):
        """Test scanning Claude Desktop config format."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {}
                },
                "puppeteer": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
                }
            }
        }
        config_file = mcp_configs_path / "claude_desktop_config.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)

        assert len(results) == 1
        assert len(results[0].servers) == 2

        server_names = [s.name for s in results[0].servers]
        assert "filesystem" in server_names
        assert "puppeteer" in server_names

    def test_detects_http_url_server(self, scanner, mcp_configs_path):
        """Test detection of HTTP URL-based MCP server."""
        config = {
            "mcpServers": {
                "remote-server": {
                    "url": "http://mcp.example.com:3000/sse"
                }
            }
        }
        config_file = mcp_configs_path / "remote-mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)

        assert len(results) == 1
        server = results[0].servers[0]
        assert server.url == "http://mcp.example.com:3000/sse"

    def test_handles_empty_config(self, scanner, mcp_configs_path):
        """Test handling of empty config file."""
        config_file = mcp_configs_path / "empty.json"
        config_file.write_text("{}")

        results = scanner.scan(config_file)

        assert isinstance(results, list)

    def test_handles_invalid_json(self, scanner, mcp_configs_path):
        """Test handling of invalid JSON."""
        config_file = mcp_configs_path / "invalid.json"
        config_file.write_text("{ invalid json }")

        results = scanner.scan(config_file)

        # Should not crash, return empty results
        assert isinstance(results, list)

    def test_extracts_environment_variables(self, scanner, mcp_configs_path):
        """Test extraction of environment variables."""
        config = {
            "mcpServers": {
                "env-server": {
                    "command": "python",
                    "args": ["server.py"],
                    "env": {
                        "DATABASE_URL": "postgres://localhost/db",
                        "API_KEY": "secret123"
                    }
                }
            }
        }
        config_file = mcp_configs_path / "env.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)

        server = results[0].servers[0]
        assert server.env["DATABASE_URL"] == "postgres://localhost/db"
        assert server.env["API_KEY"] == "secret123"


class TestMCPConfigPatterns:
    """Test detection of various MCP config patterns."""

    @pytest.fixture
    def scanner(self):
        return MCPConfigScanner()

    def test_finds_config_in_directory(self, scanner, tmp_path):
        """Test finding MCP config files in a directory."""
        config = {"mcpServers": {"server": {"command": "node", "args": ["server.js"]}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config))

        results = scanner.scan(tmp_path)

        assert len(results) >= 1
        assert any(s.name == "server" for r in results for s in r.servers)

    def test_server_defaults_not_verified(self, scanner, tmp_path):
        """Test that servers default to not verified."""
        config = {
            "mcpServers": {
                "server": {
                    "command": "npx",
                    "args": ["@unknown/server"]
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config))

        results = scanner.scan(tmp_path)

        assert len(results) >= 1
        server = results[0].servers[0]
        # Servers without explicit verified flag default to False
        assert server.verified is False
