"""MCP configuration scanner for static analysis of MCP server configs."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

import yaml

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class MCPServerConfig:
    """Parsed MCP server configuration."""
    name: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    verified: bool = False
    _line: int = 1  # Source line for error reporting
    _source_file: str = ""


@dataclass
class MCPConfigScanResult(ScanResult):
    """Result of MCP configuration scanning."""
    servers: List[MCPServerConfig] = field(default_factory=list)
    config_type: str = "unknown"  # claude_desktop, docker_mcp, standard


class MCPConfigScanner(BaseScanner):
    """
    Static scanner for MCP configuration files.

    Supports:
    - Claude Desktop config (mcpServers)
    - Docker MCP config (gateway.servers)
    - Standard MCP config (servers[])
    """

    name = "MCP Config Scanner"

    # Known config file names
    CONFIG_FILENAMES = [
        'claude_desktop_config.json',
        'mcp.json',
        'mcp.yaml',
        'mcp.yml',
        'docker-mcp.json',
        'docker-mcp.yaml',
    ]

    # Trusted MCP server sources
    TRUSTED_SOURCES = [
        'docker.io/mcp-catalog/',
        'ghcr.io/anthropics/',
        'ghcr.io/modelcontextprotocol/',
        '@modelcontextprotocol/',
    ]

    def __init__(self, config_paths: Optional[List[Path]] = None):
        """
        Initialize the MCP config scanner.

        Args:
            config_paths: Specific config files to scan. If None,
                         auto-discovers config files.
        """
        self.config_paths = config_paths

    def scan(self, path: Path) -> List[MCPConfigScanResult]:
        """
        Scan for MCP configuration files.

        Args:
            path: Directory or file to scan

        Returns:
            List of scan results
        """
        results = []
        config_files = self._find_config_files(path)

        for config_file in config_files:
            result = self._scan_config_file(config_file)
            if result:
                results.append(result)

        return results

    def _find_config_files(self, path: Path) -> List[Path]:
        """Find MCP configuration files."""
        if self.config_paths:
            return [p for p in self.config_paths if p.exists()]

        if path.is_file():
            if path.name in self.CONFIG_FILENAMES or self._looks_like_mcp_config(path):
                return [path]
            return []

        config_files = []

        # Check for known config file names
        for filename in self.CONFIG_FILENAMES:
            config_path = path / filename
            if config_path.exists():
                config_files.append(config_path)

        # Check .claude directory
        claude_dir = path / '.claude'
        if claude_dir.exists():
            for json_file in claude_dir.glob('*.json'):
                if self._looks_like_mcp_config(json_file):
                    config_files.append(json_file)

        return config_files

    def _looks_like_mcp_config(self, file_path: Path) -> bool:
        """Check if a file looks like an MCP config."""
        try:
            content = file_path.read_text(encoding='utf-8')

            if file_path.suffix == '.json':
                data = json.loads(content)
            elif file_path.suffix in {'.yaml', '.yml'}:
                data = yaml.safe_load(content)
            else:
                return False

            if not isinstance(data, dict):
                return False

            # Check for MCP config indicators
            return any(key in data for key in [
                'mcpServers', 'servers', 'gateway'
            ])

        except Exception:
            return False

    def _scan_config_file(self, file_path: Path) -> Optional[MCPConfigScanResult]:
        """Scan a single config file."""
        try:
            content = file_path.read_text(encoding='utf-8')

            if file_path.suffix == '.json':
                data = json.loads(content)
            elif file_path.suffix in {'.yaml', '.yml'}:
                data = yaml.safe_load(content)
            else:
                logger.warning(f"Unsupported config format: {file_path}")
                return None

            if not isinstance(data, dict):
                return None

            # Detect config type and parse
            servers, config_type = self._parse_config(data, str(file_path))

            return MCPConfigScanResult(
                source_file=str(file_path),
                servers=servers,
                config_type=config_type
            )

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error in {file_path}: {e}")
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")

        return None

    def _parse_config(
        self,
        data: Dict[str, Any],
        source_file: str
    ) -> tuple[List[MCPServerConfig], str]:
        """Parse MCP config and detect format."""
        servers: List[MCPServerConfig] = []
        config_type = "unknown"

        # Claude Desktop format: { "mcpServers": { "name": { ... } } }
        if 'mcpServers' in data:
            config_type = "claude_desktop"
            mcp_servers = data['mcpServers']
            if isinstance(mcp_servers, dict):
                for name, config in mcp_servers.items():
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        # Docker MCP format: { "gateway": { "servers": [ ... ] } }
        elif 'gateway' in data and isinstance(data['gateway'], dict):
            config_type = "docker_mcp"
            gateway_servers = data['gateway'].get('servers', [])
            if isinstance(gateway_servers, list):
                for config in gateway_servers:
                    name = config.get('name', config.get('image', 'unknown'))
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        # Standard MCP format: { "servers": [ ... ] }
        elif 'servers' in data:
            config_type = "standard"
            if isinstance(data['servers'], list):
                for config in data['servers']:
                    name = config.get('name', 'unknown')
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)
            elif isinstance(data['servers'], dict):
                for name, config in data['servers'].items():
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        return servers, config_type

    def _parse_server_config(
        self,
        name: str,
        config: Dict[str, Any],
        source_file: str
    ) -> MCPServerConfig:
        """Parse a single server configuration."""
        server = MCPServerConfig(
            name=name,
            command=config.get('command'),
            args=config.get('args', []),
            url=config.get('url'),
            env=config.get('env', {}),
            verified=self._is_verified_source(config),
            _source_file=source_file
        )

        return server

    def _is_verified_source(self, config: Dict[str, Any]) -> bool:
        """
        Check if a server configuration is from a trusted source.

        Trusted sources include:
        - Official MCP catalog Docker images
        - Anthropic's GitHub packages
        - ModelContextProtocol npm packages
        """
        # Check URL
        url = config.get('url', '')
        if url and any(url.startswith(src) for src in self.TRUSTED_SOURCES):
            return True

        # Check Docker image
        image = config.get('image', '')
        if image and any(image.startswith(src) for src in self.TRUSTED_SOURCES):
            return True

        # Check npm package in args
        args = config.get('args', [])
        for arg in args:
            if isinstance(arg, str):
                if any(src in arg for src in self.TRUSTED_SOURCES):
                    return True

        return False

    def get_dangerous_env_vars(self, server: MCPServerConfig) -> List[Dict[str, Any]]:
        """
        Find potentially dangerous environment variables.

        Returns list of env vars that may contain credentials.
        """
        dangerous = []
        sensitive_patterns = [
            'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
            'API_KEY', 'AUTH', 'PRIVATE'
        ]

        for key, value in server.env.items():
            key_upper = key.upper()
            if any(pattern in key_upper for pattern in sensitive_patterns):
                # Check if it looks like a hardcoded secret
                if isinstance(value, str) and len(value) > 10:
                    if not value.startswith('${') and not value.startswith('$'):
                        dangerous.append({
                            'key': key,
                            'value_preview': value[:10] + '...',
                            'reason': 'Potential hardcoded credential'
                        })

        return dangerous

    def check_filesystem_access(self, server: MCPServerConfig) -> Dict[str, Any]:
        """
        Check for overly permissive filesystem access.

        Returns analysis of filesystem access configuration.
        """
        accessible_paths: List[str] = []
        result: Dict[str, Any] = {
            'has_root_access': False,
            'has_home_access': False,
            'accessible_paths': accessible_paths,
            'risk_level': 'low'
        }

        # Check args for path access
        for arg in server.args:
            if isinstance(arg, str):
                if arg == '/':
                    result['has_root_access'] = True
                    result['risk_level'] = 'critical'
                elif arg.startswith('/home') or arg == '~' or arg.startswith('$HOME'):
                    result['has_home_access'] = True
                    result['risk_level'] = 'high' if result['risk_level'] != 'critical' else 'critical'
                elif arg.startswith('/'):
                    accessible_paths.append(arg)

        return result
