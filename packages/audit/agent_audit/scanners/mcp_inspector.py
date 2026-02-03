"""
MCP Inspector - Runtime MCP Server probe ("Agent Nmap").

Connects to MCP servers to discover and analyze their capabilities
WITHOUT executing any tools.
"""

import asyncio
import logging
import sys
import time
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager

from agent_core.models.tool import ToolDefinition, PermissionType, RiskLevel, ToolParameter
from agent_audit.utils.mcp_client import (
    BaseMCPTransport, TransportType, create_client, infer_transport_type
)


# Python 3.9 compatibility for asyncio.timeout
if sys.version_info >= (3, 11):
    from asyncio import timeout as async_timeout
else:
    @asynccontextmanager
    async def async_timeout(delay: float):
        """Compatibility wrapper for asyncio.timeout on Python < 3.11."""
        task = asyncio.current_task()
        loop = asyncio.get_event_loop()
        deadline = loop.time() + delay
        handle = loop.call_at(deadline, task.cancel)
        try:
            yield
        except asyncio.CancelledError:
            raise asyncio.TimeoutError()
        finally:
            handle.cancel()

logger = logging.getLogger(__name__)


@dataclass
class MCPInspectionResult:
    """Result of MCP server inspection."""
    server_name: str
    server_version: Optional[str] = None
    transport: TransportType = TransportType.SSE

    # Tools
    tools: List[ToolDefinition] = field(default_factory=list)
    tool_count: int = 0

    # Resources
    resources: List[Dict[str, Any]] = field(default_factory=list)
    resource_count: int = 0

    # Prompts
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    prompt_count: int = 0

    # Security analysis
    risk_score: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    capabilities_declared: List[str] = field(default_factory=list)

    # Connection info
    connected: bool = False
    connection_error: Optional[str] = None
    response_time_ms: float = 0.0


class MCPInspector:
    """
    Safe MCP Server inspector.

    Security principles:
    1. Only sends: initialize, tools/list, resources/list, prompts/list
    2. NEVER calls tools/call (no tool execution)
    3. Timeout protection against malicious servers
    4. Does not trust server responses for code execution
    """

    # High-risk tool name keywords
    HIGH_RISK_KEYWORDS = {
        'exec', 'shell', 'command', 'run', 'eval', 'system',
        'sudo', 'admin', 'root', 'delete', 'remove', 'drop',
        'truncate', 'format', 'destroy', 'kill', 'rm',
    }

    # Keywords indicating specific permissions
    PERMISSION_KEYWORDS = {
        PermissionType.SHELL_EXEC: ['exec', 'shell', 'command', 'bash', 'terminal', 'run'],
        PermissionType.FILE_READ: ['read', 'file', 'load', 'open', 'cat', 'get_file'],
        PermissionType.FILE_WRITE: ['write', 'save', 'create', 'modify', 'edit', 'put_file'],
        PermissionType.FILE_DELETE: ['delete', 'remove', 'unlink', 'rm', 'rmdir'],
        PermissionType.NETWORK_OUTBOUND: ['http', 'request', 'fetch', 'api', 'url', 'web', 'download', 'upload'],
        PermissionType.DATABASE_READ: ['query', 'sql', 'database', 'db', 'select'],
        PermissionType.DATABASE_WRITE: ['insert', 'update', 'drop', 'alter'],
        PermissionType.SECRET_ACCESS: ['secret', 'credential', 'password', 'key', 'token', 'auth'],
        PermissionType.BROWSER_CONTROL: ['browser', 'playwright', 'puppeteer', 'selenium', 'chrome'],
    }

    # Sensitive resource patterns (cross-platform)
    SENSITIVE_RESOURCE_PATTERNS = [
        # Unix sensitive paths
        '/etc/', '.ssh/', '.aws/', '.env',
        'credentials', 'secret', 'password', 'token',
        'private_key', '.git/config', '.npmrc',
        # Windows equivalents
        'system32/config', 'AppData/Roaming', 'AppData/Local',
        '%USERPROFILE%', '%APPDATA%', 'id_rsa', 'id_ed25519',
    ]

    def __init__(self, timeout: int = 30):
        """
        Initialize the inspector.

        Args:
            timeout: Connection and request timeout in seconds
        """
        self.timeout = timeout

    async def inspect(
        self,
        target: str,
        transport: Optional[TransportType] = None
    ) -> MCPInspectionResult:
        """
        Inspect an MCP server.

        Args:
            target: Server target specification
                - "https://example.com/sse" -> SSE transport
                - "python server.py" -> STDIO transport
            transport: Explicit transport type (auto-detected if None)

        Returns:
            Inspection result with tools, resources, prompts, and risk analysis
        """
        start_time = time.perf_counter()

        # Infer transport type if not specified
        if transport is None:
            transport = infer_transport_type(target)

        result = MCPInspectionResult(
            server_name="unknown",
            transport=transport
        )

        client: Optional[BaseMCPTransport] = None

        try:
            async with async_timeout(self.timeout):
                # Connect to server
                client = await create_client(target, transport)

                # 1. Initialize connection
                init_response = await client.send("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agent-audit-inspector",
                        "version": "0.1.0"
                    }
                })

                result.server_name = init_response.get("serverInfo", {}).get("name", "unknown")
                result.server_version = init_response.get("serverInfo", {}).get("version")
                result.capabilities_declared = list(init_response.get("capabilities", {}).keys())

                # Send initialized notification
                await client.notify("notifications/initialized", {})

                # 2. List tools
                tools_response = await client.send("tools/list", {})
                raw_tools = tools_response.get("tools", [])
                result.tools = [self._analyze_tool(t) for t in raw_tools]
                result.tool_count = len(result.tools)

                # 3. List resources (may not be supported)
                try:
                    resources_response = await client.send("resources/list", {})
                    result.resources = resources_response.get("resources", [])
                    result.resource_count = len(result.resources)
                except Exception:
                    pass  # Server may not support resources

                # 4. List prompts (may not be supported)
                try:
                    prompts_response = await client.send("prompts/list", {})
                    result.prompts = prompts_response.get("prompts", [])
                    result.prompt_count = len(result.prompts)
                except Exception:
                    pass  # Server may not support prompts

                result.connected = True

        except asyncio.TimeoutError:
            result.connection_error = f"Connection timed out after {self.timeout}s"
        except Exception as e:
            result.connection_error = str(e)
        finally:
            if client:
                try:
                    await client.close()
                except Exception:
                    pass

        result.response_time_ms = (time.perf_counter() - start_time) * 1000

        # Perform security analysis
        if result.connected:
            result.risk_score = self._calculate_risk_score(result)
            result.findings = self._generate_findings(result)

        return result

    def _analyze_tool(self, raw_tool: Dict[str, Any]) -> ToolDefinition:
        """Analyze a tool definition from the server."""
        name = raw_tool.get("name", "unknown")
        description = raw_tool.get("description", "")
        input_schema = raw_tool.get("inputSchema", {})

        # Infer permissions from name and description
        permissions = self._infer_permissions(name, description)

        # Analyze input schema for validation
        schema_analysis = self._analyze_input_schema(input_schema)

        # Extract parameters
        parameters = self._extract_parameters(input_schema)

        tool = ToolDefinition(
            name=name,
            description=description,
            source_file="mcp_server",
            source_line=0,
            permissions=permissions,
            parameters=parameters,
            has_input_validation=schema_analysis.get("has_validation", False),
            mcp_server="remote",
        )

        tool.update_capability_flags()
        tool.risk_level = tool.infer_risk_level()

        return tool

    def _infer_permissions(self, name: str, description: str) -> Set[PermissionType]:
        """Infer tool permissions from name and description."""
        permissions: Set[PermissionType] = set()
        combined = (name + " " + description).lower()

        for permission, keywords in self.PERMISSION_KEYWORDS.items():
            if any(kw in combined for kw in keywords):
                permissions.add(permission)

        return permissions

    def _analyze_input_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze input schema for security properties."""
        result = {
            "has_validation": False,
            "unconstrained_strings": [],
            "has_enum": False,
            "has_pattern": False,
        }

        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        for param_name, param_def in properties.items():
            param_type = param_def.get("type", "string")

            if param_type == "string":
                if "enum" in param_def:
                    result["has_enum"] = True
                    result["has_validation"] = True
                elif "pattern" in param_def:
                    result["has_pattern"] = True
                    result["has_validation"] = True
                elif "maxLength" in param_def or "minLength" in param_def:
                    result["has_validation"] = True
                else:
                    result["unconstrained_strings"].append(param_name)

            elif param_type in ("integer", "number"):
                if "minimum" in param_def or "maximum" in param_def:
                    result["has_validation"] = True

        return result

    def _extract_parameters(self, schema: Dict[str, Any]) -> List[ToolParameter]:
        """Extract parameter definitions from schema."""
        parameters = []
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        for param_name, param_def in properties.items():
            param_type = param_def.get("type", "string")
            is_constrained = (
                "enum" in param_def or
                "pattern" in param_def or
                "maxLength" in param_def
            )

            param = ToolParameter(
                name=param_name,
                type=param_type,
                required=param_name in required,
                description=param_def.get("description"),
                allows_arbitrary_input=not is_constrained and param_type == "string",
                sanitization_present=is_constrained,
            )
            parameters.append(param)

        return parameters

    def _calculate_risk_score(self, result: MCPInspectionResult) -> float:
        """Calculate overall risk score for the server."""
        if not result.connected:
            return 0.0

        score = 0.0

        # Tool risk contributions
        for tool in result.tools:
            tool_risk = tool.calculate_risk_score()
            score += tool_risk * 0.15  # Each tool contributes to overall risk

        # High-risk tool name bonus
        for tool in result.tools:
            name_lower = tool.name.lower()
            if any(kw in name_lower for kw in self.HIGH_RISK_KEYWORDS):
                score += 0.8

        # Unconstrained string parameters
        for tool in result.tools:
            unconstrained = sum(
                1 for p in tool.parameters
                if p.allows_arbitrary_input
            )
            score += unconstrained * 0.2

        # Sensitive resource exposure
        for resource in result.resources:
            uri = resource.get("uri", "").lower()
            name = resource.get("name", "").lower()
            if any(pattern in uri or pattern in name
                  for pattern in self.SENSITIVE_RESOURCE_PATTERNS):
                score += 0.5

        # Excessive tool count
        if result.tool_count > 20:
            score += 1.0
        elif result.tool_count > 10:
            score += 0.5

        return min(10.0, score)

    def _generate_findings(self, result: MCPInspectionResult) -> List[Dict[str, Any]]:
        """Generate security findings from inspection."""
        findings = []

        # Check for high-risk tools
        for tool in result.tools:
            name_lower = tool.name.lower()
            if any(kw in name_lower for kw in self.HIGH_RISK_KEYWORDS):
                findings.append({
                    "type": "high_risk_tool",
                    "tool": tool.name,
                    "description": f"Tool name contains high-risk keyword",
                    "severity": "high"
                })

            # Check for unconstrained input
            unconstrained = [
                p.name for p in tool.parameters
                if p.allows_arbitrary_input
            ]
            if unconstrained and PermissionType.SHELL_EXEC in tool.permissions:
                findings.append({
                    "type": "unconstrained_dangerous_input",
                    "tool": tool.name,
                    "parameters": unconstrained,
                    "description": "Shell execution tool accepts unconstrained string input",
                    "severity": "critical"
                })

        # Check for sensitive resources
        for resource in result.resources:
            uri = resource.get("uri", "").lower()
            for pattern in self.SENSITIVE_RESOURCE_PATTERNS:
                if pattern in uri:
                    findings.append({
                        "type": "sensitive_resource",
                        "resource": resource.get("uri"),
                        "pattern": pattern,
                        "description": "Resource exposes potentially sensitive path",
                        "severity": "medium"
                    })
                    break

        # Check for excessive permissions
        all_permissions: Set[PermissionType] = set()
        for tool in result.tools:
            all_permissions.update(tool.permissions)

        dangerous_combo = {
            PermissionType.SECRET_ACCESS,
            PermissionType.NETWORK_OUTBOUND
        }
        if dangerous_combo.issubset(all_permissions):
            findings.append({
                "type": "dangerous_permission_combo",
                "description": "Server has tools for both secret access and network outbound - potential data exfiltration",
                "severity": "high"
            })

        return findings
