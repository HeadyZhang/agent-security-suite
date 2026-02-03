"""Tool definition models for agent analysis."""

from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum, auto


class PermissionType(Enum):
    """Permission types that tools may require."""
    FILE_READ = auto()
    FILE_WRITE = auto()
    FILE_DELETE = auto()
    SHELL_EXEC = auto()
    NETWORK_OUTBOUND = auto()
    NETWORK_INBOUND = auto()
    DATABASE_READ = auto()
    DATABASE_WRITE = auto()
    SECRET_ACCESS = auto()
    BROWSER_CONTROL = auto()
    PROCESS_SPAWN = auto()


class RiskLevel(Enum):
    """Risk levels for tools."""
    SAFE = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class ToolParameter:
    """Tool parameter definition."""
    name: str
    type: str
    required: bool = False
    description: Optional[str] = None
    allows_arbitrary_input: bool = False
    sanitization_present: bool = False


@dataclass
class ToolDefinition:
    """
    Agent tool definition.

    Represents a tool that an agent can call, with its permissions,
    risk level, and security properties.
    """
    name: str
    description: str
    source_file: str
    source_line: int

    permissions: Set[PermissionType] = field(default_factory=set)
    risk_level: RiskLevel = RiskLevel.LOW
    parameters: List[ToolParameter] = field(default_factory=list)

    # MCP-specific fields
    mcp_server: Optional[str] = None
    mcp_server_verified: bool = False

    # Security properties
    has_input_validation: bool = False
    has_output_sanitization: bool = False
    runs_in_sandbox: bool = False
    requires_approval: bool = False

    # Capability flags (derived from permissions)
    can_execute_code: bool = False
    can_access_filesystem: bool = False
    can_access_network: bool = False
    can_access_secrets: bool = False

    def calculate_risk_score(self) -> float:
        """
        Calculate risk score (0.0 - 10.0).

        Takes into account:
        - Permission weights (shell exec is highest risk)
        - Mitigating factors (input validation, sandbox)
        - MCP server verification status
        """
        score = 0.0

        # Permission weights
        permission_weights = {
            PermissionType.SHELL_EXEC: 3.0,
            PermissionType.SECRET_ACCESS: 2.5,
            PermissionType.FILE_DELETE: 2.0,
            PermissionType.DATABASE_WRITE: 2.0,
            PermissionType.NETWORK_OUTBOUND: 1.5,
            PermissionType.FILE_WRITE: 1.5,
            PermissionType.PROCESS_SPAWN: 2.0,
            PermissionType.BROWSER_CONTROL: 1.5,
            PermissionType.FILE_READ: 0.5,
            PermissionType.DATABASE_READ: 0.5,
            PermissionType.NETWORK_INBOUND: 1.0,
        }

        for perm in self.permissions:
            score += permission_weights.get(perm, 0.5)

        # Mitigating factors
        if self.has_input_validation:
            score *= 0.7
        if self.runs_in_sandbox:
            score *= 0.5
        if self.requires_approval:
            score *= 0.6

        # MCP verification penalty
        if self.mcp_server and not self.mcp_server_verified:
            score *= 1.3

        return min(10.0, score)

    def infer_risk_level(self) -> RiskLevel:
        """Infer risk level from calculated score."""
        score = self.calculate_risk_score()
        if score >= 8.0:
            return RiskLevel.CRITICAL
        elif score >= 6.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score >= 2.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    def update_capability_flags(self):
        """Update capability flags based on permissions."""
        self.can_execute_code = PermissionType.SHELL_EXEC in self.permissions
        self.can_access_filesystem = any(
            p in self.permissions for p in [
                PermissionType.FILE_READ,
                PermissionType.FILE_WRITE,
                PermissionType.FILE_DELETE
            ]
        )
        self.can_access_network = any(
            p in self.permissions for p in [
                PermissionType.NETWORK_OUTBOUND,
                PermissionType.NETWORK_INBOUND
            ]
        )
        self.can_access_secrets = PermissionType.SECRET_ACCESS in self.permissions

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "permissions": [p.name for p in self.permissions],
            "risk_level": self.risk_level.name,
            "risk_score": self.calculate_risk_score(),
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "required": p.required,
                    "description": p.description,
                    "allows_arbitrary_input": p.allows_arbitrary_input,
                    "sanitization_present": p.sanitization_present,
                }
                for p in self.parameters
            ],
            "mcp_server": self.mcp_server,
            "mcp_server_verified": self.mcp_server_verified,
            "has_input_validation": self.has_input_validation,
            "has_output_sanitization": self.has_output_sanitization,
            "runs_in_sandbox": self.runs_in_sandbox,
            "requires_approval": self.requires_approval,
            "can_execute_code": self.can_execute_code,
            "can_access_filesystem": self.can_access_filesystem,
            "can_access_network": self.can_access_network,
            "can_access_secrets": self.can_access_secrets,
        }
