"""Risk assessment models."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


def _normalize_path(path: str) -> str:
    """Normalize path to use forward slashes for cross-platform consistency."""
    return path.replace("\\", "/")


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class Category(Enum):
    """Categories for security findings."""
    # Original categories
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PROMPT_INJECTION = "prompt_injection"
    EXCESSIVE_PERMISSION = "excessive_permission"

    # OWASP Agentic Top 10 (2026) extended categories
    GOAL_HIJACK = "goal_hijack"                              # ASI-01
    TOOL_MISUSE = "tool_misuse"                              # ASI-02
    IDENTITY_PRIVILEGE_ABUSE = "identity_privilege_abuse"    # ASI-03
    SUPPLY_CHAIN_AGENTIC = "supply_chain_agentic"            # ASI-04
    UNEXPECTED_CODE_EXECUTION = "unexpected_code_execution"  # ASI-05
    MEMORY_POISONING = "memory_poisoning"                    # ASI-06
    INSECURE_INTER_AGENT_COMM = "insecure_inter_agent_comm"  # ASI-07
    CASCADING_FAILURES = "cascading_failures"                # ASI-08
    TRUST_EXPLOITATION = "trust_exploitation"                # ASI-09
    ROGUE_AGENT = "rogue_agent"                              # ASI-10


@dataclass
class Location:
    """Code location for a finding."""
    file_path: str
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None

    def __post_init__(self):
        """Normalize file_path to use forward slashes for cross-platform consistency."""
        self.file_path = _normalize_path(self.file_path)


@dataclass
class RiskScore:
    """Risk score calculation result."""
    score: float  # 0.0 - 10.0
    factors: dict  # Contributing factors and their weights

    def is_high_risk(self) -> bool:
        """Check if this represents high risk."""
        return self.score >= 7.0

    def is_medium_risk(self) -> bool:
        """Check if this represents medium risk."""
        return 4.0 <= self.score < 7.0

    def is_low_risk(self) -> bool:
        """Check if this represents low risk."""
        return self.score < 4.0
