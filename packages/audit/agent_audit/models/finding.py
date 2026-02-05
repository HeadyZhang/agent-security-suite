"""Finding model for security scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List

from agent_audit.models.risk import Severity, Category, Location


# OWASP Agentic Top 10 (2026) ID to name mapping
OWASP_AGENTIC_MAP: Dict[str, str] = {
    "ASI-01": "Agent Goal Hijack",
    "ASI-02": "Tool Misuse and Exploitation",
    "ASI-03": "Identity and Privilege Abuse",
    "ASI-04": "Agentic Supply Chain Vulnerabilities",
    "ASI-05": "Unexpected Code Execution",
    "ASI-06": "Memory and Context Poisoning",
    "ASI-07": "Insecure Inter-Agent Communication",
    "ASI-08": "Cascading Failures",
    "ASI-09": "Human-Agent Trust Exploitation",
    "ASI-10": "Rogue Agents",
}


# v0.8.0: Tier thresholds (recalibrated)
TIER_THRESHOLDS = {
    "BLOCK": 0.92,  # v0.8.0: Raised from 0.90 to reduce FP in BLOCK tier
    "WARN": 0.60,
    "INFO": 0.30,
}

# Privilege rules that always allow BLOCK tier regardless of context
# These rules are critical even in test/example/infrastructure code
BLOCK_EXEMPT_RULES = {
    "AGENT-043",  # Daemon privileges
    "AGENT-044",  # Sudoers NOPASSWD
    "AGENT-046",  # System credential store access
}


# v0.9.0: Rule subsumption map
# When a more severe rule fires on the same line, it subsumes less severe rules
# This reduces noise from redundant findings
RULE_SUBSUMPTION_MAP: Dict[str, List[str]] = {
    # Command injection (AGENT-001) subsumes:
    # - No sandbox subprocess (AGENT-047): If we have injection, sandbox is moot
    # - No input validation (AGENT-034): Confirmed injection > missing validation
    "AGENT-001": ["AGENT-047", "AGENT-034"],
    # Code execution (AGENT-017) also subsumes these
    "AGENT-017": ["AGENT-047", "AGENT-034"],
}


def deduplicate_findings(findings: List["Finding"]) -> List["Finding"]:
    """
    Deduplicate findings on the same line.

    v0.9.0: P0 fix for same-line multi-rule redundancy (MLAgentBench, SWE-agent).

    Rules:
    1. Same rule + same file:line → keep only the highest confidence finding
    2. Rule subsumption: AGENT-001 firing subsumes AGENT-047/AGENT-034 on same line

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings
    """
    # Group by file:line
    from collections import defaultdict
    by_location: Dict[str, List["Finding"]] = defaultdict(list)

    for f in findings:
        key = f"{f.location.file_path}:{f.location.start_line}"
        by_location[key].append(f)

    result: List["Finding"] = []

    for loc_key, loc_findings in by_location.items():
        if len(loc_findings) == 1:
            result.append(loc_findings[0])
            continue

        # Rule 1: Same rule deduplication - keep highest confidence
        rule_to_findings: Dict[str, List["Finding"]] = defaultdict(list)
        for f in loc_findings:
            rule_to_findings[f.rule_id].append(f)

        # Keep best finding per rule
        best_per_rule: Dict[str, "Finding"] = {}
        for rule_id, rule_findings in rule_to_findings.items():
            # Sort by confidence descending, keep first
            best = max(rule_findings, key=lambda x: x.confidence)
            best_per_rule[rule_id] = best

        # Rule 2: Apply subsumption
        rules_present = set(best_per_rule.keys())
        subsumed_rules: set = set()

        for dominant_rule, subsumed_list in RULE_SUBSUMPTION_MAP.items():
            if dominant_rule in rules_present:
                # This dominant rule subsumes others
                for subsumed in subsumed_list:
                    if subsumed in rules_present:
                        subsumed_rules.add(subsumed)

        # Add non-subsumed findings to result
        for rule_id, finding in best_per_rule.items():
            if rule_id not in subsumed_rules:
                result.append(finding)

    return result


def confidence_to_tier(confidence: float) -> str:
    """
    Convert confidence score to reporting tier.

    v0.8.0: BLOCK threshold raised to 0.92 to reduce false positives.

    Tiers:
    - BLOCK: confidence >= 0.92 (high confidence, should block/fail CI)
    - WARN: confidence >= 0.60 (medium confidence, warn user)
    - INFO: confidence >= 0.30 (low confidence, informational)
    - SUPPRESSED: confidence < 0.30 (very low confidence, suppress by default)

    Args:
        confidence: Confidence score between 0.0 and 1.0

    Returns:
        Tier string: "BLOCK", "WARN", "INFO", or "SUPPRESSED"
    """
    if confidence >= TIER_THRESHOLDS["BLOCK"]:
        return "BLOCK"
    elif confidence >= TIER_THRESHOLDS["WARN"]:
        return "WARN"
    elif confidence >= TIER_THRESHOLDS["INFO"]:
        return "INFO"
    else:
        return "SUPPRESSED"


def compute_tier_with_context(
    confidence: float,
    file_context: str,
    rule_id: str
) -> str:
    """
    Compute tier with BLOCK double-confirmation mechanism.

    v0.8.0: BLOCK layer gatekeeper - test/example/infrastructure code
    cannot enter BLOCK tier unless the rule is a privilege rule.

    Args:
        confidence: Confidence score
        file_context: File context string ("test", "example", "infrastructure", etc.)
        rule_id: Rule identifier

    Returns:
        Tier string
    """
    base_tier = confidence_to_tier(confidence)

    if base_tier != "BLOCK":
        return base_tier

    # BLOCK tier double confirmation
    # Privilege rules can always be BLOCK
    if rule_id in BLOCK_EXEMPT_RULES:
        return "BLOCK"

    # Non-privilege rules in special contexts get downgraded to WARN
    non_block_contexts = {"test", "fixture", "example", "infrastructure"}
    if file_context.lower() in non_block_contexts:
        return "WARN"

    return "BLOCK"


@dataclass
class Remediation:
    """Remediation guidance for a finding."""
    description: str
    code_example: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class OperationContext:
    """
    Additional context about a finding for enhanced analysis.

    Used primarily for AGENT-018 (Memory Poisoning) to reduce false positives.
    """
    operation_type: Optional[str] = None  # "read", "write", "clear", "unknown"
    data_source: Optional[str] = None     # "user_input", "llm_output", "internal", "unknown"
    has_sanitization: bool = False
    framework_detected: Optional[str] = None
    is_framework_standard: bool = False


@dataclass
class Finding:
    """
    Security finding result.

    Represents a single security issue discovered during scanning.
    Includes fields from both technical-spec.md and delta-spec.md.
    """
    rule_id: str                      # e.g., "AGENT-001"
    title: str
    description: str
    severity: Severity
    category: Category
    location: Location

    # Delta-spec additions for confidence scoring
    confidence: float = 1.0           # 0.0-1.0 confidence score
    tier: str = "BLOCK"               # BLOCK/WARN/INFO/SUPPRESSED (v0.4.1)
    suppressed: bool = False
    suppressed_reason: Optional[str] = None
    suppressed_by: Optional[str] = None  # config file path

    # v0.3.0: Enhanced context analysis
    needs_review: bool = False        # True if confidence is marginal (0.3-0.7)
    context: Optional[OperationContext] = None  # Operation context for memory ops

    # Standard fields
    cwe_id: Optional[str] = None      # e.g., "CWE-78"
    owasp_id: Optional[str] = None    # e.g., "OWASP-AGENT-01"
    remediation: Optional[Remediation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def is_actionable(self, min_confidence: float = 0.30) -> bool:
        """
        Determine if this finding requires user attention.

        A finding is actionable if:
        - It is not suppressed
        - Its confidence meets or exceeds the minimum threshold (default 0.30)
        - Its tier is not "SUPPRESSED"

        Args:
            min_confidence: Minimum confidence threshold (default 0.30, matching SUPPRESSED tier)

        Returns:
            True if the finding should be shown to the user
        """
        return (not self.suppressed and
                self.confidence >= min_confidence and
                self.tier != "SUPPRESSED")

    def to_sarif(self) -> Dict[str, Any]:
        """Convert to SARIF 2.1.0 result format."""
        result = {
            "ruleId": self.rule_id,
            "level": self._severity_to_sarif_level(),
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.location.file_path},
                    "region": {
                        "startLine": self.location.start_line,
                        "endLine": self.location.end_line
                    }
                }
            }]
        }

        # Add column information if available
        region = result["locations"][0]["physicalLocation"]["region"]  # type: ignore[index]
        if self.location.start_column is not None:
            region["startColumn"] = self.location.start_column
        if self.location.end_column is not None:
            region["endColumn"] = self.location.end_column

        # Add fingerprint for deduplication
        result["fingerprints"] = {
            "primary": self._compute_fingerprint()
        }

        # Add properties for additional metadata
        properties: Dict[str, Any] = {}
        if self.confidence < 1.0:
            properties["confidence"] = self.confidence
        if self.cwe_id:
            properties["cwe"] = self.cwe_id
        if self.owasp_id:
            properties["owasp"] = self.owasp_id
        if properties:
            result["properties"] = properties

        return result

    def _severity_to_sarif_level(self) -> str:
        """Map severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping[self.severity]

    def _compute_fingerprint(self) -> str:
        """Compute a stable fingerprint for deduplication."""
        import hashlib
        components = [
            self.rule_id,
            self.location.file_path,
            str(self.location.start_line),
            (self.location.snippet or "")[:50]
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "location": {
                "file_path": self.location.file_path,
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "start_column": self.location.start_column,
                "end_column": self.location.end_column,
                "snippet": self.location.snippet,
            },
            "confidence": self.confidence,
            "tier": self.tier,
            "suppressed": self.suppressed,
            "suppressed_reason": self.suppressed_reason,
            "suppressed_by": self.suppressed_by,
            "needs_review": self.needs_review,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            # v0.4.0: Add asi_categories list for backward compatibility with benchmark scripts
            "asi_categories": [self.owasp_id] if self.owasp_id else [],
            "remediation": {
                "description": self.remediation.description,
                "code_example": self.remediation.code_example,
                "reference_url": self.remediation.reference_url,
            } if self.remediation else None,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }

        # Add context if present (for AGENT-018 and similar rules)
        if self.context:
            result["context"] = {
                "operation_type": self.context.operation_type,
                "data_source": self.context.data_source,
                "has_sanitization": self.context.has_sanitization,
                "framework_detected": self.context.framework_detected,
                "is_framework_standard": self.context.is_framework_standard,
            }

        return result
