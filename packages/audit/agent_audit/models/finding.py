"""Finding model for security scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

from agent_audit.models.risk import Severity, Category, Location


@dataclass
class Remediation:
    """Remediation guidance for a finding."""
    description: str
    code_example: Optional[str] = None
    reference_url: Optional[str] = None


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
    suppressed: bool = False
    suppressed_reason: Optional[str] = None
    suppressed_by: Optional[str] = None  # config file path

    # Standard fields
    cwe_id: Optional[str] = None      # e.g., "CWE-78"
    owasp_id: Optional[str] = None    # e.g., "OWASP-AGENT-01"
    remediation: Optional[Remediation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def is_actionable(self, min_confidence: float = 0.5) -> bool:
        """
        Determine if this finding requires user attention.

        A finding is actionable if:
        - It is not suppressed
        - Its confidence meets or exceeds the minimum threshold

        Args:
            min_confidence: Minimum confidence threshold (default 0.5)

        Returns:
            True if the finding should be shown to the user
        """
        return not self.suppressed and self.confidence >= min_confidence

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
        return {
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
            "suppressed": self.suppressed,
            "suppressed_reason": self.suppressed_reason,
            "suppressed_by": self.suppressed_by,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "remediation": {
                "description": self.remediation.description,
                "code_example": self.remediation.code_example,
                "reference_url": self.remediation.reference_url,
            } if self.remediation else None,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }
