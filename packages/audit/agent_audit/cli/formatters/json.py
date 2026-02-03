"""JSON output formatter."""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from agent_core.models.finding import Finding
from agent_audit.version import __version__


class JSONFormatter:
    """JSON output formatter for scan results."""

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def format(
        self,
        findings: List[Finding],
        scan_path: str = "",
        scanned_files: int = 0
    ) -> Dict[str, Any]:
        """
        Format findings as JSON.

        Args:
            findings: List of findings to format
            scan_path: Path that was scanned
            scanned_files: Number of files scanned

        Returns:
            JSON-serializable dictionary
        """
        return {
            "version": __version__,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "scan_path": scan_path,
            "scanned_files": scanned_files,
            "summary": self._create_summary(findings),
            "findings": [self._finding_to_dict(f) for f in findings],
        }

    def format_to_string(
        self,
        findings: List[Finding],
        scan_path: str = "",
        scanned_files: int = 0
    ) -> str:
        """Format findings as JSON string."""
        data = self.format(findings, scan_path, scanned_files)
        indent = 2 if self.pretty else None
        return json.dumps(data, indent=indent, default=str)

    def save(
        self,
        findings: List[Finding],
        output_path: Path,
        scan_path: str = "",
        scanned_files: int = 0
    ):
        """Save findings as JSON file."""
        json_str = self.format_to_string(findings, scan_path, scanned_files)
        output_path.write_text(json_str, encoding="utf-8")

    def _create_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Create summary statistics."""
        total = len(findings)
        actionable = sum(1 for f in findings if f.is_actionable())
        suppressed = sum(1 for f in findings if f.suppressed)

        by_severity = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        by_category = {}
        for f in findings:
            cat = f.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total": total,
            "actionable": actionable,
            "suppressed": suppressed,
            "by_severity": by_severity,
            "by_category": by_category,
            "risk_score": self._calculate_risk_score(findings),
        }

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return finding.to_dict()

    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate risk score."""
        from agent_core.models.risk import Severity

        if not findings:
            return 0.0

        weights = {
            Severity.CRITICAL: 3.0,
            Severity.HIGH: 2.0,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }

        score = sum(
            weights[f.severity] * f.confidence
            for f in findings
            if not f.suppressed
        )

        return min(10.0, round(score, 2))


def format_json(
    findings: List[Finding],
    scan_path: str = "",
    scanned_files: int = 0,
    pretty: bool = True
) -> str:
    """Convenience function to format findings as JSON."""
    formatter = JSONFormatter(pretty=pretty)
    return formatter.format_to_string(findings, scan_path, scanned_files)


def save_json(
    findings: List[Finding],
    output_path: Path,
    scan_path: str = "",
    scanned_files: int = 0
):
    """Convenience function to save findings as JSON."""
    formatter = JSONFormatter()
    formatter.save(findings, output_path, scan_path, scanned_files)
