"""SARIF 2.1.0 output formatter for GitHub Code Scanning."""

import json
from typing import List, Dict, Any
from pathlib import Path

from agent_core.models.finding import Finding
from agent_core.models.risk import Severity
from agent_audit.version import __version__


class SARIFFormatter:
    """
    SARIF 2.1.0 formatter for GitHub Code Scanning.

    Produces SARIF-compliant JSON output that can be uploaded to
    GitHub's code scanning feature.
    """

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"

    def __init__(self, tool_name: str = "agent-audit"):
        self.tool_name = tool_name

    def format(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Format findings as SARIF.

        Args:
            findings: List of findings to format

        Returns:
            SARIF document as dictionary
        """
        rules = self._extract_rules(findings)
        results = [self._finding_to_result(f) for f in findings]

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": __version__,
                        "informationUri": "https://github.com/your-org/agent-audit",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

    def format_to_string(self, findings: List[Finding], indent: int = 2) -> str:
        """Format findings as SARIF JSON string."""
        sarif = self.format(findings)
        return json.dumps(sarif, indent=indent)

    def save(self, findings: List[Finding], output_path: Path):
        """Save findings as SARIF file."""
        sarif_str = self.format_to_string(findings)
        output_path.write_text(sarif_str)

    def _extract_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Extract unique rules from findings."""
        rules_map: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            if finding.rule_id not in rules_map:
                rule = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_level(finding.severity)
                    },
                    "properties": {
                        "security-severity": self._severity_to_score(finding.severity)
                    }
                }

                # Add help text if remediation available
                if finding.remediation:
                    rule["help"] = {
                        "text": finding.remediation.description,
                        "markdown": finding.remediation.description
                    }

                # Add CWE/OWASP tags
                tags = []
                if finding.cwe_id:
                    tags.append(f"external/cwe/{finding.cwe_id.lower()}")
                if finding.owasp_id:
                    tags.append(f"external/owasp/{finding.owasp_id}")
                if finding.category:
                    tags.append(finding.category.value)
                if tags:
                    rule["properties"]["tags"] = tags

                rules_map[finding.rule_id] = rule

        return list(rules_map.values())

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        result = finding.to_sarif()

        # Add suppression info if suppressed
        if finding.suppressed:
            result["suppressions"] = [{
                "kind": "inSource" if "noaudit" in (finding.suppressed_reason or "") else "external",
                "justification": finding.suppressed_reason or "Suppressed by configuration"
            }]

        return result

    def _severity_to_level(self, severity: Severity) -> str:
        """Map severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping[severity]

    def _severity_to_score(self, severity: Severity) -> str:
        """Map severity to security-severity score (1.0-10.0)."""
        mapping = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }
        return mapping[severity]


def format_sarif(findings: List[Finding]) -> str:
    """Convenience function to format findings as SARIF."""
    formatter = SARIFFormatter()
    return formatter.format_to_string(findings)


def save_sarif(findings: List[Finding], output_path: Path):
    """Convenience function to save findings as SARIF."""
    formatter = SARIFFormatter()
    formatter.save(findings, output_path)
