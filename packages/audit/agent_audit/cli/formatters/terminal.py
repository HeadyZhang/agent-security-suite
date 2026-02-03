"""Terminal formatter with Rich output."""

from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box

from agent_audit.models.finding import Finding
from agent_audit.models.risk import Severity

console = Console()


class TerminalFormatter:
    """Rich terminal output formatter for scan results."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet

    def format_findings(
        self,
        findings: List[Finding],
        scan_path: str,
        scanned_files: int = 0
    ):
        """Format and display findings."""
        if self.quiet and not findings:
            return

        # Header
        self._print_header(scan_path, scanned_files, findings)

        if not findings:
            console.print("[green]✓ No security issues found![/green]")
            return

        # Group findings by severity
        by_severity = self._group_by_severity(findings)

        # Print findings by severity (highest first)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                        Severity.LOW, Severity.INFO]:
            severity_findings = by_severity.get(severity, [])
            if severity_findings:
                self._print_severity_section(severity, severity_findings)

        # Summary
        self._print_summary(findings)

    def _print_header(
        self,
        scan_path: str,
        scanned_files: int,
        findings: List[Finding]
    ):
        """Print the report header."""
        risk_score = self._calculate_risk_score(findings)
        risk_color = "green" if risk_score < 4 else "yellow" if risk_score < 7 else "red"

        header = Text()
        header.append("Agent Audit Security Report\n", style="bold")
        header.append(f"Scanned: {scan_path}\n", style="dim")
        if scanned_files:
            header.append(f"Files analyzed: {scanned_files}\n", style="dim")
        header.append(f"Risk Score: ", style="dim")
        header.append(f"{risk_score:.1f}/10", style=f"bold {risk_color}")

        console.print(Panel(header, border_style=risk_color))
        console.print()

    def _print_severity_section(
        self,
        severity: Severity,
        findings: List[Finding]
    ):
        """Print findings for a severity level."""
        icon = self.SEVERITY_ICONS[severity]
        color = self.SEVERITY_COLORS[severity]
        count = len(findings)

        console.print(f"{icon} [{color}]{severity.value.upper()} ({count})[/{color}]")
        console.print()

        for finding in findings:
            self._print_finding(finding)

        console.print()

    def _print_finding(self, finding: Finding):
        """Print a single finding."""
        color = self.SEVERITY_COLORS[finding.severity]

        # Title and confidence
        confidence_str = ""
        if finding.confidence < 1.0:
            confidence_str = f" (confidence: {finding.confidence:.0%})"

        console.print(f"  [{color}]{finding.rule_id}[/{color}]: {finding.title}{confidence_str}")

        # Location
        loc = finding.location
        console.print(f"    [dim]Location:[/dim] {loc.file_path}:{loc.start_line}")

        # Code snippet
        if loc.snippet:
            console.print(f"    [dim]Code:[/dim] {loc.snippet[:80]}...")

        # Remediation
        if finding.remediation and self.verbose:
            console.print(f"    [dim]Fix:[/dim] {finding.remediation.description[:100]}...")

        console.print()

    def _print_summary(self, findings: List[Finding]):
        """Print summary table."""
        # Count by severity
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        suppressed = sum(1 for f in findings if f.suppressed)

        # Summary line
        parts = []
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                        Severity.LOW, Severity.INFO]:
            if counts[severity] > 0:
                color = self.SEVERITY_COLORS[severity]
                parts.append(f"[{color}]{counts[severity]} {severity.value}[/{color}]")

        console.print("━" * 50)
        console.print(f"[bold]Findings:[/bold] {', '.join(parts)}")

        if suppressed:
            console.print(f"[dim]Suppressed: {suppressed} (configure in .agent-audit.yaml)[/dim]")

        # Risk bar
        risk_score = self._calculate_risk_score(findings)
        self._print_risk_bar(risk_score)

    def _print_risk_bar(self, risk_score: float):
        """Print a visual risk score bar."""
        bar_width = 30
        filled = int((risk_score / 10) * bar_width)

        if risk_score < 4:
            color = "green"
            label = "LOW"
        elif risk_score < 7:
            color = "yellow"
            label = "MEDIUM"
        else:
            color = "red"
            label = "HIGH"

        bar = "█" * filled + "░" * (bar_width - filled)
        console.print(f"[bold]Risk Score:[/bold] [{color}]{bar}[/{color}] {risk_score:.1f}/10 ({label})")

    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0

        severity_weights = {
            Severity.CRITICAL: 3.0,
            Severity.HIGH: 2.0,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }

        score = sum(
            severity_weights[f.severity] * f.confidence
            for f in findings
            if not f.suppressed
        )

        return min(10.0, score)

    def _group_by_severity(
        self,
        findings: List[Finding]
    ) -> Dict[Severity, List[Finding]]:
        """Group findings by severity."""
        groups: Dict[Severity, List[Finding]] = {}
        for finding in findings:
            if finding.suppressed and not self.verbose:
                continue
            if finding.severity not in groups:
                groups[finding.severity] = []
            groups[finding.severity].append(finding)
        return groups


def format_scan_results(
    findings: List[Finding],
    scan_path: str,
    scanned_files: int = 0,
    verbose: bool = False,
    quiet: bool = False
):
    """Convenience function to format scan results."""
    formatter = TerminalFormatter(verbose=verbose, quiet=quiet)
    formatter.format_findings(findings, scan_path, scanned_files)
