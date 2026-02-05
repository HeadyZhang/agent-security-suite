"""Terminal formatter with Rich output."""

import math
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from agent_audit.models.finding import Finding
from agent_audit.models.risk import Severity

console = Console()


# v0.5.2: AGENT-046 credential store deduplication
CREDENTIAL_STORE_TYPES = {
    "macos_keychain": ["keychain", "security find-generic-password",
                       "security find-internet-password", "secitemcopymatching",
                       "ksecclass", "readkeychainpassword"],
    "linux_keyring": ["gnome-keyring", "libsecret", "kwallet", "secretservice"],
    "password_manager_bitwarden": ["rbw get", "rbw unlock", "bitwarden"],
    "password_manager_1password": ["1password-cli", "op get item", "op item get"],
    "password_manager_lastpass": ["lastpass-cli", "lpass show"],
    "password_manager_pass": ["pass show", "pass insert"],
    "windows_dpapi": ["dpapi", "cryptprotectdata", "cryptunprotectdata",
                      "credread", "credwrite", "get-storedcredential"],
}


def deduplicate_credential_store_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate AGENT-046 findings by credential store type.

    v0.5.2: Same credential store type (e.g., macOS Keychain) is only
    reported once, keeping the finding with highest confidence.

    Args:
        findings: All findings from scan

    Returns:
        Deduplicated findings list
    """
    others: List[Finding] = []
    by_store_type: Dict[str, List[Finding]] = {}

    for f in findings:
        if f.rule_id != "AGENT-046":
            others.append(f)
            continue

        # Determine store type from snippet and description
        snippet = ""
        if hasattr(f, 'location') and f.location and hasattr(f.location, 'snippet'):
            snippet = (f.location.snippet or "").lower()
        description = (f.description or "").lower()
        combined = f"{snippet} {description}"

        matched_type = "unknown_store"
        for store_type, keywords in CREDENTIAL_STORE_TYPES.items():
            if any(kw.lower() in combined for kw in keywords):
                matched_type = store_type
                break

        if matched_type not in by_store_type:
            by_store_type[matched_type] = []
        by_store_type[matched_type].append(f)

    # Keep only the highest confidence finding per store type
    result = others[:]
    for store_type, group in by_store_type.items():
        best = max(group, key=lambda f: f.confidence)
        result.append(best)

    return result


def finalize_findings(findings: List[Finding]) -> List[Finding]:
    """
    Post-process findings before output.

    v0.5.2: Applies deduplication and sorting.
    """
    # 1. AGENT-046 credential store deduplication
    result = deduplicate_credential_store_findings(findings)

    # 2. Sort by confidence (descending), then by rule_id
    result.sort(key=lambda f: (-f.confidence, f.rule_id))

    return result


# Tier display configuration
TIER_CONFIG = {
    "BLOCK": {"icon": "🔴", "label": "BLOCK", "color": "red bold", "threshold": "≥ 90%"},
    "WARN": {"icon": "🟠", "label": "WARN", "color": "yellow", "threshold": "≥ 60%"},
    "INFO": {"icon": "ℹ️ ", "label": "INFO", "color": "blue", "threshold": "≥ 30%"},
    "SUPPRESSED": {"icon": "⬛", "label": "SUPPRESSED", "color": "dim", "threshold": "< 30%"},
}

# Tier display order (highest to lowest)
TIER_ORDER = ["BLOCK", "WARN", "INFO", "SUPPRESSED"]


def calculate_risk_score(findings: List[Finding]) -> float:
    """
    Calculate confidence-weighted risk score from findings.

    v0.5.2: Uses smoother logarithmic scaling (natural log) to prevent saturation.
    v0.8.0: Infrastructure context findings have reduced weight (0.5x).

    The formula scales smoothly up to ~200 findings before approaching 9.8.

    Calibration targets:
    - 0 findings → 0.0
    - 3 WARN findings → ~2.7 (LOW-MEDIUM)
    - 10 WARN findings → ~5.0 (MEDIUM)
    - 20 WARN findings → ~5.8 (MEDIUM)
    - 50 WARN + 5 BLOCK → ~9.3 (HIGH)

    v0.8.0 changes:
    - Only BLOCK + WARN tier findings contribute (INFO/SUPPRESSED ignored)
    - Infrastructure context findings contribute half weight
    - This reduces Risk Score inflation from sandbox/infrastructure code findings

    Args:
        findings: List of findings to score

    Returns:
        Risk score from 0.0 to 9.8 (10.0 reserved for theoretical extremes)
    """
    SEVERITY_WEIGHT = {
        "critical": 3.0,
        "high": 1.5,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.1,
    }

    raw = 0.0
    block_count = 0

    for f in findings:
        tier = getattr(f, 'tier', 'WARN')
        if tier not in ('BLOCK', 'WARN') or f.suppressed:
            continue

        severity_weight = SEVERITY_WEIGHT.get(f.severity.value, 0.5)

        # v0.8.0: Infrastructure context findings contribute half weight
        # This reduces Risk Score inflation from sandbox/infrastructure code
        context_weight = 1.0
        if hasattr(f, 'metadata') and f.metadata.get('infrastructure_context'):
            context_weight = 0.5

        raw += f.confidence * severity_weight * context_weight

        if tier == 'BLOCK':
            block_count += 1

    if raw <= 0:
        return 0.0

    # v0.5.2: Use natural log (ln) with smaller coefficient for smoother scaling
    # Target: raw=10 → ~5.0, raw=30 → ~7.0, raw=80 → ~8.5
    base_score = 1.8 * math.log(1 + raw)

    # BLOCK (CRITICAL) bonus: +0.3 per BLOCK, capped at 2.0
    block_bonus = min(2.0, block_count * 0.3)

    score = base_score + block_bonus

    # Hard cap at 9.8 - 10.0 reserved for theoretical extreme cases
    return round(min(9.8, score), 1)


def get_risk_label(score: float) -> str:
    """Get human-readable risk label for a score."""
    if score < 2.0:
        return "LOW"
    elif score < 4.0:
        return "LOW-MEDIUM"
    elif score < 6.0:
        return "MEDIUM"
    elif score < 8.0:
        return "MEDIUM-HIGH"
    else:
        return "HIGH"


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

    def __init__(
        self,
        verbose: bool = False,
        quiet: bool = False,
        min_tier: Optional[str] = None,
        no_color: bool = False
    ):
        self.verbose = verbose
        self.quiet = quiet
        self.min_tier = min_tier or ("INFO" if verbose else "WARN")
        self.no_color = no_color

    def format_findings(
        self,
        findings: List[Finding],
        scan_path: str,
        scanned_files: int = 0
    ):
        """Format and display findings."""
        if self.quiet and not findings:
            return

        # v0.5.2: Apply deduplication and post-processing
        findings = finalize_findings(findings)

        # Header with risk score
        self._print_header(scan_path, scanned_files, findings)

        if not findings:
            console.print("[green]No security issues found![/green]")
            return

        # Group findings by tier
        by_tier = self._group_by_tier(findings)

        # Print findings by tier (BLOCK, WARN, INFO, SUPPRESSED)
        for tier in TIER_ORDER:
            tier_findings = by_tier.get(tier, [])
            self._print_tier_section(tier, tier_findings, findings)

        # Summary
        self._print_summary(findings, by_tier)

    def _print_header(
        self,
        scan_path: str,
        scanned_files: int,
        findings: List[Finding]
    ):
        """Print the report header with risk score."""
        risk_score = calculate_risk_score(findings)
        risk_label = get_risk_label(risk_score)
        risk_color = "green" if risk_score < 4 else "yellow" if risk_score < 7 else "red"

        header = Text()
        header.append("Agent Audit Security Report\n", style="bold")
        header.append(f"Scanned: {scan_path}\n", style="dim")
        if scanned_files:
            header.append(f"Files analyzed: {scanned_files}\n", style="dim")
        header.append("Risk Score: ", style="dim")
        header.append(f"{risk_score}/10 ({risk_label})", style=f"bold {risk_color}")

        console.print(Panel(header, border_style=risk_color))
        console.print()

    def _print_tier_section(
        self,
        tier: str,
        tier_findings: List[Finding],
        all_findings: List[Finding]
    ):
        """Print findings for a tier level."""
        tier_cfg = TIER_CONFIG[tier]
        icon = tier_cfg["icon"]
        label = tier_cfg["label"]
        color = tier_cfg["color"]
        threshold = tier_cfg["threshold"]
        count = len(tier_findings)

        # Determine if this tier should be shown
        tier_index = TIER_ORDER.index(tier)
        min_tier_index = TIER_ORDER.index(self.min_tier)

        # Show header for all tiers, but only show findings for visible tiers
        should_show_findings = tier_index <= min_tier_index

        if should_show_findings:
            console.print(f"{icon} [{color}]{label} — Tier {tier_index + 1} (Confidence {threshold}) — {count} findings[/{color}]")
            console.print()

            for finding in tier_findings:
                self._print_finding(finding)

            if tier_findings:
                console.print()
        else:
            # Show hidden tier summary
            if count > 0:
                console.print(f"{icon} [{color}]{label} — Tier {tier_index + 1} (hidden, use --verbose to show) — {count} findings[/{color}]")
                console.print()

    def _print_finding(self, finding: Finding):
        """Print a single finding."""
        color = self.SEVERITY_COLORS[finding.severity]

        # Title with confidence
        confidence_str = f" [confidence: {finding.confidence:.2f}]"

        console.print(f"  [{color}]{finding.rule_id}[/{color}]: {finding.title}{confidence_str}")

        # Location
        loc = finding.location
        console.print(f"    [dim]Location:[/dim] {loc.file_path}:{loc.start_line}")

        # Code snippet
        if loc.snippet:
            snippet_display = loc.snippet[:80]
            if len(loc.snippet) > 80:
                snippet_display += "..."
            console.print(f"    [dim]Code:[/dim] {snippet_display}")

        # Reason (from description or metadata)
        reason = finding.metadata.get("reason") or finding.description
        if reason:
            reason_display = reason[:100]
            if len(reason) > 100:
                reason_display += "..."
            console.print(f"    [dim]Reason:[/dim] {reason_display}")

        # Remediation (verbose only)
        if finding.remediation and self.verbose:
            console.print(f"    [dim]Fix:[/dim] {finding.remediation.description[:100]}...")

        console.print()

    def _print_summary(self, findings: List[Finding], by_tier: Dict[str, List[Finding]]):
        """Print summary table."""
        console.print("📊 [bold]Summary:[/bold]")

        # Count by tier
        tier_counts = {tier: len(by_tier.get(tier, [])) for tier in TIER_ORDER}

        # Tier summary line
        tier_parts = []
        for tier in TIER_ORDER:
            cfg = TIER_CONFIG[tier]
            count = tier_counts[tier]
            tier_parts.append(f"[{cfg['color']}]{cfg['label']}: {count}[/{cfg['color']}]")

        console.print(f"  {' | '.join(tier_parts)}")

        # Risk bar
        risk_score = calculate_risk_score(findings)
        self._print_risk_bar(risk_score)

    def _print_risk_bar(self, risk_score: float):
        """Print a visual risk score bar."""
        bar_width = 30
        filled = int((risk_score / 10) * bar_width)

        if risk_score < 4:
            color = "green"
        elif risk_score < 7:
            color = "yellow"
        else:
            color = "red"

        label = get_risk_label(risk_score)
        bar = "█" * filled + "░" * (bar_width - filled)
        console.print(f"  [bold]Risk Score:[/bold] [{color}]{bar}[/{color}] {risk_score}/10 ({label})")

    def _group_by_tier(
        self,
        findings: List[Finding]
    ) -> Dict[str, List[Finding]]:
        """Group findings by tier."""
        groups: Dict[str, List[Finding]] = {tier: [] for tier in TIER_ORDER}
        for finding in findings:
            tier = getattr(finding, 'tier', 'WARN')
            if tier not in groups:
                tier = 'WARN'  # Fallback
            groups[tier].append(finding)
        return groups


def format_scan_results(
    findings: List[Finding],
    scan_path: str,
    scanned_files: int = 0,
    verbose: bool = False,
    quiet: bool = False,
    min_tier: Optional[str] = None,
    no_color: bool = False
):
    """Convenience function to format scan results."""
    formatter = TerminalFormatter(
        verbose=verbose,
        quiet=quiet,
        min_tier=min_tier,
        no_color=no_color
    )
    formatter.format_findings(findings, scan_path, scanned_files)
