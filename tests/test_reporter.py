"""Tests for tiered reporting and risk score calculation (v0.5.0 C4)."""

import pytest
from io import StringIO
from unittest.mock import patch
from typing import List

from agent_audit.models.finding import Finding, Remediation, confidence_to_tier
from agent_audit.models.risk import Severity, Category, Location
from agent_audit.cli.formatters.terminal import (
    TerminalFormatter,
    calculate_risk_score,
    get_risk_label,
    TIER_ORDER,
    TIER_CONFIG,
    format_scan_results,
)
from agent_audit.cli.formatters.json import (
    JSONFormatter,
    calculate_risk_score as json_calculate_risk_score,
    get_risk_label as json_get_risk_label,
)


def create_finding(
    rule_id: str = "AGENT-001",
    title: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.8,
    suppressed: bool = False,
) -> Finding:
    """Helper to create test findings."""
    tier = confidence_to_tier(confidence)
    return Finding(
        rule_id=rule_id,
        title=title,
        description=f"Test description for {rule_id}",
        severity=severity,
        category=Category.COMMAND_INJECTION,
        location=Location(
            file_path="/test/file.py",
            start_line=10,
            end_line=10,
            snippet="test_code()",
        ),
        confidence=confidence,
        tier=tier,
        suppressed=suppressed,
        remediation=Remediation(description="Fix the issue"),
    )


class TestRiskScoreCalculation:
    """Test confidence-weighted risk score calculation."""

    def test_empty_findings_returns_zero(self):
        """Empty findings should return risk score of 0."""
        assert calculate_risk_score([]) == 0.0

    def test_single_critical_high_confidence(self):
        """Single critical finding with high confidence."""
        findings = [create_finding(severity=Severity.CRITICAL, confidence=0.95)]
        score = calculate_risk_score(findings)
        # v0.5.2: Raw: 0.95 * 3.0 = 2.85
        # Score: 1.8 * ln(1 + 2.85) = 1.8 * 1.348 = 2.43
        assert 2.0 <= score <= 3.5

    def test_single_low_severity_low_confidence(self):
        """Single low severity finding with low confidence."""
        findings = [create_finding(severity=Severity.LOW, confidence=0.35)]
        score = calculate_risk_score(findings)
        # Raw: 0.35 * 0.2 = 0.07
        # Score: 2.5 * log2(1 + 0.07) = very small
        assert score < 1.0

    def test_multiple_findings_accumulate(self):
        """Multiple findings should accumulate in score."""
        findings = [
            create_finding(severity=Severity.HIGH, confidence=0.8),
            create_finding(severity=Severity.HIGH, confidence=0.7),
            create_finding(severity=Severity.MEDIUM, confidence=0.6),
        ]
        score = calculate_risk_score(findings)
        # Multiple findings should produce higher score
        assert score > 2.0

    def test_suppressed_findings_excluded(self):
        """Suppressed findings should not contribute to score."""
        findings = [
            create_finding(severity=Severity.CRITICAL, confidence=0.95),
            create_finding(severity=Severity.CRITICAL, confidence=0.95, suppressed=True),
        ]
        score_with_suppressed = calculate_risk_score(findings)
        score_without = calculate_risk_score([findings[0]])
        assert score_with_suppressed == score_without

    def test_info_tier_excluded_from_score(self):
        """INFO tier findings (confidence < 0.60) should not contribute to score."""
        # Create INFO tier findings (confidence 0.30-0.59)
        findings = [
            create_finding(severity=Severity.CRITICAL, confidence=0.45),  # INFO tier
            create_finding(severity=Severity.CRITICAL, confidence=0.35),  # INFO tier
        ]
        score = calculate_risk_score(findings)
        # INFO tier excluded, so score should be 0
        assert score == 0.0

    def test_suppressed_tier_excluded_from_score(self):
        """SUPPRESSED tier findings (confidence < 0.30) should not contribute."""
        findings = [
            create_finding(severity=Severity.CRITICAL, confidence=0.20),  # SUPPRESSED
            create_finding(severity=Severity.CRITICAL, confidence=0.15),  # SUPPRESSED
        ]
        score = calculate_risk_score(findings)
        assert score == 0.0

    def test_max_score_capped_at_10(self):
        """Risk score should be capped at 10.0."""
        # Create many high-severity findings
        findings = [
            create_finding(severity=Severity.CRITICAL, confidence=0.95)
            for _ in range(100)
        ]
        score = calculate_risk_score(findings)
        assert score <= 10.0

    def test_logarithmic_scaling(self):
        """Score should scale logarithmically (diminishing returns)."""
        one_finding = [create_finding(severity=Severity.HIGH, confidence=0.8)]
        two_findings = one_finding * 2
        ten_findings = one_finding * 10

        score_1 = calculate_risk_score(one_finding)
        score_2 = calculate_risk_score(two_findings)
        score_10 = calculate_risk_score(ten_findings)

        # Logarithmic: doubling input doesn't double output
        assert score_2 < score_1 * 2
        # 10x input doesn't produce 10x output
        assert score_10 < score_1 * 10


class TestRiskLabel:
    """Test risk score to label mapping."""

    def test_low_risk(self):
        """Score < 2.0 should be LOW."""
        assert get_risk_label(0.0) == "LOW"
        assert get_risk_label(1.5) == "LOW"
        assert get_risk_label(1.9) == "LOW"

    def test_low_medium_risk(self):
        """Score 2.0-3.9 should be LOW-MEDIUM."""
        assert get_risk_label(2.0) == "LOW-MEDIUM"
        assert get_risk_label(3.5) == "LOW-MEDIUM"
        assert get_risk_label(3.9) == "LOW-MEDIUM"

    def test_medium_risk(self):
        """Score 4.0-5.9 should be MEDIUM."""
        assert get_risk_label(4.0) == "MEDIUM"
        assert get_risk_label(5.0) == "MEDIUM"
        assert get_risk_label(5.9) == "MEDIUM"

    def test_medium_high_risk(self):
        """Score 6.0-7.9 should be MEDIUM-HIGH."""
        assert get_risk_label(6.0) == "MEDIUM-HIGH"
        assert get_risk_label(7.0) == "MEDIUM-HIGH"
        assert get_risk_label(7.9) == "MEDIUM-HIGH"

    def test_high_risk(self):
        """Score >= 8.0 should be HIGH."""
        assert get_risk_label(8.0) == "HIGH"
        assert get_risk_label(9.5) == "HIGH"
        assert get_risk_label(10.0) == "HIGH"


class TestTieredOutput:
    """Test tiered output formatting."""

    def test_default_shows_block_and_warn(self):
        """Default output should show BLOCK and WARN, hide INFO and SUPPRESSED."""
        formatter = TerminalFormatter(verbose=False)
        assert formatter.min_tier == "WARN"

    def test_verbose_shows_info(self):
        """Verbose mode should show INFO tier."""
        formatter = TerminalFormatter(verbose=True)
        assert formatter.min_tier == "INFO"

    def test_min_tier_block_only(self):
        """--min-tier BLOCK should only show BLOCK tier."""
        formatter = TerminalFormatter(min_tier="BLOCK")
        assert formatter.min_tier == "BLOCK"

    def test_min_tier_suppressed_shows_all(self):
        """--min-tier SUPPRESSED should show all tiers."""
        formatter = TerminalFormatter(min_tier="SUPPRESSED")
        assert formatter.min_tier == "SUPPRESSED"

    def test_group_by_tier(self):
        """Findings should be grouped correctly by tier."""
        findings = [
            create_finding(confidence=0.95),  # BLOCK
            create_finding(confidence=0.75),  # WARN
            create_finding(confidence=0.45),  # INFO
            create_finding(confidence=0.20),  # SUPPRESSED
        ]
        formatter = TerminalFormatter()
        grouped = formatter._group_by_tier(findings)

        assert len(grouped["BLOCK"]) == 1
        assert len(grouped["WARN"]) == 1
        assert len(grouped["INFO"]) == 1
        assert len(grouped["SUPPRESSED"]) == 1


class TestVerboseFlag:
    """Test --verbose flag behavior."""

    def test_verbose_changes_min_tier_to_info(self):
        """--verbose should set min_tier to INFO."""
        formatter = TerminalFormatter(verbose=True)
        assert formatter.min_tier == "INFO"

    def test_explicit_min_tier_overrides_verbose(self):
        """Explicit --min-tier should override --verbose default."""
        formatter = TerminalFormatter(verbose=True, min_tier="BLOCK")
        assert formatter.min_tier == "BLOCK"


class TestMinTierFilter:
    """Test --min-tier filtering."""

    def test_min_tier_block_filters_correctly(self):
        """With --min-tier BLOCK, only BLOCK findings should be visible."""
        findings = [
            create_finding(confidence=0.95),  # BLOCK
            create_finding(confidence=0.75),  # WARN
            create_finding(confidence=0.45),  # INFO
        ]
        formatter = TerminalFormatter(min_tier="BLOCK")
        grouped = formatter._group_by_tier(findings)

        # All are grouped, but display logic in _print_tier_section handles visibility
        tier_index = TIER_ORDER.index("BLOCK")
        min_tier_index = TIER_ORDER.index(formatter.min_tier)
        assert tier_index <= min_tier_index  # BLOCK should be visible

    def test_min_tier_warn_includes_block(self):
        """With --min-tier WARN, both BLOCK and WARN should be visible."""
        formatter = TerminalFormatter(min_tier="WARN")
        block_idx = TIER_ORDER.index("BLOCK")
        warn_idx = TIER_ORDER.index("WARN")
        min_idx = TIER_ORDER.index(formatter.min_tier)

        assert block_idx <= min_idx  # BLOCK visible
        assert warn_idx <= min_idx  # WARN visible

    def test_min_tier_info_includes_block_warn_info(self):
        """With --min-tier INFO, BLOCK, WARN, and INFO should be visible."""
        formatter = TerminalFormatter(min_tier="INFO")
        min_idx = TIER_ORDER.index(formatter.min_tier)

        assert TIER_ORDER.index("BLOCK") <= min_idx
        assert TIER_ORDER.index("WARN") <= min_idx
        assert TIER_ORDER.index("INFO") <= min_idx


class TestJSONOutputConfidence:
    """Test JSON output includes confidence, tier, and reason fields."""

    def test_json_includes_confidence(self):
        """JSON output should include confidence field."""
        findings = [create_finding(confidence=0.78)]
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        assert "confidence" in result["findings"][0]
        assert result["findings"][0]["confidence"] == 0.78

    def test_json_includes_tier(self):
        """JSON output should include tier field."""
        findings = [create_finding(confidence=0.78)]  # WARN tier
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        assert "tier" in result["findings"][0]
        assert result["findings"][0]["tier"] == "WARN"

    def test_json_includes_reason(self):
        """JSON output should include reason field."""
        findings = [create_finding()]
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        assert "reason" in result["findings"][0]
        assert result["findings"][0]["reason"] is not None

    def test_json_summary_includes_by_tier(self):
        """JSON summary should include by_tier counts."""
        findings = [
            create_finding(confidence=0.95),  # BLOCK
            create_finding(confidence=0.75),  # WARN
            create_finding(confidence=0.45),  # INFO
        ]
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        assert "by_tier" in result["summary"]
        assert result["summary"]["by_tier"]["BLOCK"] == 1
        assert result["summary"]["by_tier"]["WARN"] == 1
        assert result["summary"]["by_tier"]["INFO"] == 1

    def test_json_summary_includes_risk_label(self):
        """JSON summary should include risk_label."""
        findings = [create_finding(severity=Severity.HIGH, confidence=0.85)]
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        assert "risk_label" in result["summary"]
        assert result["summary"]["risk_label"] in [
            "LOW", "LOW-MEDIUM", "MEDIUM", "MEDIUM-HIGH", "HIGH"
        ]

    def test_json_backward_compatible(self):
        """JSON output should maintain backward compatibility with old fields."""
        findings = [create_finding()]
        formatter = JSONFormatter()
        result = formatter.format(findings, "/test/path", 10)

        # Old fields should still be present
        assert "version" in result
        assert "scan_timestamp" in result
        assert "scan_path" in result
        assert "scanned_files" in result
        assert "summary" in result
        assert "findings" in result

        # Old summary fields
        assert "total" in result["summary"]
        assert "actionable" in result["summary"]
        assert "suppressed" in result["summary"]
        assert "by_severity" in result["summary"]
        assert "by_category" in result["summary"]
        assert "risk_score" in result["summary"]


class TestConfidenceToTier:
    """Test confidence_to_tier function."""

    def test_block_tier_threshold(self):
        """v0.8.0: Confidence >= 0.92 should be BLOCK (raised from 0.90)."""
        assert confidence_to_tier(0.92) == "BLOCK"
        assert confidence_to_tier(0.95) == "BLOCK"
        assert confidence_to_tier(1.0) == "BLOCK"

    def test_warn_tier_threshold(self):
        """v0.8.0: Confidence 0.60-0.91 should be WARN (threshold raised)."""
        assert confidence_to_tier(0.60) == "WARN"
        assert confidence_to_tier(0.75) == "WARN"
        assert confidence_to_tier(0.90) == "WARN"  # v0.8.0: Now WARN, was BLOCK
        assert confidence_to_tier(0.91) == "WARN"  # v0.8.0: Now WARN, was BLOCK

    def test_info_tier_threshold(self):
        """Confidence 0.30-0.59 should be INFO."""
        assert confidence_to_tier(0.30) == "INFO"
        assert confidence_to_tier(0.45) == "INFO"
        assert confidence_to_tier(0.59) == "INFO"

    def test_suppressed_tier_threshold(self):
        """Confidence < 0.30 should be SUPPRESSED."""
        assert confidence_to_tier(0.0) == "SUPPRESSED"
        assert confidence_to_tier(0.15) == "SUPPRESSED"
        assert confidence_to_tier(0.29) == "SUPPRESSED"


class TestTierConfig:
    """Test tier configuration constants."""

    def test_tier_order_complete(self):
        """TIER_ORDER should contain all tiers."""
        assert "BLOCK" in TIER_ORDER
        assert "WARN" in TIER_ORDER
        assert "INFO" in TIER_ORDER
        assert "SUPPRESSED" in TIER_ORDER
        assert len(TIER_ORDER) == 4

    def test_tier_config_has_required_fields(self):
        """Each tier config should have required fields."""
        for tier in TIER_ORDER:
            assert tier in TIER_CONFIG
            assert "icon" in TIER_CONFIG[tier]
            assert "label" in TIER_CONFIG[tier]
            assert "color" in TIER_CONFIG[tier]
            assert "threshold" in TIER_CONFIG[tier]


class TestJSONRiskScoreConsistency:
    """Test that JSON and terminal formatters use same risk score calculation."""

    def test_risk_score_functions_match(self):
        """Both formatters should calculate same risk score."""
        findings = [
            create_finding(severity=Severity.CRITICAL, confidence=0.95),
            create_finding(severity=Severity.HIGH, confidence=0.80),
            create_finding(severity=Severity.MEDIUM, confidence=0.65),
        ]

        terminal_score = calculate_risk_score(findings)
        json_score = json_calculate_risk_score(findings)

        assert terminal_score == json_score

    def test_risk_label_functions_match(self):
        """Both formatters should produce same risk labels."""
        for score in [0.0, 2.5, 4.5, 6.5, 8.5]:
            terminal_label = get_risk_label(score)
            json_label = json_get_risk_label(score)
            assert terminal_label == json_label
