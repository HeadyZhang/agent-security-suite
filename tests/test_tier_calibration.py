"""Tests for tier calibration and risk score (v0.8.0)."""

import pytest
from agent_audit.models.finding import (
    confidence_to_tier,
    compute_tier_with_context,
    TIER_THRESHOLDS,
    BLOCK_EXEMPT_RULES,
)


class TestTierThresholds:
    """Test tier threshold configuration."""

    def test_block_threshold_is_092(self):
        """BLOCK threshold should be 0.92 in v0.8.0."""
        assert TIER_THRESHOLDS["BLOCK"] == 0.92

    def test_warn_threshold_unchanged(self):
        """WARN threshold should still be 0.60."""
        assert TIER_THRESHOLDS["WARN"] == 0.60

    def test_info_threshold_unchanged(self):
        """INFO threshold should still be 0.30."""
        assert TIER_THRESHOLDS["INFO"] == 0.30


class TestConfidenceToTier:
    """Test basic confidence to tier conversion."""

    def test_high_confidence_blocks(self):
        """Confidence >= 0.92 should be BLOCK."""
        assert confidence_to_tier(0.92) == "BLOCK"
        assert confidence_to_tier(0.95) == "BLOCK"
        assert confidence_to_tier(1.0) == "BLOCK"

    def test_borderline_confidence_warns(self):
        """Confidence 0.90-0.91 should now be WARN (threshold raised)."""
        assert confidence_to_tier(0.90) == "WARN"
        assert confidence_to_tier(0.91) == "WARN"

    def test_medium_confidence_warns(self):
        """Confidence 0.60-0.91 should be WARN."""
        assert confidence_to_tier(0.60) == "WARN"
        assert confidence_to_tier(0.75) == "WARN"

    def test_low_confidence_info(self):
        """Confidence 0.30-0.59 should be INFO."""
        assert confidence_to_tier(0.30) == "INFO"
        assert confidence_to_tier(0.45) == "INFO"
        assert confidence_to_tier(0.59) == "INFO"

    def test_very_low_confidence_suppressed(self):
        """Confidence < 0.30 should be SUPPRESSED."""
        assert confidence_to_tier(0.29) == "SUPPRESSED"
        assert confidence_to_tier(0.10) == "SUPPRESSED"
        assert confidence_to_tier(0.0) == "SUPPRESSED"


class TestComputeTierWithContext:
    """Test context-aware tier computation."""

    def test_production_code_blocks(self):
        """High confidence + production context should be BLOCK."""
        tier = compute_tier_with_context(0.95, "production", "AGENT-004")
        assert tier == "BLOCK"

    def test_test_code_downgraded_to_warn(self):
        """High confidence + test context should be downgraded to WARN."""
        tier = compute_tier_with_context(0.95, "test", "AGENT-004")
        assert tier == "WARN"

    def test_example_code_downgraded_to_warn(self):
        """High confidence + example context should be downgraded to WARN."""
        tier = compute_tier_with_context(0.95, "example", "AGENT-020")
        assert tier == "WARN"

    def test_infrastructure_code_downgraded_to_warn(self):
        """High confidence + infrastructure context should be downgraded to WARN."""
        tier = compute_tier_with_context(0.95, "infrastructure", "AGENT-047")
        assert tier == "WARN"

    def test_fixture_code_downgraded_to_warn(self):
        """High confidence + fixture context should be downgraded to WARN."""
        tier = compute_tier_with_context(0.95, "fixture", "AGENT-004")
        assert tier == "WARN"

    def test_privilege_rule_always_blocks(self):
        """AGENT-044 should always BLOCK regardless of context."""
        # Test context should not prevent BLOCK
        tier = compute_tier_with_context(0.95, "test", "AGENT-044")
        assert tier == "BLOCK"

        # Infrastructure context should not prevent BLOCK
        tier = compute_tier_with_context(0.95, "infrastructure", "AGENT-044")
        assert tier == "BLOCK"

    def test_all_exempt_rules_block(self):
        """All privilege-exempt rules should BLOCK in any context."""
        for rule_id in BLOCK_EXEMPT_RULES:
            tier = compute_tier_with_context(0.95, "test", rule_id)
            assert tier == "BLOCK", f"{rule_id} should always BLOCK"

    def test_warn_tier_not_affected(self):
        """WARN tier findings should stay WARN regardless of context."""
        tier = compute_tier_with_context(0.75, "test", "AGENT-004")
        assert tier == "WARN"

    def test_info_tier_not_affected(self):
        """INFO tier findings should stay INFO regardless of context."""
        tier = compute_tier_with_context(0.45, "test", "AGENT-004")
        assert tier == "INFO"


class TestRiskScoreIntegration:
    """Test risk score calculation with infrastructure context."""

    def test_infrastructure_context_reduces_weight(self):
        """Infrastructure context findings should have reduced weight."""
        from agent_audit.cli.formatters.terminal import calculate_risk_score
        from agent_audit.models.finding import Finding
        from agent_audit.models.risk import Severity, Category, Location

        # Create normal finding
        normal_finding = Finding(
            rule_id="AGENT-047",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            location=Location(file_path="test.py", start_line=1, end_line=1),
            confidence=0.75,
            tier="WARN",
        )

        # Create infrastructure finding
        infra_finding = Finding(
            rule_id="AGENT-047",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            location=Location(file_path="docker.py", start_line=1, end_line=1),
            confidence=0.75,
            tier="WARN",
            metadata={"infrastructure_context": True},
        )

        # Normal finding should contribute more to risk score
        score_normal = calculate_risk_score([normal_finding])
        score_infra = calculate_risk_score([infra_finding])

        assert score_infra < score_normal

    def test_suppressed_findings_not_counted(self):
        """SUPPRESSED tier findings should not contribute to risk score."""
        from agent_audit.cli.formatters.terminal import calculate_risk_score
        from agent_audit.models.finding import Finding
        from agent_audit.models.risk import Severity, Category, Location

        suppressed_finding = Finding(
            rule_id="AGENT-004",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=Category.CREDENTIAL_EXPOSURE,
            location=Location(file_path="test.py", start_line=1, end_line=1),
            confidence=0.20,
            tier="SUPPRESSED",
        )

        score = calculate_risk_score([suppressed_finding])
        assert score == 0.0

    def test_info_tier_not_counted(self):
        """INFO tier findings should not contribute to risk score."""
        from agent_audit.cli.formatters.terminal import calculate_risk_score
        from agent_audit.models.finding import Finding
        from agent_audit.models.risk import Severity, Category, Location

        info_finding = Finding(
            rule_id="AGENT-004",
            title="Test",
            description="Test",
            severity=Severity.MEDIUM,
            category=Category.CREDENTIAL_EXPOSURE,
            location=Location(file_path="test.py", start_line=1, end_line=1),
            confidence=0.45,
            tier="INFO",
        )

        score = calculate_risk_score([info_finding])
        assert score == 0.0
