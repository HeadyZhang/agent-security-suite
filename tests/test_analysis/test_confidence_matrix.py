"""Tests for confidence matrix."""

import pytest
from agent_audit.analysis.confidence_matrix import (
    ConfidenceAdjustment,
    AdjustmentDirection,
    CONFIDENCE_ADJUSTMENTS,
    calculate_final_confidence,
    should_suppress,
    get_tier_from_confidence,
    get_adjustment,
    get_uuid_adjustment,
    get_data_identifier_adjustment,
    get_placeholder_adjustment,
    get_known_format_adjustment,
    get_test_file_adjustment,
)


class TestConfidenceAdjustment:
    """Test ConfidenceAdjustment dataclass."""

    def test_adjustment_creation(self):
        """Test creating an adjustment."""
        adj = ConfidenceAdjustment(
            condition="test",
            multiplier=0.5,
            description="Test adjustment",
            priority=1,
            direction=AdjustmentDirection.DECREASE,
        )
        assert adj.condition == "test"
        assert adj.multiplier == 0.5
        assert adj.direction == AdjustmentDirection.DECREASE

    def test_negative_multiplier_raises(self):
        """Negative multiplier should raise ValueError."""
        with pytest.raises(ValueError):
            ConfidenceAdjustment(
                condition="test",
                multiplier=-0.5,
                description="Invalid",
                priority=1,
            )


class TestGetAdjustment:
    """Test getting adjustments by condition."""

    def test_get_existing_adjustment(self):
        """Test getting an existing adjustment."""
        adj = get_adjustment("uuid_format")
        assert adj is not None
        assert adj.condition == "uuid_format"

    def test_get_nonexistent_adjustment(self):
        """Test getting a non-existent adjustment."""
        adj = get_adjustment("nonexistent_condition")
        assert adj is None


class TestCalculateFinalConfidence:
    """Test final confidence calculation."""

    def test_no_adjustments(self):
        """Test with no adjustments."""
        result, applied = calculate_final_confidence(
            base_confidence=0.8,
            adjustments=[],
            is_known_format=True,
        )
        assert result == 0.8
        assert len(applied) == 0

    def test_single_decrease_adjustment(self):
        """Test with a single decrease adjustment."""
        result, applied = calculate_final_confidence(
            base_confidence=0.8,
            adjustments=[("uuid_format", 0.2)],
            is_known_format=False,
        )
        # 0.8 * 0.2 = 0.16, but generic format max is 0.70
        assert result <= 0.70
        assert len(applied) >= 1

    def test_known_format_minimum(self):
        """Known format should have minimum confidence of 0.75."""
        result, applied = calculate_final_confidence(
            base_confidence=0.5,
            adjustments=[],
            is_known_format=True,
        )
        assert result >= 0.75

    def test_generic_format_maximum(self):
        """Generic format should have maximum confidence of 0.70."""
        result, applied = calculate_final_confidence(
            base_confidence=0.9,
            adjustments=[],
            is_known_format=False,
        )
        assert result <= 0.70

    def test_multiple_adjustments(self):
        """Test with multiple adjustments."""
        result, applied = calculate_final_confidence(
            base_confidence=0.8,
            adjustments=[
                ("test_file_generic_pattern", 0.4),
                ("short_random_string", 0.5),
            ],
            is_known_format=False,
        )
        # 0.8 * 0.4 * 0.5 = 0.16
        assert result < 0.20
        assert len(applied) >= 2


class TestShouldSuppress:
    """Test suppression logic."""

    def test_low_confidence_suppressed(self):
        """Low confidence should be suppressed."""
        assert should_suppress(0.3, is_known_format=False) is True
        assert should_suppress(0.4, is_known_format=False) is True

    def test_high_confidence_not_suppressed(self):
        """High confidence should not be suppressed."""
        assert should_suppress(0.7, is_known_format=False) is False
        assert should_suppress(0.9, is_known_format=False) is False

    def test_known_format_lower_threshold(self):
        """Known formats should have lower suppression threshold."""
        # Known format only suppressed below 0.30
        assert should_suppress(0.25, is_known_format=True) is True
        assert should_suppress(0.35, is_known_format=True) is False


class TestGetTierFromConfidence:
    """Test tier assignment."""

    def test_block_tier(self):
        """High confidence should be BLOCK."""
        assert get_tier_from_confidence(0.90, is_known_format=False) == "BLOCK"
        assert get_tier_from_confidence(0.95, is_known_format=False) == "BLOCK"

    def test_warn_tier(self):
        """Medium confidence should be WARN."""
        assert get_tier_from_confidence(0.60, is_known_format=False) == "WARN"
        assert get_tier_from_confidence(0.70, is_known_format=False) == "WARN"

    def test_info_tier(self):
        """Low confidence should be INFO."""
        assert get_tier_from_confidence(0.35, is_known_format=False) == "INFO"
        assert get_tier_from_confidence(0.45, is_known_format=False) == "INFO"

    def test_suppressed_tier(self):
        """Very low confidence should be SUPPRESSED."""
        assert get_tier_from_confidence(0.20, is_known_format=False) == "SUPPRESSED"
        assert get_tier_from_confidence(0.10, is_known_format=False) == "SUPPRESSED"

    def test_known_format_boosted_tiers(self):
        """Known formats should have boosted tier thresholds."""
        # Known format at 0.75 should be BLOCK
        assert get_tier_from_confidence(0.75, is_known_format=True) == "BLOCK"
        # Known format at 0.40 should be WARN
        assert get_tier_from_confidence(0.40, is_known_format=True) == "WARN"


class TestUtilityFunctions:
    """Test utility functions for common adjustments."""

    def test_get_uuid_adjustment(self):
        """Test UUID adjustment utility."""
        condition, multiplier = get_uuid_adjustment()
        assert condition == "uuid_format"
        assert multiplier == 0.2

    def test_get_data_identifier_adjustment(self):
        """Test data identifier adjustment utility."""
        condition, multiplier = get_data_identifier_adjustment()
        assert condition == "data_identifier_name"
        assert multiplier == 0.15

    def test_get_placeholder_adjustment(self):
        """Test placeholder adjustment utility."""
        condition, multiplier = get_placeholder_adjustment()
        assert condition == "placeholder_detected"
        assert multiplier == 0.1

    def test_get_known_format_adjustment(self):
        """Test known format adjustment utility."""
        condition, multiplier = get_known_format_adjustment()
        assert condition == "known_format_prefix"
        assert multiplier == 1.3

    def test_get_test_file_adjustment(self):
        """Test test file adjustment utility."""
        condition, multiplier = get_test_file_adjustment()
        assert condition == "test_file_generic_pattern"
        assert multiplier == 0.4
