"""
Placeholder value detection for false positive reduction.

Identifies common placeholder patterns used in example code, docs, and templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class PlaceholderResult:
    """Result of placeholder detection."""
    is_placeholder: bool
    confidence: float  # 0.0-1.0, higher = more confident it's a placeholder
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None


# Placeholder patterns with descriptions
# Format: (pattern, description, confidence)
PLACEHOLDER_PATTERNS: List[Tuple[str, str, float]] = [
    # Explicit placeholder markers
    (r'^your[-_]?api[-_]?key[-_]?here$', 'your-api-key-here pattern', 0.99),
    (r'^<your[-_]?.*[-_]?key>$', '<your-key> placeholder', 0.99),
    (r'^<.*[-_]?api[-_]?key.*>$', '<api_key> placeholder', 0.99),
    (r'^<.*[-_]?secret.*>$', '<secret> placeholder', 0.99),
    (r'^<.*[-_]?token.*>$', '<token> placeholder', 0.99),
    (r'^\[YOUR[-_]?.*\]$', '[YOUR_KEY] placeholder', 0.99),
    (r'^\{YOUR[-_]?.*\}$', '{YOUR_KEY} placeholder', 0.99),
    (r'^TODO[-_:]?', 'TODO marker', 0.95),
    (r'^CHANGEME$', 'CHANGEME marker', 0.99),
    (r'^REPLACE[-_]?ME$', 'REPLACE_ME marker', 0.99),
    (r'^INSERT[-_]?HERE$', 'INSERT_HERE marker', 0.99),
    (r'^FIXME$', 'FIXME marker', 0.90),

    # Repeated characters
    (r'^x{3,}$', 'xxx placeholder', 0.99),
    (r'^X{3,}$', 'XXX placeholder', 0.99),
    (r'^0{5,}$', '00000 placeholder', 0.90),
    (r'^\*{3,}$', '*** placeholder', 0.95),
    (r'^\.{3,}$', '... placeholder', 0.85),

    # Example/test markers
    (r'^test[-_]?', 'test_ prefix', 0.70),
    (r'^demo[-_]?', 'demo_ prefix', 0.75),
    (r'^sample[-_]?', 'sample_ prefix', 0.80),
    (r'^example[-_]?', 'example_ prefix', 0.85),
    (r'^fake[-_]?', 'fake_ prefix', 0.90),
    (r'^dummy[-_]?', 'dummy_ prefix', 0.90),
    (r'^mock[-_]?', 'mock_ prefix', 0.85),
    (r'[-_]?test$', '_test suffix', 0.60),
    (r'[-_]?example$', '_example suffix', 0.75),

    # AWS example patterns
    (r'^AKIAIOSFODNN7EXAMPLE$', 'AWS example key', 0.99),
    (r'^wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY$', 'AWS example secret', 0.99),

    # GitHub/Anthropic example patterns
    (r'^ghp_[a-zA-Z0-9]{36}example$', 'GitHub example token', 0.95),
    (r'^sk-ant-api[0-9]{2}-example', 'Anthropic example key', 0.95),
    (r'^sk-proj-example', 'OpenAI example key', 0.95),

    # Documentation URL patterns
    (r'example\.com', 'example.com domain', 0.80),
    (r'example\.org', 'example.org domain', 0.80),
    (r'localhost', 'localhost', 0.70),
    (r'127\.0\.0\.1', 'loopback IP', 0.70),

    # Common dev/test values
    (r'^password$', 'literal "password"', 0.95),
    (r'^secret$', 'literal "secret"', 0.95),
    (r'^admin$', 'literal "admin"', 0.85),
    (r'^root$', 'literal "root"', 0.80),
    (r'^default$', 'literal "default"', 0.80),
    (r'^changeit$', 'literal "changeit"', 0.95),
    (r'^hunter2$', 'literal "hunter2" meme', 0.95),
    (r'^abc123$', 'literal "abc123"', 0.90),
    (r'^qwerty$', 'literal "qwerty"', 0.90),
    (r'^letmein$', 'literal "letmein"', 0.90),
    (r'^1234567890?$', 'numeric sequence', 0.85),

    # Empty/null-like values
    (r'^null$', 'literal "null"', 0.95),
    (r'^none$', 'literal "none"', 0.95),
    (r'^undefined$', 'literal "undefined"', 0.95),
    (r'^n/a$', 'literal "n/a"', 0.90),
    (r'^na$', 'literal "na"', 0.85),
    (r'^tbd$', 'literal "tbd"', 0.90),
]


def is_placeholder(value: str) -> PlaceholderResult:
    """
    Detect if a value is a placeholder.

    Checks against known placeholder patterns to identify values that are
    likely not real credentials (e.g., "your-api-key-here", "xxx", "TODO").

    Args:
        value: String value to check

    Returns:
        PlaceholderResult with detection result and confidence
    """
    if not value:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=1.0,
            reason="Empty value"
        )

    # Normalize for comparison
    normalized = value.strip().lower()

    # Check each pattern
    for pattern, description, confidence in PLACEHOLDER_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return PlaceholderResult(
                is_placeholder=True,
                confidence=confidence,
                matched_pattern=pattern,
                reason=description,
            )

    # Check for very short values (likely placeholders)
    if len(value) < 4:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.80,
            reason=f"Very short value ({len(value)} chars)"
        )

    # Check for all same character
    if len(set(value)) == 1:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.95,
            reason="Single repeated character"
        )

    # Check for environment variable reference
    if value.startswith('${') or value.startswith('$') or value.startswith('%'):
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.99,
            reason="Environment variable reference"
        )

    # v0.5.1: Check for file path patterns and non-credential patterns
    path_patterns = [
        (r'^/[a-zA-Z0-9_/.-]+$', 'Unix absolute path'),
        (r'^[a-zA-Z]:\\', 'Windows absolute path'),
        (r'\.(xpc|app|framework|bundle|dylib|so|dll|exe)(/|$)', 'Binary/framework path'),
        (r'/Contents/MacOS/', 'macOS app bundle path'),
        (r'/Versions/[A-Z]/', 'macOS framework version path'),
        (r'/usr/(bin|lib|share|local)/', 'Unix system path'),
        (r'/Library/', 'macOS Library path'),
        (r'/XPCServices/', 'macOS XPC service path'),
        # Option/action lists (e.g., "present/hide/navigate/eval")
        (r'^[a-z]+(/[a-z]+){3,}$', 'Option/action list pattern'),
        # Slash-separated descriptive text
        (r'^[a-z]+(/[a-z0-9]+)+$', 'Slash-separated descriptive pattern'),
    ]
    for pattern, desc in path_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return PlaceholderResult(
                is_placeholder=True,
                confidence=0.95,
                reason=f"File path pattern: {desc}"
            )

    # Not detected as placeholder
    return PlaceholderResult(
        is_placeholder=False,
        confidence=0.0,
        reason=None
    )


def placeholder_confidence(value: str) -> float:
    """
    Get confidence score that value is a placeholder.

    Convenience function that returns just the confidence score.

    Args:
        value: String to check

    Returns:
        Confidence score (0.0 = definitely not placeholder, 1.0 = definitely placeholder)
    """
    result = is_placeholder(value)
    return result.confidence if result.is_placeholder else 0.0


# ============================================================================
# v0.8.0: Vendor Example Keys Detection
# ============================================================================

# Known vendor example/test keys that appear in documentation
# These are NOT real credentials and should not trigger findings
VENDOR_EXAMPLE_KEYS = {
    # AWS official documentation examples
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIAI44QH8DHBEXAMPLE",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",

    # Stripe test key patterns (use regex patterns instead of actual keys)
    # Pattern: sk_test_* or pk_test_* followed by alphanumeric
    # Actual detection handled by STRIPE_TEST_KEY_PATTERN below

    # GitHub documentation examples
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "github_pat_EXAMPLE",

    # Generic placeholder markers
    "test-api-key",
    "fake-api-key",
    "mock-api-key",
    "dummy-secret",
    "placeholder-token",
    "no-key",
    "api-key-here",
    "your-api-key",
}

# Patterns that indicate example/test values (not just specific strings)
# NOTE: These patterns are for API keys/tokens, NOT for connection strings
# Connection strings may contain example.com but still have real credentials
VENDOR_EXAMPLE_VALUE_PATTERNS = [
    # Stripe test keys (sk_test_ or pk_test_ prefix)
    (r"^(sk|pk)_test_", 0.95, "Stripe test key prefix"),
    # Value starts with or is named "example" (not just contains it)
    # Avoids matching example.com in URLs/connection strings
    (r"(?i)^example[-_]", 0.90, "starts with 'example_'"),
    (r"(?i)[-_]example$", 0.85, "ends with '_example'"),
    (r"(?i)^example$", 0.90, "is 'example'"),
    # EXAMPLEKEY suffix (common in AWS docs)
    (r"EXAMPLEKEY$", 0.95, "ends with 'EXAMPLEKEY'"),
    # Starts with test_/test-
    (r"(?i)^test[-_]", 0.85, "starts with 'test_'"),
    # Starts with fake_/fake-
    (r"(?i)^fake[-_]", 0.90, "starts with 'fake_'"),
    # Starts with dummy
    (r"(?i)^dummy", 0.90, "starts with 'dummy'"),
    # Starts with sample
    (r"(?i)^sample", 0.85, "starts with 'sample'"),
    # Starts with mock
    (r"(?i)^mock", 0.85, "starts with 'mock'"),
    # Contains consecutive x's (8+)
    (r"x{8,}", 0.95, "consecutive x characters"),
    # Contains consecutive 0's (8+)
    (r"0{8,}", 0.90, "consecutive 0 characters"),
    # Contains consecutive 1's (8+)
    (r"1{8,}", 0.85, "consecutive 1 characters"),
    # Sequential digits
    (r"^1234567", 0.85, "sequential digits"),
    # All same character
    (r"^(.)\1{7,}$", 0.95, "repeated single character"),
]


def is_vendor_example(value: str) -> Tuple[bool, float, Optional[str]]:
    """
    Check if a value is a known vendor example key.

    These are keys that appear in official documentation and are
    explicitly marked as examples (not real credentials).

    Args:
        value: The potential credential value

    Returns:
        Tuple of (is_example, confidence, reason)
        - is_example: True if this looks like a vendor example key
        - confidence: How confident we are (0.0-1.0)
        - reason: Description of why this was identified as an example

    v0.8.0: Added for AGENT-004 false positive reduction.
    """
    if not value:
        return (False, 0.0, None)

    # Clean up the value
    stripped = value.strip().strip("'\"")

    # Skip vendor example detection for connection strings
    # These may contain example.com but still have real credentials
    if '://' in stripped and '@' in stripped:
        return (False, 0.0, None)

    # Exact match against known example keys
    if stripped in VENDOR_EXAMPLE_KEYS:
        return (True, 0.98, "Known vendor example key")

    # Case-insensitive check for known keys
    stripped_lower = stripped.lower()
    for known_key in VENDOR_EXAMPLE_KEYS:
        if known_key.lower() == stripped_lower:
            return (True, 0.98, "Known vendor example key (case-insensitive)")

    # Pattern matching for example-like values
    for pattern, confidence, reason in VENDOR_EXAMPLE_VALUE_PATTERNS:
        if re.search(pattern, stripped):
            return (True, confidence, f"Pattern match: {reason}")

    return (False, 0.0, None)
