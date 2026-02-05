"""
Per-Rule context confidence multipliers.

Core Innovation: Different rules have different tolerance for different contexts.
- AGENT-020 (network channel) in test code is almost always FP → ×0.05
- AGENT-004 (credentials) in test code is mostly FP, but occasionally real → ×0.15
- AGENT-044 (sudoers) is important in any context → no reduction

v0.8.0: Initial implementation for aggressive false positive suppression.

This module provides the configuration for how each rule should have its
confidence adjusted based on file context. The adjustments are applied
AFTER the base confidence is calculated by the rule-specific scanner.
"""

from __future__ import annotations

from typing import Dict, Optional

from agent_audit.analysis.context_classifier import FileContext


# Per-Rule context multipliers
# Format: rule_id -> { FileContext -> multiplier }
# Multiplier of 1.0 means no change
# Lower multiplier = more aggressive suppression

RULE_CONTEXT_MULTIPLIERS: Dict[str, Dict[FileContext, float]] = {
    # === Network-related rules: test code almost always produces FP ===
    "AGENT-020": {
        # Unencrypted channel detection - localhost URLs in tests are always FP
        FileContext.TEST: 0.05,           # Basically suppress
        FileContext.FIXTURE: 0.05,
        FileContext.EXAMPLE: 0.15,
        FileContext.DOCUMENTATION: 0.70,
        FileContext.TEMPLATE: 0.10,
        FileContext.VENDOR: 0.05,
    },

    # === Browser automation: test code always produces FP ===
    "AGENT-045": {
        # Browser without sandbox - Playwright/Puppeteer E2E tests
        FileContext.TEST: 0.05,           # Suppress - E2E tests need this
        FileContext.FIXTURE: 0.05,
        FileContext.EXAMPLE: 0.20,
        FileContext.INFRASTRUCTURE: 0.30,  # CI setup may need browser tests
        FileContext.VENDOR: 0.05,
    },

    # === Credential detection: test code mostly FP but occasionally real ===
    # v0.8.0 P7: Lowered TEST/FIXTURE multipliers to suppress test file FPs
    # Test files with credentials should go to INFO or SUPPRESSED, not BLOCK
    "AGENT-004": {
        # Hardcoded credentials - test files often have fake/example keys
        # AWS example keys (AKIAIOSFODNN7EXAMPLE) should be suppressed
        FileContext.TEST: 0.25,           # v0.8.0 P7: 1.0 * 0.25 = 0.25 -> SUPPRESSED
        FileContext.FIXTURE: 0.20,        # Fixtures are almost always test data
        FileContext.EXAMPLE: 0.30,        # Example code may have placeholders
        FileContext.TEMPLATE: 0.20,       # .env.example files often have placeholders
        FileContext.DOCUMENTATION: 0.50,  # Docs may have examples
        FileContext.VENDOR: 0.15,         # Vendor code shouldn't be flagged
    },

    # === Subprocess execution: infrastructure code has legitimate uses ===
    "AGENT-047": {
        # Subprocess without sandbox - sandbox builders use this intentionally
        FileContext.TEST: 0.15,
        FileContext.INFRASTRUCTURE: 0.20,  # Dockerfile, scripts often need subprocess
        FileContext.FIXTURE: 0.10,
        FileContext.VENDOR: 0.10,
    },

    # === Command injection: infrastructure code has legitimate uses ===
    "AGENT-001": {
        # Command injection - runtime init scripts may need shell
        FileContext.TEST: 0.20,
        FileContext.INFRASTRUCTURE: 0.30,
        FileContext.FIXTURE: 0.15,
        FileContext.VENDOR: 0.10,
    },

    # === Memory poisoning: test code often has example data ===
    "AGENT-018": {
        FileContext.TEST: 0.20,
        FileContext.FIXTURE: 0.15,
        FileContext.EXAMPLE: 0.25,
        FileContext.VENDOR: 0.10,
    },

    # === Tool input validation: test code has mock inputs ===
    "AGENT-034": {
        FileContext.TEST: 0.20,
        FileContext.FIXTURE: 0.15,
        FileContext.EXAMPLE: 0.30,
        FileContext.VENDOR: 0.10,
    },

    # === MCP configuration: examples/templates are not real config ===
    "AGENT-029": {
        FileContext.EXAMPLE: 0.15,
        FileContext.TEMPLATE: 0.10,
        FileContext.DOCUMENTATION: 0.20,
    },
    "AGENT-030": {
        FileContext.EXAMPLE: 0.15,
        FileContext.TEMPLATE: 0.10,
        FileContext.DOCUMENTATION: 0.20,
    },
    "AGENT-031": {
        FileContext.EXAMPLE: 0.15,
        FileContext.TEMPLATE: 0.10,
        FileContext.DOCUMENTATION: 0.20,
    },
    "AGENT-032": {
        FileContext.EXAMPLE: 0.15,
        FileContext.TEMPLATE: 0.10,
        FileContext.DOCUMENTATION: 0.20,
    },
    "AGENT-033": {
        FileContext.EXAMPLE: 0.15,
        FileContext.TEMPLATE: 0.10,
        FileContext.DOCUMENTATION: 0.20,
    },
}

# Default multipliers for rules not explicitly configured
# These are more conservative (less aggressive suppression)
DEFAULT_CONTEXT_MULTIPLIERS: Dict[FileContext, float] = {
    FileContext.TEST: 0.25,
    FileContext.FIXTURE: 0.15,
    FileContext.DOCUMENTATION: 0.85,
    FileContext.EXAMPLE: 0.40,
    FileContext.TEMPLATE: 0.20,
    FileContext.VENDOR: 0.10,
    FileContext.INFRASTRUCTURE: 0.60,  # Infrastructure code is often legitimate
    FileContext.PRODUCTION: 1.0,       # No change for production code
}

# Rules that should NEVER be dampened regardless of context
# These are privilege/permission rules that are always important
EXEMPT_RULES: set = {
    "AGENT-043",  # Daemon privileges
    "AGENT-044",  # Sudoers NOPASSWD
    "AGENT-046",  # System credential store access
}


def get_context_multiplier(rule_id: str, context: FileContext) -> float:
    """
    Get the confidence multiplier for a specific rule in a specific context.

    Args:
        rule_id: The rule identifier (e.g., "AGENT-004")
        context: The file context classification

    Returns:
        Multiplier to apply to base confidence (0.0 to 1.0)
    """
    # Exempt rules always return 1.0 (no dampening)
    if rule_id in EXEMPT_RULES:
        return 1.0

    # Production context always returns 1.0
    if context == FileContext.PRODUCTION:
        return 1.0

    # Check for rule-specific configuration
    rule_config = RULE_CONTEXT_MULTIPLIERS.get(rule_id)
    if rule_config:
        multiplier = rule_config.get(context)
        if multiplier is not None:
            return multiplier

    # Fall back to default multipliers
    return DEFAULT_CONTEXT_MULTIPLIERS.get(context, 1.0)


def is_exempt_rule(rule_id: str) -> bool:
    """Check if a rule is exempt from context-based dampening."""
    return rule_id in EXEMPT_RULES


def get_all_configured_rules() -> set:
    """Get the set of rules with explicit context configuration."""
    return set(RULE_CONTEXT_MULTIPLIERS.keys())


# === Localhost URL detection for AGENT-020 ===

# Patterns that match localhost/loopback URLs (should be suppressed in most contexts)
LOCALHOST_URL_PATTERNS = [
    r"https?://localhost[:/]",
    r"https?://127\.0\.0\.1[:/]",
    r"https?://0\.0\.0\.0[:/]",
    r"https?://\[::1\][:/]",
    r"https?://localhost$",
    r"https?://127\.0\.0\.1$",
]

# Pre-compiled patterns
import re
_LOCALHOST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in LOCALHOST_URL_PATTERNS]


def is_localhost_url(url: str) -> bool:
    """
    Check if a URL points to localhost/loopback.

    These URLs should have very low confidence in AGENT-020 findings
    as they are almost always test/development endpoints.

    Args:
        url: The URL to check

    Returns:
        True if the URL points to localhost/loopback
    """
    for pattern in _LOCALHOST_PATTERNS:
        if pattern.search(url):
            return True
    return False


# === Browser test detection for AGENT-045 ===

# Patterns that indicate browser automation testing (Playwright, Puppeteer, Selenium)
BROWSER_TEST_PATTERNS = [
    r"page\.evaluate\(",
    r"page\.goto\(",
    r"browser\.newPage\(",
    r"browser\.launch\(",
    r"chromium\.launch\(",
    r"firefox\.launch\(",
    r"webkit\.launch\(",
    r"@playwright/test",
    r"from playwright",
    r"puppeteer\.launch\(",
    r"webdriver\.",
    r"from selenium",
]

_BROWSER_TEST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in BROWSER_TEST_PATTERNS]


def is_browser_test_pattern(content: str) -> bool:
    """
    Check if content contains browser automation test patterns.

    Args:
        content: The file content or line to check

    Returns:
        True if browser automation patterns are detected
    """
    for pattern in _BROWSER_TEST_PATTERNS:
        if pattern.search(content):
            return True
    return False
