"""Tests for file context classifier (v0.8.0)."""

import pytest
from agent_audit.analysis.context_classifier import (
    ContextClassifier,
    FileContext,
    classify_file_context,
    get_classifier,
)
from agent_audit.analysis.rule_context_config import (
    get_context_multiplier,
    is_localhost_url,
    is_browser_test_pattern,
    is_exempt_rule,
    EXEMPT_RULES,
)


class TestContextClassifier:
    """File context classifier tests."""

    def test_test_directory(self):
        """Test files in test directories should be classified as TEST."""
        c = ContextClassifier()
        assert c.classify("tests/test_auth.py") == FileContext.TEST
        assert c.classify("test/test_auth.py") == FileContext.TEST
        assert c.classify("src/__tests__/auth.test.ts") == FileContext.TEST
        assert c.classify("spec/models/user_spec.rb") == FileContext.TEST

    def test_test_file_suffix(self):
        """Test files with test suffixes should be classified as TEST."""
        c = ContextClassifier()
        assert c.classify("src/auth_test.py") == FileContext.TEST
        assert c.classify("src/auth.test.ts") == FileContext.TEST
        assert c.classify("src/auth.spec.js") == FileContext.TEST
        assert c.classify("src/test_auth.py") == FileContext.TEST

    def test_e2e_directory(self):
        """E2E test directories should be classified as TEST."""
        c = ContextClassifier()
        assert c.classify("e2e/test_browsing.py") == FileContext.TEST
        assert c.classify("integration/test_api.py") == FileContext.TEST
        assert c.classify("unit/test_utils.py") == FileContext.TEST

    def test_conftest(self):
        """Pytest conftest.py should be classified as TEST."""
        c = ContextClassifier()
        assert c.classify("tests/conftest.py") == FileContext.TEST
        assert c.classify("src/conftest.py") == FileContext.TEST

    def test_fixture_directory(self):
        """Fixture directories should be classified as FIXTURE."""
        c = ContextClassifier()
        assert c.classify("tests/fixtures/test_data.json") == FileContext.FIXTURE
        assert c.classify("tests/mocks/user.py") == FileContext.FIXTURE
        assert c.classify("tests/__mocks__/api.ts") == FileContext.FIXTURE
        assert c.classify("tests/stubs/service.py") == FileContext.FIXTURE

    def test_infrastructure_files(self):
        """Infrastructure files should be classified as INFRASTRUCTURE."""
        c = ContextClassifier()
        assert c.classify("Dockerfile") == FileContext.INFRASTRUCTURE
        assert c.classify("docker-compose.yml") == FileContext.INFRASTRUCTURE
        assert c.classify(".github/workflows/ci.yml") == FileContext.INFRASTRUCTURE
        assert c.classify("deploy/terraform/main.tf") == FileContext.INFRASTRUCTURE
        assert c.classify("scripts/setup.sh") == FileContext.INFRASTRUCTURE
        assert c.classify("Makefile") == FileContext.INFRASTRUCTURE

    def test_documentation_files(self):
        """Documentation files should be classified as DOCUMENTATION."""
        c = ContextClassifier()
        assert c.classify("docs/setup.md") == FileContext.DOCUMENTATION
        assert c.classify("README.md") == FileContext.DOCUMENTATION
        assert c.classify("CHANGELOG.rst") == FileContext.DOCUMENTATION
        assert c.classify("docs/api.txt") == FileContext.DOCUMENTATION

    def test_example_files(self):
        """Example files should be classified as EXAMPLE."""
        c = ContextClassifier()
        assert c.classify("examples/demo.py") == FileContext.EXAMPLE
        assert c.classify("demos/agent.ts") == FileContext.EXAMPLE
        assert c.classify("samples/config.json") == FileContext.EXAMPLE
        assert c.classify("tutorials/getting_started.py") == FileContext.EXAMPLE

    def test_template_files(self):
        """Template files should be classified as TEMPLATE."""
        c = ContextClassifier()
        assert c.classify(".env.example") == FileContext.TEMPLATE
        assert c.classify("config.yaml.template") == FileContext.TEMPLATE
        assert c.classify("templates/email.html") == FileContext.TEMPLATE

    def test_vendor_files(self):
        """Vendor files should be classified as VENDOR."""
        c = ContextClassifier()
        assert c.classify("node_modules/express/index.js") == FileContext.VENDOR
        assert c.classify("vendor/github.com/pkg/errors/errors.go") == FileContext.VENDOR
        assert c.classify("third-party/lib.py") == FileContext.VENDOR

    def test_production_files(self):
        """Production code should be classified as PRODUCTION."""
        c = ContextClassifier()
        assert c.classify("src/auth/login.py") == FileContext.PRODUCTION
        assert c.classify("packages/core/scanner.ts") == FileContext.PRODUCTION
        assert c.classify("app/models/user.py") == FileContext.PRODUCTION
        assert c.classify("lib/utils.js") == FileContext.PRODUCTION

    def test_classify_with_reason(self):
        """classify_with_reason should return the matching reason."""
        c = ContextClassifier()
        context, reason = c.classify_with_reason("tests/test_auth.py")
        assert context == FileContext.TEST
        assert "test" in reason.lower()

    def test_is_test_context(self):
        """is_test_context should identify test and fixture contexts."""
        c = ContextClassifier()
        assert c.is_test_context("tests/test_auth.py") is True
        assert c.is_test_context("tests/fixtures/data.json") is True
        assert c.is_test_context("src/auth.py") is False

    def test_is_non_production(self):
        """is_non_production should identify all non-production contexts."""
        c = ContextClassifier()
        assert c.is_non_production("tests/test_auth.py") is True
        assert c.is_non_production("docs/setup.md") is True
        assert c.is_non_production("examples/demo.py") is True
        assert c.is_non_production("src/auth.py") is False

    def test_singleton(self):
        """get_classifier should return a singleton."""
        c1 = get_classifier()
        c2 = get_classifier()
        assert c1 is c2

    def test_classify_file_context_function(self):
        """classify_file_context convenience function should work."""
        assert classify_file_context("tests/test_auth.py") == FileContext.TEST
        assert classify_file_context("src/auth.py") == FileContext.PRODUCTION


class TestRuleContextMultipliers:
    """Per-rule context multiplier tests."""

    def test_agent020_test_multiplier(self):
        """AGENT-020 in test code should get very low multiplier."""
        m = get_context_multiplier("AGENT-020", FileContext.TEST)
        assert m <= 0.10, f"AGENT-020 test multiplier too high: {m}"

    def test_agent020_fixture_multiplier(self):
        """AGENT-020 in fixture code should get very low multiplier."""
        m = get_context_multiplier("AGENT-020", FileContext.FIXTURE)
        assert m <= 0.10, f"AGENT-020 fixture multiplier too high: {m}"

    def test_agent045_test_multiplier(self):
        """AGENT-045 (browser) in test code should get very low multiplier."""
        m = get_context_multiplier("AGENT-045", FileContext.TEST)
        assert m <= 0.10, f"AGENT-045 test multiplier too high: {m}"

    def test_agent004_test_multiplier(self):
        """v0.8.0 P7: AGENT-004 in test code should get aggressive multiplier to suppress.

        Test files with credentials are almost always false positives (mock data,
        examples, test fixtures). Use low multiplier to push them to SUPPRESSED tier.
        """
        m = get_context_multiplier("AGENT-004", FileContext.TEST)
        # v0.8.0 P7: Lowered to 0.25 so test file credentials go to SUPPRESSED
        assert m <= 0.30, f"AGENT-004 test multiplier too high: {m}"
        assert m >= 0.20, f"AGENT-004 test multiplier too low: {m}"

    def test_agent044_test_multiplier(self):
        """AGENT-044 (sudoers) should NOT be dampened in test code."""
        m = get_context_multiplier("AGENT-044", FileContext.TEST)
        assert m >= 0.80, f"AGENT-044 (exempt) test multiplier too low: {m}"

    def test_agent044_exempt(self):
        """AGENT-044 should be in exempt rules."""
        assert is_exempt_rule("AGENT-044")
        assert "AGENT-044" in EXEMPT_RULES

    def test_agent047_infrastructure_multiplier(self):
        """AGENT-047 in infrastructure code should get significant reduction."""
        m = get_context_multiplier("AGENT-047", FileContext.INFRASTRUCTURE)
        assert m <= 0.30, f"AGENT-047 infrastructure multiplier too high: {m}"

    def test_production_always_full(self):
        """Production context should always return 1.0."""
        assert get_context_multiplier("AGENT-004", FileContext.PRODUCTION) == 1.0
        assert get_context_multiplier("AGENT-020", FileContext.PRODUCTION) == 1.0
        assert get_context_multiplier("AGENT-047", FileContext.PRODUCTION) == 1.0

    def test_unknown_rule_uses_defaults(self):
        """Unknown rules should use default multipliers."""
        m = get_context_multiplier("AGENT-999", FileContext.TEST)
        # Default test multiplier is 0.25
        assert 0.15 <= m <= 0.30, f"Default test multiplier unexpected: {m}"

    def test_vendor_low_multiplier(self):
        """Vendor context should have low multipliers for most rules."""
        m = get_context_multiplier("AGENT-004", FileContext.VENDOR)
        assert m <= 0.25, f"AGENT-004 vendor multiplier too high: {m}"


class TestLocalhostDetection:
    """Localhost URL detection tests."""

    def test_localhost_http(self):
        """http://localhost should be detected."""
        assert is_localhost_url("http://localhost:8080")
        assert is_localhost_url("http://localhost/api")
        assert is_localhost_url("http://localhost")

    def test_127_0_0_1(self):
        """http://127.0.0.1 should be detected."""
        assert is_localhost_url("http://127.0.0.1:8080")
        assert is_localhost_url("http://127.0.0.1/api")
        assert is_localhost_url("http://127.0.0.1")

    def test_0_0_0_0(self):
        """http://0.0.0.0 should be detected."""
        assert is_localhost_url("http://0.0.0.0:8080")
        assert is_localhost_url("http://0.0.0.0/api")

    def test_ipv6_localhost(self):
        """http://[::1] should be detected."""
        assert is_localhost_url("http://[::1]:8080")
        assert is_localhost_url("http://[::1]/api")

    def test_external_not_localhost(self):
        """External URLs should not be detected as localhost."""
        assert not is_localhost_url("http://example.com:8080")
        assert not is_localhost_url("http://api.production.com/api")
        assert not is_localhost_url("https://secure.example.com")


class TestBrowserTestPatterns:
    """Browser test pattern detection tests."""

    def test_playwright_patterns(self):
        """Playwright patterns should be detected."""
        assert is_browser_test_pattern("await page.goto('http://localhost')")
        assert is_browser_test_pattern("await page.evaluate(() => {})")
        assert is_browser_test_pattern("browser.newPage()")
        assert is_browser_test_pattern("chromium.launch()")

    def test_puppeteer_patterns(self):
        """Puppeteer patterns should be detected."""
        assert is_browser_test_pattern("puppeteer.launch()")

    def test_selenium_patterns(self):
        """Selenium patterns should be detected."""
        assert is_browser_test_pattern("from selenium import webdriver")
        assert is_browser_test_pattern("webdriver.Chrome()")

    def test_regular_code_not_detected(self):
        """Regular code should not be detected as browser test."""
        assert not is_browser_test_pattern("def main():")
        assert not is_browser_test_pattern("print('hello')")
        assert not is_browser_test_pattern("subprocess.run(['ls'])")
