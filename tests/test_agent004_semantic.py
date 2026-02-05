"""
Tests for AGENT-004 semantic analysis.

Tests the three-stage semantic analyzer for credential detection:
- Stage 1: Candidate Discovery
- Stage 2: Value Analysis
- Stage 3: Context Adjustment

Tests cover both false positive exclusion and true positive detection.
"""

import pytest
from pathlib import Path

from agent_audit.analysis.semantic_analyzer import (
    SemanticAnalyzer,
    analyze_credential_candidate,
    AnalysisContext,
    SemanticCandidate,
    HIGH_CONFIDENCE_PREFIXES,
)
from agent_audit.parsers.treesitter_parser import ValueType


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def analyzer():
    """Create a semantic analyzer instance."""
    return SemanticAnalyzer()


# ============================================================================
# False Positive Exclusion Tests (8 cases)
# ============================================================================

class TestFalsePositiveExclusion:
    """Tests for false positive scenarios that should be excluded."""

    def test_function_call_excluded(self, analyzer):
        """Function calls should not be flagged as credentials."""
        # api_key = get_secret("key")
        result = analyze_credential_candidate(
            identifier="api_key",
            value="get_secret('key')",
            line=1,
            column=10,
            end_column=30,
            raw_line='api_key = get_secret("key")',
            file_path="/app/config.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert "function call" in result.reason.lower()

    def test_schema_definition_excluded(self, analyzer):
        """Type definitions/schemas should not be flagged."""
        # class Config(BaseModel):
        #     api_key: SecretStr
        result = analyze_credential_candidate(
            identifier="api_key",
            value="SecretStr",
            line=5,
            column=4,
            end_column=20,
            raw_line="    api_key: SecretStr",
            file_path="/app/models.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        # Either type annotation or class name detection
        assert any(x in result.reason.lower() for x in ["type", "class", "annotation", "variable"])

    def test_variable_passing_excluded(self, analyzer):
        """Variable references (not literals) should be excluded."""
        # client = OpenAI(api_key=api_key_from_env)
        result = analyze_credential_candidate(
            identifier="api_key",
            value="api_key_from_env",
            line=10,
            column=25,
            end_column=41,
            raw_line="client = OpenAI(api_key=api_key_from_env)",
            file_path="/app/client.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert "variable" in result.reason.lower() or "identifier" in result.reason.lower()

    def test_env_read_excluded(self, analyzer):
        """Environment variable reads should be excluded."""
        # api_key = os.environ.get("API_KEY")
        result = analyze_credential_candidate(
            identifier="api_key",
            value="os.environ.get('API_KEY')",
            line=3,
            column=10,
            end_column=35,
            raw_line="api_key = os.environ.get('API_KEY')",
            file_path="/app/config.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert "environment" in result.reason.lower() or "function" in result.reason.lower()

    def test_function_name_excluded(self, analyzer):
        """Function declarations should not be flagged."""
        # def get_api_key():
        result = analyze_credential_candidate(
            identifier="get_api_key",
            value="",
            line=1,
            column=4,
            end_column=15,
            raw_line="def get_api_key():",
            file_path="/app/utils.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert "function" in result.reason.lower() or "short" in result.reason.lower()

    def test_placeholder_excluded(self, analyzer):
        """Placeholder values should be excluded."""
        # api_key = "your-api-key-here"
        result = analyze_credential_candidate(
            identifier="api_key",
            value="your-api-key-here",
            line=5,
            column=11,
            end_column=29,
            raw_line='api_key = "your-api-key-here"',
            file_path="/app/example.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert result.is_placeholder or "placeholder" in result.reason.lower()

    def test_value_equals_name_excluded(self, analyzer):
        """Value that equals variable name should be excluded (placeholder pattern)."""
        # api_key = "api_key"
        result = analyze_credential_candidate(
            identifier="api_key",
            value="api_key",
            line=1,
            column=11,
            end_column=18,
            raw_line='api_key = "api_key"',
            file_path="/app/config.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        assert "variable name" in result.reason.lower() or "short" in result.reason.lower()

    def test_null_assignment_excluded(self, analyzer):
        """Null/None assignments should be excluded."""
        # api_key = None
        result = analyze_credential_candidate(
            identifier="api_key",
            value="None",
            line=1,
            column=11,
            end_column=15,
            raw_line="api_key = None",
            file_path="/app/config.py",
            pattern_name="Generic API Key",
        )
        assert not result.should_report
        # None is detected as a variable reference (Python keyword)
        assert any(x in result.reason.lower() for x in ["null", "short", "variable"])


# ============================================================================
# True Positive Tests (6 cases)
# ============================================================================

class TestTruePositiveDetection:
    """Tests for real credentials that should be detected."""

    def test_postgres_connection_string(self, analyzer):
        """PostgreSQL connection string with credentials should be detected."""
        conn_str = "postgresql://admin:SuperSecret123!@db.example.com/mydb"
        result = analyze_credential_candidate(
            identifier="DATABASE_URL",
            value=conn_str,
            line=5,
            column=15,
            end_column=70,
            raw_line=f'DATABASE_URL = "{conn_str}"',
            file_path="/app/production.py",
            pattern_name="Database Connection String with Credentials",
        )
        assert result.should_report
        assert result.confidence >= 0.5

    def test_openai_key_detected(self, analyzer):
        """OpenAI API key (sk-proj-*) should be detected with high confidence."""
        # This is a fake key for testing
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="OPENAI_API_KEY",
            value=openai_key,
            line=3,
            column=18,
            end_column=72,
            raw_line=f'OPENAI_API_KEY = "{openai_key}"',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        assert result.should_report
        assert result.confidence >= 0.9
        assert result.format_matched is not None
        assert "OpenAI" in result.format_matched

    def test_anthropic_key_detected(self, analyzer):
        """Anthropic API key (sk-ant-*) should be detected with high confidence."""
        # This is a fake key for testing
        anthropic_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz12345678901234567890123456"
        result = analyze_credential_candidate(
            identifier="ANTHROPIC_API_KEY",
            value=anthropic_key,
            line=4,
            column=20,
            end_column=80,
            raw_line=f'ANTHROPIC_API_KEY = "{anthropic_key}"',
            file_path="/app/config.py",
            pattern_name="Anthropic API Key",
        )
        assert result.should_report
        assert result.confidence >= 0.9
        assert result.format_matched is not None
        assert "Anthropic" in result.format_matched

    def test_github_token_detected(self, analyzer):
        """GitHub Personal Access Token should be detected."""
        # This is a fake token for testing
        github_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = analyze_credential_candidate(
            identifier="GITHUB_TOKEN",
            value=github_token,
            line=10,
            column=15,
            end_column=55,
            raw_line=f'GITHUB_TOKEN = "{github_token}"',
            file_path="/app/ci.py",
            pattern_name="GitHub Personal Access Token",
        )
        assert result.should_report
        assert result.confidence >= 0.9
        assert result.format_matched is not None
        assert "GitHub" in result.format_matched

    def test_aws_key_detected(self, analyzer):
        """AWS Access Key ID should be detected."""
        # This is a fake key for testing (correct format)
        aws_key = "AKIAIOSFODNN7SECRETX"
        result = analyze_credential_candidate(
            identifier="AWS_ACCESS_KEY_ID",
            value=aws_key,
            line=2,
            column=20,
            end_column=40,
            raw_line=f'AWS_ACCESS_KEY_ID = "{aws_key}"',
            file_path="/app/aws.py",
            pattern_name="AWS Access Key ID",
        )
        assert result.should_report
        assert result.confidence >= 0.9
        assert result.format_matched is not None
        assert "AWS" in result.format_matched

    def test_high_entropy_secret_detected(self, analyzer):
        """High entropy string that looks like a secret should be detected."""
        # Random-looking string with high entropy
        high_entropy = "x7Kp2mQwL9vNcR5hT3jU8sYbD6fG4aE1"
        result = analyze_credential_candidate(
            identifier="SECRET_KEY",
            value=high_entropy,
            line=15,
            column=14,
            end_column=46,
            raw_line=f'SECRET_KEY = "{high_entropy}"',
            file_path="/app/secrets.py",
            pattern_name="Generic Secret/Password",
        )
        assert result.should_report
        assert result.confidence >= 0.5
        assert result.entropy >= 3.5


# ============================================================================
# Context Adjustment Tests
# ============================================================================

class TestContextAdjustment:
    """Tests for Stage 3 context-based confidence adjustment."""

    def test_test_file_reduces_confidence(self, analyzer):
        """v0.8.0 P7: Credentials in test files should be SUPPRESSED.

        Test files with credential patterns are almost always false positives
        (test data, mocks, examples). They should be suppressed to reduce noise.
        """
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="api_key",
            value=openai_key,
            line=10,
            column=13,
            end_column=67,
            raw_line=f'    api_key = "{openai_key}"',
            file_path="/app/tests/test_client.py",
            pattern_name="OpenAI Project API Key",
        )
        # v0.8.0 P7: Test files should be SUPPRESSED (confidence < 0.30)
        # This reduces BLOCK FP rate from test file credentials
        assert result.tier == "SUPPRESSED"
        assert result.confidence < 0.30

    def test_markdown_file_reduces_confidence(self, analyzer):
        """Credentials in markdown files should have reduced confidence."""
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="",
            value=openai_key,
            line=25,
            column=0,
            end_column=56,
            raw_line=openai_key,
            file_path="/app/docs/setup.md",
            pattern_name="OpenAI Project API Key",
        )
        # Markdown files get reduced confidence
        assert result.confidence < 0.95

    def test_example_comment_reduces_confidence(self, analyzer):
        """Lines with '# example' should have reduced confidence."""
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="api_key",
            value=openai_key,
            line=5,
            column=13,
            end_column=67,
            raw_line=f'api_key = "{openai_key}"  # example',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        # Should have reduced confidence due to example comment
        assert result.confidence < 0.95


# ============================================================================
# Known Format Tests (KNOWN-004 fix verification)
# ============================================================================

class TestKnownFormats:
    """Tests for known credential format detection."""

    def test_sk_proj_prefix_recognized(self, analyzer):
        """sk-proj- prefix should be recognized as OpenAI key."""
        value = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456789012"
        result = analyze_credential_candidate(
            identifier="key",
            value=value,
            line=1,
            column=7,
            end_column=60,
            raw_line=f'key = "{value}"',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        assert result.should_report
        assert result.format_matched is not None
        assert "OpenAI" in result.format_matched

    def test_sk_ant_prefix_recognized(self, analyzer):
        """sk-ant- prefix should be recognized as Anthropic key."""
        value = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz12345678901234567890"
        result = analyze_credential_candidate(
            identifier="key",
            value=value,
            line=1,
            column=7,
            end_column=70,
            raw_line=f'key = "{value}"',
            file_path="/app/config.py",
            pattern_name="Anthropic API Key",
        )
        assert result.should_report
        assert result.format_matched is not None
        assert "Anthropic" in result.format_matched

    def test_co_prefix_recognized(self, analyzer):
        """co- prefix should be recognized as Cohere key."""
        value = "co-1234567890abcdefghijklmnopqrstuvwxyz"
        result = analyze_credential_candidate(
            identifier="key",
            value=value,
            line=1,
            column=7,
            end_column=45,
            raw_line=f'key = "{value}"',
            file_path="/app/config.py",
            pattern_name="Cohere API Key",
        )
        assert result.should_report
        assert result.format_matched is not None
        assert "Cohere" in result.format_matched


# ============================================================================
# ValueType Classification Tests
# ============================================================================

class TestValueTypeClassification:
    """Tests for value type inference."""

    def test_env_read_detection(self, analyzer):
        """Environment variable read patterns should be detected."""
        patterns = [
            "os.environ.get('KEY')",
            "os.environ['KEY']",
            "os.getenv('KEY')",
            "settings.API_KEY",
            "config.secret_key",
        ]
        for pattern in patterns:
            result = analyze_credential_candidate(
                identifier="key",
                value=pattern,
                line=1,
                column=7,
                end_column=len(pattern) + 7,
                raw_line=f'key = {pattern}',
                file_path="/app/config.py",
                pattern_name="Generic API Key",
            )
            assert not result.should_report, f"Should exclude env read: {pattern}"

    def test_class_name_detection(self, analyzer):
        """PascalCase class names should be excluded."""
        class_names = [
            "ConversationBufferMemory",
            "TokenHandler",
            "SecretManager",
            "APIKeyProvider",
        ]
        for name in class_names:
            result = analyze_credential_candidate(
                identifier="memory",
                value=name,
                line=1,
                column=10,
                end_column=len(name) + 10,
                raw_line=f'memory = {name}()',
                file_path="/app/agent.py",
                pattern_name="Generic Token",
            )
            assert not result.should_report, f"Should exclude class name: {name}"


# ============================================================================
# Integration Tests with SecretScanner
# ============================================================================

class TestSecretScannerIntegration:
    """Tests for integration with the SecretScanner."""

    def test_scanner_uses_semantic_analyzer(self, tmp_path):
        """SecretScanner should use semantic analyzer for filtering."""
        from agent_audit.scanners.secret_scanner import SecretScanner

        # Create a test file with both FP and TP
        test_file = tmp_path / "config.py"
        test_file.write_text('''
# Real credential (should be detected)
OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"

# False positive (should be excluded)
api_key = os.environ.get("API_KEY")

# False positive (placeholder)
demo_key = "your-api-key-here"

# False positive (function definition)
def get_api_key():
    pass
''')

        scanner = SecretScanner()
        results = scanner.scan(test_file)

        assert len(results) == 1
        result = results[0]
        assert len(result.secrets) == 1
        secret = result.secrets[0]
        assert secret.pattern_name == "OpenAI Project API Key"
        assert secret.confidence >= 0.9

    def test_scanner_confidence_in_match(self, tmp_path):
        """SecretMatch should include confidence and tier from semantic analysis."""
        from agent_audit.scanners.secret_scanner import SecretScanner

        test_file = tmp_path / "secrets.py"
        test_file.write_text('''
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
''')

        scanner = SecretScanner()
        results = scanner.scan(test_file)

        assert len(results) == 1
        secret = results[0].secrets[0]
        assert hasattr(secret, 'confidence')
        assert hasattr(secret, 'tier')
        assert secret.confidence >= 0.9
        assert secret.tier in ("BLOCK", "WARN", "INFO", "SUPPRESSED")


# ============================================================================
# Tier Classification Tests
# ============================================================================

class TestTierClassification:
    """Tests for confidence-to-tier conversion."""

    def test_block_tier_for_high_confidence(self, analyzer):
        """High confidence (>=0.9) should map to BLOCK tier."""
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="key",
            value=openai_key,
            line=1,
            column=7,
            end_column=60,
            raw_line=f'key = "{openai_key}"',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        assert result.tier == "BLOCK"

    def test_suppressed_tier_for_low_confidence(self, analyzer):
        """Very low confidence (<0.3) should map to SUPPRESSED tier."""
        result = analyze_credential_candidate(
            identifier="key",
            value="abc",  # Too short
            line=1,
            column=7,
            end_column=10,
            raw_line='key = "abc"',
            file_path="/app/config.py",
            pattern_name="Generic API Key",
        )
        assert result.tier == "SUPPRESSED"
        assert not result.should_report
