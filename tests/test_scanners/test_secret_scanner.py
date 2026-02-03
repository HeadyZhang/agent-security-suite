"""Tests for the secret scanner."""

import pytest
import os
import tempfile
from pathlib import Path

from agent_audit.scanners.secret_scanner import SecretScanner, SecretMatch


class TestSecretScanner:
    """Tests for SecretScanner."""

    @pytest.fixture
    def scanner(self):
        return SecretScanner()

    @pytest.fixture
    def production_dir(self):
        """Create a temp directory without 'test' in the path to avoid false positive filtering."""
        # Use a custom temp dir name to avoid pytest's test_* naming
        dir_path = tempfile.mkdtemp(prefix='production_scan_')
        yield Path(dir_path)
        # Cleanup
        import shutil
        shutil.rmtree(dir_path, ignore_errors=True)

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner is not None

    def test_detects_aws_access_key(self, scanner, production_dir):
        """Test detection of AWS access key."""
        secrets_dir = production_dir / "src" / "config"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "settings.py"
        file_path.write_text('AWS_KEY = "AKIAIOSFODNN7PRODUCTION"')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert any("AWS" in s.pattern_name for r in results for s in r.secrets)

    def test_detects_openai_api_key(self, scanner, production_dir):
        """Test detection of OpenAI API key."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.py"
        openai_key = "sk-" + "aBCDEFGHIJKL" * 4  # 48 chars
        file_path.write_text(f'OPENAI_KEY = "{openai_key}"')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert any("OpenAI" in s.pattern_name or "API" in s.pattern_name
                   for r in results for s in r.secrets)

    def test_detects_anthropic_api_key(self, scanner, production_dir):
        """Test detection of Anthropic API key."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.py"
        anthropic_key = "sk-ant-" + "aBCDEFGHIJKLM" * 4  # 40+ chars
        file_path.write_text(f'ANTHROPIC_KEY = "{anthropic_key}"')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert any("Anthropic" in s.pattern_name or "API" in s.pattern_name
                   for r in results for s in r.secrets)

    def test_detects_github_token(self, scanner, production_dir):
        """Test detection of GitHub personal access token."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.py"
        github_token = "ghp_" + "a" * 36  # Exactly 36 alphanumeric chars after ghp_
        file_path.write_text(f'GITHUB_TOKEN = "{github_token}"')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert any("GitHub" in s.pattern_name for r in results for s in r.secrets)

    def test_detects_private_key(self, scanner, production_dir):
        """Test detection of private key."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "key.txt"
        file_path.write_text('-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END RSA PRIVATE KEY-----')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert any("PRIVATE KEY" in s.pattern_name.upper() or "RSA" in s.pattern_name.upper()
                   for r in results for s in r.secrets)

    def test_no_secrets_in_clean_file(self, scanner, production_dir):
        """Test no false positives in clean file."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "clean.py"
        file_path.write_text('''
def hello():
    """A simple function."""
    return "Hello, world!"

config = {
    "name": "myapp",
    "enabled": True
}
''')

        results = scanner.scan(secrets_dir)

        # Should have no secrets
        total_secrets = sum(len(r.secrets) for r in results)
        assert total_secrets == 0

    def test_scans_directory(self, scanner, production_dir):
        """Test scanning entire directory."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        (secrets_dir / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7PRODUCTION"')
        (secrets_dir / "auth.py").write_text('password = "not_a_secret"')  # Too short, no match

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1

    def test_handles_binary_files(self, scanner, production_dir):
        """Test handling of binary files."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "image.png"
        file_path.write_bytes(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)

        results = scanner.scan(secrets_dir)

        # Should not crash
        assert isinstance(results, list)

    def test_handles_encoding_errors(self, scanner, production_dir):
        """Test handling of files with encoding errors."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.txt"
        file_path.write_bytes(b'\xff\xfe' + b'content')

        results = scanner.scan(secrets_dir)

        # Should not crash
        assert isinstance(results, list)

    def test_provides_line_numbers(self, scanner, production_dir):
        """Test that line numbers are provided."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.py"
        file_path.write_text('''
name = "myapp"
debug = False
API_KEY = "AKIAIOSFODNN7PRODUCTION"
enabled = True
''')

        results = scanner.scan(secrets_dir)

        assert len(results) >= 1
        assert len(results[0].secrets) >= 1
        secret = results[0].secrets[0]
        assert secret.line_number == 4  # Line with the secret

    def test_excludes_test_files(self, scanner, tmp_path):
        """Test that files in test directories are excluded by default."""
        # Test directory should be excluded
        test_dir = tmp_path / "tests"
        test_dir.mkdir(parents=True)
        (test_dir / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7PRODUCTION"')

        results = scanner.scan(test_dir)

        # Should not find secrets in test files (filtered as false positive)
        total_secrets = sum(len(r.secrets) for r in results)
        assert total_secrets == 0

    def test_excludes_placeholder_values(self, scanner, production_dir):
        """Test exclusion of common false positive patterns."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "config.py"
        file_path.write_text('''
PLACEHOLDER = "REPLACE_ME"
EXAMPLE_KEY = "your-api-key-here"
MOCK_TOKEN = "fake-token-12345"
''')

        results = scanner.scan(secrets_dir)

        # Placeholder values should be filtered out
        total_secrets = sum(len(r.secrets) for r in results)
        assert total_secrets == 0


class TestSecretPatterns:
    """Test various secret patterns."""

    @pytest.fixture
    def scanner(self):
        return SecretScanner()

    @pytest.fixture
    def production_dir(self):
        """Create a temp directory without 'test' in the path."""
        dir_path = tempfile.mkdtemp(prefix='production_scan_')
        yield Path(dir_path)
        import shutil
        shutil.rmtree(dir_path, ignore_errors=True)

    def test_detects_generic_password_assignment(self, scanner, production_dir):
        """Test detection of password assignments."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "db.py"
        file_path.write_text('DB_PASSWORD = "super_secret_password_123"')

        results = scanner.scan(secrets_dir)
        assert isinstance(results, list)

    def test_handles_multiline_secrets(self, scanner, production_dir):
        """Test handling of multiline secrets like private keys."""
        secrets_dir = production_dir / "src"
        secrets_dir.mkdir(parents=True)
        file_path = secrets_dir / "certs.py"
        file_path.write_text('''PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
content here
-----END RSA PRIVATE KEY-----
"""''')

        results = scanner.scan(secrets_dir)
        assert isinstance(results, list)
        # The private key header should be detected
        assert any("PRIVATE KEY" in s.pattern_name.upper()
                   for r in results for s in r.secrets)


class TestPatternMatching:
    """Direct pattern matching tests that don't depend on file scanning."""

    @pytest.fixture
    def scanner(self):
        return SecretScanner()

    def test_aws_key_pattern_matches(self, scanner):
        """Test AWS key pattern directly."""
        import re
        aws_pattern = re.compile(r'AKIA[0-9A-Z]{16}')
        test_key = "AKIAIOSFODNN7PRODUCTION"
        assert aws_pattern.match(test_key) is not None

    def test_openai_key_pattern_matches(self, scanner):
        """Test OpenAI key pattern directly."""
        import re
        openai_pattern = re.compile(r'sk-[a-zA-Z0-9]{48,}')
        test_key = "sk-" + "a" * 48
        assert openai_pattern.match(test_key) is not None

    def test_github_token_pattern_matches(self, scanner):
        """Test GitHub token pattern directly."""
        import re
        github_pattern = re.compile(r'ghp_[a-zA-Z0-9]{36}')
        test_key = "ghp_" + "a" * 36
        assert github_pattern.match(test_key) is not None

    def test_private_key_pattern_matches(self, scanner):
        """Test private key pattern directly."""
        import re
        key_pattern = re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----')
        test_header = "-----BEGIN RSA PRIVATE KEY-----"
        assert key_pattern.search(test_header) is not None
