"""Tests for configuration file scanner."""

import json
import pytest
import tempfile
from pathlib import Path

import yaml

from agent_audit.scanners.config_scanner import (
    ConfigScanner,
    ConfigScanResult,
    ConfigIssue,
)


class TestConfigScanner:
    """Tests for ConfigScanner class."""

    def test_scanner_initialization(self):
        """Scanner should initialize with default settings."""
        scanner = ConfigScanner()
        assert scanner.name == "Config Scanner"
        assert isinstance(scanner.config_filenames, set)
        assert len(scanner.config_filenames) > 0

    def test_scanner_initialization_with_exclude_paths(self):
        """Scanner should accept exclude paths."""
        scanner = ConfigScanner(exclude_paths=["tests/**", "venv/**"])
        assert "tests/**" in scanner.exclude_paths

    def test_scanner_initialization_with_custom_filenames(self):
        """Scanner should accept custom config filenames."""
        scanner = ConfigScanner(config_filenames=["custom.yaml"])
        assert "custom.yaml" in scanner.config_filenames


class TestConfigScannerDangerousPatterns:
    """Tests for detecting dangerous configuration patterns."""

    def test_detects_debug_mode_enabled(self):
        """Should detect debug mode enabled in config."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("debug: true", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            issues = results[0].issues
            debug_issues = [i for i in issues if "debug" in i.key_path.lower()]
            assert len(debug_issues) > 0
            assert debug_issues[0].severity == "high"

    def test_detects_ssl_verification_disabled(self):
        """Should detect SSL verification disabled."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("verify_ssl: false", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            ssl_issues = [i for i in results[0].issues if "ssl" in i.key_path.lower()]
            assert len(ssl_issues) > 0
            assert ssl_issues[0].severity == "critical"

    def test_detects_insecure_mode(self):
        """Should detect insecure mode enabled."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("insecure: true", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            insecure_issues = [i for i in results[0].issues if "insecure" in i.key_path.lower()]
            assert len(insecure_issues) > 0

    def test_detects_anonymous_access(self):
        """Should detect anonymous access enabled."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("allow_anonymous: true", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            anon_issues = [i for i in results[0].issues if "anonymous" in i.key_path.lower()]
            assert len(anon_issues) > 0

    def test_detects_cors_allow_all(self):
        """Should detect CORS allowing all origins."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text('allowed_origins: "*"', encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            cors_issues = [i for i in results[0].issues if "origins" in i.key_path.lower()]
            assert len(cors_issues) > 0

    def test_detects_sandbox_disabled(self):
        """Should detect sandbox mode disabled."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("sandbox: disabled", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            sandbox_issues = [i for i in results[0].issues if "sandbox" in i.key_path.lower()]
            assert len(sandbox_issues) > 0

    def test_detects_all_interfaces_binding(self):
        """Should detect binding to all interfaces (0.0.0.0)."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("host: 0.0.0.0\nport: 8080", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            host_issues = [i for i in results[0].issues if i.issue_type == "network_exposure"]
            assert len(host_issues) > 0


class TestConfigScannerNestedConfig:
    """Tests for scanning nested configuration structures."""

    def test_scans_nested_config(self):
        """Should scan nested configuration objects."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config = {
                "server": {
                    "debug": True,
                    "security": {
                        "verify_ssl": False
                    }
                }
            }
            config_path.write_text(yaml.dump(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            issues = results[0].issues
            # Should find issues in nested structures
            assert any("debug" in i.key_path.lower() for i in issues)
            assert any("ssl" in i.key_path.lower() for i in issues)

    def test_nested_key_paths_are_correct(self):
        """Key paths should correctly reflect nesting."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config = {
                "server": {
                    "security": {
                        "debug": True
                    }
                }
            }
            config_path.write_text(yaml.dump(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            debug_issues = [i for i in results[0].issues if "debug" in i.key_path.lower()]
            assert len(debug_issues) > 0
            # Key path should include parent keys
            assert "server" in debug_issues[0].key_path or "security" in debug_issues[0].key_path


class TestConfigScannerFileFormats:
    """Tests for different configuration file formats."""

    def test_scans_json_config(self):
        """Should scan JSON configuration files."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config = {"debug": True}
            config_path.write_text(json.dumps(config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            assert any("debug" in i.key_path.lower() for i in results[0].issues)

    def test_scans_yaml_config(self):
        """Should scan YAML configuration files."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("debug: true", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1

    def test_scans_yml_config(self):
        """Should scan .yml configuration files."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yml"
            config_path.write_text("debug: true", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1

    def test_handles_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text("{invalid json", encoding="utf-8")

            results = scanner.scan(config_path)

            # Should return empty results, not crash
            assert len(results) == 0

    def test_handles_invalid_yaml(self):
        """Should handle invalid YAML gracefully."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text(":\n  :\n    :", encoding="utf-8")

            results = scanner.scan(config_path)

            # Should handle gracefully
            assert isinstance(results, list)


class TestConfigScannerDirectoryScan:
    """Tests for scanning directories."""

    def test_scans_directory_for_config_files(self):
        """Should find and scan config files in a directory."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple config files
            config1 = Path(tmpdir) / "config.yaml"
            config1.write_text("debug: true", encoding="utf-8")

            config2 = Path(tmpdir) / "settings.json"
            config2.write_text('{"verify_ssl": false}', encoding="utf-8")

            results = scanner.scan(Path(tmpdir))

            # Should find multiple config files
            assert len(results) >= 1

    def test_finds_known_config_filenames(self):
        """Should find known configuration file names."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a config file with known name
            config = Path(tmpdir) / "app.yaml"
            config.write_text("debug: true", encoding="utf-8")

            results = scanner.scan(Path(tmpdir))

            assert len(results) == 1


class TestConfigIssue:
    """Tests for ConfigIssue dataclass."""

    def test_issue_creation(self):
        """ConfigIssue should be created with required fields."""
        issue = ConfigIssue(
            issue_type="dangerous_setting",
            description="Test issue",
            key_path="test.key",
            current_value=True,
        )

        assert issue.issue_type == "dangerous_setting"
        assert issue.description == "Test issue"
        assert issue.key_path == "test.key"
        assert issue.current_value is True

    def test_issue_with_recommended_value(self):
        """ConfigIssue should support recommended value."""
        issue = ConfigIssue(
            issue_type="dangerous_setting",
            description="Test issue",
            key_path="test.key",
            current_value=True,
            recommended_value=False,
        )

        assert issue.recommended_value is False

    def test_issue_default_severity(self):
        """ConfigIssue should have default severity of medium."""
        issue = ConfigIssue(
            issue_type="test",
            description="Test",
            key_path="test",
            current_value=None,
        )

        assert issue.severity == "medium"


class TestConfigScanResult:
    """Tests for ConfigScanResult dataclass."""

    def test_result_creation(self):
        """ConfigScanResult should be created with source file."""
        result = ConfigScanResult(source_file="/path/to/config.yaml")

        assert result.source_file == "/path/to/config.yaml"
        assert result.issues == []
        assert result.config_data == {}

    def test_result_with_issues(self):
        """ConfigScanResult should store issues."""
        issue = ConfigIssue(
            issue_type="test",
            description="Test",
            key_path="test",
            current_value=None,
        )
        result = ConfigScanResult(
            source_file="/path/to/config.yaml",
            issues=[issue],
        )

        assert len(result.issues) == 1

    def test_result_with_config_data(self):
        """ConfigScanResult should store original config data."""
        result = ConfigScanResult(
            source_file="/path/to/config.yaml",
            config_data={"key": "value"},
        )

        assert result.config_data == {"key": "value"}


class TestConfigScannerSafeConfig:
    """Tests for configurations that should not raise issues."""

    def test_no_issues_for_safe_config(self):
        """Safe configuration should not raise issues."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            safe_config = {
                "debug": False,
                "verify_ssl": True,
                "sandbox": True,
                "rate_limit": 100,
            }
            config_path.write_text(yaml.dump(safe_config), encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            # Should have minimal or no dangerous setting issues
            dangerous_issues = [
                i for i in results[0].issues
                if i.issue_type == "dangerous_setting"
            ]
            assert len(dangerous_issues) == 0

    def test_debug_false_is_safe(self):
        """debug: false should not raise issues."""
        scanner = ConfigScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text("debug: false", encoding="utf-8")

            results = scanner.scan(config_path)

            assert len(results) == 1
            debug_issues = [
                i for i in results[0].issues
                if "debug" in i.key_path.lower() and i.issue_type == "dangerous_setting"
            ]
            assert len(debug_issues) == 0
