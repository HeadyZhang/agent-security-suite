"""Tests for ignore/allowlist configuration."""

import pytest
import json
import yaml
from pathlib import Path

from agent_core.models.finding import Finding
from agent_core.models.risk import Severity, Category, Location
from agent_audit.config.ignore import (
    IgnoreManager,
    IgnoreRule,
    AllowlistConfig,
    create_default_config,
    compute_fingerprint,
    save_baseline,
    load_baseline,
    filter_by_baseline
)


class TestIgnoreManager:
    """Tests for IgnoreManager."""

    @pytest.fixture
    def manager(self):
        return IgnoreManager()

    @pytest.fixture
    def sample_finding(self):
        return Finding(
            rule_id="AGENT-001",
            title="Command Injection",
            description="Command injection vulnerability",
            severity=Severity.CRITICAL,
            category=Category.COMMAND_INJECTION,
            location=Location(
                file_path="tools/shell.py",
                start_line=10,
                end_line=10,
                snippet="subprocess.run(cmd, shell=True)"
            )
        )

    def test_manager_initialization(self, manager):
        """Test manager initializes correctly."""
        assert manager is not None
        assert manager.config is None

    def test_load_yaml_config(self, manager, tmp_path):
        """Test loading YAML configuration."""
        config = {
            'ignore': [
                {
                    'rule_id': 'AGENT-001',
                    'reason': 'False positive in test file'
                }
            ]
        }
        config_file = tmp_path / ".agent-audit.yaml"
        config_file.write_text(yaml.dump(config))

        result = manager.load(tmp_path)

        assert result is True
        assert manager.config is not None
        assert len(manager.config.ignore_rules) >= 1

    def test_apply_ignore_by_rule_id(self, manager, sample_finding, tmp_path):
        """Test applying ignore by rule ID."""
        config = {
            'ignore': [
                {
                    'rule_id': 'AGENT-001',
                    'reason': 'Known false positive'
                }
            ]
        }
        config_file = tmp_path / ".agent-audit.yaml"
        config_file.write_text(yaml.dump(config))
        manager.load(tmp_path)

        manager.apply_to_finding(sample_finding)

        assert sample_finding.suppressed is True
        assert sample_finding.suppressed_reason == "Known false positive"

    def test_apply_ignore_by_path_pattern(self, manager, sample_finding, tmp_path):
        """Test applying ignore by path pattern."""
        config = {
            'ignore': [
                {
                    'rule_id': 'AGENT-001',
                    'paths': ['tools/*'],
                    'reason': 'Intentionally dangerous for testing'
                }
            ]
        }
        config_file = tmp_path / ".agent-audit.yaml"
        config_file.write_text(yaml.dump(config))
        manager.load(tmp_path)

        manager.apply_to_finding(sample_finding)

        assert sample_finding.suppressed is True

    def test_no_ignore_when_not_matching(self, manager, sample_finding, tmp_path):
        """Test finding not suppressed when no match."""
        config = {
            'ignore': [
                {
                    'rule_id': 'AGENT-999',
                    'reason': 'Different rule'
                }
            ]
        }
        config_file = tmp_path / ".agent-audit.yaml"
        config_file.write_text(yaml.dump(config))
        manager.load(tmp_path)

        manager.apply_to_finding(sample_finding)

        assert sample_finding.suppressed is False

    def test_multiple_rules(self, manager, sample_finding, tmp_path):
        """Test multiple ignore rules."""
        config = {
            'ignore': [
                {'rule_id': 'AGENT-002', 'reason': 'A'},
                {'rule_id': 'AGENT-001', 'reason': 'B'}
            ]
        }
        config_file = tmp_path / ".agent-audit.yaml"
        config_file.write_text(yaml.dump(config))
        manager.load(tmp_path)

        manager.apply_to_finding(sample_finding)

        assert sample_finding.suppressed is True
        assert sample_finding.suppressed_reason == "B"


class TestIgnoreRule:
    """Tests for IgnoreRule."""

    def test_rule_with_rule_id(self):
        """Test creating rule with rule_id."""
        rule = IgnoreRule(
            rule_id="AGENT-001",
            reason="Test reason"
        )
        assert rule.rule_id == "AGENT-001"
        assert rule.reason == "Test reason"

    def test_rule_with_paths(self):
        """Test creating rule with paths pattern."""
        rule = IgnoreRule(
            paths=["**/test_*.py"],
            reason="Ignore test files"
        )
        assert "**/test_*.py" in rule.paths

    def test_rule_with_tools(self):
        """Test creating rule with tools."""
        rule = IgnoreRule(
            tools=["execute_command"],
            reason="Specific tool ignore"
        )
        assert "execute_command" in rule.tools


class TestBaseline:
    """Tests for baseline functionality."""

    @pytest.fixture
    def sample_findings(self):
        return [
            Finding(
                rule_id="AGENT-001",
                title="Command Injection",
                description="Command injection vulnerability",
                severity=Severity.CRITICAL,
                category=Category.COMMAND_INJECTION,
                location=Location(
                    file_path="tools/shell.py",
                    start_line=10,
                    end_line=10,
                    snippet="subprocess.run(cmd, shell=True)"
                )
            ),
            Finding(
                rule_id="AGENT-004",
                title="Hardcoded Credentials",
                description="Hardcoded API key",
                severity=Severity.CRITICAL,
                category=Category.CREDENTIAL_EXPOSURE,
                location=Location(
                    file_path="config.py",
                    start_line=5,
                    end_line=5,
                    snippet="API_KEY = 'secret'"
                )
            )
        ]

    def test_compute_fingerprint_stable(self, sample_findings):
        """Test that fingerprint is stable."""
        fp1 = compute_fingerprint(sample_findings[0])
        fp2 = compute_fingerprint(sample_findings[0])

        assert fp1 == fp2

    def test_compute_fingerprint_unique(self, sample_findings):
        """Test that different findings have different fingerprints."""
        fp1 = compute_fingerprint(sample_findings[0])
        fp2 = compute_fingerprint(sample_findings[1])

        assert fp1 != fp2

    def test_save_baseline(self, sample_findings, tmp_path):
        """Test saving baseline."""
        baseline_file = tmp_path / "baseline.json"

        save_baseline(sample_findings, baseline_file)

        assert baseline_file.exists()
        data = json.loads(baseline_file.read_text())
        assert 'fingerprints' in data
        assert len(data['fingerprints']) == 2

    def test_load_baseline(self, sample_findings, tmp_path):
        """Test loading baseline."""
        baseline_file = tmp_path / "baseline.json"
        save_baseline(sample_findings, baseline_file)

        baseline = load_baseline(baseline_file)

        # load_baseline returns a Set of fingerprints
        assert isinstance(baseline, set)
        assert len(baseline) == 2

    def test_filter_by_baseline(self, sample_findings, tmp_path):
        """Test filtering findings by baseline."""
        baseline_file = tmp_path / "baseline.json"
        save_baseline(sample_findings, baseline_file)
        baseline = load_baseline(baseline_file)

        # Same findings should be filtered out
        filtered = filter_by_baseline(sample_findings, baseline)

        assert len(filtered) == 0

    def test_filter_by_baseline_new_finding(self, sample_findings, tmp_path):
        """Test that new findings pass through baseline filter."""
        baseline_file = tmp_path / "baseline.json"

        # Save only first finding to baseline
        save_baseline([sample_findings[0]], baseline_file)
        baseline = load_baseline(baseline_file)

        # Filter both findings - second should pass through
        filtered = filter_by_baseline(sample_findings, baseline)

        assert len(filtered) == 1
        assert filtered[0].rule_id == "AGENT-004"


class TestDefaultConfig:
    """Tests for default configuration generation."""

    def test_create_default_config(self):
        """Test creating default config."""
        config = create_default_config()

        assert isinstance(config, str)
        assert 'agent-audit' in config.lower() or 'ignore' in config.lower()

    def test_default_config_is_valid_yaml(self):
        """Test that default config is valid YAML."""
        config = create_default_config()
        data = yaml.safe_load(config)

        assert isinstance(data, dict)

    def test_default_config_has_examples(self):
        """Test that default config has example entries."""
        config = create_default_config()

        # Should have commented examples or sections
        assert 'ignore' in config.lower() or 'allowlist' in config.lower()
