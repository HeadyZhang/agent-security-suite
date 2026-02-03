"""Tests for output formatters."""

import pytest
import json
from datetime import datetime

from agent_core.models.finding import Finding, Remediation
from agent_core.models.risk import Severity, Category, Location
from agent_audit.cli.formatters.json import format_json, JSONFormatter
from agent_audit.cli.formatters.sarif import SARIFFormatter


class TestJSONFormatter:
    """Tests for JSON formatter."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
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
                ),
                cwe_id="CWE-78"
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
                ),
                cwe_id="CWE-798"
            )
        ]

    def test_format_json_basic(self, sample_findings):
        """Test basic JSON formatting."""
        output = format_json(sample_findings, "/project", 10)
        data = json.loads(output)

        assert 'findings' in data
        assert 'summary' in data
        assert 'scan_path' in data

    def test_format_json_findings_count(self, sample_findings):
        """Test findings count in JSON output."""
        output = format_json(sample_findings, "/project", 10)
        data = json.loads(output)

        assert len(data['findings']) == 2

    def test_format_json_summary(self, sample_findings):
        """Test summary in JSON output."""
        output = format_json(sample_findings, "/project", 10)
        data = json.loads(output)

        summary = data['summary']
        assert 'total' in summary
        assert 'by_severity' in summary
        assert summary['total'] == 2

    def test_format_json_finding_fields(self, sample_findings):
        """Test finding fields in JSON output."""
        output = format_json(sample_findings, "/project", 10)
        data = json.loads(output)

        finding = data['findings'][0]
        assert 'rule_id' in finding
        assert 'title' in finding
        assert 'severity' in finding
        assert 'location' in finding

    def test_format_json_empty_findings(self):
        """Test JSON formatting with no findings."""
        output = format_json([], "/project", 0)
        data = json.loads(output)

        assert data['findings'] == []
        assert data['summary']['total'] == 0


class TestSARIFFormatter:
    """Tests for SARIF formatter."""

    @pytest.fixture
    def formatter(self):
        return SARIFFormatter()

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
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
                    start_column=5,
                    end_column=40,
                    snippet="subprocess.run(cmd, shell=True)"
                ),
                cwe_id="CWE-78",
                remediation=Remediation(
                    description="Use argument lists instead of shell=True"
                )
            )
        ]

    def test_sarif_schema_version(self, formatter, sample_findings):
        """Test SARIF schema and version."""
        sarif = formatter.format(sample_findings)

        assert sarif['$schema'] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert sarif['version'] == "2.1.0"

    def test_sarif_has_runs(self, formatter, sample_findings):
        """Test SARIF has runs array."""
        sarif = formatter.format(sample_findings)

        assert 'runs' in sarif
        assert len(sarif['runs']) == 1

    def test_sarif_tool_info(self, formatter, sample_findings):
        """Test SARIF tool information."""
        sarif = formatter.format(sample_findings)
        tool = sarif['runs'][0]['tool']['driver']

        assert 'name' in tool
        assert tool['name'] == 'agent-audit'

    def test_sarif_results(self, formatter, sample_findings):
        """Test SARIF results."""
        sarif = formatter.format(sample_findings)
        results = sarif['runs'][0]['results']

        assert len(results) == 1
        result = results[0]

        assert result['ruleId'] == 'AGENT-001'
        assert result['level'] == 'error'  # CRITICAL maps to error
        assert 'message' in result

    def test_sarif_location(self, formatter, sample_findings):
        """Test SARIF location information."""
        sarif = formatter.format(sample_findings)
        result = sarif['runs'][0]['results'][0]
        location = result['locations'][0]['physicalLocation']

        assert location['artifactLocation']['uri'] == 'tools/shell.py'
        assert location['region']['startLine'] == 10
        assert location['region']['startColumn'] == 5

    def test_sarif_severity_mapping(self, formatter):
        """Test SARIF severity level mapping."""
        severities = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]

        for severity, expected_level in severities:
            finding = Finding(
                rule_id="TEST",
                title="Test",
                description="Test",
                severity=severity,
                category=Category.COMMAND_INJECTION,
                location=Location(file_path="test.py", start_line=1, end_line=1)
            )
            sarif = formatter.format([finding])
            assert sarif['runs'][0]['results'][0]['level'] == expected_level

    def test_sarif_fingerprint(self, formatter, sample_findings):
        """Test SARIF fingerprint."""
        sarif = formatter.format(sample_findings)
        result = sarif['runs'][0]['results'][0]

        assert 'fingerprints' in result

    def test_sarif_format_to_string(self, formatter, sample_findings):
        """Test SARIF string formatting."""
        output = formatter.format_to_string(sample_findings)

        # Should be valid JSON
        data = json.loads(output)
        assert data['version'] == "2.1.0"

    def test_sarif_empty_findings(self, formatter):
        """Test SARIF with no findings."""
        sarif = formatter.format([])

        assert sarif['runs'][0]['results'] == []

    def test_sarif_rules(self, formatter, sample_findings):
        """Test SARIF rules in tool."""
        sarif = formatter.format(sample_findings)
        rules = sarif['runs'][0]['tool']['driver'].get('rules', [])

        # Should have rule definitions
        assert len(rules) >= 1
        rule = rules[0]
        assert rule['id'] == 'AGENT-001'


class TestTerminalFormatter:
    """Tests for terminal formatter (smoke tests)."""

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
            )
        ]

    def test_format_scan_results_import(self):
        """Test that terminal formatter can be imported."""
        from agent_audit.cli.formatters.terminal import format_scan_results
        assert format_scan_results is not None

    def test_format_scan_results_runs(self, sample_findings):
        """Test that terminal formatter runs without error."""
        from agent_audit.cli.formatters.terminal import format_scan_results
        from io import StringIO

        # Should not raise
        format_scan_results(sample_findings, "/project", 10, quiet=True)
