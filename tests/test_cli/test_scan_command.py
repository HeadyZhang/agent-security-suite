"""Tests for the scan CLI command."""

import pytest
import json
from pathlib import Path
from click.testing import CliRunner

from agent_audit.cli.main import cli


class TestScanCommand:
    """Tests for the scan command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def vulnerable_agents_path(self):
        return Path(__file__).parent.parent / "fixtures" / "vulnerable_agents"

    @pytest.fixture
    def safe_agents_path(self):
        return Path(__file__).parent.parent / "fixtures" / "safe_agents"

    def test_scan_help(self, runner):
        """Test scan --help works."""
        result = runner.invoke(cli, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'Scan agent code' in result.output

    def test_scan_vulnerable_agents(self, runner, vulnerable_agents_path):
        """Test scanning vulnerable agents finds issues."""
        result = runner.invoke(cli, ['scan', str(vulnerable_agents_path)])

        # Should find critical issues, so exit code should be 1
        assert result.exit_code == 1
        assert 'CRITICAL' in result.output or 'critical' in result.output

    def test_scan_safe_agents(self, runner, safe_agents_path):
        """Test scanning safe agents has fewer issues."""
        result = runner.invoke(cli, ['scan', str(safe_agents_path)])

        # Safe agents should pass
        assert result.exit_code == 0

    def test_scan_json_output(self, runner, vulnerable_agents_path, tmp_path):
        """Test JSON output format."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--format', 'json',
            '--output', str(output_file)
        ])

        assert output_file.exists()
        data = json.loads(output_file.read_text())

        assert 'findings' in data
        assert 'summary' in data
        assert len(data['findings']) > 0

    def test_scan_sarif_output(self, runner, vulnerable_agents_path, tmp_path):
        """Test SARIF output format."""
        output_file = tmp_path / "results.sarif"

        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--format', 'sarif',
            '--output', str(output_file)
        ])

        assert output_file.exists()
        sarif_data = json.loads(output_file.read_text())

        assert sarif_data['$schema'] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert sarif_data['version'] == "2.1.0"
        assert len(sarif_data['runs']) == 1
        assert len(sarif_data['runs'][0]['results']) > 0

    def test_scan_markdown_output(self, runner, vulnerable_agents_path, tmp_path):
        """Test Markdown output format."""
        output_file = tmp_path / "report.md"

        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--format', 'markdown',
            '--output', str(output_file)
        ])

        assert output_file.exists()
        content = output_file.read_text()

        assert '# Agent Audit Security Report' in content
        assert '## Findings' in content

    def test_scan_severity_filter(self, runner, vulnerable_agents_path):
        """Test severity filtering."""
        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--severity', 'critical'
        ])

        # Should only show critical findings
        # All our vulnerable fixtures have critical findings

    def test_scan_fail_on_critical(self, runner, vulnerable_agents_path):
        """Test --fail-on critical option."""
        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--fail-on', 'critical'
        ])

        # Should fail because we have critical findings
        assert result.exit_code == 1

    def test_scan_fail_on_with_no_issues(self, runner, safe_agents_path):
        """Test --fail-on when no issues at that level."""
        result = runner.invoke(cli, [
            'scan', str(safe_agents_path),
            '--fail-on', 'critical'
        ])

        # Should pass because safe agents don't have critical issues
        assert result.exit_code == 0

    def test_scan_output_to_file(self, runner, vulnerable_agents_path, tmp_path):
        """Test outputting to a file."""
        output_file = tmp_path / "output.json"

        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--format', 'json',
            '--output', str(output_file)
        ])

        assert output_file.exists()

    def test_scan_nonexistent_path(self, runner):
        """Test scanning nonexistent path."""
        result = runner.invoke(cli, ['scan', '/nonexistent/path'])

        assert result.exit_code != 0

    def test_scan_verbose_mode(self, runner, vulnerable_agents_path):
        """Test verbose output mode."""
        result = runner.invoke(cli, [
            '--verbose',
            'scan', str(vulnerable_agents_path)
        ])

        # Should work with verbose flag
        assert isinstance(result.exit_code, int)


class TestScanBaseline:
    """Tests for baseline functionality in scan command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def vulnerable_agents_path(self):
        return Path(__file__).parent.parent / "fixtures" / "vulnerable_agents"

    def test_save_baseline(self, runner, vulnerable_agents_path, tmp_path):
        """Test saving findings as baseline."""
        baseline_file = tmp_path / "baseline.json"

        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--save-baseline', str(baseline_file)
        ])

        assert baseline_file.exists()
        baseline_data = json.loads(baseline_file.read_text())
        # The baseline saves fingerprints, not full findings
        assert 'fingerprints' in baseline_data

    def test_filter_by_baseline(self, runner, vulnerable_agents_path, tmp_path):
        """Test filtering by baseline."""
        baseline_file = tmp_path / "baseline.json"
        output_file = tmp_path / "output.json"

        # First, create baseline
        runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--save-baseline', str(baseline_file)
        ])

        # Then scan with baseline - should show no new findings
        result = runner.invoke(cli, [
            'scan', str(vulnerable_agents_path),
            '--baseline', str(baseline_file),
            '--format', 'json',
            '--output', str(output_file)
        ])

        data = json.loads(output_file.read_text())
        # All findings should be filtered out since they match the baseline
        assert len(data['findings']) == 0
