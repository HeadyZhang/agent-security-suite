"""Tests for the init CLI command."""

import pytest
import tempfile
from pathlib import Path
from click.testing import CliRunner

from agent_audit.cli.commands.init import init


class TestInitCommand:
    """Tests for the init CLI command."""

    def test_init_help(self):
        """Init command should show help."""
        runner = CliRunner()
        result = runner.invoke(init, ["--help"])

        assert result.exit_code == 0
        assert "Initialize agent-audit configuration" in result.output

    def test_init_creates_config_file(self):
        """Init command should create configuration file."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            result = runner.invoke(init)

            assert result.exit_code == 0
            assert Path(".agent-audit.yaml").exists()
            assert "Created configuration file" in result.output

    def test_init_config_contains_defaults(self):
        """Created config should contain default settings."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            runner.invoke(init)

            config_content = Path(".agent-audit.yaml").read_text(encoding="utf-8")
            assert "allowed_hosts" in config_content
            assert "ignore" in config_content

    def test_init_does_not_overwrite_existing(self):
        """Init should not overwrite existing config without --force."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create existing config
            Path(".agent-audit.yaml").write_text("existing: true", encoding="utf-8")

            result = runner.invoke(init)

            assert result.exit_code == 1
            assert "already exists" in result.output

            # Original content should be preserved
            content = Path(".agent-audit.yaml").read_text(encoding="utf-8")
            assert "existing: true" in content

    def test_init_force_overwrites(self):
        """Init --force should overwrite existing config."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create existing config
            Path(".agent-audit.yaml").write_text("existing: true", encoding="utf-8")

            result = runner.invoke(init, ["--force"])

            assert result.exit_code == 0
            assert "Created configuration file" in result.output

            # Content should be replaced
            content = Path(".agent-audit.yaml").read_text(encoding="utf-8")
            assert "existing: true" not in content
            assert "allowed_hosts" in content

    def test_init_output_has_guidance(self):
        """Init output should include guidance for editing config."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            result = runner.invoke(init)

            assert "Edit this file to:" in result.output
            assert "allowed hosts" in result.output.lower()
