"""Init command for creating configuration files."""

import sys
from pathlib import Path

import click
from rich.console import Console

from agent_audit.config.ignore import create_default_config

console = Console()


@click.command()
@click.option('--force', '-f', is_flag=True, help='Overwrite existing config')
def init(force: bool):
    """
    Initialize agent-audit configuration.

    Creates a .agent-audit.yaml file in the current directory with
    default settings and example ignore rules.

    Examples:

        agent-audit init

        agent-audit init --force
    """
    config_path = Path('.agent-audit.yaml')

    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration file already exists: {config_path}[/yellow]")
        console.print("Use --force to overwrite")
        sys.exit(1)

    config_content = create_default_config()
    config_path.write_text(config_content, encoding="utf-8")

    console.print(f"[green]Created configuration file: {config_path}[/green]")
    console.print()
    console.print("Edit this file to:")
    console.print("  - Add allowed hosts for network destinations")
    console.print("  - Configure ignore rules for false positives")
    console.print("  - Set scan exclusion patterns")
