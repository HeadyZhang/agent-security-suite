"""CLI main entry point for agent-audit."""

import click
from rich.console import Console

from agent_audit.version import __version__

console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Only show errors')
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool):
    """Agent Audit - Security scanner for AI agents and MCP configurations."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet


# Register commands
from agent_audit.cli.commands.inspect import inspect
from agent_audit.cli.commands.scan import scan
from agent_audit.cli.commands.init import init

cli.add_command(inspect)
cli.add_command(scan)
cli.add_command(init)


if __name__ == '__main__':
    cli()
