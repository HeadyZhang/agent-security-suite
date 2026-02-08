"""Inspect command for probing MCP servers."""

import asyncio
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from agent_audit.scanners.mcp_inspector import MCPInspector, MCPInspectionResult
from agent_audit.utils.mcp_client import TransportType

console = Console()


def render_inspection_result(result: MCPInspectionResult, output_format: str = "terminal"):
    """Render inspection result to the console."""
    if output_format == "json":
        _render_json(result)
    else:
        _render_terminal(result)


def _render_terminal(result: MCPInspectionResult):
    """Render result as Rich terminal output."""
    # Status indicator
    if result.connected:
        status = "[green]✓ Connected[/green]"
        border_style = "blue" if result.risk_score < 5 else "red"
    else:
        status = "[red]✗ Failed[/red]"
        border_style = "red"

    # Header panel
    header_text = (
        f"[bold]MCP Server Inspection[/bold]\n"
        f"Server: {result.server_name}"
    )
    if result.server_version:
        header_text += f" v{result.server_version}"
    header_text += "\n"
    header_text += f"Status: {status}  |  Response: {result.response_time_ms:.0f}ms\n"
    header_text += f"Risk Score: {result.risk_score:.1f}/10"

    console.print(Panel.fit(header_text, border_style=border_style))

    if not result.connected:
        console.print(f"[red]Error: {result.connection_error}[/red]")
        return

    # Capabilities
    if result.capabilities_declared:
        caps = ", ".join(result.capabilities_declared) or "none"
        console.print(f"\n[dim]Capabilities:[/dim] {caps}")

    # Tools table
    console.print(f"\n[bold]Tools ({result.tool_count})[/bold]")

    if result.tools:
        tool_table = Table(show_header=True, header_style="bold cyan")
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Permissions", style="yellow")
        tool_table.add_column("Risk", justify="center")
        tool_table.add_column("Validation")

        risk_emoji = {
            1: "🟢",  # SAFE
            2: "🟢",  # LOW
            3: "🟡",  # MEDIUM
            4: "🟠",  # HIGH
            5: "🔴",  # CRITICAL
        }

        for tool in result.tools:
            perms = ", ".join(p.name for p in tool.permissions) or "none"
            risk_value = tool.risk_level.value if hasattr(tool.risk_level, 'value') else 1
            risk = risk_emoji.get(risk_value, "⚪")
            validation = "✅" if tool.has_input_validation else "❌"

            # Truncate description if needed
            tool_name = tool.name
            if len(tool_name) > 30:
                tool_name = tool_name[:27] + "..."

            tool_table.add_row(tool_name, perms, risk, validation)

        console.print(tool_table)
    else:
        console.print("[dim]No tools exposed[/dim]")

    # Resources
    if result.resources:
        console.print(f"\n[bold]Resources ({result.resource_count})[/bold]")
        for res in result.resources[:10]:  # Limit display
            uri = res.get('uri', 'unknown')
            console.print(f"  📄 {uri}")
        if result.resource_count > 10:
            console.print(f"  [dim]... and {result.resource_count - 10} more[/dim]")

    # Prompts
    if result.prompts:
        console.print(f"\n[bold]Prompts ({result.prompt_count})[/bold]")
        for prompt in result.prompts[:10]:
            name = prompt.get('name', 'unknown')
            console.print(f"  💬 {name}")
        if result.prompt_count > 10:
            console.print(f"  [dim]... and {result.prompt_count - 10} more[/dim]")

    # Security findings
    if result.findings:
        console.print(f"\n[bold red]Security Findings ({len(result.findings)})[/bold red]")

        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue"
        }

        for finding in result.findings:
            severity = finding.get("severity", "medium")
            color = severity_colors.get(severity, "white")
            desc = finding.get("description", "Unknown issue")
            tool_name = finding.get("tool", "")

            if tool_name:
                console.print(f"  [{color}]⚠ {severity.upper()}[/{color}]: {desc} (tool: {tool_name})")
            else:
                console.print(f"  [{color}]⚠ {severity.upper()}[/{color}]: {desc}")


def _render_json(result: MCPInspectionResult):
    """Render result as JSON."""
    import json

    output = {
        "server_name": result.server_name,
        "server_version": result.server_version,
        "transport": result.transport.value,
        "connected": result.connected,
        "connection_error": result.connection_error,
        "response_time_ms": result.response_time_ms,
        "risk_score": result.risk_score,
        "capabilities": result.capabilities_declared,
        "tool_count": result.tool_count,
        "tools": [t.to_dict() for t in result.tools],
        "resource_count": result.resource_count,
        "resources": result.resources,
        "prompt_count": result.prompt_count,
        "prompts": result.prompts,
        "findings": result.findings,
    }

    console.print_json(json.dumps(output, indent=2))


async def run_inspect_async(
    target: str,
    transport: Optional[str],
    timeout: int,
    output_format: str
) -> int:
    """Run the inspection asynchronously."""
    inspector = MCPInspector(timeout=timeout)

    # Determine transport type
    transport_type: Optional[TransportType] = None
    if transport:
        transport_type = TransportType(transport)

    result = await inspector.inspect(target, transport_type)
    render_inspection_result(result, output_format)

    # Return exit code based on risk
    if not result.connected:
        return 2  # Connection failure
    elif result.risk_score >= 7.0:
        return 1  # High risk
    return 0


def run_inspect(
    target: str,
    transport: Optional[str],
    timeout: int,
    output_format: str
) -> int:
    """Run the inspection."""
    return asyncio.run(run_inspect_async(target, transport, timeout, output_format))


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.argument('transport_type', type=click.Choice(['stdio', 'sse']), required=True)
@click.argument('target', nargs=-1, type=click.UNPROCESSED, required=True)
@click.option('--timeout', '-t', default=30, help='Connection timeout in seconds')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['terminal', 'json']), default='terminal',
              help='Output format')
def inspect(transport_type: str, target: tuple, timeout: int, output_format: str):
    """
    Inspect a running MCP server and analyze its tools.

    TRANSPORT_TYPE is either 'stdio' or 'sse'.

    For stdio, TARGET is the command to run the server:

        agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp

    For sse, TARGET is the URL:

        agent-audit inspect sse https://example.com/sse

    The inspector connects to the server, retrieves its tool definitions,
    and analyzes them for security risks WITHOUT executing any tools.
    """
    # Join target parts back together
    target_str = ' '.join(target)

    # Handle the "--" separator for stdio
    if target_str.startswith('-- '):
        target_str = target_str[3:]

    if not target_str:
        console.print("[red]Error: No target specified[/red]")
        sys.exit(1)

    exit_code = run_inspect(
        target=target_str,
        transport=transport_type,
        timeout=timeout,
        output_format=output_format
    )

    sys.exit(exit_code)
