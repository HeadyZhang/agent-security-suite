"""Entry point for running agent-audit as a module."""

import sys

# Windows event loop policy fix - must be set before any asyncio imports
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from agent_audit.cli.main import cli

if __name__ == "__main__":
    cli()
