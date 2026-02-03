# Agent Security Suite

## What This Is

A Python monorepo containing two security products for AI agents:
- **agent-audit** — CLI static analysis tool ("ESLint for AI agents")
- **agent-firewall** — Runtime middleware (Phase 2, not built yet)

We are building **agent-audit first**. The firewall comes later.

## Tech Stack

- Python 3.11+, Poetry for packaging
- Click (CLI), Rich (terminal UI), Pydantic (models), PyYAML (config)
- Python `ast` module for code analysis (NOT Semgrep — see specs for rationale)
- pytest for testing, Black + Ruff for formatting, mypy for type checking

## Project Structure

```
agent-security-suite/
├── packages/
│   ├── core/          # Shared models, rules engine, utils
│   │   └── agent_core/
│   ├── audit/         # agent-audit CLI
│   │   └── agent_audit/
│   │       ├── cli/commands/      # scan, inspect, init, ignore
│   │       ├── scanners/          # python, mcp_config, mcp_inspector, config, secret
│   │       ├── analyzers/         # permission, chain, supply_chain
│   │       ├── rules/builtin/     # YAML rule files
│   │       ├── config/            # ignore.py (allowlist manager)
│   │       ├── models/            # finding, tool, risk
│   │       └── utils/             # ast_helpers, mcp_client
│   └── firewall/      # agent-firewall (Phase 2)
├── rules/builtin/     # YAML rule definitions
├── tests/
│   ├── test_scanners/
│   ├── test_analyzers/
│   ├── test_rules/
│   ├── test_layers/
│   └── fixtures/      # vulnerable_agents/, safe_agents/, mcp_configs/
└── docker/
```

## Architecture Specs (READ THESE)

Two spec documents contain ALL implementation details — data models, code, rules, tests:

1. **`specs/technical-spec.md`** — Complete architecture, code for every module, data models, rule definitions, directory structure, CLI implementation, GitHub Action, deployment
2. **`specs/delta-spec.md`** — Amendments: adds IgnoreManager, confidence scoring, baseline scanning, MCP Inspector with STDIO/SSE transport, removes `watch` command

**When delta-spec.md conflicts with technical-spec.md, delta-spec.md wins.**

## Cross-Platform (MANDATORY)

This tool MUST run correctly on Windows, macOS, and Linux. Every module must follow these rules:

- **Paths**: Always use `pathlib.Path`, never string concatenation with `/`. Never hardcode `/` or `\\` as separator.
- **Subprocesses**: Use `asyncio.create_subprocess_exec()` with list args, never `shell=True`. On Windows, STDIO pipes need `asyncio.WindowsProactorEventLoopPolicy` — detect and set it at entry point.
- **File I/O**: Use `encoding="utf-8"` explicitly on every `open()` call. Windows defaults to locale encoding.
- **Config locations**: Use `Path.home() / ".agent-audit.yaml"`, never `~/.agent-audit.yaml` string.
- **Temp files**: Use `tempfile` module, never hardcode `/tmp/`.
- **Line endings**: Read files with `newline=None` (universal newlines). Write with `newline="\n"` for consistency.
- **Sensitive paths in rules**: Detection patterns for paths like `/etc/passwd`, `~/.ssh` must also cover Windows equivalents (`C:\Windows\System32\config\SAM`, `%USERPROFILE%\.ssh`).
- **CI matrix**: GitHub Actions CI must test on `ubuntu-latest`, `macos-latest`, `windows-latest`.

## Coding Standards

- All public functions: type hints + docstring
- Use `@dataclass` or Pydantic `BaseModel` for all data structures
- Async code: `async/await` (especially MCP client, firewall)
- Custom exceptions, never swallow errors
- `logging` module, never `print`
- Each module gets a corresponding test file
- Line length: 100 (Black config)

## How To Verify

```bash
# Run tests
cd packages/audit && poetry run pytest --cov=agent_audit -v

# Type checking
poetry run mypy agent_audit/

# Lint
poetry run ruff check .

# Manual smoke test
poetry run agent-audit scan ../../tests/fixtures/vulnerable_agents/
poetry run agent-audit inspect stdio -- python ../../tests/fixtures/mock_mcp_server.py
```

## Build Order (DO NOT SKIP AHEAD)

Phase 1: `packages/core/` → Phase 2: `packages/audit/` → Phase 3: tests + fixtures → Phase 4: CLI integration

Within each phase, follow the step order in the execution prompt. Complete and verify each step before moving to the next.

## Key Decisions (Do Not Revisit)

- Use Python `ast`, NOT Semgrep (40MB dep, license risk, only covers 20% of our checks)
- No `watch` command in CLI (CLI ≠ proxy; realtime interception is firewall's job)
- YAML for rule definitions (not Python/Rego — needs to be editable by non-devs)
- agent-firewall is Phase 2. Do not build any firewall code during Phase 1.
- Cross-platform first: Windows/macOS/Linux. pathlib everywhere, no Unix assumptions.