# Agent Audit

## Identity

CLI static analysis tool for AI agent security — "ESLint for AI agents".
Detects vulnerabilities mapped to the OWASP Agentic Top 10 (2026).
Source in `packages/audit/`. Tests at project root `tests/`. Rules in `rules/builtin/`.

## Current Mission

Expand from 5 rules (AGENT-001~005) to full OWASP Agentic Top 10 coverage (ASI-01~ASI-10).
**Read `owasp-execution-plan.md` in the repo root for the step-by-step implementation plan.**
Follow its staged approach (阶段 1→10) sequentially. Do not skip ahead.

## Architecture Constraints (Do Not Violate)

- **AST only** → Use Python `ast` module for all code analysis. NEVER introduce Semgrep (40MB, license risk).
- **Single package** → All source in `packages/audit/agent_audit/`. No separate `packages/core/`.
- **Cross-platform** → `pathlib` everywhere. No hardcoded `/` separators. No Unix-only APIs.
- **Python 3.9+** → Use `from __future__ import annotations` or `Optional[X]` syntax, not `X | None`.
- **Zero heavy deps** → Core scanning depends only on stdlib (`ast`, `json`, `re`, `pathlib`) + `click` + `rich` + `pyyaml`.
- **YAML rules are declarative** → Detection logic lives in Python scanners, not in YAML. YAML defines metadata + pattern hints; scanners implement the actual detection.

## Code Standards

- Type hints on all functions. `Sequence[ScanResult]` for scanner base return type (not `List` — invariance issue).
- Google-style docstrings on public methods.
- `logging` module only, never `print`.
- `dataclass` for models. No Pydantic in core (optional for config validation).
- Black line-length=100. Ruff for linting. mypy must pass.
- Every new rule needs: YAML definition + scanner detection logic + test fixture + test case.

## Rule ID Scheme

| Range | Category | Status |
|-------|----------|--------|
| AGENT-001~005 | v0.1.0 original rules | ✅ Existing |
| AGENT-010~011 | ASI-01 Goal Hijack | 🔨 New |
| AGENT-013~014 | ASI-03 Identity/Privilege | 🔨 New |
| AGENT-015~016 | ASI-04 Supply Chain | 🔨 New |
| AGENT-017 | ASI-05 Code Execution | 🔨 New |
| AGENT-018~019 | ASI-06 Memory Poisoning | 🔨 New |
| AGENT-020 | ASI-07 Inter-Agent Comm | 🔨 New |
| AGENT-021~022 | ASI-08 Cascading Failures | 🔨 New |
| AGENT-023 | ASI-09 Trust Exploitation | 🔨 New |
| AGENT-024~025 | ASI-10 Rogue Agents | 🔨 New |

New rules go in `rules/builtin/owasp_agentic_v2.yaml`. Do NOT modify existing YAML files.

## Known Pitfalls (Hard-Won — Read Before Coding)

### Type System (mypy)

- Scanner base return type → `Sequence[ScanResult]` not `List[ScanResult]` → List is invariant, subclasses break.
- Loop variables → Use DIFFERENT names per loop (`for py_result in ...` / `for mcp_result in ...`) → Same name across loops causes mypy type conflict.
- Dict with List value → Extract to typed variable first, then append → `result["items"].append(x)` fails mypy because inferred as `object`.
- Class-level dicts → Must have explicit annotation `PATTERNS: Dict[str, Dict[str, Any]] = {...}` → Otherwise mypy infers `object`.

### CI/CD

- Tests live at project root → `poetry run pytest ../../tests/` from `packages/audit/`, or `pytest tests/` from root.
- Never use `continue-on-error: true` in CI → Masks real failures as green.
- mypy needs `types-PyYAML` installed → Add to CI lint job deps.
- Pin Poetry to `1.8.5` → Poetry 2.x drops Python 3.9 support.

### AST Scanner Patterns

- `_get_call_name()` can return None → Always guard: `if func_name:` before using.
- f-string detection → `ast.JoinedStr` node type. Check both positional args and keyword args.
- `@tool` decorator can be `@tool`, `@tool()`, or `@langchain.tools.tool` → Match with `any(t in dec_name for t in TOOL_DECORATORS)`.
- Fixture `.py` files are parsed by AST → Do NOT add real `import langchain` at top (CI has no langchain). Use function-local or string-based patterns.

### Config Scanner

- MCP config `args` field → Can be `str` or `list` → Normalize: `args if isinstance(args, list) else shlex.split(args)`.
- `mcpServers` key (Claude Desktop) vs `servers` key (Docker MCP Gateway) → Check both.

### YAML Rule Loading

- `owasp_agentic_id` field may be None → All downstream code must guard with `if rule.owasp_agentic_id:`.
- Support both single-rule dict and multi-rule list formats in YAML.
- Custom rules via `--rules-dir` merge with (not replace) built-in rules.

### SARIF Output

- SARIF `ruleId` must exactly match `Finding.rule_id` → No prefix/suffix transformation.
- Add `properties.tags` array with `OWASP-Agentic-{ASI-XX}` for each rule that has an owasp_agentic_id.

### README / Release

- Python version badge → Use static shields.io badge, not dynamic PyPI lookup (often fails).
- `@v1` tag in GitHub Action usage example → Must exist as a git tag pointing to latest release.

## Project Layout

```
agent-security-suite/
├── packages/audit/
│   └── agent_audit/
│       ├── cli/commands/       # scan.py, inspect_cmd.py, init.py
│       ├── cli/formatters/     # terminal.py, json.py, sarif.py, markdown.py
│       ├── scanners/           # python_scanner.py, mcp_scanner.py, config_scanner.py, secret_scanner.py
│       ├── rules/              # engine.py, loader.py
│       ├── models/             # finding.py (Category enum, Finding dataclass), tool.py
│       └── config/             # ignore.py (IgnoreManager)
├── rules/builtin/             # YAML rule definitions
├── tests/                     # pytest suite (run from root!)
│   ├── fixtures/vulnerable_agents/
│   └── fixtures/mcp_configs/
├── owasp-execution-plan.md    # Step-by-step implementation plan ← FOLLOW THIS
└── .github/workflows/ci.yml
```

## Verification Commands

```bash
# From project root:
cd packages/audit && poetry install

# Unit tests (MUST pass before any commit)
poetry run pytest ../../tests/ -v --cov=agent_audit --cov-report=term-missing

# Type checking
poetry run mypy agent_audit/

# Linting
poetry run ruff check .

# Smoke test — scan vulnerable fixtures
poetry run agent-audit scan ../../tests/fixtures/vulnerable_agents/

# SARIF output test
poetry run agent-audit scan ../../tests/fixtures/vulnerable_agents/ --format sarif -o /tmp/test.sarif

# Custom rules test (after implementing --rules-dir)
poetry run agent-audit scan . --rules-dir /path/to/custom/rules/

# Full OWASP coverage validation (after all rules implemented)
poetry run pytest ../../tests/test_owasp_agentic.py -v
```

## Commit Convention

```
feat: description     # New rules, new detection logic
fix: description      # Bug fixes
test: description     # Test additions
docs: description     # README, CHANGELOG
refactor: description # Internal restructure, no behavior change
```

Branch: `feat/owasp-full-coverage` → PR to `master` when all 10 ASI categories pass tests.
