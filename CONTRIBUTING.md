# Contributing to Agent Audit

Thank you for your interest in contributing to Agent Audit! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Development Setup

### Prerequisites

- Python 3.9, 3.10, 3.11, or 3.12
- [Poetry](https://python-poetry.org/) 1.8.x for dependency management
- Git

### Getting Started

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR-USERNAME/agent-audit.git
cd agent-audit
```

2. **Install dependencies**

```bash
cd packages/audit
poetry install
```

3. **Verify installation**

```bash
poetry run agent-audit --version
poetry run agent-audit scan .
```

4. **Run local package (development mode)**

When developing, ensure you're using the local package:

```bash
cd packages/audit

# Option A: Install in editable mode (recommended)
pip install -e .

# Option B: Use Poetry shell
poetry shell
agent-audit scan /path/to/target

# Option C: Use PYTHONPATH
PYTHONPATH="$(pwd):$PYTHONPATH" python -m agent_audit scan /path/to/target
```

> **Important:** Without this, `agent-audit scan` may use a globally installed version instead of your local changes.

### Project Structure

```
agent-security-suite/
├── packages/audit/           # Main package source
│   └── agent_audit/
│       ├── cli/              # Click CLI commands & formatters
│       ├── config/           # Configuration handling
│       ├── models/           # Data models (Finding, Severity, etc.)
│       ├── rules/            # Rule engine & loader
│       ├── scanners/         # AST, MCP, Secret scanners
│       ├── analysis/         # Semantic analysis, taint tracking
│       └── utils/            # Utilities
│
├── rules/builtin/            # Rule definitions (YAML)
├── tests/                    # ALL tests (at project root!)
│   ├── fixtures/             # Test code samples
│   ├── benchmark/            # Benchmark test suite
│   ├── test_scanners/        # Scanner unit tests
│   ├── test_cli/             # CLI tests
│   └── ...
├── docs/                     # Documentation
├── action.yml                # GitHub Action definition
└── .github/workflows/        # CI/CD workflows
```

---

## Running Tests

**Important:** Tests are located at the **project root** (`tests/`), not inside `packages/audit/`.

### Quick Start

```bash
cd packages/audit

# Run all tests
poetry run pytest ../../tests/ -v

# Run with coverage report
poetry run pytest ../../tests/ -v --cov=agent_audit --cov-report=term-missing

# Generate HTML coverage report
poetry run pytest ../../tests/ -v --cov=agent_audit --cov-report=html
# Open htmlcov/index.html in browser
```

### Running Specific Tests

```bash
# Run a specific test file
poetry run pytest ../../tests/test_scanners/test_python_scanner.py -v

# Run tests matching a pattern
poetry run pytest ../../tests/ -k "test_secret" -v

# Run tests for a specific rule
poetry run pytest ../../tests/ -k "AGENT_004" -v

# Run only fast tests (skip slow integration tests)
poetry run pytest ../../tests/ -m "not slow" -v
```

### Running Benchmark Tests

```bash
# Run the full benchmark suite
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_harness.py

# Check benchmark status
cat ../../tests/benchmark/BENCHMARK_STATUS.md
```

### Test Categories

| Directory | Description | When to Run |
|-----------|-------------|-------------|
| `tests/test_scanners/` | Scanner unit tests | Always |
| `tests/test_cli/` | CLI command tests | When modifying CLI |
| `tests/test_analysis/` | Semantic analysis tests | When modifying analysis |
| `tests/test_formatters/` | Output formatter tests | When modifying output |
| `tests/benchmark/` | Benchmark integration tests | Before releases |

### Debugging Test Failures

```bash
# Run with verbose output
poetry run pytest ../../tests/test_file.py -v -s

# Run with debugger on failure
poetry run pytest ../../tests/test_file.py --pdb

# Show local variables on failure
poetry run pytest ../../tests/test_file.py -l

# Run last failed tests only
poetry run pytest ../../tests/ --lf
```

---

## Code Style

We use the following tools for code quality:

| Tool | Purpose | Config |
|------|---------|--------|
| **Ruff** | Linting | `pyproject.toml` |
| **Black** | Code formatting | Line length 100 |
| **MyPy** | Type checking | Strict mode |

### Running Code Quality Checks

```bash
cd packages/audit

# Format code
poetry run black .

# Lint code
poetry run ruff check .

# Auto-fix lint issues
poetry run ruff check . --fix

# Type check
poetry run mypy agent_audit/

# Run all checks (as CI does)
poetry run black --check . && poetry run ruff check . && poetry run mypy agent_audit/
```

### Code Standards

- **Type hints**: Required on all functions
- **Docstrings**: Google-style on public methods
- **Imports**: Use `from __future__ import annotations` for forward references
- **Logging**: Use `logging` module, never `print()`
- **Data classes**: Use `@dataclass` for models, not Pydantic in core

---

## Making Changes

### Adding a New Rule

1. **Define the rule in YAML** (`rules/builtin/`)

```yaml
- id: AGENT-XXX
  title: "Your Rule Title"
  description: "What this rule detects"
  severity: high  # critical, high, medium, low, info
  category: your_category
  owasp_agentic_id: "ASI-XX"
  cwe_id: "CWE-XXX"
  detection:
    type: ast
    patterns:
      - pattern_type: "your_pattern"
  remediation:
    description: "How to fix"
    code_example: |
      # Fixed code
```

2. **Implement detection logic** in the appropriate scanner

3. **Add test fixture** in `tests/fixtures/`

4. **Add test case** in `tests/test_scanners/`

```python
def test_agent_xxx_detection():
    """Test AGENT-XXX: Your Rule Title"""
    results = scanner.scan_file("tests/fixtures/your_fixture.py")
    assert any(r.rule_id == "AGENT-XXX" for r in results)
```

5. **Update RULES.md** with the new rule documentation

### Adding a New Scanner

1. Create scanner in `packages/audit/agent_audit/scanners/`
2. Implement the `Scanner` interface from `base.py`
3. Return `Sequence[ScanResult]` (not `List` - invariance issue)
4. Register in scan command
5. Add comprehensive tests

### Adding a New Output Format

1. Create formatter in `packages/audit/agent_audit/cli/formatters/`
2. Register in CLI options
3. Add tests for the new format

---

## Pull Request Process

### Before You Start

1. **Check existing issues** - Someone may already be working on it
2. **Open an issue first** for significant changes to discuss the approach
3. **Sync with main** to avoid merge conflicts

### Step-by-Step PR Workflow

#### 1. Create a feature branch

```bash
git checkout main
git pull origin main
git checkout -b feat/your-feature-name
```

Branch naming conventions:
- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation
- `refactor/` - Code refactoring
- `test/` - Test additions

#### 2. Make your changes

- Write clear, atomic commits
- Add tests for new functionality
- Update documentation as needed

#### 3. Run the full test suite

```bash
cd packages/audit

# Run all tests
poetry run pytest ../../tests/ -v

# Run linting
poetry run ruff check .

# Run type checking
poetry run mypy agent_audit/

# Run formatting check
poetry run black --check .
```

**All checks must pass before submitting PR.**

#### 4. Commit with conventional format

```bash
git add .
git commit -m "feat(scanner): add SQL injection detection for AGENT-041"
```

#### 5. Push and create PR

```bash
git push origin feat/your-feature-name
```

Then open a PR on GitHub with:
- Clear title following conventional commits
- Description of what changed and why
- Link to related issue (if any)
- Screenshots/examples for UI changes

### PR Requirements Checklist

- [ ] All tests pass (`poetry run pytest ../../tests/ -v`)
- [ ] Code is formatted (`poetry run black --check .`)
- [ ] Linting passes (`poetry run ruff check .`)
- [ ] Type checking passes (`poetry run mypy agent_audit/`)
- [ ] New features have tests
- [ ] Documentation updated (if applicable)
- [ ] Commits follow conventional format
- [ ] PR description explains the change

### After PR is Submitted

1. CI will automatically run tests
2. Maintainers will review within a few days
3. Address any feedback with new commits
4. Once approved, maintainer will merge

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code refactoring (no behavior change) |
| `perf` | Performance improvement |
| `chore` | Maintenance tasks |
| `ci` | CI/CD changes |

### Examples

```
feat(scanner): add SQL injection detection for AGENT-041

fix(cli): handle empty directory gracefully
Fixes #123

docs(rules): add remediation examples for AGENT-034

test(benchmark): add WILD-005 test case for memory poisoning

refactor(analysis): extract taint tracking to separate module
```

---

## Reporting Issues

We have specific templates for different issue types:

### Bug Reports

Use the **Bug Report** template for:
- Crashes or errors
- Unexpected behavior
- Installation problems

Include:
- Agent Audit version (`agent-audit --version`)
- Python version (`python --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### False Positive / False Negative Reports

Use the **FP/FN Report** template for:
- Rule triggered on safe code (False Positive)
- Rule missed actual vulnerability (False Negative)

Include:
- Rule ID (e.g., AGENT-034)
- Minimal code sample reproducing the issue
- Why you believe it's a FP/FN
- Your confidence level

### Feature Requests

Use the **Feature Request** template for:
- New rules
- New scanners
- CLI improvements
- Output format additions

---

## Security Vulnerabilities

If you discover a security vulnerability in Agent Audit itself:

1. **Do NOT open a public issue**
2. Email security details to: `security@agent-audit.dev`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
4. We will respond within 48 hours

---

## Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/HeadyZhang/agent-audit/discussions)
- **Bugs**: Open an [Issue](https://github.com/HeadyZhang/agent-audit/issues) with the Bug Report template
- **Feature ideas**: Open an [Issue](https://github.com/HeadyZhang/agent-audit/issues) with the Feature Request template

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Agent Audit!
