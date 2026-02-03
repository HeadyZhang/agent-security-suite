# Contributing to Agent Audit

Thank you for your interest in contributing to Agent Audit! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.9 or higher
- [Poetry](https://python-poetry.org/) for dependency management

### Getting Started

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR-USERNAME/agent-security-suite.git
cd agent-security-suite
```

2. **Install dependencies**

```bash
# Install core package
cd packages/core
poetry install

# Install audit package (includes core as dependency)
cd ../audit
poetry install
```

3. **Verify installation**

```bash
poetry run agent-audit --version
poetry run agent-audit scan .
```

## Project Structure

```
agent-security-suite/
├── packages/
│   ├── core/           # Core scanning engine
│   │   ├── agent_core/
│   │   │   ├── scanners/    # AST, MCP, Secret scanners
│   │   │   ├── models/      # Data models (Finding, Severity, etc.)
│   │   │   └── rules/       # Detection rules
│   │   └── pyproject.toml
│   │
│   └── audit/          # CLI and output formatters
│       ├── agent_audit/
│       │   ├── cli/         # Click CLI commands
│       │   └── formatters/  # Output formatters (JSON, SARIF, etc.)
│       └── pyproject.toml
│
├── tests/              # Integration tests
├── rules/              # Rule definitions (YAML)
├── specs/              # Test specifications
├── action.yml          # GitHub Action definition
└── .github/workflows/  # CI/CD workflows
```

## Running Tests

```bash
cd packages/audit

# Run all tests
poetry run pytest tests/ -v

# Run with coverage
poetry run pytest tests/ -v --cov=agent_core --cov=agent_audit --cov-report=html

# Run specific test file
poetry run pytest tests/test_scanners.py -v

# Run tests matching a pattern
poetry run pytest tests/ -k "test_secret" -v
```

## Code Style

We use the following tools for code quality:

- **Ruff** for linting
- **Black** for code formatting
- **MyPy** for type checking

```bash
# Format code
poetry run black .

# Lint code
poetry run ruff check .

# Type check
poetry run mypy . --ignore-missing-imports
```

## Making Changes

### Adding a New Scanner

1. Create a new scanner in `packages/core/agent_core/scanners/`
2. Implement the `Scanner` interface
3. Register the scanner in the scan orchestrator
4. Add tests in `tests/`

### Adding a New Rule

1. Define the rule in `rules/` (YAML format)
2. Implement detection logic in the appropriate scanner
3. Add test cases in `specs/`

### Adding a New Output Format

1. Create a formatter in `packages/audit/agent_audit/formatters/`
2. Register it in the CLI
3. Add tests

## Pull Request Process

1. **Create a feature branch**

```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**
   - Write clear, concise commit messages
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and linting**

```bash
poetry run pytest tests/ -v
poetry run ruff check .
poetry run mypy .
```

4. **Push and create PR**

```bash
git push origin feature/your-feature-name
```

5. **PR Requirements**
   - All tests pass
   - Code is formatted and linted
   - Documentation is updated
   - Commits are clean and descriptive

## Commit Message Format

We follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add SQL injection detection
fix(cli): handle empty directory gracefully
docs: update installation instructions
test: add coverage for MCP scanner
```

## Reporting Issues

When reporting issues, please include:

1. Agent Audit version (`agent-audit --version`)
2. Python version (`python --version`)
3. Operating system
4. Steps to reproduce
5. Expected vs actual behavior
6. Relevant logs or error messages

## Security Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead, email us at security@example.com with details.

## Questions?

- Open a [GitHub Discussion](https://github.com/HeadyZhang/agent-audit/discussions)
- Check existing [Issues](https://github.com/HeadyZhang/agent-audit/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
