# Agent Audit

[![PyPI version](https://badge.fury.io/py/agent-audit.svg)](https://badge.fury.io/py/agent-audit)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/HeadyZhang/agent-audit/branch/master/graph/badge.svg)](https://codecov.io/gh/HeadyZhang/agent-audit)

> 🛡️ Security scanner for AI agents and MCP configurations. Detects vulnerabilities based on the **OWASP Agentic Top 10**.

<p align="center">
  <img src="docs/demo.gif" alt="Agent Audit Demo" width="800">
</p>

## ✨ Features

- **🔍 Python AST Scanning** - Detects dangerous patterns like `shell=True`, `eval()`, and tainted input flows
- **⚙️ MCP Configuration Scanning** - Validates MCP server configurations for security issues
- **🔐 Secret Detection** - Finds hardcoded credentials (AWS keys, API tokens, private keys)
- **🌐 Runtime MCP Inspection** - Probes MCP servers without executing tools ("Agent Nmap")
- **📊 Multiple Output Formats** - Terminal, JSON, SARIF (for GitHub Code Scanning), Markdown

## 🚀 Quick Start

### Installation

```bash
pip install agent-audit
```

### Basic Usage

```bash
# Scan current directory
agent-audit scan .

# Scan with JSON output
agent-audit scan ./my-agent --format json

# Scan with SARIF output for GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif

# Fail CI on critical findings only
agent-audit scan . --fail-on critical

# Inspect an MCP server at runtime
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## 🔗 GitHub Action

Add Agent Audit to your CI/CD pipeline with just a few lines:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  agent-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Agent Audit
        uses: HeadyZhang/agent-audit@v1
        with:
          path: '.'
          fail-on: 'high'
          upload-sarif: 'true'
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format: `terminal`, `json`, `sarif`, `markdown` | `sarif` |
| `severity` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` | `low` |
| `fail-on` | Exit with error if findings at this severity | `high` |
| `baseline` | Path to baseline file for incremental scanning | - |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |

## 🎯 Detected Issues

| Rule ID | Title | Severity |
|---------|-------|----------|
| AGENT-001 | Command Injection via Unsanitized Input | 🔴 Critical |
| AGENT-002 | Excessive Agent Permissions | 🟡 Medium |
| AGENT-003 | Potential Data Exfiltration Chain | 🟠 High |
| AGENT-004 | Hardcoded Credentials | 🔴 Critical |
| AGENT-005 | Unverified MCP Server | 🟠 High |

## ⚙️ Configuration

Create a `.agent-audit.yaml` file to customize scanning:

```yaml
# Allowed network hosts (reduces AGENT-003 confidence)
allowed_hosts:
  - "*.internal.company.com"
  - "api.openai.com"

# Ignore rules
ignore:
  - rule_id: AGENT-003
    paths:
      - "auth/**"
    reason: "Auth module legitimately communicates externally"

# Scan settings
scan:
  exclude:
    - "tests/**"
    - "venv/**"
  min_severity: low
  fail_on: high
```

## 📈 Baseline Scanning

Track new findings incrementally:

```bash
# Save current findings as baseline
agent-audit scan . --save-baseline baseline.json

# Only report new findings
agent-audit scan . --baseline baseline.json
```

## 📖 CLI Reference

```
Usage: agent-audit [OPTIONS] COMMAND [ARGS]...

Commands:
  scan     Scan agent code and configurations
  inspect  Inspect an MCP server at runtime
  init     Initialize configuration file

Options:
  --version   Show version
  -v          Enable verbose output
  -q          Only show errors
  --help      Show this message
```

## 🛠️ Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
# Clone the repository
git clone https://github.com/HeadyZhang/agent-audit
cd agent-security-suite

# Install dependencies
cd packages/core && poetry install
cd ../audit && poetry install

# Run tests
poetry run pytest tests/ -v

# Run the scanner
poetry run agent-audit scan .
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Based on the [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-security/)
- Inspired by the need for better AI agent security tooling

---

<p align="center">
  Made with ❤️ for the AI agent security community
</p>
