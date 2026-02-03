# Agent Audit

Security scanner for AI agents and MCP configurations. Detects vulnerabilities based on the OWASP Agentic Top 10.

## Features

- **Python AST Scanning**: Detects dangerous patterns like `shell=True`, `eval()`, and tainted input flows
- **MCP Configuration Scanning**: Validates MCP server configurations for security issues
- **Secret Detection**: Finds hardcoded credentials (AWS keys, API tokens, private keys)
- **Runtime MCP Inspection**: Probes MCP servers without executing tools ("Agent Nmap")
- **Multiple Output Formats**: Terminal, JSON, SARIF (for GitHub Code Scanning), Markdown

## Installation

```bash
pip install agent-audit
```

## Quick Start

```bash
# Scan current directory
agent-audit scan .

# Scan with JSON output
agent-audit scan ./my-agent --format json

# Scan with SARIF output for GitHub
agent-audit scan . --format sarif --output results.sarif

# Fail CI on critical findings only
agent-audit scan . --fail-on critical

# Inspect an MCP server
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## GitHub Action

Add agent-audit to your CI/CD pipeline:

```yaml
- name: Run Agent Audit
  uses: HeadyZhang/agent-security-suite@v1
  with:
    path: './src'
    fail-on: 'high'
    upload-sarif: 'true'
```

## Detected Issues

| Rule ID | Title | Severity |
|---------|-------|----------|
| AGENT-001 | Command Injection via Unsanitized Input | Critical |
| AGENT-002 | Excessive Agent Permissions | Medium |
| AGENT-003 | Potential Data Exfiltration Chain | High |
| AGENT-004 | Hardcoded Credentials | Critical |
| AGENT-005 | Unverified MCP Server | High |

## Configuration

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

## Baseline Scanning

Track new findings incrementally:

```bash
# Save current findings as baseline
agent-audit scan . --save-baseline baseline.json

# Only report new findings
agent-audit scan . --baseline baseline.json
```

## CLI Reference

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

## Development

```bash
# Clone the repository
git clone https://github.com/HeadyZhang/agent-security-suite
cd agent-audit

# Install dependencies
cd packages/core && poetry install
cd ../audit && poetry install

# Run tests
poetry run pytest tests/ -v

# Run the scanner
poetry run agent-audit scan .
```

## License

MIT
