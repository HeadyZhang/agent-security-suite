# Agent Audit

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)

> 🛡️ Security scanner for AI agents and MCP configurations. Detects vulnerabilities based on the **OWASP Agentic Top 10**.
>
> 🛡️ 基于 **OWASP Agentic Top 10** 的 AI Agent 和 MCP 配置安全扫描器

<!-- 
<p align="center">
  <img src="docs/demo.gif" alt="Agent Audit Demo" width="800">
</p>
-->

## ✨ Features | 功能特性

- **🔍 Python AST Scanning** - Detects dangerous patterns like `shell=True`, `eval()`, and tainted input flows
- **⚙️ MCP Configuration Scanning** - Validates MCP server configurations for security issues
- **🔐 Secret Detection** - Finds hardcoded credentials (AWS keys, API tokens, private keys)
- **🌐 Runtime MCP Inspection** - Probes MCP servers without executing tools ("Agent Nmap")
- **📊 Multiple Output Formats** - Terminal, JSON, SARIF (for GitHub Code Scanning), Markdown

---

- **🔍 Python AST 扫描** - 检测危险模式，如 `shell=True`、`eval()`、受污染的输入流
- **⚙️ MCP 配置扫描** - 验证 MCP 服务器配置的安全问题
- **🔐 密钥检测** - 发现硬编码凭证（AWS 密钥、API Token、私钥）
- **🌐 MCP 运行时检查** - 在不执行工具的情况下探测 MCP 服务器
- **📊 多种输出格式** - 终端、JSON、SARIF、Markdown

## 🚀 Quick Start | 快速开始

### Installation | 安装

```bash
pip install agent-audit
```

### Basic Usage | 基本使用

```bash
# Scan current directory | 扫描当前目录
agent-audit scan .

# Scan with JSON output | JSON 格式输出
agent-audit scan ./my-agent --format json

# Scan with SARIF output for GitHub Code Scanning
# SARIF 格式输出（用于 GitHub 代码扫描）
agent-audit scan . --format sarif --output results.sarif

# Fail CI on critical findings only | 仅在严重问题时失败
agent-audit scan . --fail-on critical

# Inspect an MCP server at runtime | 运行时检查 MCP 服务器
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## 🔗 GitHub Action

Add Agent Audit to your CI/CD pipeline | 添加到你的 CI/CD 流程：

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

### Action Inputs | Action 参数

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format: `terminal`, `json`, `sarif`, `markdown` | `sarif` |
| `severity` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` | `low` |
| `fail-on` | Exit with error if findings at this severity | `high` |
| `baseline` | Path to baseline file for incremental scanning | - |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |

## 🎯 Detected Issues | 检测规则

| Rule ID | Title | Severity |
|---------|-------|----------|
| AGENT-001 | Command Injection via Unsanitized Input | 🔴 Critical |
| AGENT-002 | Excessive Agent Permissions | 🟡 Medium |
| AGENT-003 | Potential Data Exfiltration Chain | 🟠 High |
| AGENT-004 | Hardcoded Credentials | 🔴 Critical |
| AGENT-005 | Unverified MCP Server | 🟠 High |

## ⚙️ Configuration | 配置

Create `.agent-audit.yaml` to customize scanning | 创建 `.agent-audit.yaml` 自定义扫描：

```yaml
# Allowed network hosts | 允许的网络主机
allowed_hosts:
  - "*.internal.company.com"
  - "api.openai.com"

# Ignore rules | 忽略规则
ignore:
  - rule_id: AGENT-003
    paths:
      - "auth/**"
    reason: "Auth module legitimately communicates externally"

# Scan settings | 扫描设置
scan:
  exclude:
    - "tests/**"
    - "venv/**"
  min_severity: low
  fail_on: high
```

## 📈 Baseline Scanning | 基线扫描

Track new findings incrementally | 增量跟踪新发现：

```bash
# Save current findings as baseline | 保存当前发现为基线
agent-audit scan . --save-baseline baseline.json

# Only report new findings | 仅报告新发现
agent-audit scan . --baseline baseline.json
```

## 📖 CLI Reference | 命令行参考

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

## 🛠️ Development | 开发

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发设置和指南。

```bash
# Clone the repository | 克隆仓库
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit

# Install dependencies | 安装依赖
cd packages/audit
poetry install

# Run tests (tests are at project root) | 运行测试（测试在项目根目录）
poetry run pytest ../../tests/ -v

# Run the scanner | 运行扫描器
poetry run agent-audit scan .
```

## 📄 License | 许可证

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments | 致谢

- Based on the [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-security/)
- Inspired by the need for better AI agent security tooling

---

<p align="center">
  Made with ❤️ for the AI agent security community
</p>
