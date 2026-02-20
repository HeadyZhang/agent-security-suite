# Agent Audit

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)
[![OWASP Coverage](https://img.shields.io/badge/OWASP%20Agentic-10%2F10-brightgreen)](https://genai.owasp.org/)

> **The first open-source static analyzer purpose-built for AI agent code.**
> Maps every finding to the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). 40+ detection rules. Native support for LangChain, CrewAI, AutoGen, and MCP.
>
> **首个专为 AI Agent 代码设计的开源静态分析器。**
> 每项发现均映射到 OWASP Agentic Top 10 (2026)。40+ 检测规则。原生支持 LangChain、CrewAI、AutoGen 和 MCP。

<p align="center">
  <img src="docs/demo.png" alt="Agent Audit Demo" width="800">
</p>

---

## ✨ Features | 核心能力

### Detection Engines | 检测引擎

| Engine | What it does |
|--------|--------------|
| **Python AST Scanner** | Deep analysis of agent code: tool decorators, executor instantiation, dangerous sinks (`eval`, `subprocess`, `cursor.execute`) |
| **Taint Tracker** | Intra-procedural data flow analysis from user input → dangerous operations |
| **Semantic Analyzer** | 3-stage credential detection: regex patterns → entropy/placeholder analysis → context scoring |
| **MCP Config Scanner** | Validates `claude_desktop_config.json` / MCP Gateway configs for filesystem exposure, unpinned packages, missing auth |
| **MCP Runtime Inspector** | Probes live MCP servers via stdio/SSE without executing tools — "Nmap for AI agents" |

### Under the Hood | 引擎细节

- **TaintTracker** — Tracks data flow from sources (`request`, `user_input`, `query`) to sinks (`exec`, `subprocess.run`, `cursor.execute`)
- **SemanticAnalyzer** — Three-stage credential analysis: (1) regex candidate discovery, (2) entropy + placeholder detection, (3) file path / framework context adjustment
- **DangerousOperationAnalyzer** — Identifies when `@tool` function parameters flow to shell execution, SQL queries, or file writes
- **PrivilegeScanner** — Detects daemon registration (`launchctl`, `systemctl`), sudoers NOPASSWD, unsandboxed browser automation, credential store access
- **Framework-aware rules** — Specific detections for `AgentExecutor`, `@tool`, `SystemMessage`, `Crew`, `ConversableAgent`
- **Confidence tiering** — Every finding scored 0.0–1.0, classified as `BLOCK` (≥0.9) / `WARN` (≥0.6) / `INFO` (≥0.3) / `SUPPRESSED`

---

## 🚀 Quick Start | 快速开始

### Installation | 安装

```bash
# 推荐：pipx（自动处理 PATH，隔离环境）
pipx install agent-audit

# 或 pip
pip install agent-audit

# 如果 pip 安装后找不到命令
python3 -m agent_audit --version
```

### Basic Usage | 基本使用

```bash
# Scan current directory
agent-audit scan .

# Output SARIF for GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif

# Fail CI only on critical/high findings
agent-audit scan . --fail-on high

# Inspect a live MCP server (without executing tools)
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

---

## 🎯 Detection Coverage | 检测覆盖

**40 rules** mapped to the complete **OWASP Agentic Top 10 (2026)**:

| ASI | Category | Rules | Key Detections |
|-----|----------|-------|----------------|
| **ASI-01** | Goal Hijacking | `AGENT-010` `011` `027` `050` | System prompt injection, f-string in `SystemMessage`, `AgentExecutor` without safety params |
| **ASI-02** | Tool Misuse | `AGENT-001` `026` `029` `032` `034` `035` `036` `040` `041` | Command injection, SQL injection via f-string, `@tool` without input validation, overly broad MCP filesystem access |
| **ASI-03** | Privilege Abuse | `AGENT-002` `013` `014` `042` | Excessive tool grants, long-lived credentials, daemon privilege escalation, >10 MCP servers |
| **ASI-04** | Supply Chain | `AGENT-004` `005` `015` `016` `030` | Hardcoded API keys, unpinned `npx` packages, unverified MCP servers, unvalidated RAG sources |
| **ASI-05** | Code Execution | `AGENT-003` `017` `031` | Unsandboxed `eval`/`exec`, data exfiltration chain (sensitive data + network access) |
| **ASI-06** | Memory Poisoning | `AGENT-018` `019` | Unsanitized input to vector stores, unbounded conversation history |
| **ASI-07** | Inter-Agent Comms | `AGENT-020` | Unencrypted/unauthenticated multi-agent channels |
| **ASI-08** | Cascading Failures | `AGENT-021` `022` `028` | Missing `max_iterations`, no error handling in tools, unbounded agent loops |
| **ASI-09** | Trust Exploitation | `AGENT-023` `033` `037` `038` `039` `052` | Opaque agent output, MCP without auth, missing human approval, agent impersonation prompts, sensitive data logging |
| **ASI-10** | Rogue Agents | `AGENT-024` `025` `053` | No kill switch, no behavioral monitoring, agent self-modification |

📖 **[Full Rule Reference →](docs/RULES.md)** — Every rule with CWE mapping, fix guidance, and code examples.

---

## 📊 Benchmark Results | 基准测试结果

agent-audit is evaluated on a **3-layer benchmark system** covering synthetic fixtures, real-world open-source projects, and a dedicated vulnerability detection benchmark.

### Agent-Vuln-Bench (AVB)

[Agent-Vuln-Bench](tests/benchmark/agent-vuln-bench/) is an SWE-bench-style evaluation suite with 19 samples across 3 vulnerability sets, each with oracle ground truth. Evaluated against Bandit and Semgrep as baselines:

| Metric | agent-audit | Bandit 1.8.6 | Semgrep 1.136.0 |
|--------|------------|-------------|--------------------|
| **Recall** | **94.6%** | 29.7% | 27.0% |
| **Precision** | 87.5% | 100.0% | 100.0% |
| **F1 Score** | **0.909** | 0.458 | 0.426 |
| True Positives | **35** | 11 | 10 |
| Scan time | 2.9s | 1.7s | 55.4s |

**Per-Set Recall:**

| Set | Description | agent-audit | Bandit | Semgrep |
|-----|-------------|------------|--------|---------|
| **A** | Injection & RCE (eval, exec, subprocess, SSRF, SQLi) | **100.0%** | 68.8% | 56.2% |
| **B** | MCP & Component (config misuse, wildcard grants, unpinned packages) | **100.0%** | 0.0% | 0.0% |
| **C** | Data & Auth (hardcoded credentials, JWT tokens, sensitive logging) | **84.6%** | 0.0% | 7.7% |

Key differentiators:
- **Set B: 100% vs 0%** — Bandit and Semgrep cannot parse MCP JSON configurations. agent-audit is the only tool that detects overly broad filesystem access, wildcard command grants, and hardcoded credentials in MCP configs.
- **Set A: @tool context awareness** — Taint analysis tracks LLM-controllable input flowing to dangerous sinks within `@tool` decorated functions, catching SQL injection, SSRF, and prompt injection that generic tools miss.
- **Set C: Semantic credential analysis** — Three-stage analyzer (pattern match, value analysis, context scoring) detects credentials in complex formats (JWT tokens, connection strings) while suppressing framework schema definitions.

### Layer 2: Real-World Framework Scan

9 real-world open-source projects scanned to validate detection quality and false positive rates:

| Target | Project | Findings | OWASP Categories |
|--------|---------|----------|------------------|
| T1 | [damn-vulnerable-llm-agent](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent) | 4 | ASI-01, ASI-02, ASI-06 |
| T2 | [DamnVulnerableLLMProject](https://github.com/harishsg993010/DamnVulnerableLLMProject) | 41 | ASI-01, ASI-02, ASI-04 |
| T3 | [langchain-core](https://github.com/langchain-ai/langchain) | 3 | ASI-01, ASI-02 |
| T6 | [openai-agents-python](https://github.com/openai/openai-agents-python) | 25 | ASI-01, ASI-02 |
| T7 | [adk-python](https://github.com/google/adk-python) | 40 | ASI-02, ASI-04, ASI-10 |
| T8 | [agentscope](https://github.com/modelscope/agentscope) | 10 | ASI-02 |
| T9 | [crewAI](https://github.com/crewAIInc/crewAI) | 155 | ASI-01, ASI-02, ASI-04, ASI-07, ASI-08, ASI-10 |
| T10 | MCP Config (100-tool server) | 8 | ASI-02, ASI-03, ASI-04, ASI-05, ASI-09 |
| T11 | [streamlit-agent](https://github.com/langchain-ai/streamlit-agent) | 6 | ASI-01, ASI-04, ASI-08 |

**Quality Gate: PASS** — 10/10 OWASP Agentic Top 10 categories detected across targets.

### Unit Tests

```
1142 passed, 1 skipped in 3.25s
```

---

## 🔗 GitHub Action

### Basic Integration | 基础集成

```yaml
name: Agent Security Scan
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

### PR Comment Integration | PR 评论集成

Automatically post scan results as a PR comment:

```yaml
name: Agent Audit PR Review
on: pull_request

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Agent Audit
        id: audit
        uses: HeadyZhang/agent-audit@v1
        with:
          path: '.'
          format: 'sarif'
          fail-on: 'high'
          upload-sarif: 'true'
        continue-on-error: true

      - name: Comment PR with Results
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const outcome = '${{ steps.audit.outcome }}';
            const status = outcome === 'success' ? '✅ Passed' : '⚠️ Issues Found';
            const body = `## 🛡️ Agent Audit Results\n\n**Status:** ${status}\n\n📄 Full results available in the **Security** tab.`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

### Scheduled Full Scan | 定时全量扫描

Run a comprehensive weekly audit:

```yaml
name: Weekly Agent Security Audit
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday 9:00 AM UTC
  workflow_dispatch:     # Allow manual trigger

jobs:
  full-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Full Audit
        uses: HeadyZhang/agent-audit@v1
        with:
          path: '.'
          severity: 'info'        # Report all findings
          fail-on: 'critical'     # Only fail on critical
          upload-sarif: 'true'
```

### Action Inputs | Action 参数

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format: `terminal`, `json`, `sarif`, `markdown` | `sarif` |
| `severity` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` | `low` |
| `fail-on` | Exit non-zero if findings at this severity or above | `high` |
| `baseline` | Path to baseline file for incremental scanning | - |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |

For GitLab CI, Jenkins, Azure DevOps → **[CI/CD Integration Guide](docs/CI-INTEGRATION.md)**

---

## 📖 Understanding Results | 理解扫描结果

| Field | Description |
|-------|-------------|
| **Rule ID** | Unique identifier (e.g., `AGENT-034`). See [Rule Reference](docs/RULES.md) |
| **Severity** | `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` |
| **Confidence** | `BLOCK` (≥0.9) / `WARN` (≥0.6) / `INFO` (≥0.3) — higher = fewer false positives |
| **Location** | File path and line number |

### What to Do | 如何处理

| Tier | Action |
|------|--------|
| **BLOCK** | Fix immediately — high-confidence exploitable vulnerability |
| **WARN** | Fix before merge — likely real issue |
| **INFO** | Review and decide — may be intentional |

Suppress known issues with `# noaudit` comment or `.agent-audit.yaml` configuration.

---

## ⚙️ Configuration | 配置

Create `.agent-audit.yaml` to customize scanning:

```yaml
# Allowed network hosts
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

## 📈 Baseline Scanning | 基线扫描

Track new findings incrementally:

```bash
# Save current findings as baseline
agent-audit scan . --save-baseline baseline.json

# Only report NEW findings
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

---

## 📚 Documentation | 文档

| Document | Description |
|----------|-------------|
| **[Rule Reference](docs/RULES.md)** | All 40 rules with CWE mapping, fix guidance, code examples |
| **[CI/CD Integration](docs/CI-INTEGRATION.md)** | GitHub Actions, GitLab CI, Jenkins, Azure DevOps |
| **[API Stability](docs/STABILITY.md)** | What interfaces you can depend on |
| **[Architecture](docs/ARCHITECTURE.md)** | Internal design and extension points |
| **[Contributing](CONTRIBUTING.md)** | Development setup and PR guidelines |

---

## 🛠️ Development | 开发

See [CONTRIBUTING.md](CONTRIBUTING.md) for full setup instructions.

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest ../../tests/ -v
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [OWASP Agentic Security Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- The AI agent security research community

---

<p align="center">
  <strong>Built for the AI agent security community</strong><br>
  <a href="https://github.com/HeadyZhang/agent-audit/issues">Report Bug</a> · <a href="https://github.com/HeadyZhang/agent-audit/issues">Request Feature</a> · <a href="docs/RULES.md">Browse Rules</a>
</p>
