# Agent Audit

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-1142%20passed-brightgreen)]()

> **The first open-source static security analyzer purpose-built for AI agent applications.**
> 40+ detection rules mapped to the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Intra-procedural taint analysis. MCP configuration auditing. Three-stage semantic credential detection.

## Evaluation Results

Evaluated on [**Agent-Vuln-Bench**](tests/benchmark/agent-vuln-bench/) (19 samples across 3 vulnerability categories), compared against Bandit and Semgrep:

| Tool | Recall | Precision | F1 |
|------|-------:|----------:|---:|
| **agent-audit** | **94.6%** | **87.5%** | **0.91** |
| Bandit 1.8 | 29.7% | 100% | 0.46 |
| Semgrep 1.x | 27.0% | 100% | 0.43 |

| Category | agent-audit | Bandit | Semgrep |
|----------|:-----------:|:-----:|:-------:|
| Set A — Injection / RCE | **100%** | 68.8% | 56.2% |
| Set B — MCP Configuration | **100%** | 0% | 0% |
| Set C — Data / Auth | **84.6%** | 0% | 7.7% |

> Neither Bandit nor Semgrep can parse MCP configuration files — they achieve **0% recall** on agent-specific configuration vulnerabilities (Set B).

Full evaluation details: [Benchmark Results](docs/BENCHMARK-RESULTS.md) | [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md)

## How It Works

```
Source Files (.py, .json, .yaml, .env, ...)
        |
        +-- PythonScanner ---- AST Analysis ---- Dangerous Patterns
        |        |                                Tool Metadata
        |        +-- TaintTracker --------------- Source->Sink Reachability
        |        +-- DangerousOperationAnalyzer - Tool Boundary Detection
        |
        +-- SecretScanner ---- Regex Candidates
        |        +-- SemanticAnalyzer ----------- 3-Stage Filtering
        |              (Known Formats -> Entropy/Placeholder -> Context)
        |
        +-- MCPConfigScanner -- Server Provenance / Path Permissions / Auth
        |
        +-- PrivilegeScanner -- Daemon / Sudoers / Sandbox / Credential Store
                 |
                 v
            RuleEngine -- 40+ Rules x OWASP Agentic Top 10 -- Findings
```

**Key technical contributions:**

- **Tool-boundary-aware taint analysis** — Tracks data flow from `@tool` function parameters to dangerous sinks (`eval`, `subprocess.run`, `cursor.execute`), with sanitization detection. Only triggers when a confirmed tool entry point has unsanitized parameters flowing to dangerous operations.

- **MCP configuration auditing** — Parses `claude_desktop_config.json` and MCP gateway configs to detect unverified server sources, overly broad filesystem permissions, missing authentication, and unpinned package versions — a category entirely missed by existing SAST tools.

- **Three-stage semantic credential detection** — (1) Regex candidate discovery with priority tiers, (2) value analysis with known-format matching, entropy scoring, and placeholder/UUID exclusion, (3) context adjustment by file type, test patterns, and framework schema detection.

## Threat Coverage

40+ detection rules covering all 10 categories of the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| OWASP Category | Rules | Example Detections |
|----------------|------:|-------------------|
| ASI-01 Agent Goal Hijack | 4 | Prompt injection via f-string in `SystemMessage` |
| ASI-02 Tool Misuse | 9 | `@tool` input to `subprocess` without validation |
| ASI-03 Identity & Privilege | 4 | Daemon privilege escalation, >10 MCP servers |
| ASI-04 Supply Chain | 5 | Unverified MCP source, unpinned `npx` packages |
| ASI-05 Code Execution | 3 | `eval`/`exec` in tool without sandbox |
| ASI-06 Memory Poisoning | 2 | Unsanitized input to vector store `upsert` |
| ASI-07 Inter-Agent Comm | 1 | Multi-agent over HTTP without TLS |
| ASI-08 Cascading Failures | 3 | `AgentExecutor` without `max_iterations` |
| ASI-09 Trust Exploitation | 6 | Critical ops without `human_in_the_loop` |
| ASI-10 Rogue Agents | 3 | No kill switch, no behavior monitoring |

Framework-specific detection for **LangChain**, **CrewAI**, **AutoGen**, and **AgentScope**.

See [Rule Reference](docs/RULES.md) for the complete catalog with CWE mappings and remediation guidance.

## Real-World Validation

Scanned 9 open-source projects to validate detection quality across intentionally vulnerable apps, production frameworks, and MCP configurations:

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

**10/10 OWASP Agentic Top 10 categories detected** across targets. Quality gate: **PASS**.

## Quick Start

### Installation

```bash
pip install agent-audit
```

### Usage

```bash
# Scan a project directory
agent-audit scan ./my-agent-project

# JSON output for programmatic use
agent-audit scan . --format json

# SARIF output for GitHub Code Scanning integration
agent-audit scan . --format sarif --output results.sarif

# Only fail CI on critical/high findings
agent-audit scan . --fail-on high

# Runtime MCP server inspection (read-only probe)
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### GitHub Actions

```yaml
name: Agent Security Scan
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HeadyZhang/agent-audit@v1
        with:
          path: '.'
          fail-on: 'high'
          upload-sarif: 'true'
```

## Configuration

```yaml
# .agent-audit.yaml
scan:
  exclude: ["tests/**", "venv/**"]
  min_severity: low
  fail_on: high

ignore:
  - rule_id: AGENT-003
    paths: ["auth/**"]
    reason: "Auth module legitimately communicates externally"

allowed_hosts:
  - "api.openai.com"
```

## Comparison with Existing Tools

| Capability | agent-audit | Bandit | Semgrep |
|-----------|:-----------:|:-----:|:-------:|
| Agent-specific threat model (OWASP Agentic Top 10) | Yes | No | No |
| MCP configuration auditing | Yes | No | No |
| Tool-boundary taint analysis | Yes | No | No |
| `@tool` decorator awareness | Yes | No | No |
| Semantic credential detection | Yes | Basic | Basic |
| General Python security | Partial | Yes | Yes |
| Multi-language support | Python-focused | Python | Multi |

agent-audit is **complementary** to general-purpose SAST tools. It targets the security gap specific to AI agent applications that existing tools cannot address.

## Limitations

- **Static analysis only**: Does not execute code; cannot detect runtime logic vulnerabilities.
- **Intra-procedural taint analysis**: Tracks data flow within functions; no cross-function or cross-module tracking yet.
- **Python-focused**: Primary support for Python source and MCP JSON configs. Limited pattern matching for other languages.
- **Framework coverage**: Deep support for LangChain, CrewAI, AutoGen, AgentScope. Other frameworks use generic `@tool` detection rules.
- **False positives**: Mitigated through semantic analysis, framework detection, and allowlists; ongoing optimization (79% FP reduction in v0.16).

## Documentation

- [Technical Specification](docs/SECURITY-ANALYSIS-SPECIFICATION.md) — Detection methodology and analysis pipeline
- [Benchmark Results](docs/BENCHMARK-RESULTS.md) — Detailed Agent-Vuln-Bench evaluation
- [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md) — Three-tool analysis vs Bandit and Semgrep
- [Rule Reference](docs/RULES.md) — Complete rule catalog with CWE mappings and remediation
- [Architecture](docs/ARCHITECTURE.md) — Internal design and extension points
- [CI/CD Integration](docs/CI-INTEGRATION.md) — GitHub Actions, GitLab CI, Jenkins, Azure DevOps

## Development

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest ../../tests/ -v  # 1142 tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development setup and PR guidelines.

## Citation

If you use agent-audit in your research, please cite:

```bibtex
@software{agent_audit_2026,
  author = {Zhang, Haiyue},
  title = {Agent Audit: Static Security Analysis for AI Agent Applications},
  year = {2026},
  url = {https://github.com/HeadyZhang/agent-audit},
  note = {Based on OWASP Agentic Top 10 (2026) threat model}
}
```

## Acknowledgments

- [OWASP Agentic Top 10 for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## License

MIT — see [LICENSE](LICENSE).
