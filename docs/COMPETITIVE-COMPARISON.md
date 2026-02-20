# Competitive Comparison: agent-audit vs Bandit vs Semgrep

Evaluated on [Agent-Vuln-Bench v1.0](../tests/benchmark/agent-vuln-bench/) — 19 samples across 3 vulnerability categories with oracle ground truth.

## Overall Performance

| Metric | agent-audit | Bandit 1.8.6 | Semgrep 1.136.0 |
|--------|------------|-------------|-----------------|
| **Recall** | **94.6%** | 29.7% | 27.0% |
| **Precision** | 87.5% | **100.0%** | **100.0%** |
| **F1 Score** | **0.909** | 0.458 | 0.426 |
| True Positives | **35** | 11 | 10 |
| False Negatives | **2** | 26 | 27 |
| False Positives | 5 | **0** | **0** |
| Scan time | 2.9s | 1.7s | 55.4s |

## Per-Set Recall

| Set | Description | agent-audit | Bandit | Semgrep |
|-----|-------------|------------|--------|---------|
| **A** | Injection & RCE | **100.0%** | 68.8% | 56.2% |
| **B** | MCP & Component | **100.0%** | 0.0% | 0.0% |
| **C** | Data & Auth | **84.6%** | 0.0% | 7.7% |

## Per-Sample Detail

| Sample | agent-audit | Bandit | Semgrep |
|--------|------------|--------|---------|
| KNOWN-001 (eval CVE) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-002 (exec CVE) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-003 (MCP config) | 3/0/2 | 0/3/0 | 0/3/0 |
| KNOWN-004 (hardcoded creds) | 5/0/0 | 0/5/0 | 0/5/0 |
| KNOWN-005 (shell exec) | 3/0/0 | 3/0/0 | 2/1/0 |
| KNOWN-006 (eval injection) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-007 (MCP multi-vuln) | 2/0/1 | 0/2/0 | 0/2/0 |
| KNOWN-008 (SQL injection) | 1/0/0 | 0/1/0 | 0/1/0 |
| KNOWN-009 (JWT hardcoded) | 2/0/0 | 0/2/0 | 1/1/0 |
| KNOWN-010 (SSRF) | 1/0/0 | 1/0/0 | 0/1/0 |
| KNOWN-011 (shell Popen) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-012 (sensitive log) | 1/0/0 | 0/1/0 | 0/1/0 |
| WILD-001 (eval calculator) | 2/0/1 | 2/0/0 | 2/0/0 |
| WILD-002 (SSRF fetcher) | 3/0/0 | 1/2/0 | 1/2/0 |
| WILD-003 (self-modify) | 1/0/0 | 0/1/0 | 0/1/0 |
| WILD-004 (token collector) | 3/0/0 | 0/3/0 | 0/3/0 |
| WILD-005 (MCP wildcard) | 2/0/1 | 0/2/0 | 0/2/0 |
| WILD-006 (prompt inject) | 2/0/0 | 0/2/0 | 0/2/0 |

*Format: TP/FN/FP*

## Key Differentiators

### Set B: MCP Configuration (agent-audit exclusive)

Bandit and Semgrep cannot parse MCP JSON configurations. They have **0% recall** on KNOWN-003, KNOWN-007, and WILD-005. agent-audit's MCPConfigScanner is the only tool that detects:

- Overly broad filesystem access (`"args": ["/"]`)
- Wildcard command grants
- Unpinned NPX packages (`npx -y @some/package` without version lock)
- Hardcoded credentials in MCP server configs
- Missing authentication on MCP transports

### Set A: Injection / RCE (@tool context awareness)

Bandit detects basic `eval()`/`exec()`/`subprocess` calls but lacks `@tool` decorator context awareness. agent-audit's tool-boundary-aware taint analysis identifies LLM-controllable input flowing to dangerous sinks, enabling detection of:

- SQL injection via f-string in tool functions (KNOWN-008)
- SSRF through unvalidated URL parameters (WILD-002)
- Prompt injection via user input in system messages (WILD-006)
- Agent self-modification through dynamic code execution (WILD-003)

### Set C: Data & Auth (semantic credential analysis)

agent-audit's three-stage semantic analyzer detects hardcoded credentials in complex formats that simple pattern matching misses:

- JWT tokens embedded in configuration
- Database connection strings with inline passwords
- Multi-field credential configurations (API key + secret pairs)
- Framework schema definitions correctly suppressed (Pydantic `Field`, type annotations)

## Methodology

- **Oracle-based evaluation**: Each sample has a hand-labeled `oracle.yaml` defining expected vulnerability locations (file + line within 5-line tolerance)
- **File + line matching**: True positives require the finding to match the oracle's file path and line number (no rule_id matching required, allowing cross-tool comparison)
- **Three dataset categories**: Set A (injection/RCE), Set B (MCP/component), Set C (data/auth)
- **Noise dataset (T12)**: Validates that tools do not over-report on benign patterns

## Complementary Use

agent-audit is designed to complement, not replace, general-purpose SAST tools:

| Use Case | Recommended Tool |
|----------|-----------------|
| AI agent code, `@tool` functions, MCP configs | **agent-audit** |
| General Python security (non-agent code) | Bandit, Semgrep |
| Multi-language security scanning | Semgrep |
| Supply chain vulnerability scanning | Trivy, Snyk |

For comprehensive coverage, run agent-audit alongside your existing SAST pipeline.
