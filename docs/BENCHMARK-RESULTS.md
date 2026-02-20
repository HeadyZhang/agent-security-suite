# Agent Audit v0.16 — Benchmark Results Report

**Date:** 2026-02-19
**Version:** 0.15.1 + v0.16.0 patches (pending version bump)
**Benchmark:** Agent-Vuln-Bench v1.0 + Layer 2 Multi-Target

---

## 1. Agent-Vuln-Bench (AVB) Results

### 1.1 Overall Metrics

| Metric | v0.4.1 Baseline | v0.15.1 | v0.16.0 |
|--------|----------------|---------|---------|
| **Recall** | 58.3% | 94.6% | **94.6%** |
| **Precision** | 80.8% | 87.5% | **87.5%** |
| **F1 Score** | 0.700 | 0.909 | **0.909** |
| Samples evaluated | 20 | 19 | 19 |
| Total TP | 14 | 35 | 35 |
| Total FN | 10 | 2 | 2 |
| Total FP | — | 5 | 5 |

### 1.2 Per-Set Recall

| Set | Description | v0.4.1 | v0.15.1 | v0.16.0 |
|-----|-------------|--------|---------|---------|
| **A** | Injection & RCE | 56.2% | 100.0% | **100.0%** |
| **B** | MCP & Component | 62.5% | 100.0% | **100.0%** |
| **C** | Data & Auth | 58.3% | 84.6% | **84.6%** |

### 1.3 Per-Sample Results

| Sample | Set | TP | FN | FP | Status |
|--------|-----|---:|---:|---:|--------|
| KNOWN-001 | A | 1 | 0 | 0 | Pass |
| KNOWN-002 | A | 1 | 0 | 0 | Pass |
| KNOWN-003 | B | 3 | 0 | 2 | Pass |
| KNOWN-004 | C | 5 | 0 | 0 | Pass |
| KNOWN-005 | A | 3 | 0 | 0 | Pass |
| KNOWN-006 | A | 1 | 0 | 0 | Pass |
| KNOWN-007 | B | 2 | 0 | 1 | Pass |
| KNOWN-008 | A | 1 | 0 | 0 | Pass |
| KNOWN-009 | C | 2 | 0 | 0 | Pass |
| KNOWN-010 | A | 1 | 0 | 0 | Pass |
| KNOWN-011 | A | 1 | 0 | 0 | Pass |
| KNOWN-012 | C | 1 | 0 | 0 | Pass |
| WILD-001 | A | 2 | 0 | 1 | Pass |
| WILD-002 | A | 3 | 0 | 0 | Pass |
| WILD-003 | A | 1 | 0 | 0 | Pass |
| WILD-004 | C | 3 | 0 | 0 | Pass |
| WILD-005 | B | 2 | 0 | 1 | Pass |
| WILD-006 | A | 2 | 0 | 0 | Pass |
| T12 (noise) | mixed | 0 | 2 | 0 | Known limitation |

### 1.4 Remaining FN Analysis

| Sample | Expected | Issue |
|--------|----------|-------|
| T12-TP-001 | AGENT-004 in SKILL.md | Markdown credential scanning not implemented |
| T12-TP-002 | AGENT-043 daemon detection | Rule not yet available (planned v0.5.0+) |

---

## 2. Competitor Comparison (Bandit / Semgrep)

### 2.1 Overall Performance

| Metric | agent-audit | Bandit 1.8.6 | Semgrep 1.136.0 |
|--------|------------|-------------|-----------------|
| **Recall** | **94.6%** | 29.7% | 27.0% |
| **Precision** | 87.5% | **100.0%** | **100.0%** |
| **F1 Score** | **0.909** | 0.458 | 0.426 |
| Total TP | **35** | 11 | 10 |
| Total FN | **2** | 26 | 27 |
| Total FP | 5 | **0** | **0** |
| Scan time | 2.9s | 1.7s | 55.4s |

### 2.2 Per-Set Comparison

| Set | Description | agent-audit | Bandit | Semgrep |
|-----|-------------|------------|--------|---------|
| **A** | Injection & RCE | **100.0%** | 68.8% | 56.2% |
| **B** | MCP & Component | **100.0%** | 0.0% | 0.0% |
| **C** | Data & Auth | **84.6%** | 0.0% | 7.7% |

### 2.3 Per-Sample Detail

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

### 2.4 Key Differentiators

**Set B (MCP & Component) — agent-audit exclusive advantage**
Bandit and Semgrep cannot parse MCP JSON configurations. They have 0% recall on KNOWN-003, KNOWN-007, and WILD-005. agent-audit's MCPConfigScanner is the only tool that detects overly broad filesystem access, wildcard command grants, unpinned packages, and hardcoded credentials in MCP configs.

**Set A (Injection) — @tool context awareness**
Bandit detects basic eval()/exec()/subprocess calls but lacks @tool decorator context awareness. agent-audit's tool-boundary-aware taint analysis identifies LLM-controllable input flowing to dangerous sinks, enabling detection of SQL injection (KNOWN-008), SSRF (WILD-002), prompt injection (WILD-006), and self-modification (WILD-003) that generic tools miss.

**Set C (Data & Auth) — semantic credential analysis**
agent-audit's three-stage semantic analyzer (pattern match, value analysis, context adjustment) detects hardcoded credentials in complex formats (JWT tokens, connection strings, multi-field configs) while framework schema definitions (Pydantic Field, type annotations) are suppressed. Bandit/Semgrep only catch simple string assignments.

---

## 3. Layer 2 Multi-Target Scan Results

### 3.1 Findings Summary

| ID | Project | v0.15.1 | v0.16.0 | Delta | OWASP Categories |
|----|---------|---------|---------|-------|------------------|
| T1 | damn-vulnerable-llm-agent | 4 | 4 | 0 | ASI-01, ASI-02, ASI-06 |
| T2 | DamnVulnerableLLMProject | 42 | 42 | 0 | ASI-01, ASI-02, ASI-04 |
| T3 | langchain-core | 27 | 27 | 0 | ASI-01, ASI-02 |
| T6 | openai-agents-python | 39 | **25** | **-14** | ASI-01, ASI-02 |
| T7 | adk-python | 55 | **39** | **-16** | ASI-02, ASI-04, ASI-10 |
| T8 | agentscope | 20 | **10** | **-10** | ASI-02 |
| T9 | crewAI | 226 | **155** | **-71** | ASI-01, ASI-02, ASI-04, ASI-07, ASI-08, ASI-10 |
| T10 | 100-tool-mcp-server | 8 | 8 | 0 | ASI-02, ASI-03, ASI-04, ASI-05, ASI-09 |
| T11 | streamlit-agent | 9 | 9 | 0 | ASI-01, ASI-02, ASI-04, ASI-08 |

### 3.2 OWASP Agentic Top 10 Coverage

**Categories detected:** 10/10

| Category | Description | Detected In |
|----------|-------------|-------------|
| ASI-01 | Prompt Injection | T1, T2, T3, T6, T9, T11 |
| ASI-02 | Tool Misuse | T1, T2, T3, T6, T7, T8, T9, T10, T11 |
| ASI-03 | Identity/Privilege | T10 |
| ASI-04 | Supply Chain | T2, T7, T9, T10, T11 |
| ASI-05 | Code Execution | T10 |
| ASI-06 | Memory Poisoning | T1 |
| ASI-07 | Inter-Agent Comm | T9 |
| ASI-08 | Cascading Failures | T9, T11 |
| ASI-09 | Trust Exploitation | T10 |
| ASI-10 | Rogue Agents | T7, T9 |

### 3.3 Quality Gate

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| OWASP coverage | 10 | 10 | **PASS** |
| T1 findings | >= 3 | 4 | **PASS** |
| T2 ASI categories | >= 3 | 3 | **PASS** |
| T5 findings | < 90 | 0 | **PASS** |
| **Overall** | | | **PASS** |

---

## 4. AGENT-034 Optimization Analysis

### 4.1 Root Cause

Two bugs in expanded detection methods caused massive false positives:

1. **`_check_expanded_eval_exec`**: Matched `simple_name in EVAL_EXEC_PATTERNS`, causing `re.compile()` to trigger (simple_name `compile` matched `compile` in the set)
2. **`_check_expanded_subprocess`**: Matched `simple_name in subprocess_funcs`, causing `asyncio.run()`, `llm.call()`, `platform.system()` to trigger (simple_names `run`, `call`, `system` matched)

### 4.2 Fix Applied

- **Eval/exec expanded**: Only allow simple_name match for unambiguous builtins (`eval`, `exec`, `__import__`). For ambiguous names like `compile`, require full qualified match (e.g., `os.system` not just `system`)
- **Subprocess expanded**: Require module-qualified names (e.g., `subprocess.run`, `os.system`). Bare `run`, `call`, `system` no longer match

### 4.3 AGENT-034 Impact by Target

| Target | Before Fix | After Fix | Reduction |
|--------|-----------|-----------|-----------|
| T6 (openai-agents) | 14 | 0 | -100% |
| T7 (adk-python) | 25 | 9 | -64% |
| T8 (agentscope) | 10 | 0 | -100% |
| T9 (crewAI) | 91 | 20 | -78% |
| **Total** | **140** | **29** | **-79%** |

---

## 5. Unit Test Results

```
1142 passed, 1 skipped in 3.34s — Zero regressions
```

---

## 6. Known Limitations

1. **T12 FN**: 2 false negatives in noise dataset (markdown credential scanning + AGENT-043 not implemented)
2. **Taint depth**: Function-level only; cross-function taint tracking not yet available
3. **Language scope**: Python and MCP JSON only; no JavaScript/TypeScript support
4. **AGENT-034 residual FP**: 20 remaining AGENT-034 findings in crewAI are legitimate detections of subprocess.run with tainted input in CLI tools

---

## 7. Paper-Ready Data Points

- **3.2x recall advantage** over Bandit (94.6% vs 29.7%)
- **3.5x recall advantage** over Semgrep (94.6% vs 27.0%)
- **100% Set B coverage** — only tool that scans MCP configurations
- **100% Set A coverage** — perfect injection/RCE detection
- **10/10 OWASP Agentic Top 10** categories covered
- **0.909 F1 score** vs 0.458 (Bandit) and 0.426 (Semgrep)
- **79% false positive reduction** in AGENT-034 via qualified name matching
