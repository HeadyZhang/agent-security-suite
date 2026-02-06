# Rule Reference

This document provides a comprehensive reference for all agent-audit security rules. Each rule maps to the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and relevant CWE identifiers.

## Quick Reference

| Rule ID | Severity | CWE | OWASP | Title |
|---------|----------|-----|-------|-------|
| [AGENT-001](#agent-001-command-injection-via-unsanitized-input) | CRITICAL | CWE-78 | ASI-02 | Command Injection via Unsanitized Input |
| [AGENT-002](#agent-002-excessive-agent-permissions) | MEDIUM | CWE-250 | ASI-03 | Excessive Agent Permissions |
| [AGENT-003](#agent-003-potential-data-exfiltration-chain) | HIGH | CWE-200 | ASI-05 | Potential Data Exfiltration Chain |
| [AGENT-004](#agent-004-hardcoded-credentials-in-agent-config) | CRITICAL | CWE-798 | ASI-04 | Hardcoded Credentials in Agent Config |
| [AGENT-005](#agent-005-unverified-mcp-server) | HIGH | CWE-494 | ASI-04 | Unverified MCP Server |
| [AGENT-010](#agent-010-system-prompt-injection-vector) | CRITICAL | CWE-77 | ASI-01 | System Prompt Injection Vector in User Input Path |
| [AGENT-011](#agent-011-missing-goal-validation) | HIGH | - | ASI-01 | Missing Goal Validation / Instruction Boundary |
| [AGENT-013](#agent-013-long-lived-credentials) | HIGH | CWE-798 | ASI-03 | Agent with Long-Lived or Shared Credentials |
| [AGENT-014](#agent-014-overly-permissive-role) | HIGH | - | ASI-03 | Overly Permissive Agent Role / Tool Access |
| [AGENT-015](#agent-015-untrusted-mcp-source) | CRITICAL | CWE-494 | ASI-04 | Untrusted MCP Server Source |
| [AGENT-016](#agent-016-unvalidated-rag-source) | HIGH | - | ASI-04 | Unvalidated RAG Data Source |
| [AGENT-017](#agent-017-unsandboxed-code-execution) | CRITICAL | CWE-94 | ASI-05 | Unsandboxed Code Execution in Agent |
| [AGENT-018](#agent-018-unsanitized-memory-input) | CRITICAL | CWE-20 | ASI-06 | Unsanitized Input to Persistent Memory |
| [AGENT-019](#agent-019-conversation-history-risk) | MEDIUM | - | ASI-06 | Conversation History Without Integrity Protection |
| [AGENT-020](#agent-020-insecure-inter-agent-channel) | HIGH | CWE-319 | ASI-07 | Unencrypted or Unauthenticated Inter-Agent Channel |
| [AGENT-021](#agent-021-missing-circuit-breaker) | HIGH | - | ASI-08 | Missing Circuit Breaker / Max Iterations |
| [AGENT-022](#agent-022-no-error-handling) | MEDIUM | - | ASI-08 | No Error Handling in Tool Execution |
| [AGENT-023](#agent-023-opaque-agent-output) | MEDIUM | - | ASI-09 | Agent Output Without Transparency / Audit Trail |
| [AGENT-024](#agent-024-no-kill-switch) | CRITICAL | - | ASI-10 | Agent Without Kill Switch / Shutdown Mechanism |
| [AGENT-025](#agent-025-no-behavioral-monitoring) | HIGH | - | ASI-10 | Agent Without Behavioral Monitoring / Logging |
| [AGENT-026](#agent-026-tool-input-not-sanitized) | CRITICAL | CWE-20 | ASI-02 | LangChain Tool Input Not Sanitized |
| [AGENT-027](#agent-027-injectable-system-prompt) | CRITICAL | CWE-77 | ASI-01 | Injectable System Prompt in LangChain Messages |
| [AGENT-028](#agent-028-unbounded-iterations) | HIGH | CWE-400 | ASI-08 | Agent Without Iteration Limit |
| [AGENT-029](#agent-029-broad-filesystem-access) | HIGH | CWE-732 | ASI-02 | Overly Broad MCP Filesystem Access |
| [AGENT-030](#agent-030-unverified-server-source) | CRITICAL | CWE-494 | ASI-04 | Unverified MCP Server Source |
| [AGENT-031](#agent-031-sensitive-env-exposure) | HIGH | CWE-798 | ASI-05 | Sensitive Environment Variable Exposure in MCP Config |
| [AGENT-032](#agent-032-no-sandbox-isolation) | MEDIUM | CWE-250 | ASI-02 | MCP Server Without Sandbox Isolation |
| [AGENT-033](#agent-033-missing-authentication) | HIGH | CWE-306 | ASI-09 | MCP Server Without Authentication |
| [AGENT-034](#agent-034-tool-no-validation) | HIGH | CWE-20 | ASI-02 | Tool Function Without Input Validation |
| [AGENT-035](#agent-035-unrestricted-execution) | CRITICAL | CWE-94 | ASI-02 | Tool With Unrestricted Code Execution |
| [AGENT-036](#agent-036-unsanitized-tool-output) | HIGH | CWE-94 | ASI-02 | Tool Output Trusted Without Sanitization |
| [AGENT-037](#agent-037-missing-human-approval) | MEDIUM | CWE-862 | ASI-09 | Missing Human-in-the-Loop for Side Effect Operations |
| [AGENT-038](#agent-038-impersonation-risk) | HIGH | CWE-290 | ASI-09 | Agent Impersonation Risk |
| [AGENT-039](#agent-039-trust-boundary-violation) | MEDIUM | CWE-306 | ASI-09 | Trust Boundary Violation in Multi-Agent System |
| [AGENT-040](#agent-040-insecure-tool-schema) | MEDIUM | CWE-20 | ASI-02 | Insecure MCP Tool Schema |
| [AGENT-041](#agent-041-sql-injection) | CRITICAL | CWE-89 | ASI-02 | SQL Injection via String Interpolation |
| [AGENT-042](#agent-042-excessive-mcp-servers) | MEDIUM | CWE-250 | ASI-03 | Excessive MCP Server Configuration |
| [AGENT-050](#agent-050-agentexecutor-risk) | HIGH | CWE-400 | ASI-01 | LangChain AgentExecutor Without Safety Parameters |
| [AGENT-052](#agent-052-sensitive-logging) | HIGH | CWE-532 | ASI-09 | Sensitive Data Logged in Output |
| [AGENT-053](#agent-053-self-modification) | CRITICAL | CWE-94 | ASI-10 | Agent Self-Modification Risk |

---

## Rules by OWASP Agentic Category

### ASI-01: Agent Goal Hijacking
Attacker manipulates agent's goals, decision logic, or task selection.

- [AGENT-010](#agent-010-system-prompt-injection-vector): System Prompt Injection Vector
- [AGENT-011](#agent-011-missing-goal-validation): Missing Goal Validation
- [AGENT-027](#agent-027-injectable-system-prompt): Injectable System Prompt
- [AGENT-050](#agent-050-agentexecutor-risk): AgentExecutor Without Safety Parameters

### ASI-02: Tool Misuse and Exploitation
Agent is manipulated to misuse tools for unauthorized actions.

- [AGENT-001](#agent-001-command-injection-via-unsanitized-input): Command Injection
- [AGENT-026](#agent-026-tool-input-not-sanitized): Tool Input Not Sanitized
- [AGENT-029](#agent-029-broad-filesystem-access): Broad Filesystem Access
- [AGENT-032](#agent-032-no-sandbox-isolation): No Sandbox Isolation
- [AGENT-034](#agent-034-tool-no-validation): Tool Without Input Validation
- [AGENT-035](#agent-035-unrestricted-execution): Unrestricted Code Execution
- [AGENT-036](#agent-036-unsanitized-tool-output): Unsanitized Tool Output
- [AGENT-040](#agent-040-insecure-tool-schema): Insecure Tool Schema
- [AGENT-041](#agent-041-sql-injection): SQL Injection

### ASI-03: Identity and Privilege Abuse
Agent misuses identity or escalates privileges beyond intended scope.

- [AGENT-002](#agent-002-excessive-agent-permissions): Excessive Permissions
- [AGENT-013](#agent-013-long-lived-credentials): Long-Lived Credentials
- [AGENT-014](#agent-014-overly-permissive-role): Overly Permissive Role
- [AGENT-042](#agent-042-excessive-mcp-servers): Excessive MCP Servers

### ASI-04: Agentic Supply Chain
External dependencies (APIs, models, MCP servers) pose security risks.

- [AGENT-004](#agent-004-hardcoded-credentials-in-agent-config): Hardcoded Credentials
- [AGENT-005](#agent-005-unverified-mcp-server): Unverified MCP Server
- [AGENT-015](#agent-015-untrusted-mcp-source): Untrusted MCP Source
- [AGENT-016](#agent-016-unvalidated-rag-source): Unvalidated RAG Source
- [AGENT-030](#agent-030-unverified-server-source): Unverified Server Source

### ASI-05: Improper Output Handling / Code Execution
Agent generates or executes malicious code.

- [AGENT-003](#agent-003-potential-data-exfiltration-chain): Data Exfiltration Chain
- [AGENT-017](#agent-017-unsandboxed-code-execution): Unsandboxed Code Execution
- [AGENT-031](#agent-031-sensitive-env-exposure): Sensitive Env Exposure

### ASI-06: Memory and Context Poisoning
Attacker corrupts agent's persistent memory or context.

- [AGENT-018](#agent-018-unsanitized-memory-input): Unsanitized Memory Input
- [AGENT-019](#agent-019-conversation-history-risk): Conversation History Risk

### ASI-07: Insecure Inter-Agent Communication
Communication between agents lacks security controls.

- [AGENT-020](#agent-020-insecure-inter-agent-channel): Insecure Inter-Agent Channel

### ASI-08: Cascading Failures
Small failures trigger system-wide uncontrolled failures.

- [AGENT-021](#agent-021-missing-circuit-breaker): Missing Circuit Breaker
- [AGENT-022](#agent-022-no-error-handling): No Error Handling
- [AGENT-028](#agent-028-unbounded-iterations): Unbounded Iterations

### ASI-09: Human-Agent Trust Exploitation
Agent manipulates human trust for unauthorized actions.

- [AGENT-023](#agent-023-opaque-agent-output): Opaque Agent Output
- [AGENT-033](#agent-033-missing-authentication): Missing Authentication
- [AGENT-037](#agent-037-missing-human-approval): Missing Human Approval
- [AGENT-038](#agent-038-impersonation-risk): Impersonation Risk
- [AGENT-039](#agent-039-trust-boundary-violation): Trust Boundary Violation
- [AGENT-052](#agent-052-sensitive-logging): Sensitive Data Logging

### ASI-10: Rogue Agents
Autonomous agents deviate from intended goals without external manipulation.

- [AGENT-024](#agent-024-no-kill-switch): No Kill Switch
- [AGENT-025](#agent-025-no-behavioral-monitoring): No Behavioral Monitoring
- [AGENT-053](#agent-053-self-modification): Self-Modification Risk

---

## Rules by Severity

### Critical (Immediate Action Required)

| Rule | Title | OWASP |
|------|-------|-------|
| AGENT-001 | Command Injection via Unsanitized Input | ASI-02 |
| AGENT-004 | Hardcoded Credentials in Agent Config | ASI-04 |
| AGENT-010 | System Prompt Injection Vector | ASI-01 |
| AGENT-015 | Untrusted MCP Server Source | ASI-04 |
| AGENT-017 | Unsandboxed Code Execution | ASI-05 |
| AGENT-018 | Unsanitized Input to Persistent Memory | ASI-06 |
| AGENT-024 | Agent Without Kill Switch | ASI-10 |
| AGENT-026 | Tool Input Not Sanitized | ASI-02 |
| AGENT-027 | Injectable System Prompt | ASI-01 |
| AGENT-030 | Unverified MCP Server Source | ASI-04 |
| AGENT-035 | Unrestricted Code Execution | ASI-02 |
| AGENT-041 | SQL Injection | ASI-02 |
| AGENT-053 | Agent Self-Modification Risk | ASI-10 |

### High (Fix Before Production)

| Rule | Title | OWASP |
|------|-------|-------|
| AGENT-003 | Potential Data Exfiltration Chain | ASI-05 |
| AGENT-005 | Unverified MCP Server | ASI-04 |
| AGENT-011 | Missing Goal Validation | ASI-01 |
| AGENT-013 | Long-Lived Credentials | ASI-03 |
| AGENT-014 | Overly Permissive Role | ASI-03 |
| AGENT-016 | Unvalidated RAG Data Source | ASI-04 |
| AGENT-020 | Insecure Inter-Agent Channel | ASI-07 |
| AGENT-021 | Missing Circuit Breaker | ASI-08 |
| AGENT-025 | No Behavioral Monitoring | ASI-10 |
| AGENT-028 | Unbounded Iterations | ASI-08 |
| AGENT-029 | Broad Filesystem Access | ASI-02 |
| AGENT-031 | Sensitive Env Exposure | ASI-05 |
| AGENT-033 | Missing Authentication | ASI-09 |
| AGENT-034 | Tool Without Validation | ASI-02 |
| AGENT-036 | Unsanitized Tool Output | ASI-02 |
| AGENT-038 | Impersonation Risk | ASI-09 |
| AGENT-050 | AgentExecutor Risk | ASI-01 |
| AGENT-052 | Sensitive Data Logging | ASI-09 |

### Medium (Address When Possible)

| Rule | Title | OWASP |
|------|-------|-------|
| AGENT-002 | Excessive Agent Permissions | ASI-03 |
| AGENT-019 | Conversation History Risk | ASI-06 |
| AGENT-022 | No Error Handling | ASI-08 |
| AGENT-023 | Opaque Agent Output | ASI-09 |
| AGENT-032 | No Sandbox Isolation | ASI-02 |
| AGENT-037 | Missing Human Approval | ASI-09 |
| AGENT-039 | Trust Boundary Violation | ASI-09 |
| AGENT-040 | Insecure Tool Schema | ASI-02 |
| AGENT-042 | Excessive MCP Servers | ASI-03 |

---

## Rule Details

### AGENT-001: Command Injection via Unsanitized Input

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse and Exploitation |

**What it detects**

Tool accepts user input passed directly to shell execution (`subprocess.run`, `os.system`, `eval`, `exec`) without proper sanitization.

**Why it matters**

Attackers can execute arbitrary system commands on your server, leading to data theft, system compromise, or service disruption.

**How to fix**

Use `shlex.quote()` to escape user input, use argument lists instead of shell strings, implement a command allowlist.

```python
# Vulnerable
subprocess.run(f"ls {user_input}", shell=True)

# Fixed
subprocess.run(["ls", shlex.quote(user_input)])
```

---

### AGENT-002: Excessive Agent Permissions

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) |
| **OWASP Agentic** | ASI-03: Excessive Agency and Privilege Escalation |

**What it detects**

Agent is configured with more permissions than necessary (e.g., > 15 tools or > 5 high-risk permissions).

**Why it matters**

Excessive permissions increase attack surface and potential damage from compromised agents.

**How to fix**

Apply principle of least privilege, split into specialized agents, require approval for high-risk operations.

---

### AGENT-003: Potential Data Exfiltration Chain

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html) |
| **OWASP Agentic** | ASI-05: Improper Output Handling |

**What it detects**

Agent has access to both sensitive data sources (secrets, files, database) and external network capabilities.

**Why it matters**

This combination enables data exfiltration where sensitive information can be sent to external servers.

**How to fix**

Implement network egress allowlist, add approval workflow for sensitive operations.

---

### AGENT-004: Hardcoded Credentials in Agent Config

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP Agentic** | ASI-04: Supply Chain Vulnerabilities |

**What it detects**

Agent configuration contains hardcoded API keys, passwords, or other secrets (AWS keys, OpenAI keys, GitHub tokens).

**Why it matters**

Hardcoded credentials can be extracted from source code, leading to unauthorized access.

**How to fix**

Use environment variables or a secrets manager.

```python
# Vulnerable
api_key = "sk-1234567890abcdef"

# Fixed
api_key = os.environ.get("OPENAI_API_KEY")
```

---

### AGENT-005: Unverified MCP Server

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) |
| **OWASP Agentic** | ASI-04: Supply Chain Vulnerabilities |

**What it detects**

Agent connects to an MCP server without signature verification or from untrusted sources.

**Why it matters**

Malicious MCP servers can execute arbitrary code in the context of the agent.

**How to fix**

Only use MCP servers from trusted registries, enable signature verification.

---

### AGENT-010: System Prompt Injection Vector

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html) |
| **OWASP Agentic** | ASI-01: Agent Goal Hijacking |

**What it detects**

User-controlled input is concatenated directly into system prompts or agent instructions without sanitization.

**Why it matters**

Enables Agent Goal Hijack where attackers can redirect the agent's planning and objectives.

**How to fix**

Never concatenate user input into system prompts. Use structured templates with clear separation.

```python
# Vulnerable
prompt = f"You are an agent. User says: {user_input}"

# Fixed
messages = [
    SystemMessage(content="You are a helpful agent."),
    HumanMessage(content=sanitize(user_input))
]
```

---

### AGENT-011: Missing Goal Validation

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **OWASP Agentic** | ASI-01: Agent Goal Hijacking |

**What it detects**

Agent configuration lacks explicit goal boundaries, `max_iterations`, or instruction immutability controls.

**Why it matters**

Without boundaries, agent objectives can be silently redirected via poisoned documents or tool outputs.

**How to fix**

Implement explicit goal boundaries, define `allowed_tools` explicitly, set `max_iterations`.

```python
agent = AgentExecutor(
    agent=agent,
    tools=allowed_tools_only,
    max_iterations=10,
    handle_parsing_errors=True,
)
```

---

### AGENT-013: Long-Lived Credentials

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP Agentic** | ASI-03: Identity and Privilege Abuse |

**What it detects**

Agent uses long-lived API keys, shared service accounts, or hardcoded tokens instead of short-lived, scoped credentials.

**Why it matters**

Long-lived credentials increase exposure window and enable persistent unauthorized access.

**How to fix**

Use short-lived, session-scoped credentials. Implement credential rotation.

```python
# Vulnerable
agent = Agent(api_key="sk-hardcoded-key-123")

# Fixed
credential = get_scoped_credential(scope="read:documents", ttl=timedelta(minutes=15))
agent = Agent(credential=credential)
```

---

### AGENT-014: Overly Permissive Role

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **OWASP Agentic** | ASI-03: Identity and Privilege Abuse |

**What it detects**

Agent configured with overly broad tool access (> 10 tools) or dangerous tool combinations (e.g., `file_read` + `network_outbound`).

**Why it matters**

Violates the Least-Agency principle and increases potential damage from compromise.

**How to fix**

Grant agents only the minimum tools needed. Review tool lists regularly.

---

### AGENT-015: Untrusted MCP Source

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) |
| **OWASP Agentic** | ASI-04: Agentic Supply Chain |

**What it detects**

MCP server loaded via `npx` without version pinning, using `@latest` tag, or from unofficial sources.

**Why it matters**

Unpinned packages can receive malicious updates. Malicious MCP servers have been documented in the wild.

**How to fix**

Pin versions explicitly. Verify integrity with checksums.

```json
// Vulnerable
"args": ["-y", "some-unknown-package"]

// Fixed
"args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]
```

---

### AGENT-016: Unvalidated RAG Source

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **OWASP Agentic** | ASI-04: Agentic Supply Chain |

**What it detects**

RAG pipeline ingests data from external sources (`WebBaseLoader`, `UnstructuredURLLoader`) without integrity validation.

**Why it matters**

Poisoned RAG data can silently corrupt agent decisions across sessions.

**How to fix**

Validate all RAG data sources. Implement integrity checks and data lineage tracking.

---

### AGENT-017: Unsandboxed Code Execution

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) |
| **OWASP Agentic** | ASI-05: Unexpected Code Execution |

**What it detects**

Agent executes dynamically generated code (`eval`, `exec`, `subprocess`) without sandbox isolation.

**Why it matters**

Enables RCE attacks where manipulated prompts lead to arbitrary code execution on the host.

**How to fix**

Use Docker containers with read-only filesystems, disabled networking, and resource limits.

```python
# Vulnerable
@tool
def run_code(code: str):
    exec(code)

# Fixed
@tool
def run_code(code: str):
    result = docker_sandbox.execute(code, timeout=30, network=False, read_only=True)
    return result
```

---

### AGENT-018: Unsanitized Memory Input

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| **OWASP Agentic** | ASI-06: Memory and Context Poisoning |

**What it detects**

User input written to persistent memory (vector database, knowledge graph) without sanitization.

**Why it matters**

Memory poisoning persists across sessions, causing long-term behavioral corruption.

**How to fix**

Sanitize and validate ALL data before writing to persistent memory.

```python
# Vulnerable
vectorstore.add_texts([user_input])

# Fixed
sanitized = sanitize_for_storage(user_input)
if validate_content(sanitized):
    vectorstore.add_texts([sanitized], metadata={"source": "user", "timestamp": now()})
```

---

### AGENT-019: Conversation History Risk

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **OWASP Agentic** | ASI-06: Memory and Context Poisoning |

**What it detects**

Agent stores conversation history without integrity protection, versioning, or expiration.

**Why it matters**

Attackers can poison conversation context to influence future agent behavior.

**How to fix**

Implement bounded memory with explicit window sizes or TTL. Add integrity checksums.

---

### AGENT-020: Insecure Inter-Agent Channel

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) |
| **OWASP Agentic** | ASI-07: Insecure Inter-Agent Communication |

**What it detects**

Multi-agent system communicates over unencrypted channels or without mutual authentication.

**Why it matters**

Enables impersonation and message tampering between agents.

**How to fix**

Apply mutual TLS (mTLS). Cryptographically sign all messages between agents.

---

### AGENT-021: Missing Circuit Breaker

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **OWASP Agentic** | ASI-08: Cascading Failures |

**What it detects**

Agent loop lacks circuit breaker, `max_iterations`, or error budget.

**Why it matters**

Minor tool failures can trigger infinite retry loops or destructive recovery attempts.

**How to fix**

Always configure `max_iterations`, `max_execution_time`, and error budgets.

```python
# Vulnerable
agent = AgentExecutor(agent=agent, tools=tools)

# Fixed
agent = AgentExecutor(
    agent=agent, tools=tools,
    max_iterations=15,
    max_execution_time=300,
    handle_parsing_errors=True,
    early_stopping_method="generate",
)
```

---

### AGENT-022: No Error Handling

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **OWASP Agentic** | ASI-08: Cascading Failures |

**What it detects**

Tool functions lack error handling, causing unhandled exceptions to propagate.

**Why it matters**

Unhandled exceptions can trigger cascading failures across the agent's execution pipeline.

**How to fix**

Wrap all tool function bodies in try/except with graceful error messages.

---

### AGENT-023: Opaque Agent Output

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **OWASP Agentic** | ASI-09: Human-Agent Trust Exploitation |

**What it detects**

Agent produces outputs without exposing reasoning chain, data sources, or tool invocations.

**Why it matters**

Makes human-in-the-loop a rubber stamp rather than a genuine review.

**How to fix**

Configure agents to return intermediate steps and reasoning.

```python
agent = AgentExecutor(
    agent=agent, tools=tools,
    return_intermediate_steps=True,
    verbose=True,
)
```

---

### AGENT-024: No Kill Switch

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **OWASP Agentic** | ASI-10: Rogue Agents |

**What it detects**

Agent operates without a kill switch or graceful shutdown mechanism.

**Why it matters**

If the agent drifts from its intended purpose, there is no way to immediately halt execution.

**How to fix**

Implement a non-negotiable, auditable kill switch. Set `max_iterations` and `max_execution_time`.

---

### AGENT-025: No Behavioral Monitoring

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **OWASP Agentic** | ASI-10: Rogue Agents |

**What it detects**

Agent actions are not logged or monitored, making behavioral drift detection impossible.

**Why it matters**

Without observability, rogue behavior goes undetected.

**How to fix**

Implement comprehensive logging. Use tracing tools like LangSmith or custom callbacks.

---

### AGENT-026: Tool Input Not Sanitized

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

`@tool` decorated function accepts string parameters that flow directly to dangerous operations without validation.

**Why it matters**

Enables attackers to use the tool for unauthorized actions (file access, command execution, SQL queries).

**How to fix**

Validate all string inputs before passing to dangerous operations.

```python
# Vulnerable
@tool
def run_query(query: str) -> str:
    return cursor.execute(query)

# Fixed
@tool
def run_query(query: str) -> str:
    if not re.match(r"^SELECT ", query, re.IGNORECASE):
        raise ValueError("Only SELECT queries allowed")
    return cursor.execute(query)
```

---

### AGENT-027: Injectable System Prompt

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html) |
| **OWASP Agentic** | ASI-01: Goal Hijacking |

**What it detects**

`SystemMessage`, `HumanMessage`, or `AIMessage` content constructed using f-strings or `.format()`.

**Why it matters**

User input can manipulate the agent's instructions and goals.

**How to fix**

Use `ChatPromptTemplate` with proper `input_variables`.

```python
# Vulnerable
msg = SystemMessage(content=f"You are {role}. User: {user_input}")

# Fixed
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{input}")
])
```

---

### AGENT-028: Unbounded Iterations

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) |
| **OWASP Agentic** | ASI-08: Cascading Failures |

**What it detects**

Agent configuration lacks iteration limits across frameworks (LangChain, CrewAI, AutoGen).

**Why it matters**

Agents can enter infinite loops or consume excessive resources.

**How to fix**

Configure iteration limits for all agent frameworks.

```python
# LangChain
executor = AgentExecutor(agent=agent, tools=tools, max_iterations=15)

# CrewAI
agent = Agent(role="...", goal="...", max_iter=10)

# AutoGen
assistant = AssistantAgent("assistant", max_consecutive_auto_reply=5)
```

---

### AGENT-029: Broad Filesystem Access

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-732: Incorrect Permission Assignment](https://cwe.mitre.org/data/definitions/732.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

MCP server configured with access to `/`, `~`, `/etc`, `/home`, or wildcards.

**Why it matters**

Enables potential data exfiltration or unauthorized file modifications.

**How to fix**

Restrict filesystem access to specific project directories.

```json
// Vulnerable
"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]

// Fixed
"args": ["-y", "@modelcontextprotocol/server-filesystem", "./data"]
```

---

### AGENT-030: Unverified Server Source

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) |
| **OWASP Agentic** | ASI-04: Supply Chain |

**What it detects**

MCP server loaded from npm without version pinning or uses HTTP instead of HTTPS.

**Why it matters**

Unpinned packages can receive malicious updates; HTTP traffic can be intercepted.

**How to fix**

Pin versions using `@x.y.z` syntax. Use HTTPS for all connections.

---

### AGENT-031: Sensitive Env Exposure

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP Agentic** | ASI-05: Improper Output Handling |

**What it detects**

MCP config contains hardcoded sensitive values in environment variables.

**Why it matters**

Credentials exposed in config files can be extracted from source control.

**How to fix**

Use environment variable references instead of hardcoded values.

```json
// Vulnerable
"env": { "API_KEY": "sk-1234567890abcdef" }

// Fixed
"env": { "API_KEY": "${OPENAI_API_KEY}" }
```

---

### AGENT-032: No Sandbox Isolation

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

MCP server runs directly on host system without container or sandbox isolation.

**Why it matters**

Increases the impact of any security vulnerability in the MCP server.

**How to fix**

Run MCP servers in isolated containers (Docker, Podman) or use sandbox tools.

---

### AGENT-033: Missing Authentication

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) |
| **OWASP Agentic** | ASI-09: Trust Exploitation |

**What it detects**

MCP server uses SSE or HTTP transport without authentication configuration.

**Why it matters**

Unauthenticated servers can be accessed by unauthorized clients.

**How to fix**

Configure authentication for all remote MCP servers.

---

### AGENT-034: Tool Without Validation

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

Tool function accepts `str` or `Any` parameters without performing input validation.

**Why it matters**

Attackers can pass malicious inputs to trigger unauthorized actions.

**How to fix**

Add input validation at the start of tool functions.

```python
# Vulnerable
@tool
def run_query(query: str) -> str:
    return cursor.execute(query)

# Fixed
@tool
def run_query(query: str) -> str:
    if not isinstance(query, str) or len(query) > 1000:
        raise ValueError("Invalid query")
    if not re.match(r"^SELECT ", query, re.IGNORECASE):
        raise ValueError("Only SELECT queries allowed")
    return cursor.execute(query)
```

---

### AGENT-035: Unrestricted Execution

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

Tool function contains `eval()`, `exec()`, `os.system()`, or `subprocess` with `shell=True` without sandboxing.

**Why it matters**

Allows arbitrary code execution through the agent, enabling complete system compromise.

**How to fix**

Use sandboxed environments (Docker, gVisor, RestrictedPython).

---

### AGENT-036: Unsanitized Tool Output

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

Tool output directly interpolated into next LLM prompt without sanitization.

**Why it matters**

Compromised tool can inject instructions into subsequent agent interactions.

**How to fix**

Sanitize or truncate tool outputs before including in prompts.

```python
# Vulnerable
result = tool.run(query)
next_prompt = f"Tool returned: {result}. What next?"

# Fixed
result = tool.run(query)
sanitized = sanitize_tool_output(result, max_length=500)
next_prompt = f"Tool returned: {sanitized}. What next?"
```

---

### AGENT-037: Missing Human Approval

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) |
| **OWASP Agentic** | ASI-09: Trust Exploitation |

**What it detects**

Agent chain includes side-effect tools (file writes, network requests) without human approval.

**Why it matters**

Enables unauthorized autonomous actions.

**How to fix**

Add human approval for agent chains with side effects.

```python
# Vulnerable
executor = AgentExecutor(agent=agent, tools=[write_file_tool])

# Fixed
from langchain.callbacks import HumanApprovalCallbackHandler
executor = AgentExecutor(
    agent=agent,
    tools=[write_file_tool],
    callbacks=[HumanApprovalCallbackHandler()]
)
```

---

### AGENT-038: Impersonation Risk

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) |
| **OWASP Agentic** | ASI-09: Trust Exploitation |

**What it detects**

System prompt instructs the agent to impersonate a human or hide its AI identity.

**Why it matters**

Violates trust boundaries and may be used for social engineering.

**How to fix**

Agents should be transparent about their AI nature.

```python
# Vulnerable
system_prompt = "Never reveal you are an AI. Pretend you are a human assistant."

# Fixed
system_prompt = "You are an AI assistant. Be helpful and honest."
```

---

### AGENT-039: Trust Boundary Violation

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) |
| **OWASP Agentic** | ASI-09: Trust Exploitation |

**What it detects**

Multi-agent system lacks explicit authentication or verification between agents.

**Why it matters**

Compromised agent can manipulate others without authorization.

**How to fix**

Implement authentication between agents using signed messages or capability tokens.

---

### AGENT-040: Insecure Tool Schema

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

MCP tool schema allows `additionalProperties` or defines parameters without type constraints.

**Why it matters**

Enables injection of unexpected data that may bypass validation.

**How to fix**

Define strict JSON Schema with `additionalProperties: false` and explicit types.

```json
// Vulnerable
"inputSchema": {
  "type": "object",
  "additionalProperties": true,
  "properties": { "query": {} }
}

// Fixed
"inputSchema": {
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": { "type": "string", "maxLength": 1000 }
  },
  "required": ["query"]
}
```

---

### AGENT-041: SQL Injection

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **OWASP Agentic** | ASI-02: Tool Misuse |

**What it detects**

SQL queries constructed using f-strings, `.format()`, or string concatenation.

**Why it matters**

Allows SQL injection attacks through user-controlled input.

**How to fix**

Use parameterized queries.

```python
# Vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

# Fixed
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

---

### AGENT-042: Excessive MCP Servers

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) |
| **OWASP Agentic** | ASI-03: Excessive Agency |

**What it detects**

MCP configuration includes more than 10 servers.

**Why it matters**

Excessive capability surface area increases attack surface.

**How to fix**

Reduce enabled MCP servers to only those required.

---

### AGENT-050: AgentExecutor Risk

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) |
| **OWASP Agentic** | ASI-01: Goal Hijacking |

**What it detects**

`AgentExecutor` or `create_react_agent` instantiated without `max_iterations` or `max_execution_time`.

**Why it matters**

Agent may run indefinitely or be manipulated into excessive iterations.

**How to fix**

Always configure safety parameters.

```python
# Vulnerable
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Fixed
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=10,
    max_execution_time=60,
    handle_parsing_errors=True,
)
```

---

### AGENT-052: Sensitive Logging

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) |
| **OWASP Agentic** | ASI-09: Trust Exploitation |

**What it detects**

Logging statements contain sensitive data (passwords, tokens, API keys).

**Why it matters**

Exposes credentials through logs.

**How to fix**

Never log sensitive data directly. Use masked representations.

```python
# Vulnerable
logger.info(f"User authenticated with token: {user.token}")

# Fixed
logger.info(f"User {user.id} authenticated successfully")
```

---

### AGENT-053: Self-Modification

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) |
| **OWASP Agentic** | ASI-10: Rogue Agents |

**What it detects**

Code writes to Python files and dynamically loads modified code using `importlib`.

**Why it matters**

Enables agent self-modification to bypass controls and become a rogue agent.

**How to fix**

Never allow agent code to modify its own source files. Use read-only deployment patterns.

```python
# Vulnerable
def update_config(new_code: str):
    with open("agent_config.py", "w") as f:
        f.write(new_code)
    importlib.reload(agent_config)

# Fixed
def update_config(config_dict: dict):
    validate_config(config_dict)
    db.save_config(config_dict)
```

---

## Rules by Scanner

### PythonScanner

The Python AST scanner detects patterns in Python source code using the built-in `ast` module.

| Rule | Title | Detection Method |
|------|-------|------------------|
| AGENT-001 | Command Injection | Dangerous function calls (`subprocess.run`, `os.system`, `eval`, `exec`) |
| AGENT-003 | Data Exfiltration Chain | Permission analysis (sensitive data + network access) |
| AGENT-010 | System Prompt Injection | f-string in `SystemMessage`, `ChatPromptTemplate` |
| AGENT-011 | Missing Goal Validation | Agent configuration without `allowed_tools`, `max_iterations` |
| AGENT-013 | Long-Lived Credentials | Hardcoded API keys near agent/tool instantiation |
| AGENT-014 | Overly Permissive Role | Dangerous tool combinations, auto-approval patterns |
| AGENT-016 | Unvalidated RAG Source | Loader functions without validation |
| AGENT-017 | Unsandboxed Code Execution | `eval`/`exec` in tool decorators without sandbox guards |
| AGENT-018 | Unsanitized Memory Input | Write functions without sanitization |
| AGENT-019 | Conversation History Risk | Unbounded memory classes |
| AGENT-020 | Insecure Inter-Agent Channel | Multi-agent classes without auth config |
| AGENT-021 | Missing Circuit Breaker | `AgentExecutor` without `max_iterations` |
| AGENT-022 | No Error Handling | Tool functions without try/except |
| AGENT-023 | Opaque Agent Output | Agent without `return_intermediate_steps` |
| AGENT-024 | No Kill Switch | Long-running agents without timeout/monitor |
| AGENT-025 | No Behavioral Monitoring | Agent without callbacks/logging |
| AGENT-026 | Tool Input Not Sanitized | `@tool` with str params flowing to dangerous sinks |
| AGENT-027 | Injectable System Prompt | f-string in message classes |
| AGENT-028 | Unbounded Iterations | Agent without iteration limits |
| AGENT-034 | Tool Without Validation | `@tool` functions missing validation checks |
| AGENT-035 | Unrestricted Execution | Tool with `eval`/`exec`/`shell=True` |
| AGENT-036 | Unsanitized Tool Output | Tool output directly in prompts |
| AGENT-037 | Missing Human Approval | Side-effect tools without approval handlers |
| AGENT-041 | SQL Injection | f-string in `cursor.execute()` |
| AGENT-050 | AgentExecutor Risk | `AgentExecutor` without safety parameters |
| AGENT-052 | Sensitive Logging | Logging with sensitive variable interpolation |
| AGENT-053 | Self-Modification | Writing to .py files + `importlib.reload` |

### SecretScanner

Regex-based credential detection with semantic analysis for false positive reduction.

| Rule | Title | Detection Method |
|------|-------|------------------|
| AGENT-004 | Hardcoded Credentials | Known API key patterns (AWS, OpenAI, Anthropic, GitHub, etc.) |

Patterns detected:
- AWS Access Keys (`AKIA...`)
- OpenAI API Keys (`sk-proj-...`, `sk-...`)
- Anthropic API Keys (`sk-ant-...`)
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`)
- Google API Keys (`AIza...`)
- Stripe Keys (`sk_live_`, `sk_test_`)
- Database connection strings with credentials
- Private keys (RSA, DSA, EC, PGP)
- Generic secrets with keyword context

### MCPConfigScanner

Static analyzer for MCP server configuration files (JSON/YAML).

| Rule | Title | Detection Method |
|------|-------|------------------|
| AGENT-005 | Unverified MCP Server | Server not from trusted sources |
| AGENT-015 | Untrusted MCP Source | `npx` without version pinning |
| AGENT-029 | Broad Filesystem Access | Dangerous paths (`/`, `~`, `/etc`) |
| AGENT-030 | Unverified Server Source | Unpinned packages, HTTP URLs |
| AGENT-031 | Sensitive Env Exposure | Hardcoded values in env config |
| AGENT-032 | No Sandbox Isolation | stdio transport without container |
| AGENT-033 | Missing Authentication | SSE/HTTP without auth config |
| AGENT-040 | Insecure Tool Schema | `additionalProperties: true`, missing types |
| AGENT-042 | Excessive MCP Servers | >10 servers configured |

Config files scanned:
- `claude_desktop_config.json`
- `mcp.json`, `mcp.yaml`
- `cline_mcp_settings.json`
- `.cursor/mcp.json`

### PrivilegeScanner

Cross-language scanner for privilege escalation patterns.

| Rule | Title | Detection Method |
|------|-------|------------------|
| AGENT-002 | Excessive Permissions | Tool count/permission analysis |
| AGENT-038 | Impersonation Risk | Regex patterns in system prompts |
| AGENT-039 | Trust Boundary Violation | Multi-agent classes without auth |

Additional patterns detected:
- Daemon/service registration (`launchctl`, `systemctl`, `pm2`)
- Sudoers/NOPASSWD configurations
- Browser automation without sandbox
- System credential store access

---

## Suppressing Findings

### Inline Suppression

Add `# noaudit` comment to suppress a specific line:

```python
api_key = "sk-test-key"  # noaudit - Test key, not real credential
```

### Configuration Suppression

In `.agent-audit.yaml`:

```yaml
ignore:
  - rule_id: AGENT-004
    paths:
      - "tests/**"
    reason: "Test fixtures contain mock credentials"
```

### Baseline Suppression

Create a baseline of existing findings:

```bash
agent-audit scan . --save-baseline baseline.json
```

Then scan for new findings only:

```bash
agent-audit scan . --baseline baseline.json
```

---

## References

- [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [MCP Security Documentation](https://modelcontextprotocol.io/docs/security)

---

*40 rules as of v0.15.1*
