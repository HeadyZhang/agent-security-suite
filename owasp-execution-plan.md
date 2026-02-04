# Agent Audit — OWASP Agentic Top 10 全覆盖执行文档

> **目标**: 将 agent-audit 从当前 5 条规则 (AGENT-001 ~ AGENT-005) 扩展到完整覆盖 OWASP Agentic Top 10 for 2026 (ASI-01 ~ ASI-10)，同时实现自定义规则加载功能。
>
> **适用对象**: Claude Code / Coding Agent
>
> **仓库**: https://github.com/HeadyZhang/agent-audit
>
> **分支策略**: 从 `master` 创建 `feat/owasp-full-coverage`，完成后 PR 回 `master`

---

## 0. 全局上下文

### 0.1 OWASP Agentic Top 10 与规则映射总表

| ASI # | OWASP 风险名称 | 现有规则 | 新增规则 ID | 优先级 | 检测方式 |
|-------|---------------|---------|------------|--------|---------|
| ASI-01 | Agent Goal Hijack (目标劫持) | 部分 (prompt injection) | AGENT-010, AGENT-011 | P0 | AST + 配置扫描 |
| ASI-02 | Tool Misuse & Exploitation (工具滥用) | ✅ AGENT-001 | AGENT-012 (加强) | P1 | AST |
| ASI-03 | Identity & Privilege Abuse (身份权限滥用) | 部分 AGENT-002 | AGENT-013, AGENT-014 | P0 | AST + 配置扫描 |
| ASI-04 | Supply Chain Vulnerabilities (供应链) | 部分 AGENT-005 | AGENT-015, AGENT-016 | P0 | 配置扫描 + MCP 扫描 |
| ASI-05 | Unexpected Code Execution / RCE | 包含于 AGENT-001 | AGENT-017 | P0 | AST |
| ASI-06 | Memory & Context Poisoning (记忆污染) | ❌ 无 | AGENT-018, AGENT-019 | P0 | AST + 配置扫描 |
| ASI-07 | Insecure Inter-Agent Communication (不安全通信) | ❌ 无 | AGENT-020 | P1 | 配置扫描 |
| ASI-08 | Cascading Failures (级联故障) | ❌ 无 | AGENT-021, AGENT-022 | P1 | AST + 配置扫描 |
| ASI-09 | Human-Agent Trust Exploitation (信任利用) | ❌ 无 | AGENT-023 | P2 | AST |
| ASI-10 | Rogue Agents (恶意/失控代理) | ❌ 无 | AGENT-024, AGENT-025 | P0 | AST + 配置扫描 |

### 0.2 当前仓库目录结构（参考）

```
agent-audit/
├── packages/audit/
│   └── agent_audit/
│       ├── cli/
│       │   ├── main.py
│       │   └── commands/
│       │       ├── scan.py
│       │       ├── inspect_cmd.py
│       │       └── init.py
│       ├── scanners/
│       │   ├── base.py
│       │   ├── python_scanner.py
│       │   ├── mcp_scanner.py
│       │   ├── config_scanner.py
│       │   └── secret_scanner.py
│       ├── rules/
│       │   ├── engine.py
│       │   └── loader.py
│       ├── models/
│       │   ├── finding.py
│       │   └── tool.py
│       └── utils/
├── rules/builtin/
│   ├── command_injection.yaml
│   ├── data_exfiltration.yaml
│   └── supply_chain.yaml
├── tests/
└── .agent-audit.yaml
```

### 0.3 编码规范（贯穿整个执行）

```
1. 所有代码使用 type hints（Python 3.9+ 兼容语法）
2. 所有公共方法有 docstring（Google style）
3. 使用 dataclass 或 Pydantic BaseModel
4. 错误处理：不吞掉异常，使用自定义异常类
5. 日志：使用 logging 模块，不用 print
6. 测试：每个模块对应测试文件，目标覆盖率 > 80%
7. 格式：Black (line-length=100), Ruff
8. YAML 规则文件使用 UTF-8，包含中英文 description
```

---

## 阶段 1: 基础设施准备（预计 2-3 小时）

### STEP 1.1: 创建分支并更新 Finding 模型

**目的**: 扩展 `Category` 枚举以支持新的 OWASP 类别，添加 `owasp_agentic_id` 字段。

**文件**: `packages/audit/agent_audit/models/finding.py`

**操作**:

1. 首先阅读现有 `finding.py` 的完整内容
2. 在 `Category` 枚举中新增以下值:

```python
class Category(Enum):
    # 现有值保持不变
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PROMPT_INJECTION = "prompt_injection"
    EXCESSIVE_PERMISSION = "excessive_permission"

    # === 新增: OWASP Agentic Top 10 扩展 ===
    GOAL_HIJACK = "goal_hijack"                         # ASI-01
    TOOL_MISUSE = "tool_misuse"                         # ASI-02
    IDENTITY_PRIVILEGE_ABUSE = "identity_privilege_abuse"  # ASI-03
    SUPPLY_CHAIN_AGENTIC = "supply_chain_agentic"       # ASI-04
    UNEXPECTED_CODE_EXECUTION = "unexpected_code_execution"  # ASI-05
    MEMORY_POISONING = "memory_poisoning"               # ASI-06
    INSECURE_INTER_AGENT_COMM = "insecure_inter_agent_comm"  # ASI-07
    CASCADING_FAILURES = "cascading_failures"           # ASI-08
    TRUST_EXPLOITATION = "trust_exploitation"           # ASI-09
    ROGUE_AGENT = "rogue_agent"                         # ASI-10
```

3. 在 `Finding` dataclass 中确保 `owasp_id` 字段存在（如不存在则添加）:

```python
owasp_id: Optional[str] = None  # e.g., "ASI-01", "ASI-02"
```

4. 添加 OWASP Agentic ID 到 SARIF 映射的辅助方法:

```python
OWASP_AGENTIC_MAP = {
    "ASI-01": "Agent Goal Hijack",
    "ASI-02": "Tool Misuse and Exploitation",
    "ASI-03": "Identity and Privilege Abuse",
    "ASI-04": "Agentic Supply Chain Vulnerabilities",
    "ASI-05": "Unexpected Code Execution",
    "ASI-06": "Memory and Context Poisoning",
    "ASI-07": "Insecure Inter-Agent Communication",
    "ASI-08": "Cascading Failures",
    "ASI-09": "Human-Agent Trust Exploitation",
    "ASI-10": "Rogue Agents",
}
```

**验收**: `python -c "from agent_audit.models.finding import Category; print(Category.GOAL_HIJACK)"` 无报错。

---

### STEP 1.2: 扩展规则 Schema

**目的**: 确保 YAML 规则可以声明 `owasp_agentic_id` 和 `detection_type` 字段。

**文件**: `rules/builtin/` 下的现有 YAML 规则（如存在 schema），以及 `packages/audit/agent_audit/rules/loader.py`

**操作**:

1. 阅读现有 `loader.py`，了解 YAML 规则的加载和解析逻辑
2. 确保规则数据结构支持以下字段:

```yaml
# 规则 YAML 标准字段
- id: "AGENT-XXX"
  name: "Rule Display Name"
  description: "What this rule detects"
  severity: "critical|high|medium|low|info"
  category: "对应 Category 枚举值"
  owasp_agentic_id: "ASI-XX"        # 新增
  cwe_id: "CWE-XXX"                  # 可选
  confidence: 0.8                     # 默认置信度
  detection:
    type: "ast|config|mcp|composite"  # 新增: 检测类型
    patterns: []                      # 匹配模式（按 type 不同解析方式不同）
  remediation:
    description: "How to fix"
    code_example: "..."               # 可选
    reference_url: "..."              # 可选
  metadata:
    introduced_in: "v0.2.0"
    references:
      - "https://genai.owasp.org/..."
```

3. 在 `loader.py` 中更新解析逻辑，确保新字段能正确加载:

```python
def _parse_rule(self, rule_data: dict) -> Rule:
    """解析单条规则数据"""
    # ... 现有解析逻辑 ...
    
    # 新增字段解析
    owasp_agentic_id = rule_data.get('owasp_agentic_id')
    detection_type = rule_data.get('detection', {}).get('type', 'ast')
    confidence = rule_data.get('confidence', 1.0)
    
    # ... 返回 Rule 对象 ...
```

**验收**: 创建一个测试 YAML 文件，加载后确认所有新字段存在。

---

### STEP 1.3: 实现自定义规则加载 `--rules-dir`

**目的**: 允许用户通过 `--rules-dir` 参数加载额外的 YAML 规则。

**文件**: 
- `packages/audit/agent_audit/cli/commands/scan.py`
- `packages/audit/agent_audit/rules/loader.py`

**操作**:

1. 在 `scan` 命令中新增 `--rules-dir` 参数:

```python
@click.option('--rules-dir', type=click.Path(exists=True, file_okay=False),
              help='Directory containing custom YAML rule files')
```

2. 在 `loader.py` 中实现目录加载:

```python
def load_rules_from_directory(self, rules_dir: Path) -> List[Rule]:
    """从指定目录加载所有 .yaml/.yml 规则文件"""
    rules = []
    for yaml_file in sorted(rules_dir.glob('*.yaml')):
        try:
            loaded = self._load_yaml_file(yaml_file)
            rules.extend(loaded)
            logger.info(f"Loaded {len(loaded)} rules from {yaml_file}")
        except Exception as e:
            logger.warning(f"Failed to load rules from {yaml_file}: {e}")
    for yml_file in sorted(rules_dir.glob('*.yml')):
        try:
            loaded = self._load_yaml_file(yml_file)
            rules.extend(loaded)
        except Exception as e:
            logger.warning(f"Failed to load rules from {yml_file}: {e}")
    return rules

def _load_yaml_file(self, path: Path) -> List[Rule]:
    """加载单个 YAML 规则文件"""
    import yaml
    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not data:
        return []
    # 支持单条规则（dict）和多条规则（list）
    if isinstance(data, dict):
        data = data.get('rules', [data])
    elif not isinstance(data, list):
        return []
    return [self._parse_rule(r) for r in data if isinstance(r, dict)]
```

3. 在 `scan.py` 的 `run_scan` 函数中，将自定义规则与内置规则合并:

```python
# 加载内置规则
rules = rule_loader.load_builtin_rules()

# 加载自定义规则（如指定）
if rules_dir:
    custom_rules = rule_loader.load_rules_from_directory(Path(rules_dir))
    rules.extend(custom_rules)
    if not quiet:
        console.print(f"[dim]Loaded {len(custom_rules)} custom rules from {rules_dir}[/dim]")
```

**验收**:
```bash
# 创建临时规则目录
mkdir /tmp/custom-rules
cat > /tmp/custom-rules/test-rule.yaml << 'EOF'
rules:
  - id: CUSTOM-001
    name: "Test Custom Rule"
    description: "Test rule for validation"
    severity: low
    category: prompt_injection
    owasp_agentic_id: ASI-01
    detection:
      type: ast
      patterns:
        - "test_pattern"
    remediation:
      description: "This is a test"
EOF

agent-audit scan . --rules-dir /tmp/custom-rules
# 应显示 "Loaded 1 custom rules from /tmp/custom-rules"
```

---

## 阶段 2: ASI-01 Agent Goal Hijack 规则实现（预计 3-4 小时）

### STEP 2.1: 创建 OWASP Agentic 规则文件

**目的**: 创建新的 YAML 规则文件 `rules/builtin/owasp_agentic_v2.yaml`，容纳所有新增规则。

**文件**: `rules/builtin/owasp_agentic_v2.yaml`

**操作**: 创建文件，先写入 ASI-01 相关规则:

```yaml
# OWASP Agentic Top 10 (2026) — Extended Rules
# Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

# =============================================================================
# ASI-01: Agent Goal Hijack
# 攻击者通过恶意输入篡改 Agent 的目标、决策逻辑或任务选择。
# 与传统 prompt injection 不同，Goal Hijack 影响的是 Agent 的多步规划行为。
# =============================================================================

rules:

  - id: AGENT-010
    name: "System Prompt Injection Vector in User Input Path"
    description: >
      User-controlled input is concatenated directly into system prompts or
      agent instructions without sanitization. This enables Agent Goal Hijack
      (ASI-01) where attackers can redirect the agent's planning and objectives.
    severity: critical
    category: goal_hijack
    owasp_agentic_id: "ASI-01"
    cwe_id: "CWE-77"
    confidence: 0.85
    detection:
      type: ast
      patterns:
        # f-string 拼接 system prompt
        - pattern_type: "function_arg_fstring"
          function_names:
            - "ChatPromptTemplate.from_messages"
            - "SystemMessage"
            - "SystemMessagePromptTemplate"
            - "HumanMessagePromptTemplate.from_template"
          arg_contains_fstring: true
          context: "system_prompt"

        # 字符串拼接构造 prompt
        - pattern_type: "string_concat_to_prompt"
          target_variables:
            - "system_prompt"
            - "system_message"
            - "instructions"
            - "system_instructions"
            - "agent_prompt"
          operations:
            - "format"
            - "+"
            - "f-string"
            - ".join"

        # 直接将 user_input 传入 prompt 模板
        - pattern_type: "unsanitized_template_variable"
          template_functions:
            - "PromptTemplate"
            - "ChatPromptTemplate"
          dangerous_variable_sources:
            - "request"
            - "user_input"
            - "query"
            - "message"
            - "input"
    remediation:
      description: >
        Never concatenate user input directly into system prompts.
        Use structured prompt templates with clear separation between
        system instructions and user data. Implement input validation
        and sanitization before passing to any prompt template.
      code_example: |
        # BAD: Direct concatenation
        prompt = f"You are an agent. User says: {user_input}"

        # GOOD: Structured separation
        messages = [
            SystemMessage(content="You are a helpful agent."),
            HumanMessage(content=sanitize(user_input))
        ]
      reference_url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
    metadata:
      introduced_in: "v0.2.0"
      references:
        - "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
        - "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

  - id: AGENT-011
    name: "Missing Goal Validation / Instruction Boundary"
    description: >
      Agent configuration lacks explicit goal boundaries or instruction
      immutability controls. Without 'Intent Capsule' patterns or goal
      validation, the agent's objectives can be silently redirected via
      poisoned documents, emails, or tool outputs (ASI-01).
    severity: high
    category: goal_hijack
    owasp_agentic_id: "ASI-01"
    confidence: 0.7
    detection:
      type: config
      patterns:
        # Agent 框架配置缺少 goal boundary
        - pattern_type: "missing_config_key"
          config_contexts:
            - framework: "langchain"
              required_keys:
                - "allowed_tools"
                - "max_iterations"
            - framework: "crewai"
              required_keys:
                - "goal"
                - "backstory"
                - "max_iter"
            - framework: "autogen"
              required_keys:
                - "system_message"
                - "max_consecutive_auto_reply"

        # Agent 配置中缺少 input validation
        - pattern_type: "agent_without_input_guard"
          indicators:
            - "AgentExecutor"
            - "initialize_agent"
            - "Agent("
          missing_guards:
            - "input_validator"
            - "input_filter"
            - "input_guard"
            - "prompt_guard"
    remediation:
      description: >
        Implement explicit goal boundaries for all agents. Use immutable
        system instructions, define allowed_tools explicitly, set
        max_iterations, and add input validation before agent execution.
      code_example: |
        # GOOD: Explicit boundaries
        agent = AgentExecutor(
            agent=agent,
            tools=allowed_tools_only,
            max_iterations=10,
            handle_parsing_errors=True,
            early_stopping_method="generate",
        )
      reference_url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
```

---

### STEP 2.2: 实现 AST 检测逻辑 — Prompt Injection Vector Detector

**目的**: 在 Python Scanner 中增加检测逻辑，识别 system prompt 中的用户输入拼接。

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

**操作**: 在 `PythonASTVisitor` 类中添加以下检测方法:

```python
# 在 PythonASTVisitor.__init__ 中新增:
self.prompt_injection_findings: List[Dict[str, Any]] = []

# 新增: Prompt 相关函数名
PROMPT_FUNCTIONS = {
    'SystemMessage', 'HumanMessage', 'AIMessage',
    'ChatPromptTemplate', 'PromptTemplate',
    'SystemMessagePromptTemplate',
    'from_messages', 'from_template',
}

# 新增: 表示 system prompt 的变量名模式
SYSTEM_PROMPT_VARNAMES = {
    'system_prompt', 'system_message', 'instructions',
    'system_instructions', 'agent_prompt', 'system_content',
    'sys_prompt', 'base_prompt',
}

def _check_prompt_injection_vector(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测 prompt 函数中是否包含 f-string 或用户输入变量"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    # 检查是否是 prompt 相关函数
    is_prompt_func = any(pf in func_name for pf in self.PROMPT_FUNCTIONS)
    if not is_prompt_func:
        return None

    # 检查参数中是否有 f-string（JoinedStr）
    for arg in node.args:
        if isinstance(arg, ast.JoinedStr):
            return {
                'type': 'prompt_injection_fstring',
                'function': func_name,
                'line': node.lineno,
                'snippet': self._get_line(node.lineno),
                'risk': 'User input may be interpolated into prompt via f-string',
            }

    # 检查 keyword 参数中的 f-string
    for kw in node.keywords:
        if kw.arg in ('content', 'template', 'messages', 'system_message'):
            if isinstance(kw.value, ast.JoinedStr):
                return {
                    'type': 'prompt_injection_fstring_kwarg',
                    'function': func_name,
                    'keyword': kw.arg,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                }

    # 检查 .format() 调用
    for arg in node.args:
        if isinstance(arg, ast.Call):
            inner_name = self._get_call_name(arg)
            if inner_name and inner_name.endswith('.format'):
                return {
                    'type': 'prompt_injection_format',
                    'function': func_name,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                }

    return None

def _check_system_prompt_concat(self, node: ast.Assign) -> Optional[Dict[str, Any]]:
    """检测 system_prompt 变量是否通过字符串拼接构造"""
    # 获取赋值目标变量名
    for target in node.targets:
        if isinstance(target, ast.Name):
            varname = target.id.lower()
            if varname not in self.SYSTEM_PROMPT_VARNAMES:
                continue

            # 检查是否使用 f-string
            if isinstance(node.value, ast.JoinedStr):
                return {
                    'type': 'system_prompt_fstring',
                    'variable': target.id,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                }

            # 检查是否使用 + 拼接
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                return {
                    'type': 'system_prompt_concat',
                    'variable': target.id,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                }

            # 检查是否使用 .format()
            if isinstance(node.value, ast.Call):
                call_name = self._get_call_name(node.value)
                if call_name and call_name.endswith('.format'):
                    return {
                        'type': 'system_prompt_format',
                        'variable': target.id,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno),
                    }
    return None
```

然后在 `visit_Call` 中调用 `_check_prompt_injection_vector`，在新增的 `visit_Assign` 中调用 `_check_system_prompt_concat`:

```python
def visit_Call(self, node: ast.Call):
    # ... 现有逻辑 ...

    # 新增: 检测 prompt injection vector
    pi_finding = self._check_prompt_injection_vector(node)
    if pi_finding:
        self.prompt_injection_findings.append(pi_finding)

    self.generic_visit(node)

def visit_Assign(self, node: ast.Assign):
    """检测赋值语句中的安全问题"""
    # 检测 system prompt 拼接
    finding = self._check_system_prompt_concat(node)
    if finding:
        self.prompt_injection_findings.append(finding)

    self.generic_visit(node)
```

**测试用例** — 创建 `tests/fixtures/vulnerable_agents/goal_hijack.py`:

```python
"""Test fixture: Agent Goal Hijack vulnerabilities (ASI-01)"""

from langchain.prompts import ChatPromptTemplate, SystemMessagePromptTemplate
from langchain.schema import SystemMessage, HumanMessage

# VULNERABLE: f-string in system prompt
def create_agent_bad_1(user_input):
    system_prompt = f"You are a helpful agent. The user wants: {user_input}"
    return SystemMessage(content=system_prompt)

# VULNERABLE: .format() in prompt template
def create_agent_bad_2(user_goal):
    template = "You are an agent with goal: {}".format(user_goal)
    return SystemMessage(content=template)

# VULNERABLE: f-string directly in SystemMessage
def create_agent_bad_3(instructions):
    return SystemMessage(content=f"Follow these instructions: {instructions}")

# VULNERABLE: string concatenation
def create_agent_bad_4(user_input):
    system_prompt = "You are an agent. " + user_input
    return system_prompt

# SAFE: hardcoded system prompt
def create_agent_good_1():
    return SystemMessage(content="You are a helpful agent.")

# SAFE: structured separation
def create_agent_good_2(user_input):
    messages = [
        SystemMessage(content="You are a helpful agent."),
        HumanMessage(content=user_input),
    ]
    return messages
```

**验收**: 运行 `agent-audit scan tests/fixtures/vulnerable_agents/goal_hijack.py`，应报告 4 个 findings（bad_1 到 bad_4），0 个 finding 对 good_1 和 good_2。

---

## 阶段 3: ASI-03 Identity & Privilege Abuse（预计 2-3 小时）

### STEP 3.1: 新增 AGENT-013, AGENT-014 规则

**文件**: `rules/builtin/owasp_agentic_v2.yaml`（追加）

```yaml
  # =============================================================================
  # ASI-03: Identity and Privilege Abuse
  # Agent 滥用自身身份或继承其他服务的凭证进行权限提升。
  # Agent 是最危险的非人类身份 (NHI)，需要零信任身份管理。
  # =============================================================================

  - id: AGENT-013
    name: "Agent with Long-Lived or Shared Credentials"
    description: >
      Agent uses long-lived API keys, shared service accounts, or
      hardcoded tokens instead of short-lived, scoped credentials.
      This violates zero-trust identity principles and enables
      Identity & Privilege Abuse (ASI-03).
    severity: high
    category: identity_privilege_abuse
    owasp_agentic_id: "ASI-03"
    cwe_id: "CWE-798"
    confidence: 0.8
    detection:
      type: ast
      patterns:
        # 硬编码长期凭证传入 Agent 或 Tool
        - pattern_type: "hardcoded_credential_in_agent"
          indicators:
            - assignment_to:
                - "api_key"
                - "secret_key"
                - "access_token"
                - "service_account_key"
                - "bearer_token"
              value_is: "string_literal"
              context_near:
                - "Agent"
                - "Tool"
                - "LLM"
                - "ChatOpenAI"
                - "Anthropic"

        # 环境变量在 Agent 初始化时直接取用（无 scope/TTL）
        - pattern_type: "unscoped_env_credential"
          functions:
            - "os.environ.get"
            - "os.getenv"
          variable_names:
            - "API_KEY"
            - "SECRET_KEY"
            - "SERVICE_TOKEN"
          missing_patterns:
            - "token_expiry"
            - "credential_scope"
            - "session_token"
    remediation:
      description: >
        Use short-lived, session-scoped credentials for agents. Each agent
        should have its own unique identity. Implement credential rotation
        and scope credentials to the minimum required permissions.
      code_example: |
        # BAD: Long-lived shared credential
        agent = Agent(api_key="sk-hardcoded-key-123")

        # GOOD: Short-lived scoped credential
        credential = get_scoped_credential(
            scope="read:documents",
            ttl=timedelta(minutes=15)
        )
        agent = Agent(credential=credential)
      reference_url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"

  - id: AGENT-014
    name: "Overly Permissive Agent Role / Tool Access"
    description: >
      Agent is configured with overly broad tool access or admin-level
      permissions when it only needs a subset. Violates the Least-Agency
      principle (ASI-03).
    severity: high
    category: identity_privilege_abuse
    owasp_agentic_id: "ASI-03"
    confidence: 0.75
    detection:
      type: ast
      patterns:
        # tools=ALL 或 tools 列表包含高危工具组合
        - pattern_type: "excessive_tool_grant"
          indicators:
            dangerous_tool_combinations:
              - ["file_read", "network_outbound"]
              - ["shell_exec", "network_outbound"]
              - ["database_write", "shell_exec"]
              - ["file_write", "file_delete", "shell_exec"]
            tool_count_threshold: 10  # 超过 10 个工具告警

        # Agent 使用 trust-all 或 auto-approve 模式
        - pattern_type: "auto_approval_pattern"
          keywords:
            - "trust_all_tools"
            - "auto_approve"
            - "no_confirm"
            - "skip_approval"
            - "--dangerously-skip-permissions"
            - "handle_tool_error=True"  # 结合无限循环
    remediation:
      description: >
        Apply Least-Agency principle: grant agents only the minimum tools
        and permissions needed for their specific task. Review tool lists
        regularly and remove unnecessary capabilities.
```

### STEP 3.2: 实现 AST 检测逻辑

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

**在 PythonASTVisitor 中新增**:

```python
# 自动审批模式关键词
AUTO_APPROVAL_KEYWORDS = {
    'trust_all_tools', 'auto_approve', 'no_confirm',
    'skip_approval', 'dangerously_skip_permissions',
    'no_interactive', 'trust_all',
}

def _check_auto_approval(self, node: ast.keyword) -> Optional[Dict[str, Any]]:
    """检测 Agent 配置中的自动审批模式"""
    if not node.arg:
        return None
    arg_lower = node.arg.lower().replace('-', '_')
    if arg_lower in self.AUTO_APPROVAL_KEYWORDS:
        if isinstance(node.value, ast.Constant) and node.value.value is True:
            return {
                'type': 'auto_approval',
                'keyword': node.arg,
                'line': node.lineno if hasattr(node, 'lineno') else 0,
            }
    return None

def _check_excessive_tools(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测 Agent 是否被赋予过多工具"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    # 检查是否是 Agent 初始化函数
    agent_init_funcs = {
        'AgentExecutor', 'initialize_agent', 'Agent',
        'create_react_agent', 'create_openai_functions_agent',
        'CrewAI', 'Crew',
    }
    if not any(af in func_name for af in agent_init_funcs):
        return None

    # 检查 tools 参数
    for kw in node.keywords:
        if kw.arg == 'tools':
            if isinstance(kw.value, ast.List) and len(kw.value.elts) > 10:
                return {
                    'type': 'excessive_tools',
                    'function': func_name,
                    'tool_count': len(kw.value.elts),
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                }

        # 检测 auto_approval
        approval = self._check_auto_approval(kw)
        if approval:
            self.dangerous_patterns.append({
                **approval,
                'function': func_name,
                'snippet': self._get_line(node.lineno),
            })

    return None
```

**测试用例** — `tests/fixtures/vulnerable_agents/privilege_abuse.py`:

```python
"""Test fixture: Identity & Privilege Abuse (ASI-03)"""

# VULNERABLE: Hardcoded long-lived credential
agent = Agent(api_key="sk-prod-12345-long-lived-key")

# VULNERABLE: Too many tools
agent2 = AgentExecutor(
    agent=base_agent,
    tools=[tool1, tool2, tool3, tool4, tool5, tool6, tool7, tool8, tool9, tool10, tool11],
)

# VULNERABLE: Auto-approval mode
agent3 = AgentExecutor(agent=base_agent, tools=tools, trust_all_tools=True)

# SAFE: Scoped credential
credential = get_scoped_credential(scope="read:docs", ttl=900)
agent4 = Agent(credential=credential)

# SAFE: Limited tools
agent5 = AgentExecutor(agent=base_agent, tools=[search_tool, calculator_tool])
```

---

## 阶段 4: ASI-04 Supply Chain + ASI-05 RCE（预计 3 小时）

### STEP 4.1: ASI-04 Supply Chain 规则（加强现有 AGENT-005）

**文件**: `rules/builtin/owasp_agentic_v2.yaml`（追加）

```yaml
  # =============================================================================
  # ASI-04: Agentic Supply Chain Vulnerabilities
  # Agent 依赖的外部组件（第三方 API、模型、RAG 数据源、MCP server）存在风险。
  # 关键点：供应链不仅包括代码，还包括数据和模型。
  # =============================================================================

  - id: AGENT-015
    name: "Untrusted MCP Server Source"
    description: >
      MCP server is loaded from an unverified source without integrity
      verification. Malicious MCP servers on npm have been documented
      in the wild (ASI-04).
    severity: critical
    category: supply_chain_agentic
    owasp_agentic_id: "ASI-04"
    cwe_id: "CWE-494"
    confidence: 0.85
    detection:
      type: config
      patterns:
        # npx 执行未固定版本的包
        - pattern_type: "npx_unfixed_version"
          in_config_keys:
            - "mcpServers"
            - "servers"
          command_patterns:
            - regex: "npx\\s+(-y\\s+)?(?!@modelcontextprotocol/)\\S+"
              description: "npx running non-official MCP package"
            - regex: "npx\\s+.*@latest"
              description: "npx with @latest tag (unpinned version)"

        # 缺少完整性校验
        - pattern_type: "missing_integrity_check"
          missing_keys:
            - "hash"
            - "integrity"
            - "checksum"
            - "sha256"

        # 从非官方来源加载 MCP server
        - pattern_type: "unofficial_mcp_source"
          untrusted_indicators:
            - "github.com"  # 直接从 GitHub clone 运行
            - "file://"
            - "http://"  # 非 HTTPS
    remediation:
      description: >
        Pin MCP server versions explicitly. Verify integrity with checksums.
        Only use MCP servers from trusted registries or official sources.
        Audit MCP server code before deploying.
      code_example: |
        // BAD: Unpinned, unknown source
        "mcpServers": {
          "risky": { "command": "npx", "args": ["-y", "some-unknown-package"] }
        }

        // GOOD: Pinned version, official source
        "mcpServers": {
          "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]
          }
        }
      reference_url: "https://www.bleepingcomputer.com/news/security/the-real-world-attacks-behind-owasp-agentic-ai-top-10/"

  - id: AGENT-016
    name: "Unvalidated RAG Data Source"
    description: >
      Agent's RAG pipeline ingests data from external sources without
      integrity validation or provenance tracking. Poisoned RAG data
      can silently corrupt agent decisions (ASI-04).
    severity: high
    category: supply_chain_agentic
    owasp_agentic_id: "ASI-04"
    confidence: 0.7
    detection:
      type: ast
      patterns:
        # 直接加载外部 URL 到向量数据库
        - pattern_type: "unvalidated_rag_ingestion"
          functions:
            - "WebBaseLoader"
            - "UnstructuredURLLoader"
            - "DirectoryLoader"
            - "CSVLoader"
            - "PyPDFLoader"
          missing_validation:
            - "validate_source"
            - "check_integrity"
            - "verify_checksum"
          chained_to:
            - "add_documents"
            - "from_documents"
            - "add_texts"
            - "upsert"
    remediation:
      description: >
        Validate all RAG data sources before ingestion. Implement data
        integrity checks, maintain data lineage, and regularly audit
        vector store contents for poisoned entries.
```

### STEP 4.2: ASI-05 Unexpected Code Execution 规则

**文件**: `rules/builtin/owasp_agentic_v2.yaml`（追加）

```yaml
  # =============================================================================
  # ASI-05: Unexpected Code Execution (RCE)
  # Agent 被操纵生成并执行恶意代码。这是 ASI-02 (Tool Misuse) 的特殊且高危形式。
  # 核心防御：硬件级沙箱 + 代码静态分析。
  # =============================================================================

  - id: AGENT-017
    name: "Unsandboxed Code Execution in Agent"
    description: >
      Agent executes dynamically generated code (via eval, exec,
      subprocess, or code interpreter tools) without sandbox isolation.
      This enables RCE attacks where manipulated prompts lead to
      arbitrary code execution on the host system (ASI-05).
    severity: critical
    category: unexpected_code_execution
    owasp_agentic_id: "ASI-05"
    cwe_id: "CWE-94"
    confidence: 0.9
    detection:
      type: ast
      patterns:
        # eval/exec 在 @tool 函数内或 Agent 上下文中
        - pattern_type: "dynamic_exec_in_agent"
          functions:
            - "eval"
            - "exec"
            - "compile"
          context:
            - inside_tool_decorator: true
            - inside_agent_class: true

        # subprocess 无沙箱保护
        - pattern_type: "subprocess_without_sandbox"
          functions:
            - "subprocess.run"
            - "subprocess.Popen"
            - "subprocess.call"
            - "os.system"
            - "os.popen"
          missing_guards:
            - "docker"
            - "sandbox"
            - "seccomp"
            - "apparmor"
            - "nsjail"
            - "firejail"
            - "--read-only"
            - "restricted"

        # Code interpreter 工具无隔离
        - pattern_type: "code_interpreter_no_sandbox"
          tool_names:
            - "PythonREPLTool"
            - "PythonAstREPLTool"
            - "ShellTool"
            - "BashTool"
            - "code_interpreter"
          missing_config:
            - "sandbox"
            - "docker"
            - "isolation"
            - "restricted"
    remediation:
      description: >
        NEVER execute LLM-generated code on the host system without
        hardware-enforced sandbox isolation. Use Docker containers with
        read-only filesystems, disabled networking, and resource limits.
        Apply static analysis to generated code before execution.
      code_example: |
        # BAD: Direct execution
        @tool
        def run_code(code: str):
            exec(code)  # RCE vulnerability

        # GOOD: Sandboxed execution
        @tool
        def run_code(code: str):
            result = docker_sandbox.execute(
                code, timeout=30, network=False, read_only=True
            )
            return result
```

### STEP 4.3: 实现 Config Scanner 增强（MCP 供应链检测）

**文件**: `packages/audit/agent_audit/scanners/config_scanner.py`

**操作**: 在现有 config scanner 中增加 MCP 供应链检测：

```python
import re

def _check_mcp_supply_chain(self, config_data: dict, file_path: str) -> List[Finding]:
    """检测 MCP 配置中的供应链风险"""
    findings = []

    # 寻找 mcpServers 配置段
    mcp_servers = config_data.get('mcpServers', {})
    if not mcp_servers:
        # 尝试 Docker MCP Gateway 格式
        mcp_servers = config_data.get('servers', {})

    for server_name, server_config in mcp_servers.items():
        command = server_config.get('command', '')
        args = server_config.get('args', [])
        full_command = f"{command} {' '.join(str(a) for a in args)}"

        # 检测 1: npx 运行非官方包
        if 'npx' in command:
            # 检查是否使用了 -y (auto-confirm)
            if '-y' in args or '--yes' in args:
                # 检查是否是非官方包
                for arg in args:
                    if isinstance(arg, str) and not arg.startswith('-'):
                        if not arg.startswith('@modelcontextprotocol/'):
                            findings.append(self._create_finding(
                                rule_id="AGENT-015",
                                title="Untrusted MCP Server Source",
                                description=f"MCP server '{server_name}' uses npx to run "
                                           f"non-official package '{arg}' with auto-confirm",
                                severity=Severity.CRITICAL,
                                category=Category.SUPPLY_CHAIN_AGENTIC,
                                file_path=file_path,
                                owasp_id="ASI-04",
                            ))

            # 检查是否使用 @latest 或无版本号
            for arg in args:
                if isinstance(arg, str) and '@latest' in arg:
                    findings.append(self._create_finding(
                        rule_id="AGENT-015",
                        title="Unpinned MCP Server Version",
                        description=f"MCP server '{server_name}' uses @latest tag. "
                                   f"Pin to a specific version for supply chain safety.",
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN_AGENTIC,
                        file_path=file_path,
                        owasp_id="ASI-04",
                    ))

        # 检测 2: HTTP (非 HTTPS)
        if 'http://' in full_command:
            findings.append(self._create_finding(
                rule_id="AGENT-015",
                title="MCP Server over Insecure HTTP",
                description=f"MCP server '{server_name}' communicates over "
                           f"insecure HTTP. Use HTTPS.",
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN_AGENTIC,
                file_path=file_path,
                owasp_id="ASI-04",
            ))

    return findings
```

**测试用例** — `tests/fixtures/mcp_configs/supply_chain_vulnerable.json`:

```json
{
  "mcpServers": {
    "risky-server": {
      "command": "npx",
      "args": ["-y", "some-unknown-mcp-package"]
    },
    "unpinned": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@latest"]
    },
    "insecure": {
      "command": "node",
      "args": ["http://some-server.com/mcp.js"]
    },
    "safe-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.0", "/tmp"]
    }
  }
}
```

**验收**: 扫描应在前 3 个 server 报告 findings，`safe-server` 不报告。

---

## 阶段 5: ASI-06 Memory Poisoning（预计 2-3 小时）

### STEP 5.1: 规则定义

**文件**: `rules/builtin/owasp_agentic_v2.yaml`（追加）

```yaml
  # =============================================================================
  # ASI-06: Memory & Context Poisoning
  # 攻击者通过注入恶意数据到 Agent 的长期记忆（向量数据库、知识图谱）中，
  # 使 Agent 在没有主动攻击时也表现出错误或恶意行为。
  # 关键区别：这是持久性腐蚀，不同于 ASI-01 的瞬时目标劫持。
  # =============================================================================

  - id: AGENT-018
    name: "Unsanitized Input to Persistent Memory"
    description: >
      User or external input is written to the agent's persistent memory
      (vector database, knowledge graph, conversation store) without
      sanitization or validation. This enables Memory Poisoning (ASI-06)
      where malicious data persists across sessions.
    severity: critical
    category: memory_poisoning
    owasp_agentic_id: "ASI-06"
    cwe_id: "CWE-20"
    confidence: 0.8
    detection:
      type: ast
      patterns:
        # 用户输入直接写入向量数据库
        - pattern_type: "unsanitized_memory_write"
          write_functions:
            - "add_documents"
            - "add_texts"
            - "upsert"
            - "insert"
            - "persist"
            - "save_context"
            - "add_message"
            - "add_memory"
            - "store"
          source_indicators:
            - "user_input"
            - "message"
            - "query"
            - "request"
            - "input"
          missing_between:
            - "sanitize"
            - "validate"
            - "filter"
            - "clean"
            - "escape"
    remediation:
      description: >
        Sanitize and validate ALL data before writing to persistent memory.
        Implement integrity checks on stored data. Use version control
        for memory stores to enable rollback if poisoning is detected.
      code_example: |
        # BAD: Direct write
        vectorstore.add_texts([user_input])

        # GOOD: Sanitized write with validation
        sanitized = sanitize_for_storage(user_input)
        if validate_content(sanitized):
            vectorstore.add_texts([sanitized], metadata={"source": "user", "timestamp": now()})

  - id: AGENT-019
    name: "Conversation History Without Integrity Protection"
    description: >
      Agent stores and retrieves conversation history without integrity
      protection, versioning, or expiration. An attacker can poison
      conversation context to influence future agent behavior (ASI-06).
    severity: medium
    category: memory_poisoning
    owasp_agentic_id: "ASI-06"
    confidence: 0.65
    detection:
      type: ast
      patterns:
        # ConversationBufferMemory 等无限制存储
        - pattern_type: "unbounded_memory"
          classes:
            - "ConversationBufferMemory"
            - "ConversationBufferWindowMemory"
            - "ConversationSummaryMemory"
          missing_config:
            - "k="              # 窗口限制
            - "max_token_limit"
            - "return_messages=False"
        
        # 会话历史无过期时间
        - pattern_type: "memory_without_expiry"
          indicators:
            - "RedisChatMessageHistory"
            - "MongoDBChatMessageHistory"
            - "FileChatMessageHistory"
          missing_config:
            - "ttl"
            - "expiry"
            - "max_age"
            - "session_timeout"
    remediation:
      description: >
        Implement bounded memory with explicit window sizes or TTL.
        Add integrity checksums to stored conversation history.
        Implement session-based isolation to prevent cross-session pollution.
```

### STEP 5.2: 实现 AST 检测逻辑

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

**新增检测方法**:

```python
# 向量数据库写入函数
MEMORY_WRITE_FUNCTIONS = {
    'add_documents', 'add_texts', 'upsert', 'insert',
    'persist', 'save_context', 'add_message', 'add_memory',
    'store', 'put', 'set',
}

# 无界记忆类名
UNBOUNDED_MEMORY_CLASSES = {
    'ConversationBufferMemory',
    'ConversationSummaryMemory',
    'ChatMessageHistory',
}

def _check_memory_poisoning(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测向量数据库/记忆存储的未消毒写入"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    # 提取方法名（最后一个 . 后的部分）
    method_name = func_name.split('.')[-1] if '.' in func_name else func_name

    if method_name not in self.MEMORY_WRITE_FUNCTIONS:
        return None

    # 检查参数是否包含可能的用户输入（变量引用而非常量）
    has_variable_input = False
    for arg in node.args:
        if isinstance(arg, (ast.Name, ast.Subscript, ast.Attribute)):
            has_variable_input = True
            break
        if isinstance(arg, ast.List):
            for elt in arg.elts:
                if isinstance(elt, (ast.Name, ast.Subscript, ast.Attribute)):
                    has_variable_input = True
                    break

    if has_variable_input:
        return {
            'type': 'unsanitized_memory_write',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
        }

    return None

def _check_unbounded_memory(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测无界/无限制的记忆配置"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    if func_name not in self.UNBOUNDED_MEMORY_CLASSES:
        return None

    # 检查是否设置了窗口大小或限制
    has_limit = False
    for kw in node.keywords:
        if kw.arg in ('k', 'max_token_limit', 'max_history', 'window_size'):
            has_limit = True
            break

    if not has_limit:
        return {
            'type': 'unbounded_memory',
            'class': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
        }

    return None
```

**测试用例** — `tests/fixtures/vulnerable_agents/memory_poisoning.py`:

```python
"""Test fixture: Memory & Context Poisoning (ASI-06)"""

from langchain.memory import ConversationBufferMemory
from langchain.vectorstores import Chroma

# VULNERABLE: Direct user input to vector store
def store_user_data(vectorstore, user_input):
    vectorstore.add_texts([user_input])

# VULNERABLE: Unbounded memory
memory = ConversationBufferMemory()

# SAFE: Bounded memory
memory_safe = ConversationBufferMemory(k=10)

# SAFE: Sanitized input
def store_user_data_safe(vectorstore, user_input):
    sanitized = sanitize(user_input)
    vectorstore.add_texts([sanitized])
```

---

## 阶段 6: ASI-07 + ASI-08 + ASI-09 + ASI-10（预计 4-5 小时）

### STEP 6.1: ASI-07 Insecure Inter-Agent Communication

**文件**: `rules/builtin/owasp_agentic_v2.yaml`（追加）

```yaml
  # =============================================================================
  # ASI-07: Insecure Inter-Agent Communication
  # 多 Agent 系统中，Agent 之间的通信通道易受拦截、伪造或重放攻击。
  # 多 Agent 系统本质上是分布式系统，必须按分布式系统安全标准保护。
  # =============================================================================

  - id: AGENT-020
    name: "Unencrypted or Unauthenticated Inter-Agent Channel"
    description: >
      Multi-agent system communicates over unencrypted channels or without
      mutual authentication. Agents trust other agents based on network
      location alone, enabling impersonation and message tampering (ASI-07).
    severity: high
    category: insecure_inter_agent_comm
    owasp_agentic_id: "ASI-07"
    cwe_id: "CWE-319"
    confidence: 0.7
    detection:
      type: composite
      patterns:
        # 多 Agent 框架配置无认证
        - pattern_type: "multi_agent_no_auth"
          framework_patterns:
            - class_names: ["GroupChat", "GroupChatManager", "ConversableAgent"]
              framework: "autogen"
              missing_config: ["authentication", "tls", "verify"]
            - class_names: ["Crew", "Agent"]
              framework: "crewai"
              missing_config: ["auth", "secure_channel"]

        # HTTP 通信无 TLS
        - pattern_type: "agent_comm_no_tls"
          url_patterns:
            - "http://"
          context_keywords:
            - "agent"
            - "delegate"
            - "handoff"
            - "message"

        # 无消息签名/验证
        - pattern_type: "no_message_verification"
          missing_patterns:
            - "verify_signature"
            - "hmac"
            - "sign_message"
            - "mutual_tls"
            - "mTLS"
    remediation:
      description: >
        Apply mutual TLS (mTLS) to all inter-agent communication.
        Cryptographically sign all messages between agents.
        Never trust agent identity based on network location alone.
```

### STEP 6.2: ASI-08 Cascading Failures

```yaml
  # =============================================================================
  # ASI-08: Cascading Failures
  # 一个组件的小故障触发连锁反应，导致系统级不可控失败。
  # Agent 的 planner 可能在尝试恢复时执行越来越危险的操作。
  # 这是弹性和架构漏洞，不一定需要恶意意图。
  # =============================================================================

  - id: AGENT-021
    name: "Missing Circuit Breaker / Max Iterations"
    description: >
      Agent loop lacks circuit breaker, max iteration limit, or error
      budget. A minor tool failure can trigger infinite retry loops or
      increasingly destructive recovery attempts (ASI-08).
    severity: high
    category: cascading_failures
    owasp_agentic_id: "ASI-08"
    confidence: 0.85
    detection:
      type: ast
      patterns:
        # AgentExecutor 无 max_iterations
        - pattern_type: "agent_without_iteration_limit"
          agent_constructors:
            - "AgentExecutor"
            - "initialize_agent"
            - "create_react_agent"
          missing_params:
            - "max_iterations"
            - "max_execution_time"
            - "max_steps"
            - "timeout"

        # while True 循环在 Agent 上下文中
        - pattern_type: "unbounded_agent_loop"
          loop_patterns:
            - "while True"
            - "while 1"
          context_near:
            - "tool"
            - "agent"
            - "llm"
            - "invoke"
            - "run"
          missing_break_conditions:
            - "max_retries"
            - "break"
            - "timeout"
    remediation:
      description: >
        Always configure max_iterations, max_execution_time, and error
        budgets for agent loops. Implement circuit breaker patterns that
        pause execution and seek human intervention on repeated failures.
      code_example: |
        # BAD: No limits
        agent = AgentExecutor(agent=agent, tools=tools)

        # GOOD: Explicit limits
        agent = AgentExecutor(
            agent=agent, tools=tools,
            max_iterations=15,
            max_execution_time=300,
            handle_parsing_errors=True,
            early_stopping_method="generate",
        )

  - id: AGENT-022
    name: "No Error Handling in Tool Execution"
    description: >
      Agent tool functions lack error handling, causing unhandled
      exceptions to propagate and potentially trigger cascading failures
      across the agent's execution pipeline (ASI-08).
    severity: medium
    category: cascading_failures
    owasp_agentic_id: "ASI-08"
    confidence: 0.7
    detection:
      type: ast
      patterns:
        - pattern_type: "tool_without_error_handling"
          indicators:
            - has_tool_decorator: true
            - missing_try_except: true
            - calls_external: true  # 调用网络/文件/子进程
    remediation:
      description: >
        Wrap all tool function bodies in try/except with graceful error
        messages. Never let raw exceptions propagate to the agent planner.
```

### STEP 6.3: ASI-09 Human-Agent Trust Exploitation

```yaml
  # =============================================================================
  # ASI-09: Human-Agent Trust Exploitation
  # 攻击者操纵 Agent 的输出来欺骗人类用户，使其绕过安全控制或批准恶意操作。
  # 本质上是利用人类对 Agent 的信任来进行社会工程攻击。
  # =============================================================================

  - id: AGENT-023
    name: "Agent Output Without Transparency / Audit Trail"
    description: >
      Agent produces outputs or recommendations without exposing its
      reasoning chain, data sources, or tool invocations to the human
      reviewer. This makes human-in-the-loop a rubber stamp rather than
      a genuine review (ASI-09).
    severity: medium
    category: trust_exploitation
    owasp_agentic_id: "ASI-09"
    confidence: 0.6
    detection:
      type: ast
      patterns:
        # Agent 输出不包含推理过程
        - pattern_type: "opaque_agent_output"
          agent_patterns:
            - "AgentExecutor"
          missing_config:
            - "return_intermediate_steps=True"
            - "verbose=True"
            - "return_source_documents"
            - "include_reasoning"
    remediation:
      description: >
        Configure agents to return intermediate steps and reasoning.
        Make all data sources and tool invocations visible to human
        reviewers. The human-in-the-loop must be a critical review
        step, not a rubber stamp.
      code_example: |
        # GOOD: Transparent output
        agent = AgentExecutor(
            agent=agent, tools=tools,
            return_intermediate_steps=True,
            verbose=True,
        )
```

### STEP 6.4: ASI-10 Rogue Agents

```yaml
  # =============================================================================
  # ASI-10: Rogue Agents
  # 自主实体偏离预定目标或表现出未对齐行为，无需外部操纵。
  # 这是最纯粹的 agentic 威胁：自发的、自主的威胁，来自内部失调。
  # 关键防御：Kill switch + 行为监控 + 治理。
  # =============================================================================

  - id: AGENT-024
    name: "Agent Without Kill Switch / Shutdown Mechanism"
    description: >
      Agent operates without a kill switch or graceful shutdown mechanism.
      If the agent drifts from its intended purpose, there is no way to
      immediately halt its execution (ASI-10).
    severity: critical
    category: rogue_agent
    owasp_agentic_id: "ASI-10"
    confidence: 0.8
    detection:
      type: ast
      patterns:
        # Agent 无最大迭代/时间限制
        - pattern_type: "no_kill_switch"
          agent_constructors:
            - "AgentExecutor"
            - "Crew"
            - "AutoGen"
          combined_missing:
            - all_of:
                - "max_iterations"
                - "max_execution_time"
                - "timeout"
                - "early_stopping"

        # 后台运行的 Agent 无监控
        - pattern_type: "daemon_agent_no_monitor"
          indicators:
            - "daemon=True"
            - "background"
            - "schedule.every"
            - "while True"
          context:
            - "agent"
            - "crew"
          missing_patterns:
            - "health_check"
            - "heartbeat"
            - "monitor"
            - "watchdog"
    remediation:
      description: >
        Implement a non-negotiable, auditable kill switch for all agents.
        Set max_iterations and max_execution_time. For long-running agents,
        implement heartbeat monitoring and automatic shutdown on anomaly.
      code_example: |
        # GOOD: Agent with kill switch
        agent = AgentExecutor(
            agent=agent, tools=tools,
            max_iterations=25,
            max_execution_time=600,
            early_stopping_method="generate",
            callbacks=[KillSwitchCallback(max_cost=10.0)],
        )

  - id: AGENT-025
    name: "Agent Without Behavioral Monitoring / Logging"
    description: >
      Agent actions are not logged or monitored, making it impossible
      to detect behavioral drift or misaligned actions. Without
      observability, rogue behavior goes undetected (ASI-10).
    severity: high
    category: rogue_agent
    owasp_agentic_id: "ASI-10"
    confidence: 0.75
    detection:
      type: ast
      patterns:
        # Agent 配置无 callback / logging
        - pattern_type: "agent_without_observability"
          agent_constructors:
            - "AgentExecutor"
            - "initialize_agent"
            - "Crew"
          missing_all_of:
            - "callbacks"
            - "callback_manager"
            - "verbose"
            - "logging"
            - "tracer"
            - "langsmith"
            - "wandb"
    remediation:
      description: >
        Implement comprehensive logging of every agent decision, tool
        call, and state change. Establish behavioral baselines and
        alert on deviations. Use tracing tools like LangSmith or
        custom callbacks for full observability.
```

### STEP 6.5: 实现所有新增 AST 检测逻辑

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

将上述所有检测逻辑统一集成到 `visit_Call` 方法中:

```python
def visit_Call(self, node: ast.Call):
    func_name = self._get_call_name(node)

    if func_name:
        call_info = {
            'name': func_name,
            'line': node.lineno,
            'in_function': self._current_function
        }
        self.function_calls.append(call_info)

        # --- 现有检测 ---
        if func_name in PythonScanner.DANGEROUS_FUNCTIONS:
            # ... 现有逻辑 ...
            pass

        if func_name in ['subprocess.run', 'subprocess.Popen', 'subprocess.call']:
            if self._has_shell_true(node):
                # ... 现有逻辑 ...
                pass

        # --- 新增: OWASP Agentic 检测 ---

        # ASI-01: Prompt injection vector
        pi_finding = self._check_prompt_injection_vector(node)
        if pi_finding:
            self.prompt_injection_findings.append(pi_finding)

        # ASI-03: Excessive tools / auto-approval
        et_finding = self._check_excessive_tools(node)
        if et_finding:
            self.dangerous_patterns.append(et_finding)

        # ASI-05: Unsandboxed code execution in tool context
        if self._current_function and self._is_in_tool_context():
            if func_name in ('eval', 'exec', 'compile'):
                self.dangerous_patterns.append({
                    'type': 'unsandboxed_code_exec_in_tool',
                    'function': func_name,
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'owasp_id': 'ASI-05',
                })

        # ASI-06: Memory poisoning
        mem_finding = self._check_memory_poisoning(node)
        if mem_finding:
            self.dangerous_patterns.append(mem_finding)
        mem_unbound = self._check_unbounded_memory(node)
        if mem_unbound:
            self.dangerous_patterns.append(mem_unbound)

        # ASI-08: Missing circuit breaker
        cb_finding = self._check_missing_circuit_breaker(node)
        if cb_finding:
            self.dangerous_patterns.append(cb_finding)

        # ASI-10: Missing kill switch / observability
        ks_finding = self._check_missing_kill_switch(node)
        if ks_finding:
            self.dangerous_patterns.append(ks_finding)

    self.generic_visit(node)


def _is_in_tool_context(self) -> bool:
    """判断当前是否在 @tool 装饰的函数内"""
    # 需要在 visit_FunctionDef 中跟踪
    return getattr(self, '_in_tool_function', False)


def _check_missing_circuit_breaker(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测 AgentExecutor 是否缺少 max_iterations"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    agent_constructors = {'AgentExecutor', 'initialize_agent', 'create_react_agent'}
    if func_name not in agent_constructors:
        return None

    has_limit = False
    for kw in node.keywords:
        if kw.arg in ('max_iterations', 'max_execution_time', 'max_steps', 'timeout'):
            has_limit = True
            break

    if not has_limit:
        return {
            'type': 'missing_circuit_breaker',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-08',
        }
    return None


def _check_missing_kill_switch(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """检测 Agent 是否缺少 kill switch 和 observability"""
    func_name = self._get_call_name(node)
    if not func_name:
        return None

    agent_constructors = {'AgentExecutor', 'initialize_agent', 'Crew'}
    if func_name not in agent_constructors:
        return None

    kw_names = {kw.arg for kw in node.keywords if kw.arg}

    # ASI-10: 检查 kill switch（max_iterations + max_execution_time 同时缺失）
    kill_switch_params = {'max_iterations', 'max_execution_time', 'timeout', 'early_stopping_method'}
    has_kill_switch = bool(kw_names & kill_switch_params)

    # ASI-10: 检查 observability
    observability_params = {'callbacks', 'callback_manager', 'verbose'}
    has_observability = bool(kw_names & observability_params)

    findings = []
    if not has_kill_switch:
        return {
            'type': 'no_kill_switch',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-10',
        }
    if not has_observability:
        return {
            'type': 'no_observability',
            'function': func_name,
            'line': node.lineno,
            'snippet': self._get_line(node.lineno),
            'owasp_id': 'ASI-10',
        }
    return None
```

---

## 阶段 7: 规则引擎集成（预计 2-3 小时）

### STEP 7.1: 将新 YAML 规则与 Scanner 检测结果关联

**目的**: 确保 Scanner 发现的 pattern 能正确映射到对应的 YAML 规则并生成 Finding。

**文件**: `packages/audit/agent_audit/rules/engine.py`

**操作**:

1. 阅读现有 `engine.py` 的完整实现
2. 确保规则引擎能根据 scanner 输出的 `type` 字段匹配到对应 YAML 规则的 pattern
3. 新增 pattern type 到 rule ID 的映射表:

```python
# 在 RuleEngine 类中新增
PATTERN_TYPE_TO_RULE_MAP = {
    # ASI-01: Goal Hijack
    'prompt_injection_fstring': 'AGENT-010',
    'prompt_injection_fstring_kwarg': 'AGENT-010',
    'prompt_injection_format': 'AGENT-010',
    'system_prompt_fstring': 'AGENT-010',
    'system_prompt_concat': 'AGENT-010',
    'system_prompt_format': 'AGENT-010',
    'agent_without_input_guard': 'AGENT-011',

    # ASI-03: Identity & Privilege Abuse
    'hardcoded_credential_in_agent': 'AGENT-013',
    'excessive_tools': 'AGENT-014',
    'auto_approval': 'AGENT-014',

    # ASI-04: Supply Chain
    'npx_unfixed_version': 'AGENT-015',
    'unofficial_mcp_source': 'AGENT-015',
    'unvalidated_rag_ingestion': 'AGENT-016',

    # ASI-05: RCE
    'unsandboxed_code_exec_in_tool': 'AGENT-017',

    # ASI-06: Memory Poisoning
    'unsanitized_memory_write': 'AGENT-018',
    'unbounded_memory': 'AGENT-019',

    # ASI-07: Insecure Communication
    'multi_agent_no_auth': 'AGENT-020',
    'agent_comm_no_tls': 'AGENT-020',

    # ASI-08: Cascading Failures
    'missing_circuit_breaker': 'AGENT-021',
    'tool_without_error_handling': 'AGENT-022',

    # ASI-09: Trust Exploitation
    'opaque_agent_output': 'AGENT-023',

    # ASI-10: Rogue Agents
    'no_kill_switch': 'AGENT-024',
    'no_observability': 'AGENT-025',
}

def match_finding_to_rule(self, pattern_type: str) -> Optional[Rule]:
    """根据 pattern type 查找对应规则"""
    rule_id = self.PATTERN_TYPE_TO_RULE_MAP.get(pattern_type)
    if rule_id:
        return self.get_rule_by_id(rule_id)
    return None
```

4. 更新 `evaluate` 方法，使新检测结果能正确生成 Finding:

```python
def evaluate(self, scan_results: List[ScanResult]) -> List[Finding]:
    """评估扫描结果并生成 Findings"""
    findings = []

    for result in scan_results:
        # 处理现有的 dangerous_patterns
        for pattern in result.dangerous_patterns:
            rule = self.match_finding_to_rule(pattern.get('type', ''))
            if rule:
                finding = Finding(
                    rule_id=rule.id,
                    title=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    category=rule.category,
                    owasp_id=rule.owasp_agentic_id,
                    confidence=rule.confidence,
                    location=Location(
                        file_path=result.source_file,
                        start_line=pattern.get('line', 0),
                        end_line=pattern.get('line', 0),
                        snippet=pattern.get('snippet', ''),
                    ),
                    remediation=rule.remediation,
                )
                findings.append(finding)

        # 处理新增的 prompt_injection_findings
        if hasattr(result, 'prompt_injection_findings'):
            for pi in result.prompt_injection_findings:
                rule = self.match_finding_to_rule(pi.get('type', ''))
                if rule:
                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        category=rule.category,
                        owasp_id=rule.owasp_agentic_id,
                        confidence=rule.confidence,
                        location=Location(
                            file_path=result.source_file,
                            start_line=pi.get('line', 0),
                            end_line=pi.get('line', 0),
                            snippet=pi.get('snippet', ''),
                        ),
                        remediation=rule.remediation,
                    )
                    findings.append(finding)

    return findings
```

---

## 阶段 8: 综合测试套件（预计 3-4 小时）

### STEP 8.1: 创建综合测试 fixture

**文件**: `tests/fixtures/vulnerable_agents/owasp_agentic_full.py`

```python
"""
Comprehensive test fixture covering all OWASP Agentic Top 10 (ASI-01 ~ ASI-10).
Each function is labeled with the expected ASI category and rule ID.
"""

from langchain.agents import AgentExecutor, initialize_agent
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage
from langchain.memory import ConversationBufferMemory
from langchain.vectorstores import Chroma
from langchain.tools import tool
import subprocess
import os


# === ASI-01: Agent Goal Hijack ===

def asi01_vulnerable_prompt_concat(user_input: str):
    """AGENT-010: f-string in system prompt"""
    system_prompt = f"You are an agent. User says: {user_input}"
    return SystemMessage(content=system_prompt)


def asi01_vulnerable_format(user_goal: str):
    """AGENT-010: .format() in prompt"""
    template = "Agent goal: {}".format(user_goal)
    return SystemMessage(content=template)


# === ASI-02: Tool Misuse (existing AGENT-001) ===

@tool
def asi02_shell_tool(command: str):
    """AGENT-001: shell=True with user input"""
    return subprocess.run(command, shell=True, capture_output=True)


# === ASI-03: Identity & Privilege Abuse ===

def asi03_hardcoded_key():
    """AGENT-013: Hardcoded credential"""
    agent = initialize_agent(tools=[], llm=None, api_key="sk-prod-hardcoded-key")
    return agent


def asi03_excessive_tools():
    """AGENT-014: Too many tools (>10)"""
    tools = [f"tool_{i}" for i in range(15)]
    agent = AgentExecutor(agent=None, tools=[1,2,3,4,5,6,7,8,9,10,11,12])
    return agent


def asi03_auto_approve():
    """AGENT-014: Auto-approval mode"""
    agent = AgentExecutor(agent=None, tools=[], trust_all_tools=True)


# === ASI-05: Unexpected Code Execution ===

@tool
def asi05_eval_in_tool(code: str):
    """AGENT-017: eval() inside @tool"""
    return eval(code)


@tool
def asi05_exec_in_tool(script: str):
    """AGENT-017: exec() inside @tool"""
    exec(script)


# === ASI-06: Memory & Context Poisoning ===

def asi06_unsanitized_memory(vectorstore, user_input):
    """AGENT-018: Direct user input to vector store"""
    vectorstore.add_texts([user_input])


def asi06_unbounded_memory():
    """AGENT-019: ConversationBufferMemory without limit"""
    memory = ConversationBufferMemory()
    return memory


# === ASI-08: Cascading Failures ===

def asi08_no_max_iterations():
    """AGENT-021: AgentExecutor without max_iterations"""
    agent = AgentExecutor(agent=None, tools=[])
    return agent


# === ASI-10: Rogue Agents ===

def asi10_no_kill_switch():
    """AGENT-024: Agent without any execution limits"""
    agent = AgentExecutor(agent=None, tools=[])
    return agent


def asi10_no_observability():
    """AGENT-025: Agent without callbacks or logging"""
    agent = AgentExecutor(
        agent=None, tools=[],
        max_iterations=10,  # has limit but no observability
    )
    return agent


# === SAFE EXAMPLES (should NOT trigger findings) ===

def safe_structured_prompt(user_input: str):
    """SAFE: Proper prompt separation"""
    messages = [
        SystemMessage(content="You are a helpful agent."),
        HumanMessage(content=user_input),
    ]
    return messages


def safe_bounded_agent():
    """SAFE: Agent with all protections"""
    agent = AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=15,
        max_execution_time=300,
        verbose=True,
        callbacks=[],
        return_intermediate_steps=True,
    )
    return agent


def safe_bounded_memory():
    """SAFE: Memory with window limit"""
    memory = ConversationBufferMemory(k=10)
    return memory
```

### STEP 8.2: 创建测试文件

**文件**: `tests/test_owasp_agentic.py`

```python
"""Tests for OWASP Agentic Top 10 rule coverage."""

import pytest
from pathlib import Path

# 根据项目实际的导入路径调整
from agent_audit.scanners.python_scanner import PythonScanner
from agent_audit.rules.engine import RuleEngine
from agent_audit.rules.loader import RuleLoader


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vulnerable_agents"


class TestOWASPAgenticTop10:
    """Test full OWASP Agentic Top 10 coverage."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.scanner = PythonScanner()
        self.loader = RuleLoader()
        self.engine = RuleEngine(self.loader.load_builtin_rules())

    def _scan_and_evaluate(self, fixture_file: str):
        """Helper: scan a fixture file and return findings."""
        path = FIXTURE_PATH / fixture_file
        results = self.scanner.scan(path)
        return self.engine.evaluate(results)

    # --- ASI-01: Agent Goal Hijack ---

    def test_asi01_prompt_fstring(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi01_findings = [f for f in findings if f.owasp_id == "ASI-01"]
        assert len(asi01_findings) >= 2, \
            f"Expected >= 2 ASI-01 findings, got {len(asi01_findings)}"

    def test_asi01_rule_ids(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        rule_ids = {f.rule_id for f in findings if f.owasp_id == "ASI-01"}
        assert "AGENT-010" in rule_ids

    # --- ASI-03: Identity & Privilege Abuse ---

    def test_asi03_excessive_tools(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi03_findings = [f for f in findings if f.owasp_id == "ASI-03"]
        assert len(asi03_findings) >= 1

    # --- ASI-05: Unexpected Code Execution ---

    def test_asi05_eval_in_tool(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi05_findings = [f for f in findings if f.owasp_id == "ASI-05"]
        assert len(asi05_findings) >= 2, \
            "Expected findings for eval() and exec() in @tool functions"

    # --- ASI-06: Memory Poisoning ---

    def test_asi06_unsanitized_memory(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi06_findings = [f for f in findings if f.owasp_id == "ASI-06"]
        assert len(asi06_findings) >= 1

    # --- ASI-08: Cascading Failures ---

    def test_asi08_no_circuit_breaker(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi08_findings = [f for f in findings if f.owasp_id == "ASI-08"]
        assert len(asi08_findings) >= 1

    # --- ASI-10: Rogue Agents ---

    def test_asi10_no_kill_switch(self):
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi10_findings = [f for f in findings if f.owasp_id == "ASI-10"]
        assert len(asi10_findings) >= 1

    # --- Safe examples should NOT trigger ---

    def test_safe_examples_no_findings(self):
        """Safe patterns should not generate false positives for new rules."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        # 确保安全示例没有被误报
        safe_functions = {'safe_structured_prompt', 'safe_bounded_agent', 'safe_bounded_memory'}
        for finding in findings:
            # 检查 finding 不来自安全函数
            if finding.location.snippet:
                for safe_fn in safe_functions:
                    if safe_fn in finding.location.snippet:
                        pytest.fail(
                            f"False positive: {finding.rule_id} triggered on "
                            f"safe function containing '{safe_fn}'"
                        )

    # --- Coverage validation ---

    def test_all_10_categories_have_rules(self):
        """Verify every ASI category has at least one rule loaded."""
        rules = self.loader.load_builtin_rules()
        owasp_ids = {r.owasp_agentic_id for r in rules if hasattr(r, 'owasp_agentic_id') and r.owasp_agentic_id}
        expected = {f"ASI-{i:02d}" for i in range(1, 11)}
        missing = expected - owasp_ids
        assert not missing, f"Missing OWASP Agentic categories: {missing}"
```

### STEP 8.3: 运行测试并修复

```bash
# 运行全部测试
cd packages/audit  # 或项目根目录
pytest tests/ -v --tb=short

# 运行仅 OWASP 测试
pytest tests/test_owasp_agentic.py -v

# 带覆盖率
pytest tests/ --cov=agent_audit --cov-report=term-missing

# 目标: 全部通过, 覆盖率 > 80%
```

---

## 阶段 9: 文档与 README 更新（预计 1-2 小时）

### STEP 9.1: 更新 Rules Reference 表

**文件**: `README.md`

更新 "Detected Issues" 表格，展示完整的 OWASP Agentic Top 10 覆盖:

```markdown
## 🎯 OWASP Agentic Top 10 Coverage

Agent Audit is the first open-source CLI tool to cover **all 10 categories**
of the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

| OWASP ASI | Risk Category | Rule IDs | Severity |
|-----------|--------------|----------|----------|
| ASI-01 | Agent Goal Hijack | AGENT-010, AGENT-011 | 🔴 Critical / 🟠 High |
| ASI-02 | Tool Misuse & Exploitation | AGENT-001, AGENT-012 | 🔴 Critical |
| ASI-03 | Identity & Privilege Abuse | AGENT-002, AGENT-013, AGENT-014 | 🟠 High |
| ASI-04 | Supply Chain Vulnerabilities | AGENT-005, AGENT-015, AGENT-016 | 🔴 Critical / 🟠 High |
| ASI-05 | Unexpected Code Execution | AGENT-017 | 🔴 Critical |
| ASI-06 | Memory & Context Poisoning | AGENT-018, AGENT-019 | 🔴 Critical / 🟡 Medium |
| ASI-07 | Insecure Inter-Agent Communication | AGENT-020 | 🟠 High |
| ASI-08 | Cascading Failures | AGENT-021, AGENT-022 | 🟠 High / 🟡 Medium |
| ASI-09 | Human-Agent Trust Exploitation | AGENT-023 | 🟡 Medium |
| ASI-10 | Rogue Agents | AGENT-024, AGENT-025 | 🔴 Critical / 🟠 High |

### Complete Rule Reference

| Rule ID | Title | ASI | Severity |
|---------|-------|-----|----------|
| AGENT-001 | Command Injection via Unsanitized Input | ASI-02 | 🔴 Critical |
| AGENT-002 | Excessive Agent Permissions | ASI-03 | 🟡 Medium |
| AGENT-003 | Potential Data Exfiltration Chain | ASI-02 | 🟠 High |
| AGENT-004 | Hardcoded Credentials | ASI-03 | 🔴 Critical |
| AGENT-005 | Unverified MCP Server | ASI-04 | 🟠 High |
| AGENT-010 | System Prompt Injection Vector | ASI-01 | 🔴 Critical |
| AGENT-011 | Missing Goal Validation | ASI-01 | 🟠 High |
| AGENT-013 | Long-Lived/Shared Agent Credentials | ASI-03 | 🟠 High |
| AGENT-014 | Overly Permissive Agent Role | ASI-03 | 🟠 High |
| AGENT-015 | Untrusted MCP Server Source | ASI-04 | 🔴 Critical |
| AGENT-016 | Unvalidated RAG Data Source | ASI-04 | 🟠 High |
| AGENT-017 | Unsandboxed Code Execution | ASI-05 | 🔴 Critical |
| AGENT-018 | Unsanitized Input to Persistent Memory | ASI-06 | 🔴 Critical |
| AGENT-019 | Conversation History Without Limits | ASI-06 | 🟡 Medium |
| AGENT-020 | Unencrypted Inter-Agent Channel | ASI-07 | 🟠 High |
| AGENT-021 | Missing Circuit Breaker | ASI-08 | 🟠 High |
| AGENT-022 | No Error Handling in Tool | ASI-08 | 🟡 Medium |
| AGENT-023 | Agent Output Without Transparency | ASI-09 | 🟡 Medium |
| AGENT-024 | Agent Without Kill Switch | ASI-10 | 🔴 Critical |
| AGENT-025 | Agent Without Behavioral Monitoring | ASI-10 | 🟠 High |
```

### STEP 9.2: 创建 CHANGELOG.md

**文件**: `CHANGELOG.md`

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-XX

### Added
- **Full OWASP Agentic Top 10 (2026) coverage** — all 10 ASI categories now have
  detection rules (ASI-01 through ASI-10)
- 16 new built-in rules: AGENT-010 through AGENT-025
- Custom rule loading via `--rules-dir` parameter
- ASI-01: Agent Goal Hijack detection (prompt injection vectors, missing goal boundaries)
- ASI-04: Enhanced supply chain checks (untrusted MCP sources, unpinned versions)
- ASI-05: Unsandboxed code execution detection in tool context
- ASI-06: Memory/context poisoning detection (unsanitized writes, unbounded memory)
- ASI-07: Insecure inter-agent communication detection
- ASI-08: Cascading failure detection (missing circuit breakers, error handling)
- ASI-09: Human-agent trust exploitation (opaque agent outputs)
- ASI-10: Rogue agent detection (missing kill switches, no observability)
- `owasp_agentic_id` field in SARIF output for standard mapping

### Changed
- Enhanced Python AST scanner with 8 new detection methods
- Enhanced config scanner with MCP supply chain analysis
- Updated SARIF output to include OWASP Agentic references
- Expanded test suite for new rules

### Fixed
- (list any bugs fixed during implementation)

## [0.1.0] - 2026-01-XX

### Added
- Initial release
- 5 built-in rules (AGENT-001 through AGENT-005)
- Python AST scanning
- MCP configuration scanning
- Secret detection
- SARIF, JSON, Markdown output formats
- Baseline scanning with `--baseline` / `--save-baseline`
- Allowlist via `.agent-audit.yaml`
- GitHub Action integration
```

### STEP 9.3: 更新 SARIF 输出

**文件**: `packages/audit/agent_audit/cli/formatters/sarif.py`

确保 SARIF 输出在 `rules` 数组中包含 OWASP Agentic 引用:

```python
def _rule_to_sarif(self, rule) -> dict:
    """将规则转换为 SARIF rule descriptor"""
    sarif_rule = {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "helpUri": rule.remediation.reference_url if rule.remediation else "",
        "properties": {}
    }

    # 添加 OWASP Agentic 标签
    tags = []
    if hasattr(rule, 'owasp_agentic_id') and rule.owasp_agentic_id:
        tags.append(f"OWASP-Agentic-{rule.owasp_agentic_id}")
        sarif_rule["properties"]["owasp-agentic-id"] = rule.owasp_agentic_id
    if hasattr(rule, 'cwe_id') and rule.cwe_id:
        tags.append(rule.cwe_id)
    if tags:
        sarif_rule["properties"]["tags"] = tags

    return sarif_rule
```

---

## 阶段 10: 最终集成与发布准备（预计 2 小时）

### STEP 10.1: 端到端集成测试

```bash
# 1. 确保所有规则文件正确加载
agent-audit scan tests/fixtures/vulnerable_agents/ -v

# 2. 验证 OWASP 全覆盖
agent-audit scan tests/fixtures/vulnerable_agents/owasp_agentic_full.py --format json \
  | python -c "
import json, sys
data = json.load(sys.stdin)
owasp_ids = set()
for finding in data.get('findings', []):
    oid = finding.get('owasp_id', '')
    if oid:
        owasp_ids.add(oid)
expected = {f'ASI-{i:02d}' for i in range(1, 11)}
# ASI-07 and ASI-09 may not have fixture triggers (config-level)
# At minimum check the ones we have AST detections for
must_have = {'ASI-01', 'ASI-05', 'ASI-06', 'ASI-08', 'ASI-10'}
missing = must_have - owasp_ids
if missing:
    print(f'FAIL: Missing OWASP IDs: {missing}')
    sys.exit(1)
print(f'PASS: Found OWASP IDs: {sorted(owasp_ids)}')
"

# 3. SARIF 输出验证
agent-audit scan tests/fixtures/vulnerable_agents/ --format sarif -o /tmp/test.sarif
python -c "
import json
with open('/tmp/test.sarif') as f:
    sarif = json.load(f)
rules = sarif['runs'][0]['tool']['driver']['rules']
print(f'Total rules in SARIF: {len(rules)}')
for r in rules:
    tags = r.get('properties', {}).get('tags', [])
    print(f'  {r[\"id\"]}: {tags}')
"

# 4. 自定义规则加载验证
agent-audit scan . --rules-dir /tmp/custom-rules -v

# 5. 全测试套件
pytest tests/ -v --cov=agent_audit --cov-report=term-missing
# 目标: 全部通过, 覆盖率 > 80%, 0 failures
```

### STEP 10.2: 版本号更新

**文件**: `packages/audit/agent_audit/version.py` (或 `pyproject.toml`)

```python
__version__ = "0.2.0"
```

### STEP 10.3: 提交与 PR

```bash
git add -A
git commit -m "feat: full OWASP Agentic Top 10 (2026) coverage

- Add 16 new rules (AGENT-010 through AGENT-025)
- Cover all 10 ASI categories (ASI-01 through ASI-10)
- Implement --rules-dir for custom YAML rules
- Enhance Python AST scanner with 8 new detection methods
- Enhance config scanner with MCP supply chain checks
- Add comprehensive test suite
- Update README with full rules reference
- Add CHANGELOG.md

Closes #XX"

git push origin feat/owasp-full-coverage
```

---

## 附录 A: OWASP ASI → CWE 映射参考

| ASI | 主要 CWE | 描述 |
|-----|---------|------|
| ASI-01 | CWE-77 | Command Injection (prompt context) |
| ASI-02 | CWE-272 | Least Privilege Violation |
| ASI-03 | CWE-798, CWE-269 | Hardcoded Credentials, Improper Privilege Management |
| ASI-04 | CWE-494, CWE-829 | Download Without Integrity Check, Untrusted Functionality |
| ASI-05 | CWE-94 | Improper Control of Code Generation |
| ASI-06 | CWE-20 | Improper Input Validation (persistent) |
| ASI-07 | CWE-319 | Cleartext Transmission |
| ASI-08 | CWE-400, CWE-754 | Resource Exhaustion, Improper Check for Exceptional Conditions |
| ASI-09 | CWE-451 | User Interface Misrepresentation |
| ASI-10 | CWE-693 | Protection Mechanism Failure |

## 附录 B: 文件修改清单汇总

| 文件路径 | 操作 | 阶段 |
|---------|------|------|
| `packages/audit/agent_audit/models/finding.py` | 修改: 扩展 Category 枚举 | 1 |
| `packages/audit/agent_audit/rules/loader.py` | 修改: 支持新字段 + --rules-dir | 1 |
| `packages/audit/agent_audit/cli/commands/scan.py` | 修改: 添加 --rules-dir 参数 | 1 |
| `rules/builtin/owasp_agentic_v2.yaml` | 新建: 全部新增规则 | 2-6 |
| `packages/audit/agent_audit/scanners/python_scanner.py` | 修改: 新增 8+ 检测方法 | 2-6 |
| `packages/audit/agent_audit/scanners/config_scanner.py` | 修改: MCP 供应链检测 | 4 |
| `packages/audit/agent_audit/rules/engine.py` | 修改: pattern→rule 映射 | 7 |
| `packages/audit/agent_audit/cli/formatters/sarif.py` | 修改: OWASP 标签 | 9 |
| `tests/fixtures/vulnerable_agents/owasp_agentic_full.py` | 新建: 综合 fixture | 8 |
| `tests/fixtures/vulnerable_agents/goal_hijack.py` | 新建: ASI-01 fixture | 2 |
| `tests/fixtures/vulnerable_agents/privilege_abuse.py` | 新建: ASI-03 fixture | 3 |
| `tests/fixtures/vulnerable_agents/memory_poisoning.py` | 新建: ASI-06 fixture | 5 |
| `tests/fixtures/mcp_configs/supply_chain_vulnerable.json` | 新建: ASI-04 fixture | 4 |
| `tests/test_owasp_agentic.py` | 新建: OWASP 测试套件 | 8 |
| `README.md` | 修改: 规则表 + 说明 | 9 |
| `CHANGELOG.md` | 新建 | 9 |
| `packages/audit/agent_audit/version.py` | 修改: 0.2.0 | 10 |

## 附录 C: 执行顺序检查表（Claude Code 执行时逐项勾选）

```
□ 阶段 1: 基础设施
  □ 1.1 扩展 Finding 模型 (Category 枚举)
  □ 1.2 扩展规则 Schema (loader.py)
  □ 1.3 实现 --rules-dir 自定义规则加载
  □ 验证: 自定义规则加载成功

□ 阶段 2: ASI-01 Agent Goal Hijack
  □ 2.1 创建 owasp_agentic_v2.yaml (AGENT-010, AGENT-011)
  □ 2.2 实现 prompt injection vector 检测 (python_scanner.py)
  □ 创建 goal_hijack.py fixture
  □ 验证: 扫描 fixture 报告正确数量的 findings

□ 阶段 3: ASI-03 Identity & Privilege Abuse
  □ 3.1 追加 AGENT-013, AGENT-014 规则到 YAML
  □ 3.2 实现 excessive tools / auto-approval 检测
  □ 创建 privilege_abuse.py fixture
  □ 验证: 扫描报告正确

□ 阶段 4: ASI-04 Supply Chain + ASI-05 RCE
  □ 4.1 追加 AGENT-015, AGENT-016 规则
  □ 4.2 追加 AGENT-017 规则
  □ 4.3 实现 config scanner MCP 供应链检测
  □ 创建 supply_chain_vulnerable.json fixture
  □ 验证: MCP 配置扫描报告正确

□ 阶段 5: ASI-06 Memory Poisoning
  □ 5.1 追加 AGENT-018, AGENT-019 规则
  □ 5.2 实现 memory write / unbounded memory 检测
  □ 创建 memory_poisoning.py fixture
  □ 验证: 扫描报告正确

□ 阶段 6: ASI-07 ~ ASI-10
  □ 6.1 追加 AGENT-020 (ASI-07)
  □ 6.2 追加 AGENT-021, AGENT-022 (ASI-08)
  □ 6.3 追加 AGENT-023 (ASI-09)
  □ 6.4 追加 AGENT-024, AGENT-025 (ASI-10)
  □ 6.5 实现所有 AST 检测逻辑
  □ 验证: 综合 fixture 扫描覆盖所有 ASI

□ 阶段 7: 规则引擎集成
  □ 7.1 更新 engine.py pattern→rule 映射
  □ 验证: evaluate() 正确生成 Finding 对象

□ 阶段 8: 测试
  □ 8.1 创建 owasp_agentic_full.py 综合 fixture
  □ 8.2 创建 test_owasp_agentic.py 测试文件
  □ 8.3 pytest 全部通过, 覆盖率 > 80%

□ 阶段 9: 文档
  □ 9.1 更新 README.md 规则表
  □ 9.2 创建 CHANGELOG.md
  □ 9.3 更新 SARIF 输出格式

□ 阶段 10: 发布准备
  □ 10.1 端到端集成测试通过
  □ 10.2 版本号更新为 0.2.0
  □ 10.3 提交并创建 PR
```
