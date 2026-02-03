# 反馈评析与技术方案改进

## 综合判断

这份反馈的技术直觉是好的，但多处建议经不起工业级验证。下面逐条评析。

---

# 一、逐条评析

## 1. ✅ 亮点评价部分 — 基本准确

反馈对方案的四个亮点评价（混合架构、SARIF 输出、操作链检测、MCP Inspector 先发优势）**均正确**，无需修正。唯一需要补充的是：

**SARIF 的战略意义比反馈描述的还大。** 不仅仅是"在 PR 里看到红色警告"，SARIF 还是 GitHub Advanced Security、Azure DevOps、GitLab SAST 的标准交换格式。支持 SARIF 意味着能零成本接入全球三大代码托管平台的安全生态。

---

## 2. ⚠️ "拥抱 Semgrep" 建议 — 反对采纳

这是反馈中**最需要警惕的建议**。表面上看很有说服力（"不要自造轮子"），但经过实际验证存在三个致命问题：

### 问题一：包体积不可接受

Semgrep 的 PyPI wheel 大小：

| 平台 | 大小 |
|------|------|
| macOS ARM64 | 39.9 MB |
| macOS x86 | 35.0 MB |
| Linux x86 | 50.5 MB |
| Windows | 43.0 MB |

对比我们的方案：Python `ast` 模块是 **CPython 内置标准库**，零额外依赖，零额外体积。

一个 CLI 工具引入 40-50MB 的依赖来获得"不需要自己写解析器"的好处，在工业实践中是不合理的。作为对比，`ruff`（Python linter）完整二进制才 ~20MB，`eslint` 完整安装 ~10MB。

### 问题二：许可证风险 — 这才是真正的阻塞项

Semgrep Rules License v1.0 **明确禁止在竞品中使用**：

> "You may use the rules only for your own internal business purposes. This license does not allow you to distribute the rules, or to make them available to others as a service."
>
> "Vendors cannot use Semgrep-maintained rules in competing products or SaaS offerings."

我们正在构建一个安全扫描产品。即使只用 Semgrep 引擎（LGPL 2.1）而不用它的规则，也面临以下问题：

- LGPL 要求对引擎的修改必须开源
- Semgrep 的 cross-file 分析（跨文件追踪）只在 **Pro 付费版** 中提供
- Semgrep CE 已经引发了社区分裂（Opengrep fork），生态不稳定

### 问题三：Semgrep 根本不能做我们需要的分析

反馈建议"将 YAML 规则编译为 Semgrep 规则"。但我们的核心检测逻辑中，**Semgrep 能覆盖的部分不到 20%**：

| 检测能力 | Python ast | Semgrep CE | Semgrep Pro |
|----------|-----------|------------|-------------|
| 危险函数调用 (AGENT-001) | ✅ | ✅ | ✅ |
| 硬编码密钥 (AGENT-004) | ✅ | ✅ | ✅ |
| 操作链分析 (AGENT-002/003) | ✅ 自定义 | ❌ 不支持 | ❌ 不支持 |
| MCP Server 探测 | ✅ 自定义 | ❌ 不支持 | ❌ 不支持 |
| MCP 配置分析 | ✅ 自定义 | ❌ 不支持 | ❌ 不支持 |
| Tool 权限推断 | ✅ 自定义 | ❌ 不支持 | ❌ 不支持 |
| @tool 装饰器识别 | ✅ 自定义 | ⚠️ 需自写规则 | ⚠️ 需自写规则 |
| 跨文件污点追踪 | ❌ 需自建 | ❌ 免费版无 | ✅ 需付费 |

**结论**：Semgrep 只能帮我们做最简单的模式匹配（我们用正则就能做），但做不了任何 Agent 特定的分析。为了 20% 的功能引入 40MB 依赖和许可证风险，收益不成立。

### 但反馈背后的担忧是对的

反馈真正想表达的是：**自建完整的污点分析（Taint Analysis）系统成本极高，别掉进这个坑**。

这个警告完全正确。V1.0 不应该做深度数据流分析。应对策略：

```
V1.0: 函数级别的模式匹配（用 Python ast，已足够）
      ├── 检测 subprocess.run(x, shell=True) ✅ 容易
      ├── 检测 @tool 装饰器 ✅ 容易
      └── 检测参数名中的危险模式 ✅ 容易

V2.0: 考虑引入 Tree-sitter（轻量级，3-5MB/语言）
      └── 支持 TypeScript MCP Server 分析

V3.0: 才考虑是否需要跨文件数据流分析
      └── 届时评估 Opengrep/Tree-sitter/自建
```

---

## 3. ✅ "Runtime Prober 边界模糊" — 完全正确，应采纳

反馈指出：

> `watch --realtime` 在 CLI 里很难实现。CLI 通常是一次性运行的。如果要实时拦截必须变成 Proxy。

这是**完全正确**的工程判断。

**应采纳的改动**：

| 原方案 | 改进后 |
|--------|--------|
| `agent-audit watch --realtime` | **移除此命令** |
| 实时拦截放在 CLI | 拦截是 Firewall 的职责 |
| scan/inspect/watch 三命令 | **scan + inspect 两命令** |

`watch` 如果要保留，语义改为 "file watcher"（检测配置文件变更后重新扫描），类似 `tsc --watch`，而不是"流量拦截"。但这是 V2.0 功能，MVP 不做。

---

## 4. ⚠️ "误报率" — 方向正确，但给出的方案不够

反馈提到 AGENT-003 的误报问题（Agent 把 API Key 发给内部鉴权服务 ≠ 数据泄露），这是**完全正确**的风险。

但反馈没有给出具体解决方案。需要实现以下机制：

### 方案 A：Allowlist 机制

```yaml
# .agent-audit.yaml
ignore:
  # 忽略特定规则
  - rule: AGENT-003
    paths:
      - "auth/*.py"
    reason: "Internal auth service communication"

  # 忽略特定工具组合
  - chain:
      source: "get_api_key"
      target: "auth_service_call"
    reason: "Legitimate auth flow"

allowed_hosts:
  - "*.internal.company.com"
  - "auth.service.local"
```

### 方案 B：Confidence Score

为每个 Finding 添加 confidence 字段，并在输出时标注：

```
🟠 HIGH (confidence: 60%) — AGENT-003: Potential Data Exfiltration Chain
   get_api_key() → http_post(target_unknown)
   ⚠️ This may be a false positive if target is an internal service.
   Suppress: agent-audit ignore AGENT-003 --path auth/client.py
```

### 方案 C：Baseline 扫描

```bash
# 首次扫描建立基线
agent-audit scan . --output baseline.json

# 后续扫描只报告新增问题
agent-audit scan . --baseline baseline.json
```

---

## 5. ⚠️ "MCP Client 模拟器" 实现建议 — 方向正确，细节需补充

反馈建议的 inspect 实现流程是对的：

> Connect → Handshake → List Tools → Audit Schema

但**遗漏了几个关键环节**：

### 遗漏 1：需要支持多种传输协议

MCP Server 不只有 HTTP/SSE，还有 STDIO（本地进程）。inspect 必须支持两种：

```bash
# HTTP/SSE 模式
agent-audit inspect https://mcp-server.example.com/sse

# STDIO 模式（本地进程）
agent-audit inspect stdio -- python my_mcp_server.py

# Docker MCP Gateway 模式
agent-audit inspect docker-mcp://filesystem
```

### 遗漏 2：安全沙箱

inspect 连接到未知 MCP Server 时，**Server 可能是恶意的**。连接过程本身就是攻击面（MCP Server 可以在 initialize 响应中注入恶意 prompt）。需要：

```python
class MCPInspector:
    """安全的 MCP Server 探测器"""

    async def inspect(self, url: str, timeout: int = 30):
        # 1. 超时保护
        async with asyncio.timeout(timeout):
            # 2. 只发送 initialize 和 tools/list
            #    绝不发送 tools/call（不执行任何工具）
            client = MCPClient(url)
            await client.initialize()
            tools = await client.list_tools()

        # 3. 分析工具定义（纯静态分析，不执行）
        return self.analyze_tool_schemas(tools)
```

### 遗漏 3：需要分析 Resource 和 Prompt

反馈只提到了 tools/list，但 MCP 协议还有 resources/list 和 prompts/list。Resource 可能暴露敏感数据路径，Prompt 可能包含注入攻击。

---

## 6. ⚠️ "Dependency Graph" — 好功能但不是 MVP

反馈建议增加 Agent 结构图可视化。这是个好想法（类似 `terraform graph`），但：

- **不是安全工具的核心功能**
- 需要额外的图渲染依赖（graphviz/mermaid）
- 增加 MVP 复杂度

**改进决策**：V1.0 只输出 JSON 格式的依赖数据，V2.0 添加 Mermaid 图渲染。

```bash
# V1.0: JSON 格式
agent-audit inspect mcp://server --format json
# 输出包含完整的 server -> tools -> permissions 层级

# V2.0: Mermaid 图
agent-audit graph ./my-agent-project
# 输出 .mermaid 文件，可在 GitHub README 中直接渲染
```

---

## 7. ⚠️ MVP 路线图重排 — 部分采纳

反馈建议的顺序：

> Week 1: MCP Nmap (inspect) → Week 2: Linter (scan) → Week 3: SARIF

**问题**：inspect 和 scan 共享数据模型（Finding, ToolDefinition, Rule）。如果先做 inspect 而不做基础模型，要么重复建设，要么后续重构。

**改进后的顺序**：

```
Week 1: 核心模型 + inspect（"MCP Nmap"）
        ├── 数据模型（Finding, Tool, Risk）
        ├── MCP Client（STDIO + SSE）
        ├── inspect 命令
        └── 终端输出

Week 2: scan（"Agent Linter"）
        ├── Python Scanner（用内置 ast）
        ├── Config Scanner（YAML/JSON）
        ├── Secret Scanner（正则）
        └── 规则引擎 + 5 条核心规则

Week 3: 输出 + 集成
        ├── SARIF 输出
        ├── GitHub Action
        ├── .agent-audit.yaml 配置
        └── allowlist/ignore 机制

Week 4: 打磨 + 发布
        ├── baseline 扫描
        ├── confidence scoring
        ├── 文档 + Demo Repo
        └── PyPI v0.1.0 发布
```

**关键调整**：inspect 提前到 Week 1（反馈建议的好处：最快产出可演示的产品），但和数据模型同步开发（我们方案的合理性：避免重构）。

---

# 二、综合改动清单

## 采纳的改动

| # | 改动 | 来源 | 影响范围 |
|---|------|------|----------|
| 1 | 移除 `watch` 命令 | 反馈建议 3 | CLI 命令集 |
| 2 | inspect 提前到 Week 1 | 反馈建议 7 | 开发顺序 |
| 3 | 添加 allowlist/ignore 机制 | 反馈建议 4（扩展） | 规则引擎 + 配置 |
| 4 | 添加 confidence scoring | 反馈建议 4（扩展） | Finding 模型 |
| 5 | 添加 baseline 扫描 | 自行补充 | CLI 命令 |
| 6 | inspect 支持 STDIO 传输 | 反馈建议 5（扩展） | MCP Client |
| 7 | inspect 增加 resources/prompts 分析 | 自行补充 | MCP Scanner |
| 8 | 依赖图数据输出（JSON） | 反馈建议 6（降级） | inspect 输出 |

## 拒绝的改动

| # | 建议 | 拒绝理由 |
|---|------|----------|
| 1 | 用 Semgrep 替代 Python ast | 40-50MB 依赖 + 许可证风险 + 只覆盖 20% 功能 |
| 2 | V1.0 做依赖图可视化 | 非核心安全功能，增加 MVP 复杂度 |

---

# 三、改进后的技术方案 Delta

以下仅列出相对上一版方案的**变更部分**，未列出的部分保持不变。

## Delta 1: CLI 命令集变更

```python
# 变更前
@cli.command() scan    # 静态扫描
@cli.command() inspect # MCP 探测
@cli.command() watch   # 实时监控  ← 移除
@cli.command() init    # 初始化配置

# 变更后
@cli.command() scan    # 静态扫描
@cli.command() inspect # MCP 探测（扩展：支持 STDIO）
@cli.command() init    # 初始化配置
@cli.command() ignore  # 新增：管理忽略规则
```

## Delta 2: Finding 模型增加 confidence

```python
# agent_audit/models/finding.py — 变更部分

@dataclass
class Finding:
    # ... 原有字段不变 ...

    # 新增字段
    confidence: float = 1.0           # 0.0-1.0 置信度

    # 新增：误报抑制信息
    suppressed: bool = False
    suppressed_reason: Optional[str] = None
    suppressed_by: Optional[str] = None  # config file path

    def is_actionable(self, min_confidence: float = 0.5) -> bool:
        """判断是否需要用户关注"""
        return not self.suppressed and self.confidence >= min_confidence
```

## Delta 3: 新增 Allowlist 配置系统

```python
# agent_audit/config/ignore.py（新文件）

from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from dataclasses import dataclass, field
import yaml
import fnmatch

@dataclass
class IgnoreRule:
    """单条忽略规则"""
    rule_id: Optional[str] = None        # 忽略特定规则，如 "AGENT-003"
    paths: List[str] = field(default_factory=list)  # glob 路径模式
    tools: List[str] = field(default_factory=list)   # 工具名
    reason: str = ""

@dataclass
class AllowlistConfig:
    """Allowlist 配置"""
    # 允许的网络目标（用于 AGENT-003 降低置信度）
    allowed_hosts: List[str] = field(default_factory=list)

    # 允许的文件路径前缀
    allowed_paths: List[str] = field(default_factory=list)

    # 忽略规则
    ignore_rules: List[IgnoreRule] = field(default_factory=list)

    # inline 忽略标记（类似 # noqa）
    inline_ignore_marker: str = "# noaudit"

class IgnoreManager:
    """忽略规则管理器"""

    CONFIG_FILENAMES = ['.agent-audit.yaml', '.agent-audit.yml', 'agent-audit.yaml']

    def __init__(self):
        self.config: Optional[AllowlistConfig] = None
        self._loaded_from: Optional[Path] = None

    def load(self, project_path: Path) -> bool:
        """从项目路径加载忽略配置"""
        for filename in self.CONFIG_FILENAMES:
            config_path = project_path / filename
            if config_path.exists():
                return self._load_file(config_path)
        return False

    def _load_file(self, path: Path) -> bool:
        """加载配置文件"""
        try:
            data = yaml.safe_load(path.read_text())
            if not data:
                return False

            self.config = AllowlistConfig(
                allowed_hosts=data.get('allowed_hosts', []),
                allowed_paths=data.get('allowed_paths', []),
                ignore_rules=[
                    IgnoreRule(**rule) for rule in data.get('ignore', [])
                ]
            )
            self._loaded_from = path
            return True
        except Exception:
            return False

    def should_ignore(self, rule_id: str, file_path: str, tool_name: str = "") -> Optional[str]:
        """
        检查是否应该忽略此发现

        Returns: 忽略原因（如果应忽略），否则 None
        """
        if not self.config:
            return None

        for ignore in self.config.ignore_rules:
            # 匹配规则 ID
            if ignore.rule_id and ignore.rule_id != rule_id:
                continue

            # 匹配路径
            if ignore.paths:
                path_matched = any(
                    fnmatch.fnmatch(file_path, pattern)
                    for pattern in ignore.paths
                )
                if not path_matched:
                    continue

            # 匹配工具名
            if ignore.tools:
                if tool_name not in ignore.tools:
                    continue

            return ignore.reason or f"Suppressed by config ({self._loaded_from})"

        return None

    def adjust_confidence(self, rule_id: str, finding_metadata: Dict[str, Any]) -> float:
        """
        基于 allowlist 调整置信度

        例：AGENT-003 如果目标 host 在 allowed_hosts 中，降低置信度
        """
        if not self.config:
            return 1.0

        adjustment = 1.0

        # 检查网络目标是否在白名单中
        if rule_id == "AGENT-003":
            target_host = finding_metadata.get('target_host', '')
            if target_host and any(
                fnmatch.fnmatch(target_host, pattern)
                for pattern in self.config.allowed_hosts
            ):
                adjustment *= 0.3  # 大幅降低置信度

        # 检查文件路径是否在允许范围内
        file_path = finding_metadata.get('file_path', '')
        if file_path and any(
            file_path.startswith(allowed)
            for allowed in self.config.allowed_paths
        ):
            adjustment *= 0.7

        return adjustment
```

### 配置文件格式

```yaml
# .agent-audit.yaml — 用户配置示例

# 扫描配置
scan:
  exclude:
    - "tests/**"
    - "venv/**"
    - "node_modules/**"
  min_severity: low
  fail_on: high

# 允许的网络目标（降低 AGENT-003 的置信度）
allowed_hosts:
  - "*.internal.company.com"
  - "auth.service.local"
  - "api.openai.com"
  - "api.anthropic.com"

# 允许的文件路径
allowed_paths:
  - "/tmp"
  - "/app/data"

# 忽略规则
ignore:
  - rule_id: AGENT-003
    paths:
      - "auth/**"
    reason: "Auth module legitimately sends credentials to internal auth service"

  - rule_id: AGENT-005
    paths:
      - "admin_agent.py"
    reason: "Admin agent intentionally has broad permissions"

  - rule_id: AGENT-004
    paths:
      - "*.example.py"
      - "docs/**"
    reason: "Example files with placeholder credentials"
```

## Delta 4: scan 命令增加 --baseline 参数

```python
# agent_audit/cli/commands/scan.py — 新增 baseline 支持

import json
from pathlib import Path
from typing import List, Optional, Set
from agent_audit.models.finding import Finding

@dataclass
class BaselineData:
    """基线数据"""
    findings_fingerprints: Set[str]
    created_at: str
    scan_path: str

def compute_fingerprint(finding: Finding) -> str:
    """
    计算 finding 的指纹（用于去重）

    指纹 = hash(rule_id + file_path + start_line + snippet前50字符)
    稳定性设计：代码移动时通过 snippet 匹配
    """
    import hashlib
    components = [
        finding.rule_id,
        finding.location.file_path,
        str(finding.location.start_line),
        (finding.location.snippet or "")[:50]
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def save_baseline(findings: List[Finding], output_path: Path):
    """保存基线文件"""
    from datetime import datetime
    baseline = {
        "version": "1.0",
        "created_at": datetime.utcnow().isoformat(),
        "fingerprints": [compute_fingerprint(f) for f in findings]
    }
    output_path.write_text(json.dumps(baseline, indent=2))

def load_baseline(baseline_path: Path) -> Set[str]:
    """加载基线文件"""
    data = json.loads(baseline_path.read_text())
    return set(data.get("fingerprints", []))

def filter_by_baseline(findings: List[Finding], baseline: Set[str]) -> List[Finding]:
    """过滤掉基线中已存在的 findings"""
    return [
        f for f in findings
        if compute_fingerprint(f) not in baseline
    ]

# scan 命令新增参数：
# --baseline PATH     只报告相对于基线的新增问题
# --save-baseline PATH  将当前结果保存为基线
```

## Delta 5: MCP Inspector 扩展实现

```python
# agent_audit/scanners/mcp_inspector.py（重构，原 mcp_scanner.py 的运行时探测部分）

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from agent_audit.models.tool import ToolDefinition, PermissionType

class TransportType(Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"

@dataclass
class MCPInspectionResult:
    """MCP Server 检查结果"""
    server_name: str
    server_version: Optional[str] = None
    transport: TransportType = TransportType.SSE

    # 工具
    tools: List[ToolDefinition] = field(default_factory=list)
    tool_count: int = 0

    # 资源（新增）
    resources: List[Dict[str, Any]] = field(default_factory=list)
    resource_count: int = 0

    # Prompt 模板（新增）
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    prompt_count: int = 0

    # 安全分析
    risk_score: float = 0.0
    findings: List = field(default_factory=list)
    capabilities_declared: List[str] = field(default_factory=list)

    # 连接信息
    connected: bool = False
    connection_error: Optional[str] = None
    response_time_ms: float = 0.0

class MCPInspector:
    """
    安全的 MCP Server 探测器（"Agent 时代的 Nmap"）

    安全设计原则：
    1. 只发送 initialize, tools/list, resources/list, prompts/list
    2. 绝不调用 tools/call（不执行任何工具）
    3. 超时保护（防止恶意 Server 无限挂起）
    4. 不信任 Server 返回的任何内容用于代码执行
    """

    # 高危工具关键词
    HIGH_RISK_KEYWORDS = {
        'exec', 'shell', 'command', 'run', 'eval', 'system',
        'sudo', 'admin', 'root', 'delete', 'remove', 'drop',
        'truncate', 'format', 'destroy', 'kill', 'rm',
    }

    # 敏感资源路径模式
    SENSITIVE_RESOURCE_PATTERNS = [
        '/etc/', '.ssh/', '.aws/', '.env',
        'credentials', 'secret', 'password', 'token',
        'private_key', '.git/config',
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def inspect(self, target: str, transport: Optional[TransportType] = None) -> MCPInspectionResult:
        """
        检查 MCP Server

        Args:
            target: MCP Server 地址
                - "https://example.com/sse" → SSE 传输
                - "stdio -- python server.py" → STDIO 传输
                - "docker-mcp://filesystem" → Docker MCP Gateway
            transport: 传输类型（不指定则自动推断）
        """
        import time
        start_time = time.perf_counter()

        # 推断传输类型
        if transport is None:
            transport = self._infer_transport(target)

        result = MCPInspectionResult(
            server_name="unknown",
            transport=transport
        )

        try:
            async with asyncio.timeout(self.timeout):
                # 连接并获取元数据
                client = await self._connect(target, transport)

                # 1. Initialize（获取 server info）
                init_response = await client.send("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agent-audit-inspector",
                        "version": "0.1.0"
                    }
                })

                result.server_name = init_response.get("serverInfo", {}).get("name", "unknown")
                result.server_version = init_response.get("serverInfo", {}).get("version")
                result.capabilities_declared = list(init_response.get("capabilities", {}).keys())

                # 发送 initialized 通知
                await client.notify("notifications/initialized", {})

                # 2. List Tools
                tools_response = await client.send("tools/list", {})
                raw_tools = tools_response.get("tools", [])
                result.tools = [self._analyze_tool(t) for t in raw_tools]
                result.tool_count = len(result.tools)

                # 3. List Resources（新增）
                try:
                    resources_response = await client.send("resources/list", {})
                    result.resources = resources_response.get("resources", [])
                    result.resource_count = len(result.resources)
                except Exception:
                    pass  # Server 可能不支持 resources

                # 4. List Prompts（新增）
                try:
                    prompts_response = await client.send("prompts/list", {})
                    result.prompts = prompts_response.get("prompts", [])
                    result.prompt_count = len(result.prompts)
                except Exception:
                    pass  # Server 可能不支持 prompts

                result.connected = True

                await client.close()

        except asyncio.TimeoutError:
            result.connection_error = f"Connection timed out after {self.timeout}s"
        except Exception as e:
            result.connection_error = str(e)

        result.response_time_ms = (time.perf_counter() - start_time) * 1000

        # 安全分析
        result.risk_score = self._calculate_risk(result)
        result.findings = self._generate_findings(result)

        return result

    def _analyze_tool(self, raw_tool: Dict[str, Any]) -> ToolDefinition:
        """分析单个工具定义"""
        name = raw_tool.get("name", "unknown")
        description = raw_tool.get("description", "")
        input_schema = raw_tool.get("inputSchema", {})

        # 从名称和描述推断权限
        permissions = self._infer_permissions(name, description)

        # 分析参数安全性
        params_analysis = self._analyze_input_schema(input_schema)

        return ToolDefinition(
            name=name,
            description=description,
            source_file="mcp_remote",
            source_line=0,
            permissions=permissions,
            has_input_validation=params_analysis.get("has_validation", False),
            mcp_server=True,
            can_execute_code=PermissionType.SHELL_EXEC in permissions,
            can_access_filesystem=any(p in permissions for p in [
                PermissionType.FILE_READ, PermissionType.FILE_WRITE
            ]),
            can_access_network=PermissionType.NETWORK_OUTBOUND in permissions,
            can_access_secrets=PermissionType.SECRET_ACCESS in permissions,
        )

    def _analyze_input_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析输入 Schema 的安全性

        检查：
        - 参数是否有 enum 约束（更安全）
        - 参数是否有 pattern 约束（更安全）
        - 是否接受任意字符串（更危险）
        """
        result = {
            "has_validation": False,
            "unconstrained_strings": [],
            "has_enum": False,
            "has_pattern": False,
        }

        properties = schema.get("properties", {})

        for param_name, param_def in properties.items():
            param_type = param_def.get("type", "string")

            if param_type == "string":
                if "enum" in param_def:
                    result["has_enum"] = True
                    result["has_validation"] = True
                elif "pattern" in param_def:
                    result["has_pattern"] = True
                    result["has_validation"] = True
                else:
                    result["unconstrained_strings"].append(param_name)

        return result

    def _analyze_resource_security(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析 Resource 暴露的安全风险"""
        risky_resources = []

        for resource in resources:
            uri = resource.get("uri", "")
            name = resource.get("name", "")

            for pattern in self.SENSITIVE_RESOURCE_PATTERNS:
                if pattern in uri.lower() or pattern in name.lower():
                    risky_resources.append({
                        "resource": uri,
                        "name": name,
                        "matched_pattern": pattern,
                        "risk": "Exposes potentially sensitive data path"
                    })
                    break

        return risky_resources

    def _analyze_prompt_security(self, prompts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析 Prompt 模板的注入风险"""
        risky_prompts = []

        injection_keywords = [
            'ignore previous', 'disregard', 'override',
            'system prompt', 'you are now', 'forget',
        ]

        for prompt in prompts:
            description = prompt.get("description", "").lower()

            for keyword in injection_keywords:
                if keyword in description:
                    risky_prompts.append({
                        "prompt": prompt.get("name", "unknown"),
                        "matched_keyword": keyword,
                        "risk": "Prompt description contains potential injection pattern"
                    })
                    break

        return risky_prompts

    def _infer_transport(self, target: str) -> TransportType:
        """从目标地址推断传输类型"""
        if target.startswith("stdio"):
            return TransportType.STDIO
        if target.startswith("docker-mcp://"):
            return TransportType.STDIO
        return TransportType.SSE

    def _infer_permissions(self, name: str, description: str) -> set:
        """从名称和描述推断权限（复用 MCP Scanner 的逻辑）"""
        # 同原方案 mcp_scanner.py 中的 _infer_permissions_from_tool
        # 此处省略，逻辑不变
        permissions = set()
        combined = (name + " " + description).lower()

        keyword_map = {
            'exec|shell|command|bash|terminal': PermissionType.SHELL_EXEC,
            'read|file|load|open|cat': PermissionType.FILE_READ,
            'write|save|create|modify|edit': PermissionType.FILE_WRITE,
            'delete|remove|unlink|rm': PermissionType.FILE_DELETE,
            'http|request|fetch|api|url|web|download|upload': PermissionType.NETWORK_OUTBOUND,
            'query|sql|database|db': PermissionType.DATABASE_READ,
            'insert|update|drop': PermissionType.DATABASE_WRITE,
            'secret|credential|password|key|token|auth': PermissionType.SECRET_ACCESS,
            'browser|playwright|puppeteer|selenium': PermissionType.BROWSER_CONTROL,
        }

        for keywords_str, perm in keyword_map.items():
            keywords = keywords_str.split('|')
            if any(kw in combined for kw in keywords):
                permissions.add(perm)

        return permissions

    def _calculate_risk(self, result: MCPInspectionResult) -> float:
        """计算整体风险分数"""
        if not result.connected:
            return 0.0

        score = 0.0

        # 工具风险
        for tool in result.tools:
            score += tool.calculate_risk_score() * 0.1

        # 敏感资源风险
        risky_resources = self._analyze_resource_security(result.resources)
        score += len(risky_resources) * 0.5

        # 高危工具数量
        high_risk_tools = [
            t for t in result.tools
            if any(kw in t.name.lower() for kw in self.HIGH_RISK_KEYWORDS)
        ]
        score += len(high_risk_tools) * 0.8

        return min(10.0, score)

    def _generate_findings(self, result: MCPInspectionResult) -> list:
        """生成检查发现"""
        # 调用规则引擎评估（复用 agent-audit 的规则引擎）
        # 此处省略，逻辑与 scan 共享
        return []

    async def _connect(self, target: str, transport: TransportType):
        """建立连接（占位，具体实现依赖 MCP SDK）"""
        from agent_audit.utils.mcp_client import create_client
        return await create_client(target, transport)
```

### inspect 命令终端输出

```python
# agent_audit/cli/commands/inspect.py

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

console = Console()

def render_inspection_result(result):
    """渲染 inspect 结果"""

    # 标题
    status = "[green]✓ Connected[/green]" if result.connected else "[red]✗ Failed[/red]"
    console.print(Panel.fit(
        f"[bold]MCP Server Inspection[/bold]\n"
        f"Server: {result.server_name} {result.server_version or ''}\n"
        f"Status: {status}  |  Response: {result.response_time_ms:.0f}ms\n"
        f"Risk Score: {result.risk_score:.1f}/10",
        border_style="blue" if result.risk_score < 5 else "red"
    ))

    if not result.connected:
        console.print(f"[red]Error: {result.connection_error}[/red]")
        return

    # 能力声明
    if result.capabilities_declared:
        console.print(f"\n[dim]Capabilities:[/dim] {', '.join(result.capabilities_declared)}")

    # 工具列表
    console.print(f"\n[bold]Tools ({result.tool_count})[/bold]")

    tool_table = Table(show_header=True)
    tool_table.add_column("Tool", style="cyan")
    tool_table.add_column("Permissions", style="yellow")
    tool_table.add_column("Risk", justify="center")
    tool_table.add_column("Input Validation")

    risk_emoji = {1: "🟢", 2: "🟢", 3: "🟡", 4: "🟠", 5: "🔴"}

    for tool in result.tools:
        perms = ", ".join(p.name for p in tool.permissions) or "none"
        risk = risk_emoji.get(tool.risk_level.value if hasattr(tool.risk_level, 'value') else 1, "⚪")
        validation = "✅" if tool.has_input_validation else "❌"

        tool_table.add_row(tool.name, perms, risk, validation)

    console.print(tool_table)

    # 资源（如果有）
    if result.resources:
        console.print(f"\n[bold]Resources ({result.resource_count})[/bold]")
        for res in result.resources:
            uri = res.get('uri', 'unknown')
            console.print(f"  📄 {uri}")

    # Prompts（如果有）
    if result.prompts:
        console.print(f"\n[bold]Prompts ({result.prompt_count})[/bold]")
        for prompt in result.prompts:
            name = prompt.get('name', 'unknown')
            console.print(f"  💬 {name}")

    # 安全发现
    if result.findings:
        console.print(f"\n[bold red]Security Findings ({len(result.findings)})[/bold red]")
        for finding in result.findings:
            console.print(f"  ⚠️  {finding}")
```

## Delta 6: 通用 MCP Client 实现

```python
# agent_audit/utils/mcp_client.py

import asyncio
import json
import sys
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

class BaseMCPTransport(ABC):
    """MCP 传输层基类"""

    @abstractmethod
    async def connect(self): pass

    @abstractmethod
    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]: pass

    @abstractmethod
    async def notify(self, method: str, params: Dict[str, Any]): pass

    @abstractmethod
    async def close(self): pass


class StdioTransport(BaseMCPTransport):
    """STDIO 传输（用于本地 MCP Server）"""

    def __init__(self, command: str, args: list = None):
        self.command = command
        self.args = args or []
        self.process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0

    async def connect(self):
        self.process = await asyncio.create_subprocess_exec(
            self.command, *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params
        }

        # 发送
        request_bytes = json.dumps(request).encode() + b"\n"
        self.process.stdin.write(request_bytes)
        await self.process.stdin.drain()

        # 接收
        response_line = await asyncio.wait_for(
            self.process.stdout.readline(), timeout=30
        )

        response = json.loads(response_line.decode())

        if "error" in response:
            raise Exception(f"MCP Error: {response['error']}")

        return response.get("result", {})

    async def notify(self, method: str, params: Dict[str, Any]):
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        notification_bytes = json.dumps(notification).encode() + b"\n"
        self.process.stdin.write(notification_bytes)
        await self.process.stdin.drain()

    async def close(self):
        if self.process:
            self.process.terminate()
            await self.process.wait()


class SSETransport(BaseMCPTransport):
    """SSE 传输（用于远程 MCP Server）"""

    def __init__(self, url: str):
        self.url = url
        self.session = None
        self._request_id = 0
        self._endpoint: Optional[str] = None

    async def connect(self):
        import aiohttp
        self.session = aiohttp.ClientSession()

        # 连接 SSE endpoint 获取 messages URL
        async with self.session.get(self.url) as response:
            async for line in response.content:
                decoded = line.decode().strip()
                if decoded.startswith("event: endpoint"):
                    next_line = await response.content.readline()
                    data = next_line.decode().strip()
                    if data.startswith("data: "):
                        self._endpoint = data[6:]
                        break

        if not self._endpoint:
            raise Exception("Failed to get messages endpoint from SSE")

    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params
        }

        async with self.session.post(self._endpoint, json=request) as response:
            result = await response.json()

        if "error" in result:
            raise Exception(f"MCP Error: {result['error']}")

        return result.get("result", {})

    async def notify(self, method: str, params: Dict[str, Any]):
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        async with self.session.post(self._endpoint, json=notification):
            pass

    async def close(self):
        if self.session:
            await self.session.close()


async def create_client(target: str, transport_type) -> BaseMCPTransport:
    """工厂函数：创建合适的 MCP 传输"""
    from agent_audit.scanners.mcp_inspector import TransportType

    if transport_type == TransportType.STDIO:
        # 解析 "stdio -- python server.py" 格式
        parts = target.replace("stdio", "").strip()
        if parts.startswith("--"):
            parts = parts[2:].strip()
        command_parts = parts.split()
        command = command_parts[0]
        args = command_parts[1:]

        transport = StdioTransport(command, args)
        await transport.connect()
        return transport

    elif transport_type == TransportType.SSE:
        transport = SSETransport(target)
        await transport.connect()
        return transport

    else:
        raise ValueError(f"Unsupported transport type: {transport_type}")
```

---

# 四、改进后的开发顺序

```
Week 1: 核心模型 + MCP Inspector
  Day 1: 项目骨架（monorepo, pyproject.toml, CI）
  Day 2: 数据模型（Finding, ToolDefinition, Risk）+ IgnoreManager
  Day 3: MCP Client（STDIO + SSE 传输层）
  Day 4: MCP Inspector（connect → tools/list → resources/list → analyze）
  Day 5: inspect CLI 命令 + 终端输出
  验收: agent-audit inspect stdio -- python fixtures/test_server.py 可运行

Week 2: Static Scanner + 规则引擎
  Day 1: Python Scanner（ast 模块，检测 @tool, 危险函数）
  Day 2: Config Scanner（MCP 配置文件解析）
  Day 3: Secret Scanner（正则模式，API key 检测）
  Day 4: 规则引擎 + 5 条 OWASP Agentic 规则
  Day 5: scan CLI 命令 + 终端输出
  验收: agent-audit scan ./fixtures/vulnerable_agents/ 报告 3+ 个发现

Week 3: 输出格式 + 集成 + 误报控制
  Day 1: SARIF 输出（GitHub Code Scanning 兼容）
  Day 2: JSON 输出 + Markdown 输出
  Day 3: .agent-audit.yaml 配置加载 + allowlist
  Day 4: baseline 扫描（--baseline, --save-baseline）
  Day 5: confidence scoring 集成到所有规则
  验收: GitHub Action 中 SARIF 上传成功

Week 4: 打磨 + 发布
  Day 1: init 命令 + ignore 命令
  Day 2: 文档（README, rules-reference, examples）
  Day 3: GitHub Action 发布
  Day 4: Demo Repo（含 vulnerable agent + CI 配置）
  Day 5: PyPI 发布 v0.1.0 + 技术博客草稿
  验收: pip install agent-audit && agent-audit scan . 全流程可用
```

---

# 五、给 Coding Agent 的变更摘要

```
相对上一版技术方案，以下是需要修改的文件和新增的文件：

修改:
  1. agent_audit/cli/main.py
     - 移除 watch 命令
     - scan 命令增加 --baseline 和 --save-baseline 参数
     - inspect 命令增加 --transport 参数（stdio/sse）

  2. agent_audit/models/finding.py
     - Finding 增加 confidence, suppressed, suppressed_reason 字段
     - 增加 is_actionable() 方法

  3. agent_audit/cli/commands/scan.py
     - 集成 IgnoreManager
     - 集成 baseline 过滤
     - 输出增加 confidence 百分比显示

  4. agent_audit/scanners/mcp_scanner.py
     - 拆分为 mcp_config_scanner.py（静态配置扫描）
     - 和 mcp_inspector.py（运行时探测）

新增:
  5. agent_audit/config/ignore.py — Allowlist/Ignore 管理器
  6. agent_audit/scanners/mcp_inspector.py — MCP Server 探测器
  7. agent_audit/utils/mcp_client.py — MCP 协议客户端（STDIO + SSE）
  8. agent_audit/cli/commands/inspect.py — inspect 命令实现
  9. agent_audit/cli/commands/ignore.py — ignore 命令实现

开发优先级:
  STEP 1: models/ （包含新增的 confidence 字段）
  STEP 2: utils/mcp_client.py （STDIO + SSE 传输）
  STEP 3: scanners/mcp_inspector.py + cli/commands/inspect.py
  STEP 4: config/ignore.py
  STEP 5: scanners/python_scanner.py（不变）
  STEP 6: rules/engine.py（不变）
  STEP 7: cli/commands/scan.py（集成 ignore + baseline）
  STEP 8: cli/formatters/sarif.py
  STEP 9: 测试 + 文档
```
