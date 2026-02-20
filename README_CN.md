# Agent Audit

> [English README](README.md)

**首个专为 AI Agent 代码设计的开源静态安全分析器。**
40+ 检测规则映射到 [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)。过程内污点分析。MCP 配置审计。三阶段语义凭证检测。

## 评估结果

在 **Agent-Vuln-Bench**（19 个样本，3 类漏洞）上与 Bandit 和 Semgrep 对比评估：

| 工具 | 召回率 | 精确率 | F1 |
|------|-------:|------:|---:|
| **agent-audit** | **94.6%** | **87.5%** | **0.91** |
| Bandit 1.8 | 29.7% | 100% | 0.46 |
| Semgrep 1.x | 27.0% | 100% | 0.43 |

## 快速开始

### 安装

```bash
# 推荐：pipx（自动处理 PATH，隔离环境）
pipx install agent-audit

# 或 pip
pip install agent-audit
```

### 基本使用

```bash
# 扫描当前目录
agent-audit scan .

# SARIF 输出用于 GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif

# 仅在 critical/high 发现时 CI 失败
agent-audit scan . --fail-on high

# 运行时 MCP 服务器检查（只读探测）
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## 威胁覆盖

40+ 检测规则覆盖 OWASP Agentic Top 10 全部 10 个类别：

| OWASP 类别 | 规则数 | 典型检测 |
|-----------|------:|---------|
| ASI-01 目标劫持 | 4 | `SystemMessage` 中的 f-string 注入 |
| ASI-02 工具滥用 | 9 | `@tool` 输入流向 `subprocess` 未经验证 |
| ASI-03 身份与权限 | 4 | 守护进程提权、超过 10 个 MCP 服务器 |
| ASI-04 供应链 | 5 | 未验证的 MCP 源、未固定版本的 `npx` 包 |
| ASI-05 代码执行 | 3 | 工具中无沙箱的 `eval`/`exec` |
| ASI-06 记忆投毒 | 2 | 未净化输入写入向量存储 |
| ASI-07 代理间通信 | 1 | 多代理通信未加密 |
| ASI-08 级联故障 | 3 | `AgentExecutor` 缺少 `max_iterations` |
| ASI-09 信任利用 | 6 | 关键操作缺少人工审批 |
| ASI-10 恶意代理 | 3 | 无终止开关、无行为监控 |

原生支持 **LangChain**、**CrewAI**、**AutoGen** 和 **AgentScope** 框架。

## 配置

```yaml
# .agent-audit.yaml
scan:
  exclude: ["tests/**", "venv/**"]
  min_severity: low
  fail_on: high

ignore:
  - rule_id: AGENT-003
    paths: ["auth/**"]
    reason: "Auth 模块需要外部通信"

allowed_hosts:
  - "api.openai.com"
```

## 文档

- [技术规格说明](docs/SECURITY-ANALYSIS-SPECIFICATION.md)
- [基准测试结果](docs/BENCHMARK-RESULTS.md)
- [规则参考](docs/RULES.md)
- [架构设计](docs/ARCHITECTURE.md)
- [CI/CD 集成](docs/CI-INTEGRATION.md)

## 开发

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest ../../tests/ -v  # 1142 个测试
```

## 许可证

MIT — 详见 [LICENSE](LICENSE)。
