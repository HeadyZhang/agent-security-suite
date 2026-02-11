# Agent-Audit Benchmark 基础设施搭建阶段性总结

**版本:** v0.4.1 → v0.5.0
**日期:** 2026-02-08
**状态:** 基础设施搭建完成，基线数据已建立

---

## 1. 总体概述

agent-audit 的 benchmark 系统采用**三层评估架构**，用于全面验证 AI Agent 安全扫描工具的检测能力。该系统借鉴了 SWE-Bench 的评估模式，设计为**工具无关**（tool-agnostic），既可评估 agent-audit 本身，也可对比 Bandit、Semgrep 等传统 SAST 工具。

### 三层架构

| 层级 | 名称 | 用途 | 当前状态 |
|------|------|------|----------|
| **Layer 1** | Synthetic Samples | 合成样本精确率/召回率 | ✅ 381 个单元测试通过 |
| **Layer 2** | Real Frameworks | 真实框架扫描稳定性 | ✅ T1-T11 共 11 个目标已配置 |
| **Agent-Vuln-Bench** | CVE + Wild + Noise | 真实漏洞检测能力评估 | ✅ v1.0 基础设施就绪 |

---

## 2. 目录结构

```
tests/benchmark/
├── agent-vuln-bench/                  # 核心 benchmark 系统
│   ├── datasets/
│   │   ├── catalog.yaml               # 数据集索引（统一入口）
│   │   ├── knowns/                    # 12 个已知漏洞样本（CVE 复现）
│   │   │   ├── KNOWN-001/ ~ KNOWN-012/
│   │   │   │   ├── vuln/             # 含漏洞版本
│   │   │   │   ├── fixed/            # 修复版本
│   │   │   │   └── oracle.yaml       # 人工标注的 ground truth
│   │   ├── wilds/                     # 6 个野外真实模式
│   │   │   └── WILD-001/ ~ WILD-006/
│   │   └── noise/                     # 2 个精确率测试项目
│   ├── harness/                       # SWE-Bench 风格评估引擎
│   │   ├── adapters/                  # 工具适配器
│   │   │   ├── base_adapter.py        # 适配器基类
│   │   │   ├── agent_audit_adapter.py # agent-audit 适配器
│   │   │   ├── bandit_adapter.py      # Bandit 适配器
│   │   │   └── semgrep_adapter.py     # Semgrep 适配器
│   │   ├── oracle_eval.py             # Oracle 评估引擎
│   │   └── run_eval.py                # AVB 评估入口
│   ├── metrics/                       # 指标计算模块
│   │   ├── compute_metrics.py         # 增强指标计算
│   │   └── compare_tools.py           # 多工具对比报告
│   ├── taxonomy/                      # 分类体系
│   │   ├── owasp_agentic_mapping.yaml # OWASP → Set A/B/C 映射
│   │   └── impact_taxonomy.yaml       # 影响分类
│   └── results/                       # 评估结果
│       ├── v041_baseline/             # v0.4.1 基线
│       └── latest/                    # 最新评估结果
├── run_benchmark.py                   # Layer 2 主运行器
├── run_all.sh                         # 一键执行全部评估
├── precision_recall.py                # Layer 1 指标计算
├── quality_gate_check.py              # 统一质量门禁检查
├── benchmark_config.yaml              # Layer 2 目标配置
├── quality_gates_v2.yaml              # v2 质量阈值定义
└── BENCHMARK_STATUS.md                # 状态追踪文档
```

---

## 3. Agent-Vuln-Bench 数据集详情

### 3.1 KNOWNS 数据集（12 个样本）

基于真实 CVE 和已知漏洞模式构造的最小化代码片段，每个样本包含 `vuln/`（含漏洞）和 `fixed/`（已修复）两个变体。

| ID | 来源 | 集合 | 语言 | 漏洞类型 | 预期规则 | 漏洞数 |
|----|------|------|------|----------|----------|--------|
| KNOWN-001 | CVE-2023-29374 | A | Python | LLMMathChain eval() | AGENT-034 | 1 |
| KNOWN-002 | CVE-2023-36258 | A | Python | PythonREPLTool exec() | AGENT-034 | 1 |
| KNOWN-003 | MCP 配置模式 | B | JSON | 过度宽泛的文件系统权限 | AGENT-029 | 3 |
| KNOWN-004 | 硬编码密钥 | C | Python | 5 个 API Key 硬编码 | AGENT-004 | 5 |
| KNOWN-005 | Auto-GPT Shell | A | Python | subprocess shell=True | AGENT-036 | 3 |
| KNOWN-006 | CVE-2023-46229 | A | Python | Calculator eval() | AGENT-034 | 1 |
| KNOWN-007 | MCP 配置模式 | B | JSON | allowAll 过度许可 | AGENT-029/030 | 2 |
| KNOWN-008 | MCP Tool | B | Python | SQL 无参数化 | AGENT-026 | 1 |
| KNOWN-009 | JWT 硬编码 | C | Python | JWT 密钥硬编码 | AGENT-004 | 2 |
| KNOWN-010 | CWE-918 | A | Python | requests.get() SSRF | AGENT-037 | 1 |
| KNOWN-011 | CWE-78 | A | Python | subprocess.Popen shell | AGENT-036 | 1 |
| KNOWN-012 | CWE-532 | C | Python | 日志记录敏感数据 | AGENT-039 | 1 |

### 3.2 WILDS 数据集（6 个样本）

从真实 GitHub 仓库中提取的漏洞模式，经过匿名化处理。

| ID | 来源 | 集合 | 漏洞数 | 描述 |
|----|------|------|--------|------|
| WILD-001 | 教程代码 | A | 2 | Calculator eval()/exec() |
| WILD-002 | Web 工具代码 | A | 3 | SSRF + curl 命令注入 |
| WILD-003 | 自修改模式 | A | 1 | Agent 修改自身配置 |
| WILD-004 | Token 收集器 | C | 2 | Discord/Telegram/Slack Token 硬编码 |
| WILD-005 | MCP 配置 | B | 2 | MCP stdio 全权限 |
| WILD-006 | Prompt 注入 | A | 2 | 用户输入拼接系统提示词 |

### 3.3 NOISE 数据集（2 个项目）

完整的真实开源项目，用于评估假阳性率（精确率测试）。

| ID | 来源 | Findings 上限 |
|----|------|--------------|
| T12 | anthropics/openclaw | 250 |
| T13 | langchain-ai/langchain (libs/core/) | 50 |

### 3.4 集合分类体系 (Set A/B/C)

全部 40 个标注漏洞按 OWASP Agentic Top 10 (2026) 分为三个集合：

| 集合 | 名称 | 漏洞数 | OWASP 映射 | 竞品差异预期 |
|------|------|--------|------------|-------------|
| **Set A** | 注入与远程执行 | 18 | ASI-01, ASI-02 | agent-audit >> Bandit/Semgrep |
| **Set B** | MCP 与组件风险 | 10 | ASI-04, ASI-06, ASI-07 | agent-audit >> 全部（无竞品理解 MCP） |
| **Set C** | 数据与鉴权 | 12 | ASI-03/05/08/09/10 | 凭据类≈竞品，权限类 >> 全部 |

---

## 4. 评估引擎架构

### 4.1 适配器模式（Tool-Agnostic）

```
BaseAdapter (抽象基类)
├── AgentAuditAdapter   # 调用 python -m agent_audit scan --format json
├── BanditAdapter       # 调用 bandit -f json
└── SemgrepAdapter      # 调用 semgrep --json
```

每个适配器实现统一接口：
- `scan(project_path)` → `List[ToolFinding]`
- `get_tool_name()` → `str`
- `get_tool_version()` → `str`
- `is_available()` → `bool`

**ToolFinding** 标准化数据结构包含：
- `file`, `line`, `rule_id`, `severity`, `message`
- `confidence` (0.0-1.0), `tier` (BLOCK/WARN/INFO/SUPPRESSED)
- `mapped_vuln_type`, `mapped_set` (A/B/C)
- `tool_specific` (工具特有数据，如 taint 信息)

**AgentAuditAdapter** 特别支持：
- Taint 元数据提取（从 `metadata.taint_analysis.dangerous_flows[]`）
- Source/Sink 类型映射（`function_param → user_input`, `shell_exec → shell_execution`）
- Tier 分类和置信度传递

### 4.2 Oracle 评估引擎 (oracle_eval.py)

核心评估流程：

```
输入: 工具 findings + oracle.yaml (ground truth)
                    ↓
Step 1: 匹配 oracle 中的 vulnerabilities → TP / FN
Step 2: 匹配 oracle 中的 safe_patterns → FP / TN
Step 3: 剩余 findings → unclassified (噪声)
                    ↓
输出: EvalResult (TP, FN, FP, TN, Taint 准确率, 按集合统计)
```

**匹配机制：**
- **文件匹配:** `endswith()` 方式，支持相对路径灵活匹配
- **行号匹配:** ±5 行容差（`line_tolerance=5`）
- **防重复:** `matched_ids` 集合追踪已匹配的 finding
- **line_range 支持:** oracle 可指定行号范围，自动扩大容差

**Taint 验证（P3 深度分析）：**
- `validates_taint_flow()`: 宽松匹配（支持等价源类型：`user_input ≡ llm_output`）
- `validates_taint_flow_strict()`: 严格匹配（无等价映射）
- `evaluate_taint_overlap()`: 部分匹配评分（source +0.33, sink +0.34, propagation +0.33）

### 4.3 Oracle YAML 结构

每个样本的 `oracle.yaml` 遵循标准化 schema：

```yaml
metadata:
  sample_id: "KNOWN-001"
  source: "CVE-2023-29374"
  language: "python"
  provenance: "cve"  # cve | wild | benchmark

taxonomy:
  set_class: "A"       # A | B | C
  owasp_asi: "ASI-02"
  cwe_id: "CWE-95"

vulnerabilities:        # 预期的真阳性
  - id: "VULN-001"
    file: "vuln/math_chain.py"
    line: 42
    rule_expected: "AGENT-034"
    severity: "CRITICAL"
    taint:              # P3: Source→Sink 数据流标注
      source:
        type: "llm_output"
        location: "vuln/math_chain.py:38"
      sink:
        type: "eval"
        location: "vuln/math_chain.py:42"
      sanitizer: null

safe_patterns:          # 预期的真阴性（FP 陷阱）
  - id: "SAFE-001"
    file: "vuln/math_chain.py"
    line: 14
    trap_type: "import_statement"
```

---

## 5. Layer 2: 真实框架扫描

### 5.1 目标列表 (T1-T11)

通过 `benchmark_config.yaml` 配置，覆盖 5 种类型的项目：

| ID | 项目 | 类别 | 扫描路径 | 质量要求 |
|----|------|------|----------|----------|
| T1 | damn-vulnerable-llm-agent | 故意漏洞 | . (全仓库) | findings >= 3 |
| T2 | DamnVulnerableLLMProject | 故意漏洞 | . (全仓库) | ASI >= 3 |
| T3 | langchain-core | 框架 | libs/core/langchain_core | findings <= 50 |
| T4 | agents-from-scratch | 教学 | . (全仓库) | - |
| T5 | deepagents | 框架 | . (全仓库) | findings <= 100 |
| T6 | openai-agents-python | 框架 | src/ | - |
| T7 | adk-python (Google) | 框架 | src/ | - |
| T8 | agentscope | 框架 | src/agentscope | - |
| T9 | crewAI | 框架 | lib/crewai | findings <= 150 |
| T10 | 100-tool-mcp-server | 配置 | 本地 JSON | - |
| T11 | streamlit-agent | 应用 | . (全仓库) | - |

### 5.2 运行流程

`run_benchmark.py` 执行流程：

1. 解析 `benchmark_config.yaml` 中的目标列表
2. `git clone --depth 1 -b <ref>` 克隆/更新仓库
3. 对每个目标执行 `agent-audit scan <path> --format json`
4. 提取 ASI 分类（兼容新旧字段名）
5. 与上次结果对比，检测回归
6. 生成 Markdown 报告 + JSON 结果 + layer2.json
7. 执行质量评估（OWASP 覆盖率、finding 上限）

---

## 6. Layer 1: 合成样本评估

### 6.1 Ground Truth

位于 `tests/ground_truth/labeled_samples.yaml`，包含：
- **81 个标注样本**（68 个含漏洞 + 13 个安全样本）
- **40 个人工标注的漏洞**
- 每个漏洞记录：文件、行号、规则 ID、OWASP ID、置信度、is_true_positive 标记

### 6.2 评估脚本

`precision_recall.py` 执行流程：

1. 加载 ground truth YAML
2. 运行 `agent-audit scan` 或读取已有结果
3. 对比计算 TP/FP/FN（±3 行容差）
4. 按 ASI 分类计算 per-ASI recall
5. 输出报告 + 质量门禁检查

---

## 7. 质量门禁系统

### 7.1 统一质量门禁 (quality_gates_v2.yaml)

三层检查统一入口 `quality_gate_check.py`：

| 检查项 | 阈值 | 是否阻断 |
|--------|------|----------|
| **Layer 1 Precision** | >= 90% | 阻断 |
| **Layer 1 Recall** | >= 85% | 阻断 |
| **Layer 1 F1** | >= 0.87 | 阻断 |
| **Layer 1 FP Rate** | <= 5% | 阻断 |
| **Layer 1 Per-ASI Recall** | ASI-01~10 各 70%~80% | 阻断 |
| **AVB Overall Recall** | >= 60% | 阻断 |
| **AVB Set A Recall** | >= 70% | 阻断 |
| **AVB Set B Recall** | >= 60% | 阻断 |
| **AVB Set C Recall** | >= 50% | 阻断 |
| **AVB Precision** | >= 80% | 阻断 |
| **AVB 回归检测** | 无样本退化 | 阻断 |
| **Layer 2 OWASP 覆盖** | 10/10 | 警告 |
| **Layer 2 最大扫描时间** | < 120s | 警告 |

### 7.2 执行方式

```bash
# 一键执行全部评估 + 质量门禁
./tests/benchmark/run_all.sh

# 分步执行
python tests/benchmark/precision_recall.py --output-json results/layer1.json
python tests/benchmark/agent-vuln-bench/harness/run_eval.py --tool agent-audit --output results/avb_results.json
python tests/benchmark/run_benchmark.py --config tests/benchmark/benchmark_config.yaml
python tests/benchmark/quality_gate_check.py --config tests/benchmark/quality_gates_v2.yaml --results results/
```

---

## 8. 当前基线数据 (v0.4.1)

### 8.1 Agent-Vuln-Bench 指标

| 指标 | 当前值 | v0.5.0 目标 | 差距 |
|------|--------|------------|------|
| Overall Recall | **17.6%** | 80% | -62.4pp |
| Set A Recall (注入) | **33.3%** | 90% | -56.7pp |
| Set B Recall (MCP) | **0.0%** | 90% | -90pp |
| Set C Recall (数据) | **0.0%** | 70% | -70pp |
| Precision | **100%** | 85%+ | ✅ 达标 |
| Taint Accuracy | **0.0%** | 30% | -30pp |

### 8.2 已识别的检测能力缺口

| 缺口 | 严重度 | 影响的样本 | 说明 |
|------|--------|-----------|------|
| eval/exec 仅在 @tool 上下文检测 | HIGH | KNOWN-001, KNOWN-002 | 非 @tool 函数中的 eval/exec 不触发 |
| MCP JSON 独立文件未扫描 | MEDIUM | KNOWN-003 | 孤立的 JSON 配置文件不会被扫描 |
| 凭据模式不够全面 | MEDIUM | KNOWN-004 | 部分 API Key 格式未覆盖 |
| SSRF 检测未完全实现 | MEDIUM | KNOWN-010 | requests.get(user_url) 不触发 |
| Taint 输出缺失 | LOW | 全部 | v0.4.x 不输出 source→sink 信息 |

### 8.3 v0.4.1 检测结果

在基线评估中，v0.4.1 仅成功检测到 1/5 个初始 KNOWN 样本：

- ✅ **KNOWN-005**: Shell 注入正确检测（3 个 finding）
- ❌ **KNOWN-001/002**: eval/exec 漏洞未检出
- ❌ **KNOWN-003**: MCP 配置漏洞未检出
- ❌ **KNOWN-004**: 硬编码凭据未检出

---

## 9. 五支柱设计框架

Agent-Vuln-Bench 基于以下五个设计支柱构建：

| 支柱 | 名称 | 状态 | 说明 |
|------|------|------|------|
| **P1** | 数据真实性 | Partial | Knowns 使用 CVE 代码切片（非完整仓库），Wilds 来自真实代码 |
| **P2** | 分类体系对齐 | Complete | OWASP Agentic Top 10 全覆盖，10/10 ASI 分类 |
| **P3** | 深度分析 | Complete | Oracle 包含 taint flow 标注（source→propagation→sink） |
| **P4** | SWE-Bench 架构 | In Progress | Oracle 驱动、工具无关，Docker 支持待实现 |
| **P5** | 硬核指标 | In Progress | Recall/Precision/FPR/Per-Set，多工具对比待完善 |

---

## 10. 已完成的里程碑

### 基础设施 (v0.4.0-v0.4.1)

- [x] 三层评估架构设计与实现
- [x] Agent-Vuln-Bench v1.0 数据集结构
- [x] 12 个 KNOWN 样本 + 6 个 WILD 样本 + 2 个 NOISE 项目
- [x] Oracle YAML schema 设计（含 taint flow 标注）
- [x] SWE-Bench 风格评估引擎 (oracle_eval.py)
- [x] 三种工具适配器 (agent-audit, bandit, semgrep)
- [x] Layer 2 benchmark runner（T1-T11 配置）
- [x] Layer 1 precision/recall 评估器
- [x] 统一质量门禁系统 (quality_gates_v2.yaml)
- [x] OWASP Agentic Top 10 → Set A/B/C 分类映射
- [x] v0.4.1 基线建立
- [x] 回归检测机制

### 最新增强 (v0.5.0 推进)

- [x] TaintTracker 函数内数据流分析模块
- [x] AgentAuditAdapter 支持 taint 元数据提取与转换
- [x] oracle_eval.py 增强：等价源类型映射、严格验证模式、部分匹配评分
- [x] EvalResult 支持 unclassified_findings 追踪
- [x] run_eval.py 支持回归检测和 CI 输出格式
- [x] 多工具对比报告生成 (compare_tools.py)
- [x] 增强的指标计算模块 (compute_metrics.py)

---

## 11. 待完成事项

### 短期 (v0.5.0)

| 优先级 | 任务 | 目标 |
|--------|------|------|
| P0 | 修复 eval/exec 通用检测 | Set A Recall → 70%+ |
| P0 | MCP 独立 JSON 文件扫描 | Set B Recall → 60%+ |
| P0 | 扩展凭据检测模式 | Set C Recall → 50%+ |
| P1 | Taint 输出集成到 JSON 格式 | Taint Accuracy → 30%+ |
| P1 | SSRF 检测实现 | KNOWN-010 通过 |
| P2 | 多工具对比基线 (Bandit, Semgrep) | 竞品数据收集 |

### 中长期

| 任务 | 说明 |
|------|------|
| Docker 隔离执行 | P4 支柱完善：沙盒环境运行扫描 |
| CI/CD 集成 | GitHub Actions 自动运行 benchmark |
| 数据集扩展 | KNOWN → 20+, WILD → 10+ |
| TypeScript 样本 | 覆盖 JS/TS 生态的 Agent 框架 |
| 社区贡献指南 | 允许外部提交新的 benchmark 样本 |

---

## 12. 运行指南

```bash
# 前置条件
cd packages/audit && poetry install

# ===== 快速验证 =====
# 运行全部单元测试（Layer 1 基础）
poetry run pytest ../../tests/ -v

# ===== Layer 1: 精确率/召回率 =====
poetry run python ../../tests/benchmark/precision_recall.py --verbose --output-json /tmp/results/layer1.json

# ===== Agent-Vuln-Bench =====
# 单工具评估
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_eval.py \
  --tool agent-audit --dataset knowns --output /tmp/results/avb_results.json

# 全数据集
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_eval.py \
  --tool agent-audit --dataset all --output /tmp/results/

# 按集合筛选
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_eval.py \
  --tool agent-audit --set A --output /tmp/results/

# 多工具对比（需安装 bandit/semgrep）
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_eval.py \
  --tool all --output /tmp/results/

# ===== Layer 2: 真实框架 =====
python tests/benchmark/run_benchmark.py --config tests/benchmark/benchmark_config.yaml

# ===== 质量门禁 =====
python tests/benchmark/quality_gate_check.py \
  --config tests/benchmark/quality_gates_v2.yaml --results /tmp/results/

# ===== 一键全部 =====
./tests/benchmark/run_all.sh
```

---

## 13. 关键设计决策记录

| 决策 | 选择 | 理由 |
|------|------|------|
| 数据集格式 | 最小化代码切片 | 降低维护成本，聚焦漏洞模式本身 |
| 评估引擎 | Oracle-driven | 消除人工判断主观性 |
| 行号容差 | ±5 行 | 不同版本工具对行号定位有差异 |
| 集合分类 | A/B/C 三集合 | 匹配 agent-audit 的差异化优势领域 |
| Taint 等价 | user_input ≡ llm_output | 安全等价：两者都是不可信外部输入 |
| 质量门禁 | Layer 1 阻断 + Layer 2 警告 | 核心指标必须达标，框架扫描允许波动 |
| 工具无关设计 | 适配器模式 | 便于横向对比，证明 agent-audit 的优势 |
