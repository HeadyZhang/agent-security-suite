# Agent-Audit Benchmark 优化 v3 执行总结

> **执行日期**: 2026-02-04  
> **版本**: v3.0  
> **状态**: ✅ 全部完成

---

## 执行概览

| 顺序 | Prompt | 状态 | 主要产出 |
|------|--------|------|----------|
| P1 | Layer 1 样本补齐 + v2.2 字段 | ✅ 完成 | 81 个样本，schema v2.2 |
| P2 | precision_recall per-ASI 输出 | ✅ 完成 | JSON 含 per_asi 结构 |
| P3 | quality_gate_check per-ASI + Layer2 | ✅ 完成 | 支持逐 ASI + Layer2 检查 |
| P4 | run_benchmark 输出 layer2.json | ✅ 完成 | layer2.json 自动生成 |
| P5 | compare_tools 集成 + CI | ✅ 完成 | comparison_report.md + CI job |
| P6 | Baseline 脚本 + CI 集成 | ✅ 完成 | save_avb_baseline.py + CI 上传 |

---

## 详细完成情况

### P1: Layer 1 样本补齐至 ≥80 + labeled_samples v2.2 字段与 schema

**完成内容:**

1. **新增 22 个 fixture 文件**，覆盖多个 ASI 类别：
   - ASI-04 (Supply Chain): 5 个新样本
     - `npm_install_runtime.py`, `curl_pipe_bash.sh`, `git_clone_exec.py`, `dynamic_requirements.py`, `pypi_typosquatting.py`
   - ASI-03 (Privilege Abuse): 4 个新样本
     - `root_shell_spawn.py`, `chmod_world_writable.py`, `setuid_binary.py`, `docker_privileged.py`
   - ASI-06 (Memory Poisoning): 4 个新样本
     - `raw_user_to_context.py`, `rag_injection.py`, `session_fixation.py`, `pickle_memory.py`
   - ASI-07 (Inter-Agent): 3 个新样本
     - `websocket_no_tls.py`, `shared_redis_no_auth.py`, `grpc_insecure.py`
   - 其他 ASI: 4 个新样本
   - Benign/FP: 2 个新样本

2. **更新 `labeled_samples.yaml`**:
   - 样本数: 59 → **81** (≥80 目标达成)
   - 新样本包含 v2.2 扩展字段 (`expected_tier`, `benchmark_gap` 等)

3. **更新 `schema.yaml`** 至 v2.2:
   - 新增可选字段: `expected_confidence_min`, `expected_confidence_max`, `expected_tier`, `benchmark_gap`, `agent_vuln_bench_link`

**验证命令:**
```bash
python3 -c "import yaml; d=yaml.safe_load(open('tests/ground_truth/labeled_samples.yaml')); print('Samples:', len(d['samples'])); assert len(d['samples'])>=80"
# 输出: Samples: 81
```

---

### P2: precision_recall.py 输出 per-ASI 指标到 --output-json

**完成内容:**

1. **新增 `PerASIMetrics` dataclass**
2. **修改 `evaluate()` 函数**:
   - 返回值改为 `Tuple[EvaluationResult, Dict[str, PerASIMetrics]]`
   - 内部跟踪每个 label 的 `owasp_id`，按 ASI 分组计算 TP/expected/recall
3. **更新 JSON 输出结构**:
   ```json
   {
     "per_asi": {
       "ASI-01": { "recall": 0.3077, "expected": 26, "tp": 8 },
       "ASI-02": { "recall": 0.16, "expected": 75, "tp": 12 },
       ...
     }
   }
   ```

**验证命令:**
```bash
python3 tests/benchmark/precision_recall.py --output-json /tmp/layer1.json
python3 -c "import json; print(json.load(open('/tmp/layer1.json')).get('per_asi',{}))"
```

---

### P3: quality_gate_check.py 实现 per-ASI 与 Layer 2 检查

**完成内容:**

1. **扩展 `check_layer1()` 函数**:
   - 读取 `per_asi` 结构
   - 对比 `quality_gates_v2.yaml` 中的 `per_asi_recall_min` 门限
   - 逐 ASI 报告 FAIL/PASS

2. **新增 `check_layer2()` 函数**:
   - 读取 `results/layer2.json`
   - 检查 `owasp_coverage_min` 和 `max_scan_time_seconds`
   - 根据 `blocking` 配置报告 FAIL 或 WARN

3. **集成到 `main()`**

**验证命令:**
```bash
python3 tests/benchmark/quality_gate_check.py --config tests/benchmark/quality_gates_v2.yaml --results results/
# 输出含: Layer 1 ASI-01 recall 30.8% < 80%, Layer 2 OWASP coverage 5 < 10 等
```

---

### P4: run_benchmark.py 输出 layer2.json 供 quality_gate_check 使用

**完成内容:**

1. **生成 `layer2.json`**:
   ```json
   {
     "owasp_coverage": 10,
     "max_scan_time_seconds": 45.5,
     "per_target": [...],
     "timestamp": "...",
     "tool_version": "..."
   }
   ```

2. **新增 CLI 参数**: `--layer2-json` 指定输出路径

3. **更新输出摘要**: 显示 `Max Scan Time` 和 `Layer2` 路径

**验证命令:**
```bash
# 运行 run_benchmark 后检查
python3 -c "import json; print(json.load(open('results/layer2.json')))"
```

---

### P5: compare_tools 集成到 run_eval + CI 多工具对比报告

**完成内容:**

1. **修改 `run_eval.py`**:
   - 导入 `compare_tools.py` 中的 `generate_detailed_report`, `generate_json_comparison`
   - 新增 CLI 参数: `--comparison-report`
   - 当 `--tool all` 且多于 1 个工具时，自动生成:
     - `comparison_report.md` (详细 Markdown 对比报告)
     - `comparison_results.json` (JSON 格式对比数据)

2. **更新 CI workflow (`.github/workflows/benchmark.yml`)**:
   - 新增 `compare-tools` job
   - 条件: `workflow_dispatch` 或 `schedule` 触发
   - 安装 bandit/semgrep (continue-on-error)
   - 上传 comparison artifacts

**验证命令:**
```bash
python tests/benchmark/agent-vuln-bench/harness/run_eval.py --tool all --output results/
# 检查 results/comparison_report.md 和 results/comparison_results.json
```

---

### P6: Baseline 生成脚本 + CI 中 baseline 的保存与使用

**完成内容:**

1. **新增 `tests/benchmark/scripts/save_avb_baseline.py`**:
   - 从 run_eval 结果提取 passing_samples 和 metrics
   - 生成 baseline.json:
     ```json
     {
       "version": "v0.5.0",
       "date": "2026-02-04T...",
       "passing_samples": ["KNOWN-001", ...],
       "metrics": { "recall": 0.75, "precision": 0.85, ... },
       "sample_count": N
     }
     ```
   - 支持 `--eval-results` 或内部运行 run_eval

2. **更新 CI workflow**:
   - 下载之前的 baseline artifact (if exists)
   - 运行 run_eval 时传入 `--baseline` 参数
   - main 分支通过时生成并上传 baseline artifact

**验证命令:**
```bash
python3 tests/benchmark/scripts/save_avb_baseline.py \
  --eval-results results/avb_results.json \
  --output results/baseline.json
# 检查 results/baseline.json
```

---

## 修改文件清单

| 文件路径 | 变更类型 | 说明 |
|----------|----------|------|
| `tests/ground_truth/labeled_samples.yaml` | 修改 | 新增 22 个样本条目，更新版本至 v2.2 |
| `tests/ground_truth/schema.yaml` | 修改 | 新增 v2.2 可选字段定义 |
| `tests/fixtures/**` | 新增 | 22 个新 fixture 文件 |
| `tests/benchmark/precision_recall.py` | 修改 | 新增 per-ASI 输出 |
| `tests/benchmark/quality_gate_check.py` | 修改 | 新增 per-ASI 和 Layer 2 检查 |
| `tests/benchmark/run_benchmark.py` | 修改 | 新增 layer2.json 输出 |
| `tests/benchmark/agent-vuln-bench/harness/run_eval.py` | 修改 | 集成 compare_tools |
| `tests/benchmark/scripts/save_avb_baseline.py` | 新增 | Baseline 生成脚本 |
| `.github/workflows/benchmark.yml` | 修改 | 新增 compare-tools job 和 baseline 处理 |

---

## 未完成项

**无。** 所有 6 个 Prompt 的交付清单项均已完成。

---

## 后续建议

1. **提升 Recall**: 当前 Layer 1 recall 约 47.5%，远低于 85% 目标。需要增强规则覆盖或减少 FN。
2. **补齐规则**: 部分 ASI 类别 (如 ASI-04 Supply Chain) recall 为 0%，需新增相应规则。
3. **运行完整 CI**: 在 main 分支上触发完整 workflow 以验证所有集成。
4. **Taint 分析**: compare_tools 报告显示 taint 分析为 0%，是后续重点改进方向。

---

*执行总结结束。*
