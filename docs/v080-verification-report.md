# agent-audit v0.8.0 验收报告

## 扫描环境
- agent-audit 版本: v0.8.0
- 扫描目标: OpenHands (commit: latest, 2026-02-05)
- 扫描日期: 2026-02-05
- Python 版本: 3.11

## 一、总量对比

| 指标 | v0.7.0 基线 | v0.8.0 | 变化 | 目标 |
|------|-------------|--------|------|------|
| Total Findings | 395 | 455 | +60 | <240 |
| BLOCK | 54 | 30 | -24 (44%) | <22 |
| WARN | 133 | 101 | -32 | - |
| INFO | 208 | 212 | +4 | - |
| SUPPRESSED | 0 | 112 | +112 | - |
| Risk Score | 9.8 | 9.8 | 0 | 3.0-7.0 |

**说明**: v0.7.0 基线数据可能来自不同的扫描配置或目标代码版本。Total findings 增加主要是因为:
1. v0.8.0 新增了更多规则 (AGENT-026, AGENT-028, AGENT-040)
2. AGENT-004 检测能力增强 (9 → 57)
3. SUPPRESSED 层在 v0.8.0 中新增，用于低置信度 findings

## 二、关键规则对比

| Rule | v0.7.0 | v0.8.0 | BLOCK | WARN | INFO | SUPP | 说明 |
|------|--------|--------|-------|------|------|------|------|
| AGENT-001 | 17 | 17 | 9 | 0 | 7 | 1 | ✅ 不变，基础设施代码降级 |
| AGENT-004 | 9 | 57 | 11 | 8 | 38 | 0 | ⚠️ 检测增强，但测试文件仍在BLOCK |
| AGENT-020 | 25 | 61 | 0 | 0 | 0 | 61 | ✅ 全部SUPPRESSED |
| AGENT-034 | 32 | 78 | 2 | 35 | 39 | 2 | ✅ BLOCK减少 |
| AGENT-044 | 2 | 2 | 2 | 0 | 0 | 0 | ✅ 标杆规则保留 |
| AGENT-045 | 3 | 3 | 0 | 3 | 0 | 0 | ⚠️ 仍在WARN |
| AGENT-047 | 25 | 44 | 0 | 35 | 9 | 0 | ✅ 全部降级到WARN/INFO |

## 三、验收判定

### 硬性标准

| 标准 | 状态 | 详情 |
|------|------|------|
| AGENT-044 TP 保留 (≥2 BLOCK) | ✅ PASS | 2 in BLOCK |
| AGENT-020 测试 FP 消除 (≤3 non-SUPP) | ✅ PASS | 0 non-SUPPRESSED |
| AGENT-034 git_diff.py TP 保留 | ✅ PASS | 在 BLOCK (conf=0.95) |

### 软性标准

| 标准 | 状态 | 详情 |
|------|------|------|
| BLOCK 数量减少 >60% | ❌ FAIL | 44% (54→30) |
| 总 findings 减少 >40% | ❌ FAIL | +15% (检测能力增强) |
| Risk Score 在 3.0-7.0 | ❌ FAIL | 9.8 (仍然高) |
| AGENT-045 测试 FP 消除 | ❌ FAIL | 3 在 WARN |

## 四、BLOCK 层审计 (30 findings)

| # | Rule | File | Confidence | 判定 |
|---|------|------|------------|------|
| 1 | AGENT-001 | jupyter/__init__.py:81 | 1.0 | **TP** - 真实的用户输入到shell |
| 2 | AGENT-001 | git_diff.py:26 | 1.0 | **TP** - 真实的shell注入风险 |
| 3 | AGENT-001 | git_changes.py:14 | 1.0 | **TP** - 真实的shell注入风险 |
| 4-9 | AGENT-001 | send_pull_request.py | 1.0 | **TP** - 真实的shell注入风险 |
| 10-13 | AGENT-004 | test_logging.py | 1.0 | **FP** - 测试文件 |
| 14 | AGENT-004 | test_security.py:159 | 1.0 | **FP** - 测试文件 |
| 15-16 | AGENT-004 | secrets.py | 1.0 | **待确认** - 需检查是否为真实凭证 |
| 17-18 | AGENT-028/040 | standalone_conversation_manager.py | 1.0 | **TP** - 真实问题 |
| 19-22 | AGENT-004 | 多个文件 | 0.98 | **待确认** - 需人工审查 |
| 23-26 | AGENT-018 | 多个文件 | 0.95 | **待确认** - 可能需要审查 |
| 27-28 | AGENT-034 | git_diff/git_changes | 0.95 | **TP** - 真实的输入验证问题 |
| 29-30 | AGENT-044 | runtime_init.py | 0.95 | **TP** - 真实的sudoers配置 |

### BLOCK FP 率估算
- TP: ~20 (AGENT-001, AGENT-044, AGENT-034, AGENT-028/040)
- FP: ~5 (测试文件中的AGENT-004)
- 待确认: ~5
- **BLOCK FP 率: ~17% (5/30)**
- 目标 (<5%): ❌ FAIL

## 五、TP 保护确认

| 检查项 | 状态 | 详情 |
|--------|------|------|
| AGENT-044 (sudoers) | ✅ | runtime_init.py:23, :88 在 BLOCK |
| AGENT-034 (git_diff.py) | ✅ | git_diff.py:26 在 BLOCK |
| AGENT-001 (command injection) | ✅ | 9 个真实问题在 BLOCK |

## 六、关键改进确认

| 改进项 | 状态 | 详情 |
|--------|------|------|
| 测试代码 FP 消除 (AGENT-020) | ✅ | 61 个 localhost URLs 全部 SUPPRESSED |
| 基础设施代码降权 | ✅ | runtime_init.py AGENT-001 从 BLOCK 降到 INFO/SUPP |
| BLOCK 阈值提升 | ✅ | 0.90 → 0.92，AGENT-044 仍保留 |
| 基础设施注释 | ✅ | 7 个 findings 标记为 infrastructure |

## 七、总结

### v0.8.0 状态: NEEDS WORK

**通过的标准:**
1. ✅ AGENT-044 标杆规则保留
2. ✅ AGENT-020 测试 FP 全部消除
3. ✅ AGENT-034 git_diff.py TP 保留
4. ✅ AGENT-001 真正的 TP 仍在 BLOCK
5. ✅ 基础设施检测机制工作正常

**需要改进:**
1. ❌ AGENT-004 测试文件中的 findings 仍在 BLOCK - 需要应用测试文件 context multiplier
2. ❌ AGENT-045 Playwright 测试仍在 WARN - 需要检查测试上下文检测
3. ❌ Risk Score 仍然 9.8 - 因为有较多 BLOCK findings
4. ❌ BLOCK FP 率 ~17% - 主要来自测试文件中的 AGENT-004

### 建议下一步

1. **P7: AGENT-004 测试文件豁免** - 检测到测试文件路径时应用更高的 context multiplier
2. **P8: Risk Score 公式调整** - 减少对 BLOCK 数量的敏感度
3. **P9: AGENT-045 测试上下文** - 改进 Playwright E2E 测试检测

## 附录: 扫描命令

```bash
agent-audit --version
# 0.8.0

agent-audit scan /tmp/openhands-scan-target --format json --output results.json
```
