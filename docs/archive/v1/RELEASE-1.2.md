# 女娲模式 1.2.0 发布说明

日期：2026-11-08
基线：1.1.0

## 主题

把 1.1 的三条待办收口成可验证的运行时约束：**日志不再丢 seq、工具面不再只拦 bash、fact 只能经 nuwa 提交**。

## 新增

| 项 | 内容 |
|---|---|
| journal 代际 GC | `Journal.gc(keep)` 删除「当前代 - keep」之前的 `journal.<gen>.jsonl` 与 `checkpoint.<gen>.json`；`compact()` 归档后自动执行，`NUWA_JOURNAL_KEEP` 默认 2 |
| 跨代 seq | `last_seq()` 取所有代际尾部最大值；`compact()` 先取 seq 再 `os.replace`，checkpoint 不再写 0 |
| 工具面策略 | 扩展 `checkTool` 覆盖 bash / task / write / edit / multi_edit / apply_patch；P-005 图目录、P-006 提交绕过、P-007 权威状态、P-009 project.json |
| 提交所有权 | `buildDirective` 与 `SKILL.md` 改为「子代理取证 → 主线程 `nuwa commit`」；`--key auto` 生成规范幂等键 |
| 夜跑校验 | `nuwa soak-verify <base>`：`REPORT.json` 的 mode/commit/minutes/samples/verdict 与 `MODE`、`COMMIT` 两侧一致才返回 0 |

## 测试读数（本机仓库布局）

| 套件 | 用例 | 结果 |
|---|---|---|
| `tests/unit.test.ts` | 30 | 30 pass |
| `tests/test_nuwa_shell.py` | 14 | 14 pass |
| `tests/test_chaos.py` | 8 | 8 pass |
| `tests/test_concurrency.py` | 5 | 5 pass |
| `tests/test_r1_core.py` | 15 | 15 pass |
| `tests/test_r2_r7.py` | 24 | 24 pass |
| `tests/test_r1_dispatch.py` | 2 | 2 pass |
| `tests/test_r1_run.py` | 1 | 1 pass |
| `tests/test_r1_multi.py` | 1 | 1 pass |
| `tests/test_e2e_deterministic.py` | 4 | 4 pass（`NUWA_ALLOW_FAKE_SAPPER=1`） |
| `tests/crash_matrix.py` | 16 runs | pass |

`tests/contract_check.py` 需要真实 sapper（PATH 中没有），本机按退出码 2 记录为环境缺依赖；
E2E 的三种反例之前因 `fake-sapper` 不识别 `FAKE_ENGINE_MODE` 而失败，1.2 补齐 noop /
hallucinate / malformed 三个分支后 4/4 通过。

## 兼容

- `nuwa commit --key` 仍必填，新增取值 `auto`；原显式键行为不变。
- `Journal.compact()` 新增可选 `keep` 参数；不传时读 `NUWA_JOURNAL_KEEP`。
- 扩展新增 `checkTool` 导出；`checkCommand` 语义未变（仍只含 P-001..P-004）。
- 策略规则 id 只增不减：P-001..P-004 保持不变，新增 P-005/P-006/P-007/P-009。

## 仍待办

- 72h 夜跑需自托管 runner 实际执行；本轮只验证入口、6 秒冒烟与报告校验器。
- `sapper flag` 直接入账仍是允许路径（P-006 只拦 done/dispatch/complete）；若要全量收口需在 R6 插件层加 flag 适配。
- journal GC 只按代数删除，不按引用计数；快照引用保护留到 R6 的快照协议。
