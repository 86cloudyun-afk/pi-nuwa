# 测试结果（1.2.1）

日期：2026-11-08
环境：本机仓库布局，Python 3.14.7，bun 1.4.4，flock；真实 sapper 1.0.0 已装 `~/.local/bin/sapper`。
原则：可离线、零模型成本；E2E 通过 `NUWA_ALLOW_FAKE_SAPPER=1` 使用替身。

## 一、套件

| 套件 | 用例 | 结果 | 备注 |
|---|---|---|---|
| `unit.test.ts` | 42 | 42 pass | 含工具策略绕过面 |
| `test_nuwa_shell.py` | 14 | 14 pass | CLI 契约 |
| `test_chaos.py` | 8 | 8 pass | 坏图/锁/只读/SIGKILL |
| `test_concurrency.py` | 5 | 5 pass | 单赢家/跨项目/锁清理 |
| `test_e2e_deterministic.py` | 4 | 4 pass | 替身引擎 |
| `test_r1_core.py` | 40 | 40 pass | journal 23 + 账本/事务 17 |
| `test_r1_dispatch.py` | 2 | 2 pass | 预留/幂等 |
| `test_r1_run.py` | 2 | 2 pass | round 循环 + goal edge 回滚 |
| `test_r1_multi.py` | 1 | 1 pass | 四项目并发 |
| `test_r2_r7.py` | 29 | 29 pass | 公平/证据/指标/策略/插件/夜跑 |
| `crash_matrix.py` | 16 runs | pass | fake 6 点 + real 4 点快速组 |
| `test_guard.py` | 16 | 16 pass | 执行层提交闸门（token/缩写/伪造/from-intent/dry-run/auto） |

合计 **163 例 + 16 runs**。

## 二、门禁

| 门禁 | 结果 | 说明 |
|---|---|---|
| `g0_baseline` | pass | `contract_check` 13/13（真实 sapper 1.0.0） |
| `g1_r1` | pass | 逐项聚合，任一套件失败都会非零 |
| `g2_r2r7` | pass | 28 例 |

`tests/run.sh` 最终 `EXIT=0`；全部套件与门禁通过。

## 三、审计反例

| 类 | 用例 |
|---|---|
| journal | 空代高水位、CURRENT 缺失不覆盖、未决事务代保护、recovery 摘要、20KB 单条记录、并发 append+compact、gen9/gen10 排序、坏 UTF-8、inflight 复活、ledger_settle 保护 |
| 策略 | `..`、符号链接、多级祖先链接、`files[]`/`apply_patch` 正文、`&&`/`sh -c`/`$()`/反斜杠/`--store`/绝对路径、`budget/global.jsonl`、`cap.json`、`recovery.json` |
| 事务 | `--key auto` 幂等、其他键冲突、`nuwa complete` 多 fact 与 kind 闸门、attempt 严格校验 |
| 夜跑 | 类型异常、非有限数、非整数 samples、duration 一致性、`--expect-commit` |

## 四、仍然缺的读数

- real 崩溃组仍用替身注入点；真实 sapper 的 4 点崩溃注入需要固定 ref 的 CI 环境。
- 72h soak 需要自托管 runner 实际执行；本机只验证入口与报告校验。
