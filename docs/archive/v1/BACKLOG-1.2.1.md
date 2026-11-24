# 1.2.1 审计 backlog

审计口径：codex `gpt-6.1-sol` / `reasoning=ultra`，只读沙盒，十六轮。
当前状态：approve_after_fixes，73/100；真实 sapper 1.0.0 下 `contract` 13/13、`tests/run.sh` EXIT=0、167 例 + 16 runs。
已关闭：B1–B5、B11–B21（其中 B6/B7/B21 仅余 shell 语义边界）、M9/M11/M12/M13/M14/M16/M23/M26。

下列项不在本轮 blocking 修复范围，按「证据 → 风险 → 下一步」登记，供 1.3 逐条处理。

| ID | 证据 | 风险 | 下一步 |
|---|---|---|---|
| M5 | 已修：`night.run` 写 `samples.jsonl`，`verify` 重算 RSS/FD growth 并与 REPORT 对比 | 剩余：verdict 其余判据仍为自报 | 1.3 补 per-project 采样 |
| M17 | 已修：`reserve_committed` 带 tokens，repair 只结算 `has_reserve` 且取摘要 tokens | 剩余：摘要 inflight 的默认值 | 1.3 补缺失字段拒绝结算 |
| M20 | 已修：`txn.lock` 内复查未终态事务，排除当前 txn | 剩余：reserve 与 prepare 之间仍有极窄窗口 | 1.3 引入 intent 级 flock |
| M21 | 已修：journal 并发用例加 `Barrier`；新增 reserve tokens 反例 | 剩余：其余套件的交错 | 1.3 为 crash_matrix 加确定性注入 |
| M22 | `nuwa/ledger.py:77`、`:112` | `has_reserve` 对 reclaim/renew/重复 rid 的边界 | 账本增加 `rid` 状态机视图，单测覆盖 reserve→reclaim→reserve |
| M25 | `nuwa/graph.py:105` | 同一 fact 多 marker 的冲突裁决 | 规定「首个 `x-nuwa-key` 为权威」，正文多 marker 只做审计线索 |
| M27 | `nuwa/journal.py:319`、`:446` | `replay_state` 与 `_summarize` 的终态归并仍有细节差异 | 抽公共 `apply_event(state, rec)`，两条路径共用 |
| M28 | `nuwa/dispatch.py:124`、`:191` | attempt 写回失败/result 读取异常的收尾 | 写回失败直接 fail-closed；result 解析统一走 `_read_result` |
| M29 | `extensions/nuwa-loop/index.ts:106` | 路径规则对 `cd` 失败分支的误报/漏报 | 把 shell 解析移到宿主侧，扩展只做字面量兜底 |
| M30/M31 | `nuwa/night.py:112`、`:136` | 夜跑时长与采样覆盖的交叉校验 | 记录每项目 `started/finished/samples`，按项目判定 |
| M32 | `nuwa/txn.py:129`、`nuwa/graph.py:76` | `patch_intent` 写盘后 validate 失败的恢复 | 统一走 `_restore_intent`，并给 `patch_intent` 加事务上下文 |
| M33 | `nuwa/journal.py:91`、`:159` | 尾读/全读在极端编码与超长行上的性能 | 加 1MB 单行基准，超限直接拒绝写入并报错 |
| M34 | `extensions/nuwa-loop/index.ts:246` | `candidateDirs` 祖先链带来的路径检查放大 | 缓存 resolve 结果；候选数上限 + 超限 fail-closed |
| M35/M36 | `nuwa/txn.py:75`、`nuwa/ledger.py:143` | 基线遗留的账本/事务边界 | 并入 M17/M22 一起处理 |

| M102 | `worker.py:69` / `txn.py:317` / `dispatch.py:185` | 父进程提交前 repair 提前 ack，后续 attempt 键冲突 | 1.3 统一 worker 退出/提交状态机 |
| M103 | `runner.py` overrun 分支 vs `ack` | 超支结算后缺 ack 终态 | 已在第七十七轮把 ack 提前到 settle 后 |

## 既定接受边界（审计已排除为 blocking）

| ID | 边界 | 缓解 |
|---|---|---|
| B6 | 目录复制/移动的隐含子路径、递归覆盖；直接改图属于宿主写入边界 | 提交语义由执行层 guard 收口；扩展只做字面兜底 |
| B23 | 同 UID 可读 token；PPID 名称子串 | token + PPID 双因子；同 UID 是信任边界 |
| B30 | 扩展侧 Node 无 flock，回滚在 `.sapper/.lock` 外 | shell/Python 锁内重判；扩展回滚仅处理 session 内单线程 |

## 结论

阻断项已从「数据丢失 / 普通输入绕过 / 虚假结算」收敛到「竞态与极端输入」。
继续用同一审计员刷分会不断产生新的推断级条目；1.3 的验收应改为：
真实 sapper 的 4 点崩溃注入、72h soak、以及上表逐条的独立反例。
