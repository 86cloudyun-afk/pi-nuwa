# 1.2.1 审计 backlog

审计口径：codex `gpt-6.1-sol` / `reasoning=ultra`，只读沙盒，十一轮。
当前状态：block，57/100；真实 sapper 1.0.0 下 `contract` 13/13、`tests/run.sh` EXIT=0。

下列项不在本轮 blocking 修复范围，按「证据 → 风险 → 下一步」登记，供 1.3 逐条处理。

| ID | 证据 | 风险 | 下一步 |
|---|---|---|---|
| M5 | `nuwa/night.py:106`、`:136` | `verdict` 的 RSS/FD 仍是 soak 自报；journal 锚点只证明事件发生 | 用 `/proc/<pid>/status` 独立采样重算 verdict，报告存原始采样 |
| M17 | `nuwa/txn.py:181`、`nuwa/journal.py:290` | 恢复摘要与账本口径在 `reserve_committed` 前后仍有默认值差异 | 摘要 inflight 强制携带 rid/tokens；repair 缺失字段时拒绝结算而非用 4000 |
| M20 | `nuwa/dispatch.py:77`、`:112` | 同 intent 并发准入靠 inflight 锁，窗口未完全消除 | 在 `txn.lock` 内做 reserve+executing_prepare，或引入 intent 级 flock |
| M21 | `tests/test_r1_dispatch.py:51`、`tests/test_r1_core.py:203` | 并发测试缺确定性交错；部分反例在旧实现也能过 | 用 `threading.Barrier` + 注入点做确定性并发；为每个反例保存旧实现失败日志 |
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

## 结论

阻断项已从「数据丢失 / 普通输入绕过 / 虚假结算」收敛到「竞态与极端输入」。
继续用同一审计员刷分会不断产生新的推断级条目；1.3 的验收应改为：
真实 sapper 的 4 点崩溃注入、72h soak、以及上表逐条的独立反例。
