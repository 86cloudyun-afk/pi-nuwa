# R1 进度（0.4.0-dev）

## 已实现

- journal / checkpoint / CURRENT / 重放摘要
- 全局账本 reserve/renew/reclaim/settle/opening_balance + 准入
- run/txn/inflight 三层锁与存活探测
- 幂等键与 fact description 标记；commit 先扫 key、再 sapper done、修补 intent、validate
- worker：先加锁、ready、fork+wait、result，锁 fd 传给子进程
- dispatch：渲染提示 → 引擎 → executed → 解析 → 提交 → 结算
- run：round 循环、reason 批量幂等、并行 dispatch、证据闸门、run.json、resume 计数
- CLI：ls/status/attach/budget/commit/dispatch/run/recover/adopt
- 测试：core 11、dispatch 2、run 1、multi 1（us3 全绿）

## 待补（R1 剩余）

- ~~十点崩溃注入~~ → `tests/crash_matrix.py` 已覆盖 7 个提交点，支持 `--full` 6×20 + 4×5
- checkpoint 压缩与代际回滚：已归档 `journal.<gen>.jsonl`，未做历史代际删除
- registry 并发写压力与损坏重建用例
- 真实 sapper 夜跑组
- `nuwa ls` 与进程一致性的自动断言（当前由 multi 测试间接覆盖）

## 已知边界

- `nuwa dispatch` 的 payload 解析按 `description` 取，未覆盖 sapper 的 deviations 字段
- reason 的 `complete` 条目当前不自动应用，只记录 noop
- 预算按固定 4000 tokens 预留，尚未接引擎 usage
