# R1 设计：多项目编排、断点续跑、最小账本

版本：0.4.0
状态：开工
依赖：0.3.1 基线
对应路线图：`docs/ROADMAP.md` 第 4 节 R1

## 1. 范围

R1 交付：
- 注册表 `registry.json` 与 `nuwa ls / status --all / attach`
- 项目状态目录 `.nuwa/`：`journal.jsonl`、`run.json`、`checkpoint.<gen>.json`、`dispatch_keys.idx`
- 全局账本 `$SAPPER_HOME/budget/global.jsonl`：`reserve/renew/reclaim/settle/opening_balance`
- 事务状态机与恢复：`reserve → executing_prepare → executing → executed → commit_prepare → done_apply → intent_verify → ledger_settle → commit_done → ack`
- 锁：`run.lock`（运行互斥）、`txn.lock`（事务短锁）、`inflight/<intent>.lock`（意图级存活锁）
- 幂等提交：fact description 带 `[nuwa:sha256:<64hex>]`
- `nuwa dispatch <id>`：渲染提示（`sapper dispatch --dry-run`）、调用引擎、提交
- `nuwa --resume <name>`、`nuwa budget`
- 0.3.x 项目接管：写 `adopt` + `opening_balance`

## 2. 目录与文件

```
<project>/.nuwa/
  run.lock                 运行互斥（长持有）
  txn.lock                 事务锁（短持有）
  journal.jsonl            权威事件流（append-only）
  journal.<gen>.jsonl      代际文件
  journal.<gen-1>.tail.jsonl  上一代尾部（双写）
  checkpoint.<gen>.json    压缩点
  dispatch_keys.idx        精确去重索引（每行 sha256:<64hex>）
  CURRENT                  当前代指针（原子 rename）
  run.json                 进度快照（派生，可由 journal 重建）
  inflight/<intent>.lock   意图级存活锁
  artifacts/<txn>/         执行结果（stdout/stderr/result.json）
$SAPPER_HOME/
  registry.json            项目注册表（缓存，可重建）
  budget/global.jsonl      全局账本（权威）
  budget/global.lock       账本锁
  budget/freeze.json       快照冻结状态（R6 使用）
```

## 3. 锁序

全系统唯一锁序：

```
global.lock → txn.lock → inflight/<intent>.lock
```

- `run.lock` 不参与锁序，只阻止两个 runner 同时跑同一项目；commit 不等 `run.lock`。
- `txn.lock` 每次事务短持有；快照 barrier 只取 `global.lock` + 各项目 `txn.lock`。
- 禁止反向获取；违反即 `lock_order_violation` 事件并退出 7。

## 4. 状态机

```
reserve
  ├─ journal: reserve_pending(txn,rid,amount,intent,attempt_seq)
  ├─ global:  append reserve(rid)
  └─ journal: reserve_committed
executing_prepare
  └─ 写 txn_id/key，spawn worker wrapper
executing
  └─ wrapper ready 后写 pid/pid_starttime
executed
  └─ 进程退出：status=ok|crashed|timeout, exit_code, artifact, tokens, settled=false, rid
commit_prepare
  └─ fact 内容、kind、doc、rid、key
done_apply
  ├─ 扫描 facts 的 [nuwa:key]
  ├─ 未命中：sapper done（description 自带 key）
  └─ 修补 intent：status=done、to、done_at、worker；sapper validate
intent_verify
  └─ status==done 且 to 指向存在 fact
ledger_settle
  └─ global: settle(rid, actual)，settled=true
commit_done
  └─ journal: commit_done
ack
  └─ 清 inflight
```

## 5. 恢复表

| 最后状态 | 动作 |
|---|---|
| reserve_pending 无 global | 删除 pending |
| reserve_pending 有 global 无 committed | 标 orphan_reserve，TTL 回收 |
| reserve_committed | 释放 intent、回滚预留，attempt_seq 不变 |
| executing_prepare | 等 ready ≤5s；锁被持 → 活；锁空闲：有 result.json 且 exit0 → executed(ok)；否则 executed(crashed) |
| executing | 同上，以 inflight 锁为准 |
| executed(ok) | 校验 result.json + exit0 + artifact → commit_prepare |
| executed(crashed/timeout) | settled=false → settle → release → attempt_seq+1 |
| commit_prepare | 按 key 扫描 facts；命中复用，否则 sapper done → done_apply |
| done_apply | 修补 intent → validate → intent_verify |
| intent_verify | 校验 → ledger_settle |
| ledger_settle | settle（rid 幂等）→ commit_done |
| commit_done | ack，不重派 |

观测切点：恢复后 inflight 为空、queue 排空，再做账本比对；记账错误必须为 0，估算误差 ≤1 次预留。

## 6. 幂等键

- `dispatch_key = "sha256:" + sha256(project|intent|attempt_seq)`
- fact 的 `description` 末尾追加 ` [nuwa:<dispatch_key>]`
- `dispatch_keys.idx` 每行一个规范键；重启加载到内存集合
- 提交前先按 key 扫描 facts；命中即复用

## 7. 账本

条目：

```json
{"type":"reserve","rid":"r-...","project":"p1","txn":"t-...","tokens":12000,"dispatches":1,"expires_at":...}
{"type":"renew","rid":"...","expires_at":...}
{"type":"settle","rid":"...","tokens_actual":9000,"status":"ok|crashed|timeout|estimated"}
{"type":"reclaim","rid":"...","reason":"expired|orphan"}
{"type":"opening_balance","project":"p1","tokens":0,"estimated":true}
```

规则：
- 容量：`global_cap - settled_total - sum(outstanding)*1.05`
- 准入：`reserve*1.05 <= remaining_global` 且 `reserve <= remaining_project`
- 结算：`settled_total += actual`，释放整笔预留
- 透支：`actual > 1.05*reserve` 记 `major_overrun`，项目冻结
- 租约：TTL 10 分钟，`executing` 每 2 分钟 renew；锁空闲且无 result.json 才可 reclaim

## 8. CLI

```
nuwa ls [--json]
nuwa status --all [--json]
nuwa attach <name>
nuwa run <url|name> [--minutes N] [--parallel K] [--resume]
nuwa dispatch <intent-id> [--model M] [--timeout S]
nuwa commit --key <dispatch_key> --intent <id> --fact <text> [--kind K]
nuwa budget [--json|--set tokens=N|--add N]
nuwa recover <name>
```

`bin/nuwa` 保持兼容：第一个参数是上述子命令时走 Python CLI；否则按旧 `nuwa <url>` 语义进入 `run`。

## 9. 验收

- 8 项目并发：`nuwa ls --json` 与进程一致（≤2s）
- 10 个崩溃点：fake 组 6×20、真实 sapper 组 4×5；同 intent 活子进程 ≤1、重复 fact 0、记账错误 0
- 0.3.1 接管：facts/intents 不丢，重启两次不重置计数，opening_balance 只写一次
- checkpoint 压缩后重放一致；run.json 截断 50% 可重放
- 单测：journal/ledger/lock/txn 各自边界

## 10. 实施顺序

1. `nuwa/paths.py`、`journal.py`、`locks.py`、`ledger.py`
2. `registry.py`、`graph.py`
3. `txn.py` + `worker.py`
4. `cli.py`（ls/status/budget/commit/recover/run）
5. `bin/nuwa` 分派
6. 测试：`tests/test_r1_*.py` + `tests/gates/g1_r1.sh`
7. us3 实跑与回归
