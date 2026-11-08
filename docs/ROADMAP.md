# 女娲模式升级路线图（0.4.0 → 1.0.0）

基线：0.3.1（2026-11-08）
- 运行时：`nuwa-loop` 续跑、预算/空转/证据闸门、JSONL 日志
- 入口：`bin/nuwa` 单项目、并行 dispatch、项目锁、看板、`--version`
- 测试：契约 13 项 + 五套 49 例 + 8 类靶场 + 编排/HTTP 矩阵 + 小长测 + C 层会话

## 1. 目标

把女娲从「单项目、单会话、靠预算兜底」推进到「多项目可编排、可断点续跑、证据可验收、成本可核算、执行可隔离」的稳定工具。

### 非目标

- 不做漏洞利用框架本身（执行仍交给 sapper + 子代理）
- 不做分布式集群调度（单机多项目足够）
- 不内置任何目标清单或资产发现
- 不改变「事实-意图图」核心模型，只做增量扩展

## 2. 阶段总览

| 阶段 | 版本 | 主题 | 规模 | 依赖 |
|---|---|---|---|---|
| R1 | 0.4.0 | 多项目编排、断点续跑、最小账本 | L | — |
| R2 | 0.5.0 | 全局预算与公平调度 | L | R1 |
| R3 | 0.6.0 | 证据质量与反幻觉 | M | R1 |
| R4 | 0.7.0 | 观测、报告与告警 | M | R1,R2 |
| R5 | 0.8.0 | 执行隔离与凭据卫生 | M | R1 |
| R6 | 0.9.0 | 插件化、schema 演进、快照与迁移回滚 | L | R1–R5 |
| R7 | 1.0.0 | 稳定性、性能、四件套回滚与冻结 | M | 全部 |

## 3. 状态、日志与恢复

### 3.1 日志分层

| 文件 | 角色 | 轮转 | 用途 |
|---|---|---|---|
| `.nuwa/journal.jsonl` | **权威**，append-only | 项目生命周期内不轮转；仅按 checkpoint 压缩 | 恢复唯一依据 |
| `.nuwa/events.jsonl` | 诊断 | 50MB / 7 天 / 7 份 | 报告明细、排障 |
| `.nuwa/artifacts/<txn>/` | 执行结果原始字节 | 30 天后销毁；**被未提交事务引用的必须保留至 commit_done 或废弃** | 恢复与重放 |
| `.nuwa/dispatch_keys.idx` | 精确去重索引（每行一个完整 key） | 随 checkpoint 增量维护 | 去重确认层 |
| `.nuwa/inflight/<intent>.lock` | 意图级存活锁 | 意图结束删除 | 存活判定与重叠防护 |

恢复只读 journal + 精确索引；报告计数以 journal 为准；events 轮转时标 `detail_truncated`。

### 3.2 状态权威矩阵

| 状态 | 文件 | 权威来源 | 损坏时动作 |
|---|---|---|---|
| 项目注册表 | `$SAPPER_HOME/registry.json` | 各项目 journal + 进程探活 | 全量重建，不阻塞 |
| 执行进度 | `<proj>/.nuwa/run.json` | journal 重放到最后 `commit_done` | 按 R1 恢复表处理 |
| 项目预算视图 | `<proj>/.nuwa/budget.json` | 全局账本派生 | 从全局账本重建 |
| 全局预算 | `$SAPPER_HOME/budget/global.jsonl` | **唯一权威**，`global.lock` 串行化 | 快照校验后重放；失败冻结全部新 dispatch |
| 图 | `<proj>/.sapper/` | sapper 自身 | 常规只读；R1 提交修复在项目锁内受控写 JSON，写完必须 `sapper validate` |
| 交接 | `<proj>/.nuwa/handoff.json` | 派生 | 可重建 |
| 会话状态 | `cache/nuwa-loop/<hash>.json` | 可重建 | schema < current → 先迁移（2→3 保留 turns/spentTokens/armedAt）；schema > current → 0.9+ 在加载前 fail-closed（写 `state_schema_too_new`，拒绝上膛，不清空）；0.3.x 的 loadState 会返回空状态，因此回滚时不得指向 schema 3 目录（用独立 state dir 或先降级迁移）；仅 JSON 损坏才重置并写 `state_reset` |

权威类损坏且无重放依据：保留现场、冻结新 dispatch、退出码 6；恢复动作写 journal。

### 3.3 checkpoint 与去重索引

```json
{
  "checkpoint_schema": 1,
  "snapshot_id": "ck-0007",
  "seq": 1234,
  "ts": "2026-11-08T12:00:00Z",
  "run": {"round": 7, "turns": 12, "spent": 34567, "deadline": 1762500000, "lastSig": "..."},
  "intents": {"i001": {"status": "done", "to": "f012", "attempt_seq": 2}},
  "dispatch_keys": {"index_file": "dispatch_keys.idx", "count": 812, "bloom": "base64..."},
  "unresolved": [{"txn_id": "t-19", "state": "executing", "pid": 4242, "pid_starttime": 998877, "intent": "i007", "attempt_seq": 1}],
  "ledger": {"global_seq": 88, "project_balance": {"tokens": 100000, "dispatches": 42}}
}
```

- `dispatch_keys.idx` 是**精确**去重层：每行一个完整 `sha256:<64 hex>`，排序后二分查找。812 条约 58KB，成本可接受。
- Bloom 仅作快速否定：Bloom 判"不存在"→ 新事务；"可能存在"→ 必须查索引；索引查不到 → **按新事务处理**，绝不跳过。
- 压缩保留 checkpoint + `seq > checkpoint.seq` 的记录 + `unresolved` 完整记录 + 全量索引。
压缩下界 = `min(所有活跃快照的 cut_seq[p], checkpoint.seq)`；`snapshots.idx` 登记每个快照的 cut 与引用计数，仍有快照引用时不得删除其后的记录，引用归零后才可 GC。
代际文件：`checkpoint.<gen>.json`、`index.<gen>.idx`、`journal.<gen>.jsonl` 一律不覆盖；每代写完 fsync 后，原子更新 `CURRENT`（tmp+rename）指向 gen；上一代保留到下一次压缩成功，截断只作用于 gen-2 及更早。切代后，新记录**同时追加**到 `journal.<gen>.jsonl` 与 `journal.<gen-1>.tail.jsonl`，直到 gen+1 压缩成功。回退上一代 = `checkpoint.<gen-1>` + `journal.<gen-1>` + tail（含切代后的全部记录），按 seq 去重；因此切代后新增的 `commit_done` 不会丢失。
重放断言：run/账本/facts 与压缩前一致，且无重复 `commit_done`。

## 4. 各阶段

### R1 多项目编排、断点续跑、最小账本（0.4.0）

**目标**：一个会话能看见并操作所有在跑项目；进程被杀后可无损续跑；预算先有最小预留/结算。

交付：
- `registry.json`、`nuwa ls [--json]`、`nuwa status --all`、`nuwa attach <name>`
- `.nuwa/run.json`（`run_schema:1`）、`journal.jsonl`、checkpoint、`dispatch_keys.idx`
- 最小账本：`reserve/settle/reclaim/opening_balance`
- 执行结果 artifact、inflight 锁
- `nuwa --resume <name>`
- **提交所有权**：R1 起所有 fact 创建走 `nuwa dispatch <id>` / `nuwa commit`，由 nuwa 渲染提示（`sapper dispatch --dry-run`）、调用引擎、按幂等键提交；SKILL 与续跑指令同步改写，禁止在女娲流程内直接调用 `sapper done` 或 `sapper dispatch <id>`（`sapper` 仅用于建图、查询、校验）
- **幂等提交**：`nuwa commit --key <dispatch_key>`，按固定锁序 `global.lock → 项目锁` 执行；全系统禁止反向获取
- **接管契约**：首次接管已有 0.3.1 项目时，写 `adopt` 记录（现有 facts/intents 快照、spent 未知则 `opening_balance=0` 且标 `estimated`），不重置既有计数
- `tests/contract_check.py`、`tests/gates/run.sh`、`tests/gates/expected`

**幂等键写进 fact 本身**：

- fact 的 `description` 末尾追加 ` [nuwa:<完整 dispatch_key>]`（64 hex）。
- 恢复按完整键精确匹配；`x-nuwa-key` 为同值辅助字段。
- 显示层可截断前 8 位，但判定只用完整键。
- 由于键随 fact 一次写入，不存在"fact 已落盘、键未落盘"的窗口。

**进程存活与重叠防护**：

- spawn 的是 `nuwa-worker-lock` 包装器：它先打开 **意图级锁** `.nuwa/inflight/<intent>.lock`、取得 `flock(LOCK_EX)`、写 `ready` 文件（pid + starttime + attempt_seq），然后 **fork 子进程执行业务命令并 wait**（不 exec，保证包装器存活到命令结束）；命令退出后写 `result.json`（exit_code + 完成标记），再释放锁。
- 包装器在 exec 前重读 intent，若 `attempt_seq` 与自身不符则直接退出（不执行）；因此被判定死亡后恢复的旧 wrapper 即使醒来也拿不到锁或版本不符。
- 父进程等待 `ready`（超时 5s）。拿到 ready 才写 `executing`；超时则 kill 并按启动失败处理。
- 业务子进程继承同一锁 fd（dup2 到固定 fd 并清除 CLOEXEC）；wrapper 与业务进程共同持锁，只有两者都退出锁才释放。
- 业务命令正常退出后，wrapper 写 `result.json`（exit_code + 完成标记）；异常退出不写。恢复只有同时看到 marker 与 exit 0 才判 ok，否则按 crashed 处理。
- 混沌用例：只杀 wrapper、保留业务子进程 → 恢复必须等待锁释放，不得重派。
- 存活判定 = 尝试 `flock(LOCK_EX|LOCK_NB)`：拿不到 → 活；拿得到 → 死。锁在任何业务代码之前取得，不存在"进程已跑、锁未持有"的窗口。
- 重派前必须先拿到旧锁（证明旧子进程已退出），再创建新 txn。
- `pid/starttime` 仅诊断。

**事务状态机**：

```
reserve → executing_prepare → executing → executed → commit_prepare
        → done_apply → intent_verify → ledger_settle → commit_done → ack
```

 - `attempt_seq` 每 intent 从 0 递增；`dispatch_key = sha256(project|intent|attempt_seq)`。
- `reserve` 分三步：journal 写 `reserve_pending(txn,rid,amount)` → 全局账本 append `reserve(rid)` → journal 写 `reserve_committed`。
- 恢复：`pending` 且全局无对应 `rid` → 删除；全局有 `rid` 但 journal 无 committed → 标 `orphan_reserve`，按 TTL 回收（R1 提供基础租约）。
- `executing_prepare`：spawn 前写，无 pid，含 txn_id、key。
- `executing`：spawn 成功后写，含 pid、pid_starttime。
- `executed`：进程退出或确认死亡后**必写**，`status: ok|crashed|timeout`，含 exit_code、artifact（可为 null）、tokens（实际或估算）、`settled:false`、`rid`。
- `commit_prepare`：fact 内容、kind、doc、rid。

**恢复规则**：

| 最后状态 | 动作 |
|---|---|
| reserve | 释放 intent、回滚预留，`attempt_seq` 不变 |
| executing_prepare | 等 `ready` ≤5s；锁被持 → 活；锁空闲：有 `result.json` 且 exit 0 → `executed{ok}`；否则 `executed{crashed}` → 结算 → 释放并以 `attempt_seq+1` 重派 |
| executing | 同上，以锁为准；pid 仅诊断；**有 `result.json` 且 exit 0 才能按 ok 恢复，部分输出按 crashed 处理** |
| executed(ok) | 校验 `result.json` 完成标记 + exit_code + artifact → commit_prepare |
| executed(crashed/timeout) | 若 `settled=false` → 结算并写 `settled:true`（按 rid 幂等）→ release intent → `attempt_seq+1` 重派（不做 commit） |
| commit_prepare | 扫描完整键；命中复用，否则 `sapper done`（描述自带键）→ done_apply |
| done_apply | 修补 intent：`status=done`、`to=<fact>`、`done_at`、`worker`（缺一不可）→ `sapper validate` → intent_verify |
| intent_verify | 校验 `intent.status==done` 且 `intent.to` 指向存在的 fact → ledger_settle |
| ledger_settle | 按 rid 幂等结算 → commit_done |
| commit_done | 补 ack，不重派 |

验收：
- 8 个项目同时运行，`nuwa ls --json` 与实际进程一致（≤2s）
- 观测切点：恢复后等待 inflight 为空且 queue 排空，再做账本比对。
- 十个崩溃点分两组：**fake-sapper 快跑组**（reserve 后、prepare 后、spawn 后、executed 后、压缩写 checkpoint 后、索引更新后）每次 20 轮；**真实 sapper 夜跑组**（执行中、done_apply 中、ledger_settle 中、journal 截断前）每次 5 轮。两组都要求：
  - 同一 intent 同时存活子进程 ≤1（inflight 锁证明）
  - 丢失 fact 0、重复 fact 0（完整键去重）
  - 崩溃尝试均有 `executed`；记账错误（漏结算/重复扣）为 0，估算误差 `|estimated-actual|` ≤1 次预留
- 0.3.1 项目接管：facts/intents 不丢，重启两次不重置计数，`opening_balance` 只写一次
- checkpoint 压缩后重放一致；run.json 截断 50% 可重放

### R2 全局预算与公平调度（0.5.0）

**目标**：多项目共享一份预算，不饿死、不超支。

预算口径：

| 类型 | 单位 | 计费时点 | 来源 | 预留 | 结算 |
|---|---|---|---|---|---|
| tokens | input+output | `executed`（任何状态） | 引擎 usage；缺失按 `ceil((prompt+artifact)/4)` 估算并标 `estimated` | `min(p95, per_task_cap)` | 实际/估算，只补不退 |
| wall | 秒（经过，暂停不计） | 项目结束 | 首次 dispatch 到结束，排除暂停区间 | 不预留 | 结束结算 |
| dispatches | 次 | `executed` | 每次尝试 | 1 | 结算 |

**准入与硬上限**：

- `remaining_global = global_cap - settled_total - sum(outstanding_reserved)*1.05`
- `reserve = min(ceil(p95*1.05), NUWA_TASK_CAP, remaining_project, remaining_global / 1.05)`
- 准入：`reserve >= MIN_VIABLE` 且 `reserve*1.05 <= remaining_global`；新预留与既有预留都计 5% 头寸。
- 预检：spawn 前估算 input tokens `ceil(prompt_chars/4)`；若超过 reserve 则拒绝或排队。支持输出上限的引擎传 `max_output_tokens = reserve - input_est`。
- `per_task_cap = reserve`；timeout 由 `NUWA_TASK_TIMEOUT` 单独设定。
- 结算：`overspend = max(0, actual - reserve) / reserve`。≤5% 记 `minor_overrun` 并继续；>5% 记 `major_overrun`，项目暂停且门禁失败。
- 准入保证 `sum(reserve)*1.05 <= global_cap` 时不透支。若引擎突破硬上限导致 `actual > 1.05*reserve`，记 `major_overrun`，`remaining_global` 允许为负，项目立即冻结并禁止新 dispatch；只能通过 `nuwa budget add <n>` 或提高 cap 补平，补平前门禁失败。
- 在途：单项目 ≤ `--parallel`，全局 ≤ `NUWA_GLOBAL_CONCURRENCY`。
- 暂停：`overdraft` 或人工暂停期间 wall 不计时（记录 pause/resume 时间戳）。

- 预留生命周期：`reserved`（执行中）→ `pending_settlement`（executed 后额度仍占用）→ `settled`（释放）。只有 `reserved` 且锁空闲、且无 executed 记录才可 `reclaim`；`pending_settlement` 必须等结算完成才释放额度，避免提前释放造成双花。
- 续租：`executing` 期间每 2 分钟 `renew`；TTL 10 分钟。
- 迟到结算：`late_settle` 按 `rid` 匹配，不重复扣。
- 超支：三类均以各自额度为分母（tokens/dispatches 用 reserve，wall 用 wall_cap）；`overspend = max(0, actual - quota)/quota`。≤5% 记 `minor_overrun` 并继续；>5% 记 `major_overrun`、项目暂停、门禁失败。
- 公平性：三个持续就绪项目共享 60s 窗口；每项目按并发槽位累计 busy 秒（sum over slots，不用并集），分母为三者之和；等权 1:1:1 各 33%±5pp，加权 2:1:1 为 50%/25%/25%±5pp；每项目 ≥10 次 dispatch。
- 退避：1/2/4/8s，上限 60s；重试使用新 `attempt_seq`。

交付：
- `global.jsonl`：`reserve/settle/reclaim/overdraft/renew/opening_balance`
- `nuwa budget [--json|--set]`、`nuwa budget fairness --projects 3 --seconds 60`
- 加权公平队列、并发上限、429 退避
- 模型路由：reason 强模型、explore 廉价模型、失败链式回退

验收：
- 公平性：等权 1:1:1（各 33%±5pp）与加权 2:1:1（50%/25%/25%，±5pp）两组，输出三项目占比与 dispatch 数，断言达标；权重失效必须被检出
- 路由：reason 使用强模型、explore 使用廉价模型；强模型失败时按链回退，事件记录 `model` 与 `fallback_from`
- 准入拒绝、硬上限截断（含 `per_task_cap` 由全局余量决定）、暂停不计 wall 三类用例通过
- 429 轮换后重复 fact 0
- 正常路径：账本并发扣减无负数；异常路径：引擎越限记为 `major_overrun` 并允许 `remaining_global` 为负，但项目必须冻结；两条路径分别验收；journal 重放与账本一致（跨项目快照一致性属 R6 验收）

### R3 证据质量与反幻觉（0.6.0）

**目标**：fact 必须可复现，模型不能只凭一段文字结案。

证据结构：

```json
{
  "evidence": {
    "command": "curl -sS -m 5 http://h:8080/flag",
    "cwd": "/work/p1",
    "exit_code": 0,
    "hash_spec": "v1",
    "raw_sha256": "...",
    "norm_sha256": "...",
    "artifact": {"dir": ".nuwa/artifacts/f012", "stdout_bytes": 1234,
                 "stderr_bytes": 0, "truncated": false},
    "captured_at": "2026-11-08T12:00:00Z",
    "duration_ms": 42,
    "target": {"host": "h", "port": 8080, "scheme": "http"},
    "intent_id": "i012",
    "project_id": "p1",
    "assertion": {"field": "stdout", "op": "contains", "value": "flag{"}
  }
}
```

- **哈希规范 v1**：`norm_sha256` 针对归一化字节（去 ANSI、CRLF→LF，步骤写死）；`raw_sha256` 针对原始字节。两者都存。
- **脱敏解耦**：R5 只作用于日志、报告、events、fact 预览；永不改写 artifact 与哈希。
- **采集来源**：由**工具执行层**采集——bash 循环在命令执行时截获 stdout/stderr/exit_code 并写 artifact；会话内子代理由 `nuwa-loop` 的 `tool_result` 钩子采集。引擎 stdout 只是模型文本，永不作为证据；`evidence.source` 取值 `executor-hook|subagent-hook`，缺失即拒绝。
- **目标绑定**：`target` 与 intent 目标一致。
- **断言**：`op` 限 `contains/regex/eq/gt/lt`；默认对 artifact 前 1MB 求值，超限置 `truncated` 并拒绝依赖截断部分的断言。
- **新鲜度**：`captured_at` 距 `done` ≤30 分钟。
- **置信度**：存于 `fact["x-nuwa"]["confidence"]`，由验收器按固定 rubric 计算：

  | 维度 | 取值 |
  |---|---|
  | 断言强度 | `eq` 0.40；`contains/regex` 0.35；`gt/lt` 0.30；无断言 0 |
  | 新鲜度 | `≤5min` 0.30；`≤30min` 0.20；`>30min` 0 |
  | 可复现性 | 命令 + exit 0 + 哈希匹配 0.30；缺一项 0.10；缺两项 0 |

  总分 0–1.0。示例：`eq + 3min + 完整 = 0.40+0.30+0.30 = 1.00`；`contains + 20min + 缺哈希 = 0.35+0.20+0.10 = 0.65`；`contains + 40min + 缺哈希 = 0.35+0+0.10 = 0.45`（若命令缺失则命中硬拒绝，直接拒绝）。
  门限：`<0.6` 只记 note；`[0.6,0.8)` 记 fact 不参与 completed；`≥0.8` 且无五类硬拒绝才可参与 completed。
- **人工覆盖**：`--force-confidence` 只影响阈值判定，对五类硬拒绝无效；覆盖记录 actor/reason，24h 后失效。
- **旧 fact**：`evidence_state: legacy`，不参与 completed；补证后升级。

五类幻觉样本：

| 样本 | 输入 | 期望 |
|---|---|---|
| 无命令 | `command` 缺失 | 拒绝，退出码 10 |
| 结论不符 | assertion 为假 | 拒绝，退出码 11 |
| 旧输出 | `captured_at` 超 30 分钟 | 拒绝，退出码 12 |
| 伪造哈希 | `norm_sha256` 不匹配 | 拒绝，退出码 13 |
| 跨目标 | `target` 与 intent 不一致 | 拒绝，退出码 14 |

**性能基准固定化**：`tests/fixtures/verify/` 放 100 个固定样本（命令固定 `curl -sS -m 2 http://127.0.0.1:18081/flag`，输出固定 4KB），p95 只在该样本集上计算；慢命令与超时样本单独分组。

验收：
- 五类样本按表拒绝，退出码一致
- 矛盾样本固定为 `tests/fixtures/contradiction/` 三组（同端口不同服务、同 flag 不同来源、同 CVE 不同版本）；标记字段 `x-nuwa:contradiction={with:[fact_ids],field,values}`；预期 facts 保留、project 仍 active、事件 `contradiction_flagged`、下一轮 dispatch 正常开始
- 固定样本集 p95 <2s（exec 到断言，排除排队）
- 置信度 rubric 单测：三类输入得到预期分值；覆盖 24h 后失效
- 单测：截断输出、非 UTF-8、超时命令、artifact 缺失

### R4 观测、报告与告警（0.7.0）

**目标**：不读日志也能判断项目健康不健康。

交付：
- `nuwa metrics --json`（`metrics_schema:1`）：dispatches/facts/rejects/stalls/tokens/耗时分位；每项目序列上限 200
- 离线 HTML 报告：单项目时间线 + 多项目总览；计数以 journal 为准
- 告警 webhook：stall、锁冲突、配额耗尽、完成；失败重试 3 次后落死信
- 日志轮转：events 50MB/7 天/7 份；journal 按 checkpoint 压缩

验收：
- metrics 字段有 schema 文档，破坏性变更升版本
- 报告断网可开；与 journal 对账 ≤1；events 轮转时标 `detail_truncated`
- stall 后 5s 内告警，重试 3 次落死信
- 单测：轮转后旧文件可读；journal 压缩后重放不变

### R5 执行隔离与凭据卫生（0.8.0）

**目标**：子代理只能做允许的事；派生副本不出现秘密，artifact 按权限保留。

策略覆盖矩阵：

| 执行路径 | 入口 | 强制点 | 加载失败 |
|---|---|---|---|
| bash 循环 | `bin/nuwa` → `nuwa dispatch` → engine wrapper（sapper 仅 `--dry-run` 渲染） | engine wrapper | fail-closed |
| 会话内子代理 | `task(agent=fujiang)` | `nuwa-loop` 的 `tool_call` 前置 + 子代理 wrapper | fail-closed |
| 出网 | 任意路径 | 项目级 netns + 防火墙规则（代理环境只是便利） | fail-closed |

交付：
- 命令 allow/deny 与规则 id
- 出网：netns / uid 防火墙规则；忽略代理变量的进程同样受约束
- 脱敏过滤器：日志、events、报告、fact 预览；`redact_spec` 版本化
- 权限审计：状态目录 0700、artifact/账本 0600；30 天后销毁 artifact
- HMAC 签名账本默认启用（1.0 起必选）；密钥在 `$SAPPER_HOME/keys/audit.key`（0600），随快照备份；旧无签名账本接管时标 `unsigned_legacy=true`，从接管点开始签名；密钥缺失时 `audit verify` fail-closed

验收：
- canary 注入 10 处（命令、输出、fact 预览、日志、报告），派生副本零泄漏
- 两条执行路径分别用本地 allow/block 目标：blocked 连接数 = 0（含 `curl --noproxy '*'` 直连阻断 IP）、allowed 成功率 = 100%、事件含 rule_id
- 策略加载失败时拒绝 dispatch / 工具调用
- 单测：脱敏不破坏 JSON；签名篡改可检出；artifact 权限与到期销毁

### R6 插件化、schema 演进、快照与迁移回滚（0.9.0）

**目标**：换执行引擎或目标类型不改核心；迁移与快照可回滚。

版本命名空间：

| 命名空间 | 归属 | 当前 | 迁移 |
|---|---|---|---|
| `graph_schema` | sapper | 由固定 sapper 版本决定 | nuwa 不迁移，只做契约测试 |
| `fact_schema` | nuwa（增量字段） | 1 | 增量写入，旧 fact 标 legacy |
| `loop_schema` | nuwa-loop | 2 | 2 → 3 |
| `run_schema` | nuwa | 1 | 按需递增 |
| `registry_schema` | nuwa | 1 | 按需递增 |
| `ledger_schema` | nuwa | 1 | 按需递增 |

**快照一致性协议**（R6 交付）：

1. 短暂获取 `global.lock`：写 `$SAPPER_HOME/budget/freeze.json`（`freeze=true`、`owner_pid`、`snapshot_id`、`renewed_at`、`expires` 10min），记录 `freeze_seq`，释放；快照进程每 60s 续租。其他进程只有在 owner 进程已死时才可清除过期 freeze（写 `freeze_recovered`）；解冻必须匹配 `snapshot_id`，旧快照不能清除新快照的 freeze。commit/结算队列持久化在 `queue.jsonl`，启动时重放。冻结后**新 dispatch 拒绝；commit 全路径与新结算一律入队**。
2. 等待 inflight 全部到达 `executed`（只等执行结束，**不等 commit 队列**），最长 120s；超时则 kill 子进程、写 `executed{crashed}` 并入队。
3. 获取 `global.lock`，再按固定顺序获取各项目锁（barrier）；记录 `global_cut_seq`、每个项目 journal 的 `cut_seq[p]` 与 `queue_cut_seq`；把队列前缀复制为 `queue.<snapshot_id>.jsonl`（此后接受的请求 seq > queue_cut，归入 delta）；导出 **`global.jsonl` 全量到 `global_cut_seq`**。
4. 在各项目锁内导出 `sapper export`、journal 尾部、run、budget 视图、checkpoint、`dispatch_keys.idx`；导出完成后校验每个项目 `post_seq == cut_seq[p]`，不一致则失败重试；释放锁。
5. 复制 artifact 原始字节到 `snapshot/artifacts/`（默认开启；关闭时标 `evidence_incomplete`）。
6. 写 `SNAPSHOT.json`：各文件 sha256、`at_cut_facts`、`at_cut_balance`、artifact 数、`global_seq`、`snapshot_id`；同时打包 `cache/nuwa-loop/*.json`（会话计数）、`keys/audit.key`（HMAC 密钥）、`components.json`（CLI/扩展/skill 版本）、`queue.jsonl`（冻结期间已接受的 commit/结算请求）。
7. 清除 `freeze`，按顺序排空 commit 队列与结算队列（按 rid 幂等落账）。恢复分两段断言：`restore` 后 facts 与余额必须等于 `at_cut_*`；重放 queue 后必须等于 `at_cut_* + queue 产生的增量`，两段分别校验。排队中的 commit 在解冻后获得新的 `seq`，全部 `> cut_seq`，因此属于增量而非快照；单独 restore 快照时，按快照内的 `queue.jsonl` 重放这批已接受请求，再按 `rid` 去重。

**增量与回滚**：`export-delta` 按项目导出 `seq > cut_seq[p]` 的 journal、新 facts、intent 迁移、新 artifact，按账本导出 `seq > global_cut_seq` 的条目，并导出 `cache/nuwa-loop/*.json` 的计数变化（turns/spentTokens/armedAt）、以及 `accepted_at > snapshot.frozen_at` 且尚未写入 journal/账本的 `queue.jsonl` 条目（按 txn_id 去重）；回滚顺序为 冻结 → 导出增量 → `restore`（校验 sha256 与 artifact 数）→ `import-delta`。降级转换：新字段写入 `x-nuwa`，账本增量以 `opening_balance` 入账，已结算 `rid` 集合随快照保存并去重；`loop_schema 3→2` 保留 turns/spentTokens/armedAt，丢弃 evidence 引用；0.9+ 扩展遇到 schema 3 必须 fail-closed（拒绝上膛并写 `state_schema_too_new`），不得静默重置；0.3.x 无此能力，回滚不得指向 schema 3 目录。

**初始化/迁移样本**：

- `tests/fixtures/migration/v0_3`：0.3.1 图 + `schema:2` 会话状态，用于验证 R1 接管与 R6 2→3 迁移。
- `tests/fixtures/migration/v0_9` / `v1_0`：0.9 ↔ 1.0 双向。
- 接管规则：首次启动写 `adopt`，`opening_balance` 只写一次（未知 spent 标 `estimated`），intent 的 `attempt_seq` 从现有状态继承，不重置。

交付：
- 引擎插件接口 `{name, api_version, detect(), run(prompt, opts) -> envelope}`，需签名与版本约束
- 目标适配接口：HTTP / Docker / SSH 内置，外部可注册
- `nuwa migrate --from auto --dry-run`
- `nuwa snapshot` / `nuwa restore` / `nuwa migrate --rollback <snapshot_id>`

验收：
- 新增 fake 引擎插件 ≤50 行，核心零改动
- 迁移保留 ID、引用完整、重复迁移零变化
- 迁移中断重试成功；`--rollback` 后 `sapper validate` 通过
- 插件 `api_version` 不兼容时拒绝加载
- 0.9.0 能读 1.0 账本（export v1）；0.3.1 能读图并忽略 `x-nuwa`
- 快照/恢复后 facts 数、artifact 数、账本余额一致；ID 无重复

### R7 稳定性、性能、四件套回滚与冻结（1.0.0）

**目标**：可以长期挂着跑，升级/回滚可整体操作。

长测协议：
- 命令：`nuwa soak --minutes 4320 --projects 4 --concurrency 2 --min-dispatch-per-hour 60`；引擎固定 omp + `deepseek-flash`，负载固定 4 项目 × 每轮 8 个 intent，单项目预算 2M tokens；产物必须写 `MODE=soak` 与 `COMMIT=<sha>`，上传前完成
- 两周观察：候选版本 = release tag；暴露量 = 72h 连续 + 14 天等价负载；出现新提交后计时重置
- 采样间隔 30s；PID 范围 = 各项目进程树；**所有判据按项目分别计算**（每项目 RSS 斜率、FD 差、dispatch/hour、facts 增长），任一项目不达标即失败；全局汇总只作展示，不得掩盖单项目停滞
- 有效运行 ≥259200 秒；提前退出、采样间隔 >60s，判失败
- **RSS**：预热 20% 后对 RSS(KB)-时间(min) 最小二乘，斜率 <1024 KB/min
- **FD**：`max(后10个采样) - min(预热后前10个采样) ≤ 0`
- **推进**：每小时 dispatch ≥60（滚动 60 分钟窗口，首小时后每窗满足）；任意连续 6 小时 facts 增长 >0
- 每 6 小时 `sapper validate`
- 唯一通过判定 = 全部条件同时成立

**四件套回滚**：CLI、扩展、skill、状态文件；`install.sh --rollback` 恢复四件套并打印版本矩阵。回滚使用 R6 的快照与增量协议，不再单靠扩展目录备份。

验收：
- 全部测试门禁绿；72h 长测全部判据通过
- 连续两周无 P0/P1（P0 = 数据丢失/重复执行；P1 = 无法续跑/预算失真）
- 快照/恢复后 facts 数、artifact 数、账本余额一致；ID 无重复
- 0.9.0 能读 1.0 账本；0.3.1 能读图并忽略 `x-nuwa`

## 5. 横切约束

- **测试先行**：每阶段先加失败用例，再实现。
- **阶段门禁**：CI 与本地都执行 `tests/run.sh`（契约 → 五套 → `gates/run.sh`）。CI 作业超时 10 分钟；72h 长测是独立 `soak.yml`，**必须跑在自托管 runner**（GitHub 托管 runner 单作业上限 6 小时），`timeout-minutes: 4500`；产物名含 commit 与 mode，发布要求 `MODE=soak` 且 `COMMIT` 与发布 commit 一致。 `gates/run.sh` 内置**只增不减的已交付清单** `DELIVERED=(0_baseline ...)`，并读取 `gates/released.json`（发布历史，只追加）；历史中每个门禁都必须在 `expected` 中且脚本非空，删除需同时改发布历史（属发布变更，需 release note）；每个名称对应 `gates/g<name>.sh` 必须存在且非空；`NUWA_REQUIRE_GATES=1` 时任何缺项失败。新增阶段时同一变更内更新 `expected` 与门禁脚本；删除清单项不能绕过核心锚点。
- **场景到命令**：

| 阶段 | 验收命令（阶段内交付） | 阈值 |
|---|---|---|
| R1 | `nuwa ls --json`；`tests/crash_inject.py --points 10 --repeat 20` | 一致 ≤2s；同 intent 活子进程 ≤1；重复 fact 0 |
| R2 | `nuwa budget fairness --projects 3 --weights 2:1:1 --seconds 60` | 50/25/25 ±5pp；等权 33% ±5pp；≥10 dispatch |
| R3 | `nuwa verify --samples 5 --expect reject`；固定样本集 100 | 5/5 拒绝；p95 <2s |
| R4 | `nuwa metrics --json`；`nuwa report --offline` | 对账 ≤1；断网可开 |
| R5 | `nuwa policy check --matrix`；`tests/canary.py` | blocked=0；派生副本泄漏 0 |
| R6 | `nuwa migrate --from auto --dry-run`；`nuwa snapshot --out snap.tar`；`nuwa restore --snapshot snap.tar` | 幂等；回滚 validate 通过 |
| R7 | `nuwa soak --minutes 4320 ...`；`install.sh --rollback` | 全部判据；四件套匹配 |

- **兼容性**：图 schema 只做增量；CLI 参数只增不减；废弃项保留 1 个 minor。
- **文档**：每阶段更新 README / CHANGELOG / TESTING / TEST-RESULTS。
- **可观测**：每个新子系统必须有 journal 事件与至少一个指标。
- **失败可恢复**：按第 3 节矩阵执行，权威状态不可静默重置。

## 6. 风险登记

| 风险 | 触发信号 | 影响 | 立即动作 | 恢复验证 |
|---|---|---|---|---|
| sapper 上游漂移 | `contract_check.py` 失败；版本字符串变化 | 派发/结案失效 | 回退固定 ref | 契约 13/13（含 dry-run 零写入） |
| omp 扩展 API 变化 | 启动版本检查失败；`session_stop` 不触发 | 续跑失效 | 切兼容层，降级 bash 循环 | 会话 block 用例 |
| 多项目锁竞争 | `nuwa ls` waiting >30s | 吞吐下降 | 降并发，检查 registry pid | 8 项目推进 |
| 模型成本失控 | 账本 1 小时增幅 >预算 20% | 超支 | 路由降级 + 硬上限 | overspend ≤5% |
| 证据验收误报 | 7 天滚动窗口拒绝率 >10% | 阻塞推进 | 仅置信度阈值可 `--force-confidence`；五类硬拒绝不可覆盖；抽样 20 条人工复核 | 复核结论与规则一致 |
| schema 迁移失败 | migrate 非零退出 | 状态不可用 | 停止升级，恢复快照 | validate + 旧版查询 |

固定依赖：sapper 固定到 `c91881dc1629409bbf278577dfdaa6b8f383b438`（CI 已写入 `SAPPER_REF`）；契约检查记录真实版本字符串；E2E 在真实 sapper 缺失时必须失败，仅 `NUWA_ALLOW_FAKE_SAPPER=1` 允许回退，CI 禁用该变量。

## 7. 里程碑

- M1（R1+R2）：可同时管 8 个项目并共享预算
- M2（R3）：事实可验收，五类幻觉样本全拒
- M3（R4+R5）：可观测、可告警、派生副本零泄漏
- M4（R6+R7）：插件化、快照可回滚、1.0 冻结
