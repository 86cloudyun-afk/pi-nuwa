# 女娲模式升级路线图（0.4.0 → 1.0.0）

基线：0.3.1（2026-11-08）
- 运行时：`nuwa-loop` 续跑、预算/空转/证据闸门、JSONL 日志
- 入口：`bin/nuwa` 单项目、并行 dispatch、项目锁、看板、`--version`
- 测试：契约 7 项 + 五套 49 例 + 8 类靶场 + 编排/HTTP 矩阵 + 小长测 + C 层会话

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
| R6 | 0.9.0 | 插件化、schema 演进、迁移回滚 | L | R1–R5 |
| R7 | 1.0.0 | 稳定性、性能、四件套回滚与冻结 | M | 全部 |

## 3. 状态、日志与恢复

### 3.1 日志分层

| 文件 | 角色 | 轮转 | 用途 |
|---|---|---|---|
| `.nuwa/journal.jsonl` | **权威**，append-only | 项目生命周期内不轮转；仅按 checkpoint 压缩 | 恢复唯一依据 |
| `.nuwa/events.jsonl` | 诊断 | 50MB / 7 天 / 7 份 | 报告明细、排障 |
| `.nuwa/artifacts/<txn>/` | 执行结果原始字节 | 30 天后销毁 | 恢复与重放 |

恢复只读 journal；报告计数以 journal 为准，events 只提供明细；events 被轮转时报告标 `detail_truncated: true`，累计计数仍精确。

### 3.2 状态权威矩阵

| 状态 | 文件 | 权威来源 | 损坏时动作 |
|---|---|---|---|
| 项目注册表 | `$SAPPER_HOME/registry.json` | 各项目 journal + 进程探活 | 全量重建，不阻塞 |
| 执行进度 | `<proj>/.nuwa/run.json` | journal 重放到最后 `commit_done` | 重放；在途事务按 4.1 恢复 |
| 项目预算视图 | `<proj>/.nuwa/budget.json` | 全局账本派生 | 从全局账本重建 |
| 全局预算 | `$SAPPER_HOME/budget/global.jsonl` | **唯一权威**，`global.lock` 串行化 | 快照校验后重放；失败冻结全部新 dispatch |
| 图 | `<proj>/.sapper/` | sapper 自身 | nuwa 只读，不重建 |
| 交接 | `<proj>/.nuwa/handoff.json` | 派生 | 可重建 |
| 会话状态 | `cache/nuwa-loop/<hash>.json` | 可重建 | 版本不匹配即重置 |

权威类损坏且无重放依据：保留现场、冻结新 dispatch、退出码 6；恢复动作写 journal。

### 3.3 checkpoint 结构

```json
{
  "checkpoint_schema": 1,
  "snapshot_id": "ck-0007",
  "seq": 1234,
  "ts": "2026-11-08T12:00:00Z",
  "run": {"round": 7, "turns": 12, "spent": 34567, "deadline": 1762500000, "lastSig": "..."},
  "intents": {"i001": {"status": "done", "to": "f012", "attempt_seq": 2}},
  "dispatch_key_recent": ["sha256:..."],
  "dispatch_key_bloom": "base64...",
  "unresolved": [{"txn_id": "t-19", "state": "executing", "pid": 4242, "intent": "i007", "attempt_seq": 1}],
  "ledger": {"global_seq": 88, "project_balance": {"tokens": 100000, "dispatches": 42}}
}
```

压缩规则：保留 checkpoint + `seq > checkpoint.seq` 的全部记录 + `unresolved` 中事务的完整记录。去重依据 = `dispatch_key_recent` + bloom + checkpoint 之后的记录。重放断言：run/账本/facts 计数与压缩前一致，且无重复 `commit_done`。

## 4. 各阶段

### R1 多项目编排、断点续跑、最小账本（0.4.0）

**目标**：一个会话能看见并操作所有在跑项目；进程被杀后可无损续跑；预算先有最小预留/结算。

交付：
- `registry.json`、`nuwa ls [--json]`、`nuwa status --all`、`nuwa attach <name>`
- `.nuwa/run.json`（`run_schema:1`）、`journal.jsonl`、checkpoint
- 最小账本：`reserve` / `settle` / `reclaim` / `opening_balance`（不含公平调度）
- 执行结果 artifact（原始 envelope）
- `nuwa --resume <name>`
- **幂等提交包装器**：`nuwa commit --key <dispatch_key>`，在项目锁内直接操作 `.sapper` JSON
- `tests/contract_check.py`、`tests/gates/run.sh`

**事务状态机**：

```
reserve → executing → executed → commit_prepare → done_apply → intent_verify → ledger_settle → commit_done → ack
```

- `attempt_seq` 每 intent 从 0 递增；`dispatch_key = sha256(project|intent|attempt_seq)`。
- `executing` 在 **spawn 之前**写入，含 pid、started_at。
- `executed` 在进程退出后写入，含 exit_code、artifact 路径、stdout/stderr 长度；**tokens 在此结算**（见 R2）。
- `commit_prepare` 写入 fact 内容摘要、kind、doc、`rid`。

**done_apply（覆盖 fact 已建、intent 未更新的窗口）**：

1. 在项目锁内扫描 `.sapper/facts/*.json` 的 `x-nuwa-key`。
2. 命中 → 复用该 fact，跳到 intent_verify。
3. 未命中 → 调 `sapper done <id> --fact ...` 创建 fact，然后原子写入 `x-nuwa-key`。
4. intent_verify：读 intent；若 `to` 为空但 fact 已存在，直接修补 intent JSON（status=done、to=fact、done_at），再跑 `sapper validate` 确认引用完整。
5. ledger_settle：按 `rid` 幂等结算；重复调用只更新不重复扣。
6. `commit_done` → `ack`。

**恢复规则**：

| 最后状态 | 动作 |
|---|---|
| reserve | 释放 intent、回滚预留，`attempt_seq` 不变 |
| executing | pid 探活：存活则等待接管；死亡则查 artifact：可解析 → 补 `executed`；否则释放并以 `attempt_seq+1` 重派 |
| executed | 校验 artifact/exit_code，进入 commit_prepare |
| commit_prepare | 从 done_apply 重放（幂等键保证不重复建 fact） |
| done_apply | 继续 intent_verify |
| intent_verify | 继续 ledger_settle |
| ledger_settle | 补 commit_done |
| commit_done | 补 ack，不重派 |

**与 sapper 的契约**：`x-nuwa-key` 是 nuwa 写入 fact 的附加字段，sapper 忽略未知字段；intent 修补后必须 `sapper validate` 通过。

验收：
- 8 个项目同时运行，`nuwa ls --json` 与实际进程一致（误差 ≤2s）
- 六个崩溃点（reserve 后、spawn 前、执行中、executed 后、done_apply 中、ledger_settle 中）各注入 20 次 SIGKILL：
  - 同一 `dispatch_key` 的 `executing` ≤1
  - 丢失 fact = 0、重复 fact = 0
  - 账本对账误差 ≤1 次预留
- run.json 截断到前 50% 能由 journal 重放
- checkpoint 压缩后重放一致
- registry 并发写 100 次无丢失

### R2 全局预算与公平调度（0.5.0）

**目标**：多项目共享一份预算，不饿死、不超支。

预算口径：

| 类型 | 单位 | 计费时点 | 来源 | 预留 | 结算 |
|---|---|---|---|---|---|
| tokens | input+output | `executed`（无论 commit 成败） | 引擎 usage；缺失按 `ceil((prompt+artifact)/4)` 估算并标 `estimated` | 项目 p95 | 实际/估算值，只补不退款 |
| wall | 秒（经过，暂停不计） | 项目结束 | 首次 dispatch 到结束 | 不预留 | 结束结算 |
| dispatches | 次 | `executed` | 每次执行 | 1 | 结算 |

- **失败也计费**：超时、解析失败、崩溃前已发生的消耗都在 `executed` 记账；只有从未 spawn 的预留可回滚。
- 预留续租：`executing` 期间每 2 分钟 `renew {rid, expires_at}`；TTL 10 分钟；pid 死亡即 `reclaim`。
- 迟到结算：reclaim 后的 `settle` 记 `late_settle`，按 `rid` 匹配，不重复扣费。
- 超支：`overspend = max(0, actual - cap) / cap`，三类分别算，任一 >5% 失败；超预留记 `overdraft`，项目暂停至补平。
- 公平性：三个等权、持续就绪项目共享 60s 窗口；每项目活跃区间取 dispatch 区间并集，分母为三个并集时长之和；每项目 ≥25%，且 ≥10 次 dispatch。
- 退避：1/2/4/8s，上限 60s；重试使用新 `attempt_seq`。

交付：
- `global.jsonl` 条目：`reserve/settle/reclaim/overdraft/renew/opening_balance`
- `nuwa budget [--json|--set]`、`nuwa budget fairness --projects 3 --seconds 60`
- 加权公平队列、单项目并发上限、429 退避
- 模型路由：reason 强模型、explore 廉价模型、失败链式回退

验收：
- 公平性命令输出三项目占比与 dispatch 数，断言达标
- 429 轮换后重复 fact = 0
- 预留过期、迟到结算、续租、失败计费四类用例通过
- 账本并发扣减无负数；快照与 journal 重放一致

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

- **哈希规范 v1**：`norm_sha256` 针对归一化字节（去 ANSI、CRLF→LF，步骤写死在 `hash_spec v1`）；`raw_sha256` 针对原始字节。两者都存。
- **脱敏解耦**：R5 只作用于日志、报告、events、fact 预览；永不改写 artifact 与两个哈希。
- **采集来源**：执行器 wrapper 采集，模型自报字段拒绝。
- **目标绑定**：`target` 与 intent 目标一致。
- **断言**：`op` 限 `contains/regex/eq/gt/lt`；默认对 artifact 前 1MB 求值，超限置 `truncated` 并拒绝依赖截断部分的断言。
- **新鲜度**：`captured_at` 距 `done` ≤30 分钟。
- **置信度**：`<0.6` 只记 note；`[0.6,0.8)` 记 fact 不参与 completed；`≥0.8` 可参与。
- **旧 fact**：`evidence_state: legacy`，不参与 completed；补证后升级 `verified`。

五类幻觉样本：

| 样本 | 输入 | 期望 |
|---|---|---|
| 无命令 | `command` 缺失 | 拒绝，退出码 10 |
| 结论不符 | assertion 为假 | 拒绝，退出码 11 |
| 旧输出 | `captured_at` 超 30 分钟 | 拒绝，退出码 12 |
| 伪造哈希 | `norm_sha256` 不匹配 | 拒绝，退出码 13 |
| 跨目标 | `target` 与 intent 不一致 | 拒绝，退出码 14 |

验收：
- 五类样本按表拒绝，退出码一致
- 3 组矛盾 fact 被标记且不阻塞推进
- `nuwa verify --samples 100` 的 p95 <2s（exec 到断言，排除排队）
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
- 报告断网可开；与 journal 对账误差 ≤1；events 轮转时标 `detail_truncated`
- stall 后 5s 内告警，重试 3 次落死信
- 单测：轮转后旧文件可读；journal 压缩后重放不变

### R5 执行隔离与凭据卫生（0.8.0）

**目标**：子代理只能做允许的事；派生副本不出现秘密，artifact 按权限保留。

策略覆盖矩阵：

| 执行路径 | 入口 | 强制点 | 加载失败 |
|---|---|---|---|
| bash 循环 | `bin/nuwa` → `sapper dispatch` → engine wrapper | engine wrapper | fail-closed |
| 会话内子代理 | `task(agent=fujiang)` | `nuwa-loop` 的 `tool_call` 前置 + 子代理 wrapper | fail-closed |
| 出网 | 任意路径 | 项目级 netns + 防火墙规则（代理环境只是便利） | fail-closed |

交付：
- 命令 allow/deny 与规则 id
- 出网：netns / uid 防火墙规则；忽略代理变量的进程同样受约束
- 脱敏过滤器：日志、events、报告、fact 预览；`redact_spec` 版本化
- 权限审计：状态目录 0700、artifact/账本 0600；30 天后销毁 artifact
- **HMAC 签名账本默认启用**（1.0 起必选），`nuwa audit verify`

验收：
- canary 注入 10 处（命令、输出、fact 预览、日志、报告），派生副本零泄漏
- 两条执行路径分别用本地 allow/block 目标：blocked 连接数 = 0（含 `curl --noproxy '*'` 直连阻断 IP）、allowed 成功率 = 100%、事件含 rule_id
- 策略加载失败时拒绝 dispatch / 工具调用
- 单测：脱敏不破坏 JSON；签名篡改可检出；artifact 权限与到期销毁

### R6 插件化、schema 演进、迁移回滚（0.9.0）

**目标**：换执行引擎或目标类型不改核心；迁移可回滚。

版本命名空间：

| 命名空间 | 归属 | 当前 | 迁移 |
|---|---|---|---|
| `graph_schema` | sapper | 由固定 sapper 版本决定 | nuwa 不迁移，只做契约测试 |
| `fact_schema` | nuwa（增量字段） | 1 | 增量写入，旧 fact 标 legacy |
| `loop_schema` | nuwa-loop | 2 | 2 → 3 |
| `run_schema` | nuwa | 1 | 按需递增 |
| `registry_schema` | nuwa | 1 | 按需递增 |
| `ledger_schema` | nuwa | 1 | 按需递增 |

交付：
- 引擎插件接口 `{name, api_version, detect(), run(prompt, opts) -> envelope}`，需签名与版本约束
- 目标适配接口：HTTP / Docker / SSH 内置，外部可注册
- `nuwa migrate --from auto --dry-run`：只迁移 nuwa 自有命名空间
- `nuwa snapshot` / `nuwa restore` / `nuwa migrate --rollback <snapshot_id>`
- 版本对样本：`tests/fixtures/migration/{v0_3,v0_9}`，覆盖 0.3.x → 0.9 → 1.0 与反向

验收：
- 新增 fake 引擎插件 ≤50 行，核心零改动
- 迁移保留 ID、引用完整、重复迁移零变化
- 迁移中断重试成功；`--rollback` 后 `sapper validate` 通过
- 插件 `api_version` 不兼容时拒绝加载
- 降级样本：用 0.3.1 二进制读取 1.0 生成的图与账本，字段落入 `x-nuwa` 备注

### R7 稳定性、性能、四件套回滚与冻结（1.0.0）

**目标**：可以长期挂着跑，升级/回滚可整体操作。

长测协议：
- 命令：`nuwa soak --minutes 4320 --projects 4 --concurrency 2 --min-dispatch-per-hour 60`
- 采样间隔 30s；PID 范围 = 各项目进程树
- 有效运行 ≥259200 秒；提前退出、采样间隔 >60s，判失败
- **RSS**：预热 20% 后对 RSS(KB)-时间(min) 最小二乘，斜率 <1024 KB/min
- **FD**：`max(后10个采样) - min(预热后前10个采样) ≤ 0`（增长即失败）
- **推进**：每小时 dispatch ≥60（滚动 60 分钟窗口，首小时后每窗满足）；任意连续 6 小时 facts 增长 >0
- 每 6 小时 `sapper validate`
- 唯一通过判定 = 全部条件同时成立

**跨项目一致快照**：

1. 短暂获取 `global.lock`，置 `freeze=true`，记录 `freeze_seq`，立即释放。
2. 等待 inflight 结算（结算正常获取 `global.lock`，不被快照阻塞），超时 120s 后强制终止并记 `forced_freeze`。
3. 再次短暂获取 `global.lock`，记录 `global_seq`，释放。
4. 逐项目记录 `cut_seq`，导出 `sapper export`、journal 尾部、run、budget 视图、checkpoint、artifact 清单。
5. 写 `SNAPSHOT.json`：各文件 sha256、facts 数、artifact 数、`global_seq`、`snapshot_id`。
6. 清除 `freeze`。

**增量与回滚**：
- `nuwa export-delta --snapshot <id>`：`seq > cut_seq` 的 journal、新 facts、账本条目、intent 迁移、新 artifact。
- 回滚：冻结 → 导出增量 → `nuwa restore --snapshot` → `nuwa import-delta`。
- 降级转换：新字段写入 `x-nuwa` 命名空间；账本增量以 `opening_balance` 入账；已结算 `rid` 集合随快照保存，导入去重。
- 四件套：CLI、扩展、skill、状态文件；`install.sh --rollback` 恢复四件套并打印版本矩阵。

验收：
- 全部测试门禁绿；72h 长测全部判据通过
- 连续两周无 P0/P1（P0 = 数据丢失/重复执行；P1 = 无法续跑/预算失真）
- 快照/恢复后 facts 数、artifact 数、账本余额一致；ID 无重复
- 降级后 0.3.1 能读图与账本；`nuwa --version` 与 `sapper validate` 通过

## 5. 横切约束

- **测试先行**：每阶段先加失败用例，再实现。
- **阶段门禁**：`tests/run.sh` = 契约检查 + 五套 + `gates/run.sh`；沙盒 `run-all.sh` 在此基础上加 C 层、靶场、矩阵、小长测。CI 与本地都跑同一入口。
  - 前置：`export NUWA_WORK=<repo> NUWA_SANDBOX=/srv/nuwa-sandbox`；同步 `tests/` 到 `layer-a/tests/`。
  - 阶段脚本放 `tests/gates/g<phase>.sh`，任一失败整段失败。
- **场景到命令**：

| 阶段 | 验收命令（阶段内交付） | 阈值 |
|---|---|---|
| R1 | `nuwa ls --json`；`tests/crash_inject.py --points 6 --repeat 20` | 一致 ≤2s；同 key executing ≤1；重复 fact 0 |
| R2 | `nuwa budget fairness --projects 3 --seconds 60` | 每项目 ≥25%，≥10 dispatch |
| R3 | `nuwa verify --samples 5 --expect reject`；`--samples 100` | 5/5 拒绝；p95 <2s |
| R4 | `nuwa metrics --json`；`nuwa report --offline` | 对账 ≤1；断网可开 |
| R5 | `nuwa policy check --matrix`；`tests/canary.py` | blocked=0；派生副本泄漏 0 |
| R6 | `nuwa migrate --from auto --dry-run`；`nuwa snapshot/restore` | 幂等；回滚 validate 通过 |
| R7 | `nuwa soak --minutes 4320 ...`；`install.sh --rollback` | 全部判据；四件套匹配 |

- **兼容性**：图 schema 只做增量；CLI 参数只增不减；废弃项保留 1 个 minor。
- **文档**：每阶段更新 README / CHANGELOG / TESTING / TEST-RESULTS。
- **可观测**：每个新子系统必须有 journal 事件与至少一个指标。
- **失败可恢复**：按第 3 节矩阵执行，权威状态不可静默重置。

## 6. 风险登记

| 风险 | 触发信号 | 影响 | 立即动作 | 恢复验证 |
|---|---|---|---|---|
| sapper 上游漂移 | `contract_check.py` 失败；版本字符串变化 | 派发/结案失效 | 回退固定 ref | 契约 7/7 |
| omp 扩展 API 变化 | 启动版本检查失败；`session_stop` 不触发 | 续跑失效 | 切兼容层，降级 bash 循环 | 会话 block 用例 |
| 多项目锁竞争 | `nuwa ls` waiting >30s | 吞吐下降 | 降并发，检查 registry pid | 8 项目推进 |
| 模型成本失控 | 账本 1 小时增幅 >预算 20% | 超支 | 路由降级 + 硬上限 | overspend ≤5% |
| 证据验收误报 | verify 拒绝率 >10% | 阻塞推进 | 人工覆盖 + 审计 | 抽样复核一致 |
| schema 迁移失败 | migrate 非零退出 | 状态不可用 | 停止升级，恢复快照 | validate + 旧版查询 |

固定依赖：sapper 固定到 `c91881dc1629409bbf278577dfdaa6b8f383b438`（CI 已写入 `SAPPER_REF`）；契约检查记录实际版本字符串；E2E 在真实 sapper 缺失时必须失败，仅 `NUWA_ALLOW_FAKE_SAPPER=1` 允许回退，CI 禁用该变量。

## 7. 里程碑

- M1（R1+R2）：可同时管 8 个项目并共享预算
- M2（R3）：事实可验收，五类幻觉样本全拒
- M3（R4+R5）：可观测、可告警、派生副本零泄漏
- M4（R6+R7）：插件化、迁移可回滚、1.0 冻结
