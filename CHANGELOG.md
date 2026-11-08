# Changelog

## 1.2.1 — 2026-11-08

codex `gpt-6.1-sol` ultra 三轮交付审计（35 → 45 → 50，均 block）后的修复：

- journal：compact 代号不覆盖、统一锁、seq 并入 checkpoint 高水位、未决事务代保护、
  recovery 摘要与 snapshot 原子读、尾读扩窗、严格 UTF-8、gen 数字排序（B1–B5、B11、M11）
- 策略：路径归一（cwd/`..`/多级祖先/符号链接/反斜杠）+ `files[]`/`apply_patch` 正文；
  P-006 覆盖 `&&`/管道/`$()`/引号/反斜杠/`--store`/绝对路径；P-007 覆盖 `budget/global.jsonl`、
  `cap.json`、`freeze.json`、`.nuwa/recovery.json`（B6–B8、B10、M1）
- 入口：URL 默认走 `nuwa dispatch` 事务提交；无 CLI/引擎 fail-closed；
  `NUWA_SUBMIT_MODE=sapper` 为显式遗留模式；`bin/nuwa` 转发 flag/complete/soak-night/soak-verify；
  收工前 `recover --repair`（B9、M6、M12）
- 完成：`nuwa complete --from` 支持多 fact、kind 校验、`[nuwa:key]` 回溯；裸 `sapper complete` 一律拦（M2、M10）
- 一致：`txn.commit(key=None)` 锁内生成规范键并拒绝其他键冲突（M3）；
  `night.verify` 严格 schema、有限数、整数 samples、duration 一致性、`--expect-commit`（M4/M5）；
  `check_prompt` 与 `check_command` 分离，避免提示误伤（M9）；`g1` 逐项聚合（M8）
- 第三轮补充：尾部缺 seq、bash 重定向/复制路径、`--store=`/`-s`、预算拒绝不虚假结算、
  其他键冲突前置、ack 终结 inflight、补丁目标过滤、recover/repair 接 recovery 摘要
- 文档：`RELEASE-1.2.1.md` 按真实状态标注 closed/partial；`TEST-RESULTS.md` 更新到 1.2.1；
  剩余 M 项登记到 `docs/BACKLOG-1.2.1.md`
- 测试：扩展 42、journal 21、r1core 37、r2r7 29，合计 143 例 + 16 runs；真实 sapper 1.0.0 下 contract 13/13、总退出码 0

## 1.2.0 — 2026-11-08

- journal 代际：`compact()` 在归档前取 seq（原先归档后取到 0，checkpoint 丢基线）；
  `last_seq()` 跨代取最大值，压缩后新记录不再与归档代撞号；新增 `gc(keep)`，
  默认保留 2 代，`NUWA_JOURNAL_KEEP=0` 关闭自动 GC
- 工具面策略：扩展新增 `checkTool`，bash / task / write / edit / multi_edit / apply_patch
  统一拦截；新增 P-005（写图目录）、P-006（绕开 nuwa 直接提交）、P-007（写权威状态）、
  P-009（直接改 project.json），`nuwa/policy.py` 同步 `check_path`
- 提交所有权：`buildDirective` 与 `SKILL.md` 不再 instruct `sapper done`，子代理只回结论，
  主线程用 `nuwa commit --key auto` 收口；`auto` 按 `sha256(project|intent|attempt)` 生成规范键
- 夜跑：`nuwa soak-verify <base>` 校验 `REPORT.json / MODE / COMMIT` 一致且判据全绿
- 测试：扩展 30 例（新增 8 条工具策略）、journal 3 例（跨代 seq / GC / 环境变量）、
  txn 1 例（auto 键幂等）、夜跑 2 例（报告校验 / 缺失报告）
- 替身：`fake-sapper` 识别 `FAKE_ENGINE_MODE` 的 noop / hallucinate / malformed，
  E2E 三种反例从 1/4 恢复到 4/4

## 1.1.0 — 2026-11-08

- 扩展侧命令拦截：`nuwa-loop` 的 `tool_call` 对 bash 执行 deny 规则（P-001..P-004），
  命中即 `block` 并写 `policy_block`；`NUWA_POLICY_ENFORCE=0` 可关
- 夜跑长测：`nuwa soak-night --base DIR --minutes 4320 --projects 4`，可续跑，
  输出 `REPORT.json / MODE / COMMIT`
- 崩溃矩阵：`tests/crash_matrix.py`，7 个提交点，支持 `--full`（20/5）
- 单测：扩展 22 例（新增 4 条命令策略）
- 安装器：新增 `nuwa-soak-night` 入口

## 1.0.0 — 2026-11-08

- R1 补齐：journal 归档压缩（`journal.<gen>.jsonl` + checkpoint + CURRENT）、崩溃注入 4 点、repair 恢复
- R5：渲染提示注入门（`policy.check_prompt`），命中 deny 规则即阻断 dispatch 并记 `policy_block`
- R6：`loop_schema 2→3` 写入迁移 + 自动备份，`migrate --dry-run/--write`
- 压力测试：16 项目 × 3 分钟并发，读数见 `docs/RELEASE-1.0.md`
- 门禁：g1 增加崩溃注入，g2 含迁移测试

## 1.0.0-rc1 — 2026-11-08

- R2：`nuwa fairness` 加权调度、账本准入、超支口径
- R3：`nuwa/evidence.py` 五类拒绝（10–14）与置信度 rubric、`nuwa verify`
- R4：`nuwa metrics --json`、`nuwa report` 离线 HTML、webhook 告警
- R5：`nuwa policy check/redact`、HMAC 签名校验
- R6：`nuwa/plugins.py`（api_version 校验）、`nuwa migrate --dry-run`
- R7：`nuwa soak` 多项目采样与判据
- 测试：R2–R7 模块 17 例；门禁 `g2_r2r7`
- 发布说明：`docs/RELEASE-1.0.md`（GA 缺口清单）

## 0.4.0-dev — 2026-11-08

R1 运行时（Python 包 `nuwa/`）：

- `journal.py`：append-only 权威事件流、并发 seq、checkpoint + CURRENT 指针、重放摘要
- `ledger.py`：全局账本 `global.jsonl`、reserve/renew/reclaim/settle/opening_balance、准入与剩余额度
- `locks.py`：`run.lock` / `txn.lock` / `inflight/<intent>.lock`，flock 封装与存活探测
- `txn.py`：幂等键、`commit`（key 扫描 + sapper done + intent 修补 + validate）、`repair`、`adopt`
- `worker.py`：先加锁、写 ready、fork+wait、写 result，锁 fd 随子进程保留
- `dispatch.py`：渲染提示 → 引擎 → executed → 解析 payload → 幂等提交 → 结算
- `runner.py`：round 循环、reason 批量幂等、并行 dispatch、证据闸门、run.json、resume 计数
- `cli.py`：`ls / status / attach / budget / commit / dispatch / run / recover / adopt`
- 测试：core 11 + dispatch 2 + run 1 + multi 1 = 15 例，全部在 us3 通过
- 门禁：`g1_r1.sh` 接入 `tests/run.sh` 与 `gates/expected`

## 0.3.1 — 2026-11-08

- `bin/nuwa --version`
- `tests/contract_check.py`：真实 sapper 与 fake-sapper 的 13 项契约对照（含正向结案、未知字段保留、dry-run 零写入、版本记录）
- `tests/gates/run.sh`：阶段门禁入口，按 `g*.sh` 聚合退出码
- E2E 在真实 sapper 缺失时拒绝静默回退（`NUWA_ALLOW_FAKE_SAPPER=1` 才允许）
- CI 固定 sapper 到 `c91881dc`

## 0.3.0 — 2026-11-08

测试机制补齐。五套测试 + 两个替身 + 八类靶场 + 小长测，全部在沙盒机执行。

### 新增测试

- `tests/unit.test.ts`（18 项）：`findRoot` / `readGraph` / `buildDirective` / `revertCompletion` / `readCfg`。
- `tests/test_chaos.py`（8 项）：损坏图、陈旧锁、活锁、SIGKILL 恢复、只读目录、1000 intent 性能、缺 python3。
- `tests/test_concurrency.py`（5 项）：同项目单赢家、跨项目并行、锁清理（正常/SIGTERM）、无重复派发。
- `tests/test_e2e_deterministic.py`（4 项）：零模型成本的完整链路、幻觉完成拦截、空 reason、非 JSON 引擎。
- `tests/soak.py`：小长测采样器，判 RSS 斜率 / FD 增长 / 状态文件体积。

### 新增替身

- `tests/fake-sapper`：sapper-v2 协议级替身，逐字复刻输出与参数约束。
- `tests/fake-claude`：确定性 claude 兼容引擎，模式 `normal` / `noop` / `hallucinate` / `malformed` / `slow`。

### 靶场扩展（沙盒）

从 4 类扩到 8 类：static / dvwa / slow / deny / redirect / basicauth / notfound / gzip。

### 修复（测试驱动）

- **完成闸门出口缺口**：frontier 为空时提前 break，绕过证据闸门 → 现在预算用尽、frontier 为空、循环末尾三个出口统一调 `completion_ok`。
- **SIGTERM 不退出**：`trap ... INT TERM` 只清锁不退出 → 改为 `on_signal` 清锁 + 收子进程 + `exit 143`。
- **损坏图未拦截**：`.sapper/project.json` 非法 JSON 时直接跑 → 现在前置校验并退出 2。
- **项目目录语义**：有 `.sapper` 即复用，非空且无图才拒绝（退出 4）。

## 0.2.0 — 2026-11-08

运行时正确性与可观测性大修。基于三层沙盒（协议仿真 / 真实靶场 / headless 会话）验证。

### P0 阻断修复

- `bin/nuwa` 增加依赖闸门：`sapper` / `python3` / `curl` 缺失时以退出码 3 立即退出，不再空转。
- `bin/nuwa` 的 frontier 取值改为 `grep -E '^i[0-9]+' | cut -f1`，不再把 `(no ready intents)` 当成 intent id。
- `buildDirective` 的 `sapper claim` 补上 `--worker`（sapper 的必填项）。
- `buildDirective` 的 `sapper doc` 补上 `--set`，避免子代理打开 `$EDITOR` 挂起。
- `install.sh` 在缺 `sapper` 时 `exit 1`，不再只打印提示。
- `install.sh` 生成 `$SAPPER_HOME/bin/omp-claude` 执行引擎。

### P1 运行时修复

- `findRoot` 删除「扫 `$SAPPER_HOME` 下 mtime 最新 active 图」兜底，改为 `cwd 向上` + `NUWA_PROJECT` + JSON 指针，指针带 `sessionId` 校验。
- 新增项目级互斥锁 `.nuwa.lock`（`flock`），退出时按 pid 清理。
- 触发词收紧为 `女娲模式|女娲渗透|开图|接入 sapper|sapper 模式`。
- `tool_call` 改为结构化判定：`bash.command` 匹配 `\bsapper\b`，或 `task.agent === "fujiang"`。
- `stall` 判据改用「有效推进」签名（排除 `note` 噪声）。
- `NUWA_MAX_TURNS` / `NUWA_MAX_STALL` / `NUWA_MAX_TOKENS` / `NUWA_IDLE_LIMIT` / `NUWA_GUARD_HOURS` 全部做数值校验，非法值回落默认。
- `session_stop` 在 block 链过长时切 `continue`，降低与其他 handler 的抢占。
- `dispatch` 超时继承 `SAPPER_TIMEOUT`，每轮按剩余预算收敛。
- URL 无 scheme 时补 `https://`，解析失败以退出码 2 退出。
- 默认项目名加 pid 后缀，同名目录冲突以退出码 4 退出。

### P2 可观测

- `events.jsonl`：每轮 `round_start` / `dispatch_start` / `dispatch_end` / `budget_exhausted` / `stall_stop` / `project_completed` / `completion_rejected`。
- `nuwa-loop` 日志 `cache/nuwa-loop/log/<sid>.jsonl`，每轮一行。
- `/nuwa-loop` 子命令：`off` / `on` / `log [n]` / `why` / `reset` / `budget <tokens>`。
- token 预算闸门（`NUWA_MAX_TOKENS`，默认 2M）。
- 空转检测（`NUWA_IDLE_LIMIT`，默认 3）。
- 状态文件带 `schema: 2`，路径用 `sha1(sessionId)` 前 16 位。
- `install.sh` 安装前备份扩展，支持 `--rollback`。

### 新增防御（沙盒实测驱动）

- **完成证据闸门**：`status=completed` 但没有任何 `flag/vuln/loot` 事实时，`bin/nuwa` 与 `nuwa-loop` 都会把状态打回 `active` 并写 hint，最多打回 3 次。解决 reason 阶段模型幻觉直接"完成任务"。
- **bash 循环 stall 熔断**：`NUWA_MAX_STALL`（默认 5）轮无有效推进即停机。noop 场景从 61.8s / 405 次 dispatch 降到 10.4s / 38 次。
- **锁清理**：`trap cleanup_lock EXIT INT TERM`，只删自己持有的锁文件。

### 沙盒

- `layer-a/`：`fake-sapper` 协议仿真 + 14 项验收测试（`tests/test_nuwa_shell.py`）。
- `layer-b/`：4 目标 Docker 靶场（静态 flag / DVWA / 慢响应 / 全 403）。
- `layer-c/`：omp headless 会话，验证 `armed` → `block` → directive 注入。
- `bin/stress.py`：并发压力测试，支持 `empty_frontier` / `noop` / `slow` / `error` 注入。
- `bin/analyze.py`：把压力、靶场访问、会话日志合成 `ANALYSIS.md`。
