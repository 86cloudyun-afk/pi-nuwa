# Changelog

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
