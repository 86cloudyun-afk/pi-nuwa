# pi-nuwa · 女娲模式

把 sapper-v2 的「长任务不会停」补进 pi / omp 的会话内部。

**女娲模式 = 一套渗透作战纪律（SKILL.md）+ 一个运行时续跑器（nuwa-loop 扩展）+ 一个一键入口（bin/nuwa）。**

## 它解决的是什么

`SKILL.md` 只是提示词，不是运行时。sapper-v2 能无人值守跑 8 小时，靠的是外部 `watchdog.sh` bash 循环。而在 pi / omp 里没有任何东西会在 task 批次返回后重新拉起主代理——模型写完一段战报，turn 就 settle，一轮即停。

`nuwa-loop` 监听 `session_stop`，读 `.sapper` 图状态；只要 `project.status != completed`，就返回 `decision: "block"` 把这一个 turn 顶回去，并注入下一步派单指令。

选 `block` 不选 `continue`：omp 18.16.0 对 continue 有 `SESSION_STOP_CONTINUATION_CAP=8` 的硬上限（`src/session/agent-session.ts:493`）；`decision === "block"` 在 `:5820` 的判断里不受该上限约束。

## 组成

| 路径 | 作用 |
|---|---|
| `extensions/nuwa-loop/index.ts` | 运行时续跑器：上膛、读图、注入续跑指令、停机 |
| `skills/nuwa-pentest/SKILL.md` | 女娲渗透纪律：触发词、唯一入口、记账、收尾 |
| `bin/nuwa` | 一键入口：建项目 → `sapper setup` → 落靶标事实 → 出意图 → 并行 dispatch → 看板 |
| `env/env.example.sh` | 网关与模型环境模板（不含凭据） |
| `install.sh` | 安装到 agent 加载目录，带备份与 `--rollback` |

依赖：[sapper-v2](https://github.com/86cloudyun-afk/sapper-v2) 提供 `sapper` CLI 与事实-意图图。

## 安装

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
./install.sh                      # 缺 sapper 会直接失败，不会假装成功
$EDITOR ~/sapper-lab/env.sh       # 填 GLM_API_KEY / DEEPSEEK_API_KEY
source ~/sapper-lab/env.sh && sapper-who
```

安装器把扩展放到 `~/.omp/agent/extensions/nuwa-loop`（无 omp 时用 `~/.pi/agent`），skill 放到 `~/.pi/agent/skills/nuwa-pentest` 并软链到 `~/.claude/skills/nuwa-pentest`，入口放到 `~/sapper-lab/bin/nuwa`，并生成 `SAPPER_BIN` 指向的 `omp-claude` 引擎。

## 使用

会话里说「女娲模式」「开图」「接入 sapper」「开始打 <目标>」，或直接：

```bash
~/sapper-lab/bin/nuwa "https://TARGET"
```

只出意图不执行：`nuwa "https://TARGET" --no-run`。
后台跑：`nuwa "https://TARGET" --detach --minutes 480`。
已有图：直接 `sapper status` / `sapper frontier`，再逐条 dispatch。

## 参数

| 变量 | 默认 | 含义 |
|---|---|---|
| `NUWA_LOOP` | `1` | `0` 关闭续跑 |
| `NUWA_MAX_TURNS` | `120` | 单会话最大自动续跑轮数 |
| `NUWA_MAX_STALL` | `10` | 会话内连续无有效变化上限 |
| `NUWA_MAX_TOKENS` | `2000000` | 累计上下文消耗上限（估算） |
| `NUWA_IDLE_LIMIT` | `3` | 连续空转轮数上限 |
| `NUWA_GUARD_HOURS` | `12` | 上膛有效期 |
| `NUWA_REQUIRE_EVIDENCE` | `1` | 无 flag/vuln/loot 事实时拒绝 completed |
| `NUWA_PROJECT` | — | 显式指定 `.sapper` 所在项目根 |
| `SAPPER_TIMEOUT` | `300` | 单次 dispatch 超时（`NUWA_DISPATCH_TIMEOUT` 可覆盖） |
| `PI_AGENT_HOME` | 自动探测 | `~/.omp/agent` 或 `~/.pi/agent` |
| `SAPPER_HOME` | `~/sapper-lab` | 项目与入口目录 |

运行时命令：`/nuwa-loop`、`/nuwa-loop off|on|reset`、`/nuwa-loop log [n]`、`/nuwa-loop why`、`/nuwa-loop budget [tokens]`。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 正常完成或预算用尽 |
| 2 | 参数 / URL 错误 |
| 3 | 依赖缺失（sapper / python3 / curl） |
| 4 | 项目目录冲突 |
| 5 | 另一个 nuwa 正在操作同一张图 |

## 停机条件

`project.status=completed` 且带证据，或 `turns > NUWA_MAX_TURNS`，或 `stall >= NUWA_MAX_STALL`，或 `idle >= NUWA_IDLE_LIMIT`，或 `spentTokens > NUWA_MAX_TOKENS`，或上膛超过 `NUWA_GUARD_HOURS`。停机后 `armed=false`，正常收工。

**完成证据闸门**：`status=completed` 但没有任何 `flag` / `vuln` / `loot` 事实时，完成会被打回 `active` 并写 hint，最多打回 3 次。这是为了防止模型在 reason 阶段脑补"已拿到 flag"。

## 排查

```bash
/nuwa-loop              # armed/turns/stall/idle/tokens + 图计数
/nuwa-loop log 20       # 最近 20 行 JSONL 事件
/nuwa-loop why          # 上一轮注入的完整指令
```

若 `armed=true` 但 turn 结束就停：确认 `.sapper/project.json` 存在、`status` 不是 `completed`、扩展确实被加载。
若从未上膛：会话里出现过触发动词，或调用过带 `sapper` 的 bash / 带 `fujiang` 的 task。
若出现 `另一个 nuwa 正在操作同一张图`：检查 `.nuwa.lock` 里的 pid 是否还活着。

细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`docs/SANDBOX.md`](docs/SANDBOX.md)、[`CHANGELOG.md`](CHANGELOG.md)。

## 许可

MIT。仅用于自己拥有或已获授权的目标。
