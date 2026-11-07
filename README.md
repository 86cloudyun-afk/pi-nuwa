# pi-nuwa · 女娲模式

把 sapper-v2 的「长任务不会停」补进 pi / omp 的会话内部。

**女娲模式 = 一套渗透作战纪律（SKILL.md）+ 一个运行时续跑器（nuwa-loop 扩展）+ 一个一键入口（bin/nuwa）。**

## 它解决的是什么

`SKILL.md` 只是提示词，不是运行时。sapper-v2 能无人值守跑 8 小时，靠的是外部 `watchdog.sh` bash 循环。而在 pi / omp 里没有任何东西会在 task 批次返回后重新拉起主代理——模型写完一段战报，turn 就 settle，一轮即停。

`nuwa-loop` 监听 `session_stop`，读 `.sapper` 图状态；只要 `project.status != completed`，就返回 `decision: "block"` 把这一个 turn 顶回去，并注入下一步派单指令。

选 `block` 不选 `continue`：omp 对 continue 有 `SESSION_STOP_CONTINUATION_CAP=8` 的硬上限（`src/session/agent-session.ts:493`），长渗透会被截断；block 路径不受该上限约束。

## 组成

| 路径 | 作用 |
|---|---|
| `extensions/nuwa-loop/index.ts` | 运行时续跑器：上膛、读图、注入续跑指令、停机 |
| `skills/nuwa-pentest/SKILL.md` | 女娲渗透纪律：触发词、唯一入口、记账、收尾 |
| `bin/nuwa` | 一键入口：建项目 → `sapper setup` → 落靶标事实 → 出意图 → 并行 dispatch → 看板 |
| `env/env.example.sh` | 网关与模型环境模板（不含凭据） |
| `install.sh` | 安装到 agent 加载目录 |

依赖：[sapper-v2](https://github.com/86cloudyun-afk/sapper-v2) 提供 `sapper` CLI 与事实-意图图。

## 安装

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
./install.sh
$EDITOR ~/sapper-lab/env.sh      # 填 GLM_API_KEY / DEEPSEEK_API_KEY
source ~/sapper-lab/env.sh && sapper-who
```

安装器把扩展放到 `~/.omp/agent/extensions/nuwa-loop`（无 omp 时用 `~/.pi/agent`），skill 放到 `~/.pi/agent/skills/nuwa-pentest` 并软链到 `~/.claude/skills/nuwa-pentest`，入口放到 `~/sapper-lab/bin/nuwa`。

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
| `NUWA_MAX_STALL` | `10` | 图状态连续无变化上限，超过停机 |
| `NUWA_PROJECT` | — | 显式指定 `.sapper` 所在项目根 |
| `PI_AGENT_HOME` | 自动探测 | `~/.omp/agent` 或 `~/.pi/agent` |
| `SAPPER_HOME` | `~/sapper-lab` | 项目与入口目录 |

运行时命令：`/nuwa-loop`、`/nuwa-loop off`、`/nuwa-loop on`。

## 停机条件

`project.status=completed`，或 `turns > NUWA_MAX_TURNS`，或 `stall >= NUWA_MAX_STALL`，或上膛超过 12 小时（`TURN_GUARD_MS`）。停机后 `armed=false`，正常收工。

卡住时的注入指令会要求先 `sapper release <id>`、`sapper hint`，再换路，不重复同一条命令。

## 排查

`/nuwa-loop` 看 `armed/turns/stall` 与图计数。若 `armed=true` 但 turn 结束就停：确认 `.sapper/project.json` 存在、`status` 不是 `completed`、扩展确实被加载（`~/.omp/agent/extensions/nuwa-loop/index.ts`）。若从未上膛：会话里出现过 `女娲`/`sapper`/`nuwa`，或调用过带 `sapper` 的 bash / 带 `fujiang` 的 task。

细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 许可

MIT。仅用于自己拥有或已获授权的目标。
