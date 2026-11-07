# 架构：女娲模式为什么能在会话里续跑

## 1. 病根

agent 的 `session_stop` 是「模型认为这一轮结束了」。SKILL.md 能告诉模型该做什么，但决定不了它什么时候停。sapper-v2 在终端里靠 `watchdog.sh` 外部循环反复拉起进程；会话内部没有这个循环，task 批次一返回，turn 就结束。

## 2. 三段式

### 上膛

三个入口任一命中即 `armed=true`：

- `before_agent_start`：prompt 命中 `女娲模式|女娲渗透|开图|接入 sapper|sapper 模式`
- `input`：用户输入命中同一正则
- `tool_call`：结构化判定——`bash` 的 `command` 匹配 `\bsapper\b`，或 `task` 的 `agent === "fujiang"`

`tool_call` 是最可靠的信号——它证明这一会话真的动过图，而不只是提了一句。

上膛写 `armedAt`，超过 `NUWA_GUARD_HOURS`（默认 12h）自动失效，防止几天后残留状态把无关会话顶起来。

### 续跑

`session_stop` 触发时按顺序判定：

1. 未上膛或已过有效期 → 放行
2. `findRoot(cwd, sessionId)` 找不到 `.sapper` → 放行
3. `status === "completed"`：
   - 有 `flag/vuln/loot` 证据 → 解除武装，放行
   - 无证据 → `revertCompletion()` 打回 `active`，最多 3 次
4. 项目锁 `.nuwa.lock` 被外部活进程持有 → 放行（让 bash 循环主导）
5. `turns++`，累计 token 消耗
6. 计算图签名 `sig = status|open|claimed|done|effective|flags`（`effective` 排除 note 噪声）
7. `sig` 与上轮相同 → `stall++`，否则清零并更新
8. 工具调用数未增长 → `idle++`，否则清零
9. 超过 `MAX_TURNS / MAX_STALL / MAX_IDLE / MAX_TOKENS` → 停机，放行
10. 否则 `return { decision: "block", reason: buildDirective(g, st) }`

`reason` 里带四段：图计数与 goal、本批待办 intent 与派发要求、收工判据、卡住时的换路指令。

### 找图

`findRoot` 依次尝试：cwd 向上逐级找 `.sapper/project.json` → `NUWA_PROJECT` → `$AGENT_HOME/cache/nuwa-current` 指针。

指针是 JSON：

```json
{ "root": "/path/to/project", "sessionId": "01a1...", "ts": 1762500000000 }
```

`sessionId` 不匹配时拒绝接管，防止多项目并行串台。旧格式（纯路径）按兼容放行。

## 3. 为什么用 block

omp 的 continue 路径有 `SESSION_STOP_CONTINUATION_CAP = 8` 的硬上限。8 轮对渗透远远不够，且到顶后是静默停止。`block` 走的是另一条判定，不受该上限约束，靠 `MAX_TURNS / MAX_STALL / MAX_IDLE / MAX_TOKENS` 自己兜底。

代价是每轮都算一次 turn，所以四个上限必须存在。

block 链过长（`NUWA_BLOCK_STREAK`，默认 3）且 `event.stop_hook_active` 为真时，切一次 `continue + additionalContext`，降低与其他 `session_stop` handler 的抢占。

## 4. 状态

`$AGENT_HOME/cache/nuwa-loop/<sha1(sessionId)[:16]>.json`：

```json
{
  "schema": 2,
  "armed": true,
  "armedAt": 1762500000000,
  "turns": 7,
  "stall": 0,
  "idle": 0,
  "blockStreak": 1,
  "spentTokens": 12000,
  "lastTokens": 9000,
  "toolCalls": 12,
  "lastToolCallsSnapshot": 10,
  "sig": "active|3|1|12|18|2",
  "lastReason": "..."
}
```

按 session 隔离，`schema` 不匹配时重置。写失败落日志，不阻塞主流程。

日志在 `cache/nuwa-loop/log/<sid>.jsonl`，每轮一行，事件包括 `armed` / `block` / `stop` / `completion_rejected`。

## 5. 项目锁

`bin/nuwa` 在项目目录创建 `.nuwa.lock`，用 `flock` 持有整个生命周期；退出时 `trap cleanup_lock EXIT INT TERM` 只删自己 pid 的锁。

`nuwa-loop` 的 `lockHeldByOther()` 读 pid 并 `process.kill(pid, 0)` 探活：活进程持锁 → 扩展放行，避免 bash 循环与会话内循环双跑。

## 6. 完成证据闸门

模型常在 `reason` 阶段直接输出「已拿到 flag」并 `complete`，但实际没有发出任何请求。两个入口都做了拦截：

- `bin/nuwa`：每轮结束检查 `status=completed` 且 facts 里没有 `flag/vuln/loot` → 把 `status` 改回 `active`、删 `completed_at`、写 hint。
- `nuwa-loop`：`session_stop` 时同样判定，打回最多 3 次；超过则停机并记录 `stop_completed_unverified`。

关闭方式：`NUWA_REQUIRE_EVIDENCE=0`。

## 7. 注入的纪律

续跑指令明确四件事，避免模型把「续跑」当成新任务或提前收工：

- 一轮 task 返回 ≠ 收工，不许输出「本轮战报」「已完成」
- 每批返回先 `sapper status` / `sapper frontier` 验收，再决定下一批
- 主线程不自己跑 nmap/ffuf/curl，扫描只发生在子代理里；子代理必须 `agent="fujiang"` 且带齐四个动作
- 四个动作的参数必须照抄：`claim --worker`、`doc --set`、`done --fact`、`complete --from`

## 8. 边界

纯会话内机制，不依赖 tmux、不切终端、不写外部守护进程。会话结束即失效；跨会话的长跑仍由 `bin/nuwa --detach` 的 bash 循环承担。两者是互补关系：脚本负责「拉起进程」，扩展负责「不让 turn 停」。

两者同时存在时，靠 `.nuwa.lock` 互斥：bash 在跑，扩展就只做验收与补位。
