# 架构：女娲模式为什么能在会话里续跑

## 1. 病根

agent 的 `session_stop` 是「模型认为这一轮结束了」。SKILL.md 能告诉模型该做什么，但决定不了它什么时候停。sapper-v2 在终端里靠 `watchdog.sh` 外部循环反复拉起进程；会话内部没有这个循环，task 批次一返回，turn 就结束。

## 2. 三段式

### 上膛

三个入口任一命中即 `armed=true`：

- `before_agent_start`：prompt 命中 `/女娲|sapper|nuwa/i`
- `input`：用户输入命中同一正则
- `tool_call`：调用了带 `sapper|nuwa|女娲` 的 bash，或带 `fujiang|sapper` 的 task

`tool_call` 是最可靠的信号——它证明这一会话真的动过图，而不只是提了一句。

上膛写 `armedAt`，超过 `TURN_GUARD_MS = 12h` 自动失效，防止几天后残留状态把无关会话顶起来。

### 续跑

`session_stop` 触发时按顺序判定：

1. 未上膛或已过 12 小时 → 放行
2. `findRoot(cwd)` 找不到 `.sapper` → 放行
3. `status === "completed"` → 解除武装，放行
4. `turns++`，计算图签名 `sig = status|open|claimed|done|facts|flags`
5. `sig` 与上轮相同 → `stall++`，否则清零并更新
6. 超过 `MAX_TURNS(120)` 或 `MAX_STALL(10)` → 停机，放行
7. 否则 `return { decision: "block", reason: buildDirective(g, st) }`

`reason` 里带四段：图计数与 goal、本批待办 intent 与派发要求、收工判据、卡住时的换路指令。

### 找图

`findRoot` 依次尝试：cwd 向上逐级找 `.sapper/project.json` → `NUWA_PROJECT` → `$AGENT_HOME/cache/nuwa-current` 指针 → `$SAPPER_HOME` 下 mtime 最新的 `active` 图。指针由 `bin/nuwa` 在创建项目时写入，所以「刚跑过 nuwa」的会话总能找回自己的图。

## 3. 为什么用 block

omp 的 continue 路径有 `SESSION_STOP_CONTINUATION_CAP = 8` 的硬上限。8 轮对渗透远远不够，且到顶后是静默停止。`block` 走的是另一条判定，不受该上限约束，靠 `MAX_TURNS / MAX_STALL` 自己兜底。代价是每轮都算一次 turn，所以两个上限必须存在。

## 4. 状态

`$AGENT_HOME/cache/nuwa-loop/<sessionId>.json`：

```json
{ "armed": true, "armedAt": 1762500000000, "turns": 7, "stall": 0, "sig": "active|3|1|12|18|2" }
```

按 session 隔离，写失败不阻塞主流程（`saveState` 吞异常）。

## 5. 注入的纪律

续跑指令明确三件事，避免模型把「续跑」当成新任务或提前收工：

- 一轮 task 返回 ≠ 收工，不许输出「本轮战报」「已完成」
- 每批返回先 `sapper status` / `sapper frontier` 验收，再决定下一批
- 主线程不自己跑 nmap/ffuf/curl，扫描只发生在子代理里；子代理必须 `agent="fujiang"` 且带齐 `claim/doc/done` 四个动作

## 6. 边界

纯会话内机制，不依赖 tmux、不切终端、不写外部守护进程。会话结束即失效；跨会话的长跑仍由 `bin/nuwa --detach` 的 bash 循环承担。两者是互补关系：脚本负责「拉起进程」，扩展负责「不让 turn 停」。
