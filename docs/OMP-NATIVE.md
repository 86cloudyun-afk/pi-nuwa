# 女娲 v2：纯 omp 运行时

## 1. 为什么要变

v1 的链路是 `bin/nuwa (bash) → nuwa/cli.py (Python) → sapper CLI → 子进程`。
任何一环出问题，整个循环就停：bash 的 flock、Python 的 journal 代际、sapper 的图写入、
`omp-claude` 的 stdout 解析，四个进程边界叠在一起，故障面大且难复现。

v2 把所有边界收进 omp 进程：

| v1 | v2 |
|---|---|
| `bin/nuwa` 建项目、循环、看板 | `nuwa_init` / `session_stop` 自动续跑 |
| `nuwa/cli.py dispatch` 渲染提示、调引擎 | `nuwa_claim` 生成 packet，主线程用 `task` 派 fujiang |
| `sapper` 事实-意图图 | `.nuwa/state.json` 单文件状态机 |
| `.nuwa/journal.jsonl` + `txn.repair` | 每次写盘前追加完整快照，load 时回放 |
| `.nuwa.lock` + `flock` | `state.lock` 单写者锁（pid + 30s 新鲜度） |
| `NUWA_*` 环境变量散落 bash/Python | 统一 `readCfg()`，一份配置 |

没有 CLI、没有 Python、没有外部守护进程。会话结束，循环就结束；下一个会话 `resume` 继续。

## 2. 架构

```
┌──────────────────────────── omp session (main) ────────────────────────────┐
│                                                                            │
│  user: 女娲模式，打 http://TARGET                                          │
│      │                                                                     │
│      ▼                                                                     │
│  nuwa_init ──► .nuwa/state.json  (project/facts/intents/runtime)           │
│      │              ▲                                                      │
│      │              │ atomic write + journal snapshot                      │
│      ▼              │                                                      │
│  nuwa_claim(iNNN) ──┘  packet: 目标/事实/命令/输出契约                     │
│      │                                                                     │
│      ▼                                                                     │
│  task({ tasks:[{agent:"fujiang", task:packet}] })                          │
│      │                                                                     │
│      ▼                                                                     │
│  subagent (fujiang): 执行命令，回 5 行结论                                 │
│      │                                                                     │
│      ▼                                                                     │
│  nuwa_commit / nuwa_flag ──► fact fNNN，intent done/blocked                │
│      │                                                                     │
│      ▼                                                                     │
│  session_stop ──► frontier? ──yes──► directive (decision:"block")          │
│      │                │                                                    │
│      │                no                                                   │
│      ▼                ▼                                                    │
│  completed/stopped   nuwa_plan(next phase) / nuwa_stop                     │
└────────────────────────────────────────────────────────────────────────────┘
```

扩展注册 11 个工具、1 个命令、3 类事件：

- `tool_execution_end`：累计工具调用数，用于 idle 判定。
- `tool_call`：执行纪律拦截（N-001..N-005）。
- `session_stop`：预算、stall/idle、证据闸门、注入 directive。

## 3. 状态模型

`.nuwa/state.json`：

```json
{
  "schema": 1,
  "version": "2.0.0",
  "project": {
    "id": "10-0-0-5-8080",
    "target": "10.0.0.5:8080",
    "url": "http://10.0.0.5:8080",
    "host": "10.0.0.5",
    "port": 8080,
    "scheme": "http",
    "goal": "打穿并拿 flag",
    "mode": "ctf",
    "status": "active",
    "phase": "recon",
    "createdAt": "2026-11-12T00:00:00.000Z",
    "updatedAt": "2026-11-12T00:01:00.000Z"
  },
  "facts": {
    "f001": {
      "id": "f001",
      "kind": "service",
      "title": "HTTP 200 nginx",
      "detail": "Server: nginx",
      "command": "curl -k -sS -D - http://10.0.0.5:8080/",
      "output": "HTTP/1.1 200 OK\nServer: nginx",
      "intent": "i001",
      "key": "3f2a...",
      "createdAt": "2026-11-12T00:00:30.000Z"
    }
  },
  "intents": {
    "i001": {
      "id": "i001",
      "phase": "recon",
      "key": "recon:http",
      "title": "HTTP 存活与响应指纹",
      "detail": "...",
      "from": [],
      "to": "f001",
      "status": "done",
      "worker": "fujiang",
      "priority": 90,
      "attempts": 1,
      "createdAt": "2026-11-12T00:00:00.000Z",
      "claimedAt": "2026-11-12T00:00:05.000Z",
      "doneAt": "2026-11-12T00:00:30.000Z"
    }
  },
  "seq": { "fact": 1, "intent": 6 },
  "runtime": {
    "startedAt": 1794412800000,
    "turns": 3,
    "stall": 0,
    "idle": 0,
    "blockStreak": 1,
    "toolCalls": 12,
    "lastToolCalls": 10,
    "tokens": 48210,
    "lastSig": "active|recon|5|0|1|0|1|0|f001",
    "lastDirective": "...",
    "completionRejects": 0,
    "emptyRounds": 0
  }
}
```

字段约束：

- `facts[*].key`：幂等键。`commit` 用 `sha1(project.id|intent.id|attempts|kind|title)`；`flag` 用 `sha1(value)`。
- `intents[*].from`：依赖的 fact id；为空表示根意图，播种即 eligible。
- `intents[*].status`：`open | claimed | done | blocked`。`claimed` 超过 `NUWA_CLAIM_TTL`（默认 900s）可被重新认领，`attempts+1`。
- `runtime.lastSig`：`status|phase|open|claimed|done|blocked|facts|flags|lastFact`，用于 stall。

## 3.5 `/nuwa` 命令（v2.1）

```
/nuwa <自然语言任务>      # 开工：抽 target/mode → init/resume → 注入第 1 轮
/nuwa                    # 看板
/nuwa log [n]            # journal 末 n 行
/nuwa why                # 上一条续跑 directive
/nuwa stop [原因]         # 停机（保留 facts/intents）
/nuwa resume             # 复活并立即起跑
```

任务模式的解析规则：

| 输入片断 | 结果 |
|---|---|
| `http://h:8080/path` | 原样作为 target |
| `10.0.0.5:8080` / `10.0.0.5` | `http://10.0.0.5:8080` / `:80` |
| `demo.target.test` | `http://demo.target.test:80`；`state.json`、`app.ts` 等文件后缀不算目标 |
| 都没有 | 读 `NUWA_TARGET` / `TARGET`；仍为空则只回用法，不落状态 |

模式：`审计|白盒|audit|review` → `audit`；`渗透|打点|提权|横向|内网|red|getshell` → `pentest`；
其余 → `ctf`。

建项目时 `seedPhase(recon)` 播 6 条；已有项目则 `addIntent(priority=95)` 把任务并入当前阶段。
落地后命令自己调 `pi.sendUserMessage(kickPrompt)` 触发一次真实轮次——命令处理器本身不产生模型
轮次，这一步是"输入 /nuwa 就开跑"的关键；流式中回退到 `sendMessage({triggerTurn:true})`。

## 4. 工具参考

### nuwa_init

建项目或恢复。默认在 cwd 建 `.nuwa/`，不接管指针里的旧项目。

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| target | string | — | URL / host:port；新建时必填 |
| goal | string | 自动 | 目标描述 |
| mode | ctf/pentest/audit | ctf | 决定完成证据 |
| root | string | cwd | 项目目录 |
| resume | bool | false | 恢复 stopped 项目，保留 facts/intents，重置预算 |
| force | bool | false | 覆盖现有 state（旧文件备份为 `.bak-<ts>`） |
| migrate | bool | false | 从同目录 `.sapper` 迁移 |

### nuwa_plan

播种阶段或追加自定义意图。`phase` 会播种该阶段全部内置意图（按 key 去重，可重复调用）；
`intents[]` 支持 `title/detail/phase/from/priority`。若 `phase` 晚于当前阶段，会把项目阶段推进到该阶段。

### nuwa_frontier

返回 eligible 意图：`status=open`，或 `claimed` 且超过 TTL；所有 `from` fact 存在。
按 `priority DESC, id ASC` 排序。

### nuwa_claim

认领并返回 packet：

```
[女娲派单 i007] vuln · SQL 注入验证
目标: http://10.0.0.5:8080
已知事实:
- f003 [service] nginx 1.18 ...
执行内容:
<该 intent 的 detail，{URL}/{HOST}/{PORT}/{OUT}/{ID} 已替换>
输出契约（子代理只回 5 行）:
结论 / 证据 / 命令 / 阻断 / 下一步
```

已认领且未过 TTL 会拒绝；过期则 `stale=true` 重领。

### nuwa_commit

| 参数 | 说明 |
|---|---|
| id | intent id |
| kind | target/asset/service/endpoint/cred/vuln/flag/loot/note/blocked |
| title/detail | 结论与细节 |
| command/output | 实际命令与关键回显；非 note 必填 |
| blocked/note | 收口卡住的 intent，不产 fact |

校验：

- `command` 非空、`output` ≥ 8 字符、不是占位符。
- `echo`/`printf` 开头的命令不算证据。
- `kind=flag` 时，若 title/detail 含 `flag{...}`，output 必须包含该值。
- 幂等：同一 `intent/attempt/kind/title` 只入账一次。

### nuwa_flag

`value` + `command` + `output`。`output` 必须包含完整 flag 值；`command` ≥ 3 字符且不能是 echo/printf。
按 `sha1(value)` 幂等。

### nuwa_complete

`from[]` 省略时使用全部证据事实。ctf 需 `flag`，pentest 需 `vuln/loot/flag`，audit 需 `vuln/loot`。
不满足 → `ok=false`，`runtime.completionRejects++`，项目保持 active。

### nuwa_status / nuwa_report / nuwa_stop / nuwa_kb

- `nuwa_status`：ASCII 看板（阶段进度、事实统计、预算、frontier）。
- `nuwa_report(write=true)`：Markdown 报告，写 `.nuwa/REPORT.md`。
- `nuwa_stop(reason)`：`status=stopped`，停止续跑；`nuwa_init(resume=true)` 恢复。
- `nuwa_kb(query, kind, limit)`：sqlite3 只读查询 `/data/nuwa-kb/kb.db`（产品卡/CVE/PoC/ATT&CK）。

## 5. 续跑算法

`session_stop` 每次触发：

1. `NUWA_LOOP=0` 或非主会话 → 放行。
2. 找 root（cwd 向上 → `NUWA_PROJECT` → `~/.omp/agent/cache/nuwa-current.json`，session 不匹配则拒绝）。
3. 无 state 或 `status != active` → 放行。
4. `state.lock` 被其它活进程持有 → 放行（兼容手动 CLI）。
5. `turns++`；更新 tokens（`ctx.getContextUsage()` 的 `tokens`/`usedTokens`）。
6. 更新 `toolCalls`（来自 `tool_execution_end` 计数）。
7. 计算 sig；相同 → `stall++`，否则 `stall=0` 并更新 sig。
8. 工具调用数未增长 → `idle++`，否则 `idle=0`。
9. 预算闸门：`turns > maxTurns` / `minutes > maxMinutes` / `tokens > maxTokens` / `stall >= maxStall` / `idle >= maxIdle`
   → `status=stopped`，写 `stopReason`，放行。
10. 生成 directive，`blockStreak++`，写 state + journal。
11. 若 `event.stop_hook_active` 且 `blockStreak > NUWA_BLOCK_STREAK` → 返回一次 `continue + additionalContext`，避免与其它 stop handler 抢占。
12. 否则返回 `{ decision: "block", reason: directive }`。

directive 包含：本轮计数、本批 intent、`claim → task(agent=fujiang) → commit` 的逐步协议、
纪律（禁止主线程扫描、禁止 CLI、禁止写 state）、stall/idle 换路提示、完成证据统计。

## 6. 证据与幂等

证据闸门在入口，而不是完成时：

- 事实写入必须带 command + output（note 除外）。
- flag 写入必须 output 包含完整值。
- 完成只接受 `proofKinds(mode)` 内的事实，且引用必须存在。

幂等两层：

1. `commit` 的 key 含 `attempts`：同一 attempt 重复提交返回已有 fact，不重复计数。
2. `flag` 的 key 是 value 哈希：同一 flag 只入账一次。

这解决 v1 的两个老问题：模型重试导致事实膨胀、reason 阶段脑补 flag。

## 7. 阶段 playbook

内置 32 条意图，播种后并行执行（`from=[]`），按阶段推进：

| 阶段 | 意图数 | 内容 |
|---|---|---|
| recon | 6 | HTTP 指纹、端口、目录、vhost、证书/SAN、技术栈→CVE |
| surface | 6 | 爬取、参数、认证面、敏感文件、API/GraphQL、上传点 |
| vuln | 10 | SQLi、XSS、SSTI、LFI、SSRF、命令注入、上传绕过、IDOR、认证绕过、组件 CVE |
| exploit | 5 | 链验证、RCE、凭据、提权、横向 |
| post | 3 | flag、loot、影响面 |
| report | 2 | 攻击链、修复建议 |

`maybeAdvance`：当前阶段所有意图 `done/blocked` 时，自动切下一阶段并播种；`nuwa_plan(phase=...)` 可手动提前。

## 8. 纪律拦截

| 规则 | 触发 | 拦截 |
|---|---|---|
| N-001 | 主会话 bash 出现 nmap/ffuf/nuclei/sqlmap 等 | 扫描必须在 fujiang 子代理 |
| N-002 | bash 出现 `bin/nuwa`、`nuwa/cli.py`、`nuwa dispatch/commit/...` | CLI 已退役 |
| N-003 | bash 重定向或 write/edit/apply_patch 目标命中 `.nuwa/state.json`、`journal*.jsonl`、`state.lock` | 状态只允许 nuwa_* 写 |
| N-004 | task 的任一 item `agent != "fujiang"`；eval 里 `agent()` 未写 fujiang | 统一使用 fujiang |
| N-005 | 子会话调用 nuwa_init/plan/claim/commit/flag/complete/stop | 只有主线程记账 |

拦截只在该 root 有 state 且 `status=active` 时生效；只读工具（status/frontier/report/kb）子代理可用。

## 9. 崩溃恢复与并发

- 每次 `saveState` 先 `journalAppend({type:"snapshot", state})`，再 `writeFileSync(tmp) + rename`。
- `loadState` 读不到合法 `state.json` 时，从 journal 末尾向前找最后一条合法 snapshot，回写 state。
- journal 超过 8MB 轮转为 `journal.1.jsonl`（只保留一代）。
- 所有写操作走 `withLock`：`open(O_EXCL)` 写 pid+ts；检测到活 pid 且 <30s 抛 `state locked`，死进程或陈旧锁直接回收。
- 工具层拒绝并发写同一状态；读操作不加锁。
- 多任务隔离（2.1.1/2.1.2）：会话指针按 `sessionId` 分文件；`project.ownerSessionId` 拒绝跨会话接管；`/tmp`、home、`/`、`/data/workspace`（可加 `NUWA_SHARED_CWDS`）不向子目录继承；同根换目标时共享 cwd 落 `cache/nuwa-projects/<target>-<sessionHash>`，非共享 cwd 落 `<cwd>/.nuwa-tasks/<target>-<sessionHash>`。
- 崩溃接管：omp 重启后 `sessionId` 变化，旧项目默认被 owner 检查拒绝。确认旧会话已死时，用 `nuwa_init(root="<旧根>", resume=true, force=true)` 显式改 owner 并保留 facts；`force` 不带 `resume` 会重建项目（旧 state 自动备份）。

## 10. 从 v1 迁移

```text
nuwa_init(migrate=true)
```

读取 `.sapper/project.json`、`facts/*.json`、`intents/*.json`：

- fact 重新编号为 `f001..`，保留 `[migrated:<oldid>]` 前缀与 `kind`（`host`→`asset`，未知→`note`）。
- intent 重新编号为 `i001..`，`from`/`to` 按映射重写，`done/complete`→`done`。
- 目标 URL 从 facts 的 JSON 文本里提取第一个 `http(s)://`；找不到用 `http://migrated.local:80`。
- 迁移事实没有 command/output；`nuwa_complete` 只按 kind 校验，迁移后建议补证据。

## 11. 安装与验收

```bash
./install.sh                 # 装 nuwa-omp + skill，退役 nuwa-loop，旧 CLI 改名 nuwa.legacy
./install.sh --keep-legacy   # 保留旧 CLI
./install.sh --rollback      # 恢复上一版扩展与 nuwa-loop
```

验收：

```bash
bun test tests/omp_nuwa.test.ts tests/omp_extension.test.ts
# 39 pass / 0 fail
```

手工冒烟（omp 会话内）：

```text
nuwa_init(target="http://127.0.0.1:8080", mode="ctf")
nuwa_status
nuwa_claim(id="i001")
nuwa_commit(id="i001", kind="service", title="HTTP 200", command="curl -sS -D - http://127.0.0.1:8080/", output="HTTP/1.1 200 OK\nServer: nginx")
nuwa_plan(phase="surface")
nuwa_report(write=false)
```

## 12. 配置

| 变量 | 默认 | 含义 |
|---|---|---|
| `NUWA_LOOP` | `1` | `0` 关闭 session_stop 续跑 |
| `NUWA_MAX_TURNS` | `200` | 单会话最大自动续跑轮数 |
| `NUWA_MAX_MINUTES` | `480` | 总时长上限 |
| `NUWA_MAX_TOKENS` | `4000000` | 上下文 tokens 上限（取峰值） |
| `NUWA_MAX_STALL` | `12` | 连续无有效推进上限 |
| `NUWA_MAX_IDLE` | `4` | 连续空转上限 |
| `NUWA_MAX_BATCH` | `4` | 单批派单上限 |
| `NUWA_CLAIM_TTL` | `900` | claim 过期秒数 |
| `NUWA_BLOCK_STREAK` | `4` | block 链长度，超过切 continue |
| `NUWA_KB_DB` | `/data/nuwa-kb/kb.db` | 知识库路径 |
| `NUWA_SCANNER_GUARD` | `1` | `0` 关闭 N-001 |
| `NUWA_REQUIRE_FUJIANG` | `1` | `0` 关闭 N-004 |
| `NUWA_PROJECT` | — | 显式项目根 |
| `PI_AGENT_HOME` | 自动 | agent home |

## 13. 与 v1 的差异 / 边界

- 不再有 `--detach` 后台模式：长跑由 omp 会话内的 `session_stop` 续跑承担；会话关闭即停。
  需要跨会话继续时，`nuwa_init(resume=true)` 从 `.nuwa/state.json` 接着跑。
- 不再有 Web 看板：`nuwa_status` 的 ASCII 表 + `nuwa_report` 的 Markdown 替代。
- 不再有 sapper 的 `view/validate`：状态一致性由 `saveState` 的原子写 + journal 回放保证。
- 知识库仍依赖外部 `kb.db`；缺失时 `nuwa_kb` 返回明确错误，其余工具不受影响。
- 迁移事实没有原始命令回显；对证据强度要求高的项目，迁移后应重新取证。
