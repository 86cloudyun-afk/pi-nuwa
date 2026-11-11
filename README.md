# pi-nuwa · 女娲模式 v2（omp 原生）

把「长任务不会停」做成 omp 会话内的运行时，而不是外部 CLI 循环。

**女娲模式 = 一套渗透纪律（SKILL.md）+ 一个运行时状态机（nuwa-omp 扩展）+ 11 个 `nuwa_*` 工具。**
没有 `bin/nuwa`，没有 Python，没有 sapper，没有 tmux/watchdog。

## 为什么 v1 要退役

v1 靠 `bin/nuwa (bash) → nuwa/cli.py (Python) → sapper → omp-claude` 四层进程拼接。
flock、journal 代际、sapper 图写入、引擎 stdout 解析，任何一层抖动都会让循环停住，而且现场难复现。
v2 把这些全部收进 omp 进程：状态在 `.nuwa/state.json`，循环在 `session_stop`，执行在 `task(agent="fujiang")`。

## 组成

| 路径 | 作用 |
|---|---|
| `omp/nuwa.ts` | 运行时：状态机、账本、证据闸门、session_stop 续跑、tool_call 纪律 |
| `skills/nuwa-pentest/SKILL.md` | 渗透纪律：触发词、每轮固定动作、证据规范 |
| `install.sh` | 安装扩展 + skill；退役 nuwa-loop；旧 CLI 改名 `nuwa.legacy` |
| `docs/OMP-NATIVE.md` | 架构、状态模型、工具参考、续跑算法、迁移、验收 |
| `tests/omp_nuwa.test.ts` | 纯状态机单测（34 例） |
| `tests/omp_extension.test.ts` | 扩展注册 / 生命周期 / 拦截 / 续跑集成测试 |

## 安装

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
./install.sh                 # 装到 ~/.omp/agent/extensions/nuwa-omp
./install.sh --rollback      # 回滚扩展与 nuwa-loop
```

依赖：omp ≥ 18.16.0。`nuwa_kb` 额外需要 `sqlite3` 与 `/data/nuwa-kb/kb.db`，缺失不影响其余工具。

## 使用

会话里说「女娲模式，打 http://TARGET:PORT」，或直接：

```text
nuwa_init(target="http://TARGET:PORT", mode="ctf", goal="打穿并拿 flag")
```

之后运行时自动推进：

```text
nuwa_status                     # 看板
nuwa_frontier(limit=4)          # 本批可执行意图
nuwa_claim(id="i001")           # 取 packet
task({tasks:[{agent:"fujiang", name:"I001", task:"<packet>", solutionSpace:"one intent"}]})
nuwa_commit(id="i001", kind="service", title="HTTP 200 nginx",
            command="curl -k -sS -D - http://TARGET/",
            output="HTTP/1.1 200 OK\nServer: nginx")
nuwa_flag(value="flag{...}", command="...", output="...")
nuwa_complete(from=["f012"])
nuwa_report(write=true)
```

每轮结束 `session_stop` 会检查 frontier、预算与证据，返回 `decision:"block"` 注入下一批派单。
不需要手动「继续」，也不允许一轮就收工。

## 工具

| 工具 | 作用 |
|---|---|
| `nuwa_init` | 建/恢复/迁移项目；播种 recon |
| `nuwa_plan` | 播种阶段（recon/surface/vuln/exploit/post/report）或自定义意图 |
| `nuwa_frontier` | 列 eligible 意图（依赖满足、未有效认领） |
| `nuwa_claim` | 认领并返回完整 packet（目标/事实/命令/输出契约） |
| `nuwa_commit` | 提交结果，生成 fact；幂等；可 blocked 收口 |
| `nuwa_flag` | 立即入账 flag；output 必须含完整值 |
| `nuwa_complete` | 完成验收；ctf 需 flag，pentest 需 vuln/loot/flag |
| `nuwa_status` | ASCII 看板 |
| `nuwa_report` | Markdown 报告，可写 `.nuwa/REPORT.md` |
| `nuwa_stop` | 主动停机 |
| `nuwa_kb` | 本地知识库（产品卡/CVE/PoC/ATT&CK） |

## 证据闸门

- 非 `note` 事实必须带 `command` + `output`；`echo/printf` 不算证据。
- `flag` 的 `output` 必须包含完整 flag 值。
- `commit` 按 `(project,intent,attempt,kind,title)` 幂等；`flag` 按 value 哈希幂等。
- `nuwa_complete` 没有 `flag`（ctf）或 `vuln/loot`（pentest）时直接拒绝，并计入 `rejects`。

## 阶段

六阶段、32 条内置意图：

```
recon(6) → surface(6) → vuln(10) → exploit(5) → post(3) → report(2)
```

当前阶段全部 `done/blocked` 时自动切下一阶段并播种；也可 `nuwa_plan(phase="surface")` 手动提前。
细节见 `docs/OMP-NATIVE.md` 第 7 节。

## 纪律拦截

| 规则 | 拦截 |
|---|---|
| N-001 | 主线程直接跑 nmap/ffuf/nuclei/sqlmap 等 → 必须走 fujiang 子代理 |
| N-002 | `bin/nuwa` / `nuwa/cli.py` / `nuwa dispatch` → CLI 已退役 |
| N-003 | 写 `.nuwa/state.json`、`journal*.jsonl`、`state.lock` → 只允许 `nuwa_*` |
| N-004 | `task` 的 agent 不是 `fujiang` → 统一 fujiang |
| N-005 | 子会话调用记账类 `nuwa_*` → 只有主线程能记账 |

## 配置

| 变量 | 默认 | 含义 |
|---|---|---|
| `NUWA_LOOP` | `1` | `0` 关闭续跑 |
| `NUWA_MAX_TURNS` | `200` | 最大续跑轮数 |
| `NUWA_MAX_MINUTES` | `480` | 总时长 |
| `NUWA_MAX_TOKENS` | `4000000` | 上下文 tokens 上限 |
| `NUWA_MAX_STALL` | `12` | 连续无推进上限 |
| `NUWA_MAX_IDLE` | `4` | 连续空转上限 |
| `NUWA_MAX_BATCH` | `4` | 单批派单上限 |
| `NUWA_CLAIM_TTL` | `900` | claim 过期秒数 |
| `NUWA_KB_DB` | `/data/nuwa-kb/kb.db` | 知识库 |
| `NUWA_SCANNER_GUARD` | `1` | `0` 关闭 N-001 |
| `NUWA_REQUIRE_FUJIANG` | `1` | `0` 关闭 N-004 |

## 从 v1 迁移

```text
nuwa_init(migrate=true)
```

读取同目录 `.sapper/`，事实/意图重新编号并保留引用，`host`→`asset`，`done/complete`→`done`。
迁移事实没有原始命令回显，建议对关键节点重新取证。

## 测试

```bash
bun test tests/omp_nuwa.test.ts tests/omp_extension.test.ts
# 39 pass / 0 fail / 120 expect()
```

覆盖：目标规范化、playbook 播种与去重、frontier 排序、claim/重领、证据拒绝、幂等、阶段推进、
flag 闸门、完成闸门、directive、N-001..N-005、扩展注册、完整生命周期、session_stop 续跑、停机。

## 旧代码

`bin/nuwa`、`nuwa/*.py`、`extensions/nuwa-loop` 保留在仓库里作为 v1 参考与回滚路径，但不再安装。
`./install.sh` 会把已安装的 `nuwa-loop` 移到 `nuwa-loop.retired-*`，避免与新运行时抢 `session_stop`。

细节见 [`docs/OMP-NATIVE.md`](docs/OMP-NATIVE.md)。
