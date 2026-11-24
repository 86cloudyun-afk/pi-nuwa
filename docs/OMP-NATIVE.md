# 女娲 v3：omp 原生自治运行时架构

## 1. 架构演进：从 v1 到 v3

- **v1**：`bin/nuwa (bash) → nuwa/cli.py (Python) → sapper CLI → 子进程`，四层进程边界易碎难复现。
- **v2**：彻底移除 Python 与 `sapper`，把状态机（`.nuwa/state.json`）、续跑循环（`session_stop`）、确定性自动批与可视化收进 omp 扩展进程。
- **v3.0**：保持单进程 12 工具面 100% 向后兼容，新增外层极薄无头守护器 `bin/nuwa-autonomous` 实现跨世代自动换血，并将运行时拆分为 9 个职责清晰的模块：

| 模块 | 部署位置 | 核心职责 |
|---|---|---|
| `omp/nuwa.ts` | `$EXT_DIR/index.ts` | 主状态机、12 个 `nuwa_*` 工具、`/nuwa` 命令、事件钩子、增量快照与容量治理 |
| `omp/types.ts` | `$EXT_DIR/types.ts` | 公共类型定义（由 `nuwa.ts` 全量 re-export，避免子模块循环依赖） |
| `omp/autoexec.ts` | `$EXT_DIR/autoexec.ts` | 跨平台确定性自动批、E2+ key 归一化、外置 JSON 规则热更新、失败三分类、预算与取消 |
| `omp/scope.ts` | `$EXT_DIR/scope.ts` | 靶标范围策略（`N-007`）、高危破坏命令拦截（`N-008`）、`.nuwa/` 权威状态防篡改（`N-003`） |
| `omp/evidence.ts` | `$EXT_DIR/evidence.ts` | 真实执行账本（`.nuwa/exec-ledger.jsonl`）防幻觉复验、本地武器库探针与指令自适配 |
| `omp/profiles.ts` | `$EXT_DIR/profiles.ts` | 5 种领域 Profile（`ctf`/`pentest`/`audit`/`coding`/`ops`）、技术栈提取与 KB 富化、战略复盘规划 |
| `omp/reincarnate.ts` | `$EXT_DIR/reincarnate.ts` | 无头世代轮转判定与 ≤1500 字交接摘要生成 |
| `omp/ui.ts` | `$EXT_DIR/ui.ts` | 纯函数状态快照与 ANSI 渲染（状态栏 / mini 看板 / board） |
| `omp/ui-native.ts` | `$EXT_DIR/ui-native.ts` | Tern 原生 TSP 节点渲染与 `cx.supports()` 逐项降级 |
| `bin/nuwa-autonomous` | `~/.local/bin/nuwa-autonomous` | 外层无头守护器：跨世代拉起全新 omp 会话、API 断流指数退避续跑 |

## 2. 运行架构

```text
┌─────────────────── 外层无头守护器 bin/nuwa-autonomous（可选）───────────────────┐
│  注入 NUWA_HEADLESS_DAEMON=1 / NUWA_REINCARNATE_* / NUWA_SCOPE_*                │
│  读 .nuwa/state.json：completed→exit 0｜stopped→exit 2｜handoff→拉起第 G+1 代    │
│  子进程崩溃/429/5xx → 指数退避重启并从磁盘续跑                                   │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        ▼
┌──────────────────────────── omp session (main) ─────────────────────────────────┐
│  /nuwa <任务> 或 nuwa_init ──► probeToolchain + defaultScopeForTarget           │
│      │                        ──► .nuwa/state.json (原子写 + 增量 .json.gz)     │
│      ▼                                                                          │
│  nuwa_claim(iNNN) ──► adaptPacketForToolchain ──► task(agent="fujiang")         │
│      │                                                                          │
│      ▼                                                                          │
│  tool_call 纪律拦截 (N-001..N-008)  &  tool_execution_end ──► exec-ledger.jsonl │
│      │                                                                          │
│      ▼                                                                          │
│  nuwa_commit / nuwa_flag ──► verifyExecutionEvidence ──► fact fNNN              │
│      │                                                                          │
│      ▼                                                                          │
│  session_stop ──► shouldReincarnate? ──(是)──► prepareNextGeneration & 放行换代  │
│      │                │(否)                                                     │
│      │                ├─ applyEmptyGuard（二维空转闸：emptyRounds/suspectRounds） │
│      │                ├─ autoPlan（reflect → 补播 → derive + KB富化 → 推进/E+1） │
│      │                ├─ claimAutoBatch + runAutoBatchManaged（预算/取消/回灌）   │
│      │                └─ 返回 decision:"block" 注入下一批 directive              │
│      ▼                                                                          │
│  nuwa_complete (按 Profile proofKinds 验收) → nuwa_report(write=true)           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 3. 状态模型与容量治理（Issue #8）

`.nuwa/state.json` 在 v2 基础上向后兼容扩展了以下关键字段：

- `project.scope`：`ScopePolicy`（`allowHosts`, `allowCidrs`, `denyHosts`, `allowSubdomains`, `allowPrivateNetwork`, `allowDestructive`）
- `project.toolchain`：`ToolchainCaps`（本地 `available` / `missing` 工具列表与探测时间）
- `facts[*].meta`：`AutoFactMeta`（结构化 `ports`/`paths`/`server`/`tech`/`status`/`san`/`waf`）与 `facts[*].verified`（执行账本核验标记）
- `intents[*].nextRunAt`：自动批遇到 `network` 失败时的冷却截止时间戳（ms）
- `runtime.generation` / `runtime.genTurns` / `runtime.handoffSummary`：世代轮转状态与交接摘要
- `runtime.suspectRounds`：二维空转闸的有工具无产出计数
- `runtime.netRetries` / `runtime.saveCount` / `runtime.stateBytes` / `runtime.rulesSource`：可观测运行指标

容量治理机制：
- `compactFacts(st)`：保留近期 200 条未被引用的 `note` 并按幂等键去重，高价值证据与被引用的事实永不裁剪；
- `compactIntents(st)`：回收过量 `blocked` 意图（默认保留最近 120 条）；
- **增量快照策略**：`saveState` 改为每 10 次写盘或关键节点（`init`/`flag`/`complete`/`stop`/`reincarnate`）才写全量 `.json.gz` 快照，普通写盘仅原子刷新 `state.json`；
- **体积告警**：监测 `state.json` 超过 2MB 时写入日志告警，`nuwa_status` 看板实时展示 `state=xxKB`、`rules=<source>`、`net-retry=<n>`、`gen=<g>`。

## 4. 多领域 Profile 引擎（升级 6）

`omp/profiles.ts` 将领域策略与核心状态机解耦，支持 5 种模式：

| `mode` | 标签 | `requireHttpTarget` | 完成验收 `proofKinds` | 适用场景 |
|---|---|---|---|---|
| `ctf` | CTF 靶场取证 | `true` | `["flag"]` | CTF 靶机与 flag 验证 |
| `pentest` | 渗透测试与安全评估 | `true` | `["vuln", "loot", "flag"]` | 授权渗透与证据链评估 |
| `audit` | 代码与配置安全审计 | `true` | `["vuln", "loot"]` | 源码/配置安全审计 |
| `coding` | 软件工程自治开发 | `false` | `["loot", "note"]` | 本地代码库重构、功能实现与测试验证 |
| `ops` | 自动化运维与排障 | `false` | `["loot", "note"]` | 服务巡检、日志聚类、根因定位与恢复验收 |

所有模式统一复用 6 阶段状态机（`recon` → `surface` → `vuln` → `exploit` → `post` → `report`），由各自 Profile 提供对应领域的内置种子清单。

## 5. `/nuwa` 命令与 12 工具面

```text
/nuwa <自然语言任务>         # 抽目标与模式 → init/resume → 自动批 + 起跑
/nuwa                        # ASCII 看板
/nuwa board                  # 全屏覆盖层只读面板（q/Esc 关闭）
/nuwa scope [动作]           # 查看或调整当前项目 Scope 范围策略
/nuwa log [n]                # journal 末 n 行
/nuwa why                    # 上一条续跑 directive
/nuwa stop [原因]            # 停机并立即中止在途自动批
/nuwa resume                 # 复活并立即起跑
```

12 个工具严格保持名称与向后兼容（`tools.size === 12`）：

| 工具 | v3.0 增强说明 |
|---|---|
| `nuwa_init` | 新增 `mode` 支持 `coding`/`ops`、新增可选参数 `scope` 与 `autoStart`；初始化时调用 `probeToolchain` 与 `defaultScopeForTarget`（支持 `NUWA_SCOPE_ALLOW_SUBDOMAINS`/`NUWA_SCOPE_ALLOW_CIDRS`）；仅在 `/nuwa <任务>` 或显式 `autoStart: true` / `NUWA_AUTO_ON_INIT=1` 时立即跑自动批，避免抢跑破坏手动 `claim` |
| `nuwa_plan` | 播种阶段或追加带 `from` 依赖链的自定义意图（复盘意图 `reflect:*` 的核心落盘入口） |
| `nuwa_frontier` | 返回 eligible 意图（依赖满足、未有效认领且不在网络冷却期） |
| `nuwa_claim` | 认领并返回 packet，通过 `adaptPacketForToolchain` 对缺失工具追加本地可用替代提示 |
| `nuwa_commit` | 支持 `meta` / `verified`；对 `vuln`/`cred`/`flag` 调用 `verifyExecutionEvidence` 复验真实执行账本 |
| `nuwa_flag` | 除要求 `output` 含完整 flag 外，同步调用 `verifyExecutionEvidence` 核验该值真实出现在近期执行流或 `/tmp/nuwa/<id>/` 产物中 |
| `nuwa_complete` | 按 `getProfile(mode).proofKinds` 验收 |
| `nuwa_status` | 展示阶段表、预算、frontier 及 `state=xxKB`、`rules=<source>`、`net-retry=<n>`、`gen=<g>` |
| `nuwa_report` | 生成 Markdown 报告，可落盘 `.nuwa/REPORT.md` |
| `nuwa_expand` | 强制扩张攻击面（集成复盘、事实派生与 KB 自动富化） |
| `nuwa_stop` | 人工停机并立即 `abort()` 在途自动批；永动模式需 `confirm="STOP"` |
| `nuwa_kb` | 只读查询本地 sqlite3 知识库（产品卡/CVE/PoC/ATT&CK） |

## 6. 纪律拦截与靶标 Scope 护栏（N-001..N-008）

| 规则 | 触发条件 | 拦截行为 |
|---|---|---|
| N-001 | 主会话 bash 跑扫描工具 | 要求改派 `fujiang` 子代理；动态读取 `NUWA_SCANNER_GUARD=0` 可放行 |
| N-002 | 调用退役的 `bin/nuwa` / `nuwa/cli.py` / `nuwa dispatch...` | 要求改用 `nuwa_*` 工具 |
| N-003 | 写工具、重定向或 bash 的 `rm`/`mv`/`cp`/`sed -i`/`truncate`/脚本篡改 `.nuwa/` 下 `state.json`、`journal`、`snap`、`state.lock` | 权威状态只允许 `nuwa_*` 写入 |
| N-004 | `task` 或 `eval agent()` 未指定 `agent:"fujiang"` | 统一执行代理（`NUWA_REQUIRE_FUJIANG=0` 可关） |
| N-005 | 子会话调用写类 `nuwa_*` 工具 | 仅主线程记账 |
| N-006 | `task` 携带 `tools` 字段 | 防止清空子代理内建工具表 |
| N-007 | bash 命令访问超出项目 `ScopePolicy` 的主机/域名/IP（`omp/scope.ts`） | 拦截越界目标；黑名单优先，支持精确主机、`*.domain`、IPv4 CIDR 掩码与回环策略 |
| N-008 | 非 `allowDestructive` 模式下执行 `rm -rf`/`mkfs`/`dd if=`/`shutdown`/`reboot`/`DROP TABLE`/`TRUNCATE` 等破坏性命令 | 阻止高危不可逆破坏 |

## 7. 真实执行账本与工具链探针（升级 3 & 5）

- **执行账本（`omp/evidence.ts`）**：每次 `tool_execution_end` 将工具输出记录至内存环形缓冲并追加到 `<root>/.nuwa/exec-ledger.jsonl`（滚动保留最近 200 条摘要及 SHA1）。
- **防幻觉复验**：`nuwa_flag` 与 `nuwa_commit(kind="vuln"|"cred"|"flag")` 调用 `verifyExecutionEvidence` 校验关键回显行或 flag 值是否真实出现在近期执行账本或 `/tmp/nuwa/<projectId>/` 产物中。若 `NUWA_STRICT_EVIDENCE=0` 直接放行；否则当开启严格模式或项目已有真实执行历史时，对凭空编造的 flag 直接拒绝入账。
- **武器库探针**：`probeToolchain` 检测本地 `curl`/`openssl`/`nmap`/`ffuf`/`nuclei`/`sqlmap`/`whatweb`/`hydra`/`python3`/`nc`/`sqlite3` 可用性；`adaptPacketForToolchain` 在派单 packet 中对缺失工具自动附带本地可用替代方案。

## 8. KB 自动富化与战略复盘（升级 2）

- **KB 自动富化**：`extractTechKeywords` 从 `service`/`endpoint`/`vuln` 中识别主流组件（`nginx`/`apache`/`tomcat`/`php`/`spring`/`fastjson`/`thinkphp`/`shiro`/`redis`/`mysql`/`postgres`/`grafana`/`gitlab`/`jenkins`/`wordpress`/`graphql`/`swagger` 等）及 `CVE-YYYY-NNNN`；`deriveKbIntents` 在 `try/catch` 中查库（缺库静默返回空数组），对有效命中派生 `key=kb:<fid>:<slug>`（`phase="vuln"`, `priority=86`, `from=[fact.id]`），按 key 严格去重。
- **战略复盘**：`autoPlan` 在阶段将尽或连续 `stall >= 3` 时调用 `buildReflectIntentSpec`，按 `reflect:e<ep>:<phase>:<bucket>` 去重生成战略复盘意图，要求模型综合已有事实与阻塞经验调用 `nuwa_plan(intents=[...])` 构建带 `from` 依赖链的新假设。

## 9. 无头守护与跨世代轮转（升级 1）

长程任务容易因单会话上下文窗口膨胀导致推理退化或被 API 限流断流。v3.0 采用「内层优雅换代 + 外层极薄守护」解耦：

1. 外层运行 `bin/nuwa-autonomous`，自动注入 `NUWA_HEADLESS_DAEMON=1`、`NUWA_REINCARNATE_TOKENS`（默认 140000）、`NUWA_REINCARNATE_TURNS`（默认 30）、`NUWA_STRICT_EVIDENCE=1`、`NUWA_LOOP=1`、`NUWA_INFINITE=1`、`NUWA_PROJECT=<root>` 以及 Scope 环境变量。
2. 会话内 `session_stop` 调用 `shouldReincarnate(st, policy)`：当 `tokens >= maxTokens` 或本代轮次 `genTurns >= maxTurns` 时，立即中止并释放正在运行的自动批，调用 `prepareNextGeneration` 递增 `generation`、写入 ≤1500 字 `handoffSummary`、清零 `genTurns`/`tokens` 与 `lastSig`，记录 `reincarnate` 事件并**返回 `undefined` 放行会话退出**。
3. 外层 `bin/nuwa-autonomous` 检测到进程退出后重读 `.nuwa/state.json`：
   - `status === "completed"` → 打印完成摘要与报告路径，退出码 `0`；
   - `status === "stopped"`（非换代标记）→ 打印停机原因，退出码 `2`；
   - 存在 `runtime.handoffSummary` 或仍为 `active` → 携带交接摘要构造干净起跑 Prompt 拉起下一代 `omp -p --cwd <root> ... -- <prompt>`；
   - 子进程非零退出（API 429/5xx 断流或崩溃）→ 按指数退避（测试可通过 `NUWA_DAEMON_BACKOFF_MS` 调小）重试并从磁盘接力。

## 10. 多会话并发、看门狗与崩溃恢复

- `armPump` 改用 `Map<string, ExtensionContext>` 按 `sessionId` 多会话隔离，`session_shutdown` 在无活跃会话时停止定时器清理资源；
- 所有状态写操作严格在 `withLock` 内读取并回写最新磁盘快照，避免并发写丢失；
- 崩溃恢复依次从 `.nuwa/state.json` → `journal*.jsonl` → `.nuwa/snap/*.json.gz` 回放恢复。

## 11. 配置一览

| 变量 | 默认 | 含义 |
|---|---|---|
| `NUWA_LOOP` | `1` | `0` 关闭 `session_stop` 续跑 |
| `NUWA_INFINITE` | `1` | `1` 永动模式（预算仅降档）；`0` 回到旧预算硬闸 |
| `NUWA_HEADLESS_DAEMON` | `0` | `1` 启用跨世代轮转放行 |
| `NUWA_REINCARNATE_TOKENS` | `140000` | 单代换血上下文 token 阈值 |
| `NUWA_REINCARNATE_TURNS` | `30` | 单代换血轮次阈值 |
| `NUWA_STRICT_EVIDENCE` | `1` | `1` 开启执行账本证据复验；`0` 关闭 |
| `NUWA_SCOPE_ALLOW_SUBDOMAINS` | `0` | `1` 放行目标主域子域名 |
| `NUWA_SCOPE_ALLOW_CIDRS` | — | 额外放行 IPv4 CIDR（逗号分隔） |
| `NUWA_AUTO` / `NUWA_AUTO_MAX` | `1` / `3` | 自动批开关与单轮上限 |
| `NUWA_AUTO_BUDGET_MS` | `90000` | 单批自动执行总预算（ms） |
| `NUWA_AUTO_CONCURRENCY` | `1` | 自动批并发度（`recon:ports` 始终独占） |
| `NUWA_AUTO_ON_INIT` | `0` | `1` 允许 `nuwa_init` 立即执行首轮自动批 |
| `NUWA_EMPTY_LIMIT` / `NUWA_SUSPECT_LIMIT` | `3` / `5` | 二维空转硬闸阈值 |
| `NUWA_MAX_ATTEMPTS` | `3` | 单意图尝试上限（网络失败不消耗） |
| `NUWA_MAX_BATCH` / `NUWA_CLAIM_TTL` | `4` / `900` | 单批派单上限 / claim 过期秒数 |
| `NUWA_TICK_MS` | `60000` | 看门狗心跳（ms） |
| `NUWA_EXPAND_DEPTH` / `NUWA_MAX_EPISODES` | `24` / `0` | 单轮扩张上限 / 扩张轮次上限（0=无限） |
| `NUWA_KB_DB` | `/data/nuwa-kb/kb.db` | 本地知识库路径 |
| `NUWA_SCANNER_GUARD` / `NUWA_REQUIRE_FUJIANG` | `1` / `1` | N-001 / N-004 开关 |
| `NUWA_UI` / `NUWA_UI_NATIVE` / `NUWA_UI_WIDGET` / `NUWA_UI_LINES` | `1`/`1`/`1`/`3` | 可视化开关与看板行数 |
| `NUWA_PROJECT` / `PI_AGENT_HOME` / `NUWA_BIN_DIR` | 自动 | 显式项目根 / agent home / 守护器安装目录 |
| `NUWA_DAEMON_BACKOFF_MS` / `NUWA_DAEMON_MAX_ERRORS` | `2000` / `5` | 守护器异常重试退避基数（ms）与连续错误上限 |
