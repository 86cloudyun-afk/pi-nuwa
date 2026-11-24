# pi-nuwa · 女娲模式 v3（omp 原生自治运行时）

把「长任务不会停、证据不造假、范围不越界、上下文可换血」做成 omp 会话内运行时 + 极薄外层无头守护器。

**女娲模式 v3 = 一套执行纪律（SKILL.md）+ 模块化 omp 原生运行时（9 个 TS 模块，12 个 `nuwa_*` 工具）+ 外层无头换血守护器（`bin/nuwa-autonomous`）。**
无需 Python、无需 `sapper`、无需 tmux/watchdog；支持安全评估（`ctf`/`pentest`/`audit`）与通用工程运维（`coding`/`ops`）五种领域模式。

## 为什么演进到 v3

- v1 靠 `bin/nuwa (bash) → nuwa/cli.py (Python) → sapper → omp-claude` 四层进程拼接，故障面大且难复现。
- v2 将状态机、续跑循环、确定性自渗透与可视化全部收进 omp 进程，实现了单会话内永动推进。
- **v3.0 在保留 12 个 `nuwa_*` 工具完全向后兼容的基础上，补齐了长程自治最关键的 6 块工程拼图**：
  1. **外层无头守护与跨世代自动换血（`bin/nuwa-autonomous` + `omp/reincarnate.ts`）**：单代上下文 token/轮次达阈值时自动精炼 ≤1500 字交接摘要并优雅放行，由外层守护进程以全新上下文自动拉起下一代，遇到 API 429/5xx 断流或崩溃按指数退避自动从磁盘续跑。
  2. **知识库自动富化与战略复盘规划（`omp/profiles.ts`）**：自动从 `service`/`endpoint`/`vuln` 提取技术栈与 CVE 查库派生核验意图；阶段将尽或连续 `stall >= 3` 时生成战略复盘意图引导 `nuwa_plan` 重规划。
  3. **真实执行账本防幻觉（`omp/evidence.ts`）**：记录 `tool_execution_end` 输出至 `.nuwa/exec-ledger.jsonl`，对 `flag`/`vuln`/`cred` 复验真实执行证据，杜绝口头编造结论。
  4. **靶标 Scope 护栏与防篡改（`omp/scope.ts`）**：新增 `N-007` 越界外链拦截、`N-008` 高危破坏命令拦截、增强 `N-003` `.nuwa/` 防篡改，支持 `/nuwa scope` 查看/调整。
  5. **武器库能力探针与自适配（`omp/evidence.ts`）**：初始化自动探测本地可用工具链，派单时对缺失工具自动附带本地合规替代指引。
  6. **多领域 Profile 解耦（`omp/profiles.ts`）**：`mode` 扩展为 `ctf` / `pentest` / `audit` / `coding` / `ops`，`coding`/`ops` 原生支持本地目录与服务标识目标。

## 组成

| 路径 | 作用 |
|---|---|
| `omp/nuwa.ts` | 主运行时入口（部署为 `index.ts`）：状态机、12 个 `nuwa_*` 工具、事件钩子、增量快照与容量治理 |
| `omp/types.ts` | 共享类型定义（由 `omp/nuwa.ts` 完整 re-export） |
| `omp/autoexec.ts` | 自渗透执行器：跨平台并发端口/HTTP/目录/TLS 探测、外置 `.nuwa/autoexec.json` 热更新、失败三分类、预算与取消 |
| `omp/scope.ts` | 靶标范围策略（`N-007`）、高危破坏拦截（`N-008`）与 `.nuwa/` 权威状态防篡改（`N-003`） |
| `omp/evidence.ts` | 真实执行账本（`.nuwa/exec-ledger.jsonl`）防幻觉复验与本地工具链探针自适配 |
| `omp/profiles.ts` | 5 种领域 Profile（`ctf`/`pentest`/`audit`/`coding`/`ops`）、技术栈提取与 KB 富化、战略复盘规划 |
| `omp/reincarnate.ts` | 会话世代轮转策略与 ≤1500 字交接摘要生成 |
| `omp/ui.ts` / `omp/ui-native.ts` | 三层可视化面（状态栏 / mini 看板 / `/nuwa board`）与 Tern 原生 TSP 节点降级层 |
| `bin/nuwa-autonomous` | 外层轻量无头守护器（支持跨世代换血、指数退避重试、Scope 透传、`--dry-run`） |
| `skills/nuwa-pentest/SKILL.md` | 执行纪律：触发词、每轮固定动作、Scope 与证据复验规范 |
| `install.sh` | 安装全部 9 个扩展模块 + skill + `nuwa-autonomous`，回显 `installed version = 3.0.0` |

## 安装

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
./install.sh                 # 安装到 ~/.omp/agent/extensions/nuwa-omp 与 ~/.local/bin/nuwa-autonomous
./install.sh --rollback      # 回滚扩展与 nuwa-loop
```

安装器支持环境变量 `PI_AGENT_HOME`（指定 agent 目录）与 `NUWA_BIN_DIR`（指定 `nuwa-autonomous` 安装目录）。
备份与退役目录写到 `$AGENT_HOME/backups/`，**绝不放在 `extensions/` 下**：omp 会把每个含 `index.ts` 的目录都当扩展加载，避免新旧两个 `session_stop` 同时抢跑。

依赖：omp ≥ 18.16.0，bun ≥ 1.1（用于运行 `nuwa-autonomous` 与测试）。`nuwa_kb` 额外需要 `sqlite3` 与 `/data/nuwa-kb/kb.db`，缺失时自动降级不影响其余工具。

## 使用

### 1. 交互式会话内开工

会话里说「女娲模式，打 http://TARGET:PORT」，或使用 `/nuwa` 命令：

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa board                  # 全屏只读面板（q/Esc 关闭）
/nuwa scope                  # 查看或调整当前项目的 Scope 范围策略
/nuwa status / log / why / stop / resume
```

或直接调用工具（支持五种领域模式）：

```text
nuwa_init(target="http://TARGET:PORT", mode="ctf", goal="打穿并拿 flag")
nuwa_init(target="/path/to/repo", mode="coding", goal="重构模块并跑通全量测试")
nuwa_init(target="svc://payments-api", mode="ops", goal="定位 5xx 峰值并验证恢复")
```

### 2. 长程无头守护（跨世代自动换血）

对于需要持续数小时的深度任务，推荐使用外层守护器：

```bash
nuwa-autonomous \
  --target http://TARGET:PORT \
  --mode pentest \
  --root ./work-target \
  --max-generations 20 \
  --max-hours 12 \
  --reincarnate-tokens 140000 \
  --reincarnate-turns 30 \
  --allow-subdomains \
  --allow-cidr 10.0.0.0/24

# 仅预检规划配置与首轮启动命令（零副作用）
nuwa-autonomous --target http://TARGET:PORT --dry-run
```

当单代会话上下文 token 或轮次到达阈值，`session_stop` 自动精炼交接摘要写入 `.nuwa/state.json` 并放行退出，守护器随即拉起全新上下文的第 N+1 代会话接力推进；若遇到 API 429/5xx 断流或子进程崩溃，自动按指数退避重启并从磁盘继续。任务验收完成退出码 `0`，人工停机退出码 `2`。

## 自渗透与自动富化

每轮 `session_stop` 扩展自动完成确定性侦察、结构化回灌与知识库富化，模型专注高价值判断：

- **跨平台自动批**：`recon:http` / `recon:ports`（`python3` 短超时并发探测，兼容 macOS/Linux）/ `recon:dirs` / `recon:tlsjs` / `surface:sensitive` / `surface:api`，E2+ 轮次 key（如 `e2:recon:http`）经 `canonicalAutoKey` 自动归一化。
- **外置规则热更新**：按 `<root>/.nuwa/autoexec.json` > `<agentHome>/nuwa-autoexec.json` > 内置加载，`mtimeMs` 缓存热更新无需重启扩展。
- **失败三分类**：`network` 错误释放回 `open` 并冷却重试（不烧 `attempts`），`blocked_by_waf` 标注拦截特征换路，`empty` 正常收口。
- **同轮回灌 + KB 富化**：自动批产出结构化 `meta`（端口/路径/SAN/指纹/WAF）后立即触发 `deriveFromFacts` 与 `deriveKbIntents`，无需等下一轮。
- **二维空转闸 + 预算取消**：区分无工具空转（`emptyRounds`）与有工具无产出（`suspectRounds=5`）；支持 90s 总预算与 `AbortSignal` 即时取消。

详见 [`docs/AUTOPILOT.md`](docs/AUTOPILOT.md)。

## 工具面（严格保持 12 个）

| 工具 | 作用 |
|---|---|
| `nuwa_init` | 建/恢复/迁移项目，探测工具链并初始化 Scope；支持 `mode` (`ctf/pentest/audit/coding/ops`)、`scope`、`autoStart` |
| `nuwa_plan` | 播种阶段或追加带 `from` 依赖链的自定义意图 |
| `nuwa_frontier` | 列 eligible 意图（依赖满足、冷却到期、未有效认领） |
| `nuwa_claim` | 认领并返回经武器库能力自适配的完整 packet |
| `nuwa_commit` | 提交结果生成 fact；对 `vuln`/`cred`/`flag` 走执行账本复验；幂等；可 blocked 收口 |
| `nuwa_flag` | 立即入账 flag；要求 output 含完整值且通过真实执行账本核验 |
| `nuwa_complete` | 完成验收；按 Profile 的 `proofKinds` 校验证据（`ctf`: flag、`audit`: vuln/loot、`pentest`: vuln/loot/flag、`coding`/`ops`: loot/note） |
| `nuwa_status` | ASCII 看板（含 `state=xxKB`、`rules=<source>`、`net-retry=<n>`、`gen=<g>`） |
| `nuwa_report` | Markdown 报告，可写 `.nuwa/REPORT.md` |
| `nuwa_expand` | 强制扩张攻击面（live → 复盘 → 补播 → 事实+KB 派生 → 推进 → 新 episode → 兜底） |
| `nuwa_stop` | 人工停机并中止在途自动批；永动模式需 `confirm="STOP"` |
| `nuwa_kb` | 本地知识库只读查询（产品卡/CVE/PoC/ATT&CK） |

## 纪律与安全护栏（N-001..N-008）

| 规则 | 拦截 |
|---|---|
| N-001 | 主线程直接跑扫描工具 → 必须走 fujiang 子代理（`NUWA_SCANNER_GUARD=0` 可动态放行） |
| N-002 | `bin/nuwa` / `nuwa/cli.py` / `nuwa dispatch` → v1 CLI 已退役 |
| N-003 | 写入、重定向、`rm`/`mv`/`cp`/`sed -i`/`truncate` 或脚本篡改 `.nuwa/` 权威状态文件 |
| N-004 | `task` / `eval agent()` 未使用 `agent:"fujiang"` |
| N-005 | 子代理调用记账类 `nuwa_*` 工具 |
| N-006 | `task` 传入 `tools` 字段导致子代理内建工具表被清空 |
| N-007 | bash 命令访问授权 Scope 之外的主机、域名或网段 |
| N-008 | 未启用 `allowDestructive` 时执行 `rm -rf`/`mkfs`/`dd if=`/`shutdown`/`reboot`/`DROP TABLE`/`TRUNCATE` 等破坏性命令 |

## 可视化

三层常驻可视面（状态栏 / mini 看板 / `/nuwa board`），Tern 下通过 `describe(cx)` 返回手写 TSP 原生节点并按 `cx.supports()` 逐项降级，零外部依赖。完整降级与 40 列窄宽度验证矩阵见 [`docs/UI-DESIGN.md`](docs/UI-DESIGN.md)。

## 常用配置

| 变量 | 默认 | 含义 |
|---|---|---|
| `NUWA_LOOP` | `1` | `0` 关闭 `session_stop` 续跑 |
| `NUWA_INFINITE` | `1` | `1` 永动模式（预算仅降档不停机）；`0` 启用旧预算硬闸 |
| `NUWA_HEADLESS_DAEMON` | `0` | `1` 开启世代轮转放行（由 `nuwa-autonomous` 自动注入） |
| `NUWA_REINCARNATE_TOKENS` | `140000` | 单代换血上下文 token 阈值 |
| `NUWA_REINCARNATE_TURNS` | `30` | 单代换血轮次阈值 |
| `NUWA_STRICT_EVIDENCE` | `1` | `1` 启用执行账本证据复验；`0` 关闭 |
| `NUWA_SCOPE_ALLOW_SUBDOMAINS` | `0` | `1` 允许目标主域子域名 |
| `NUWA_SCOPE_ALLOW_CIDRS` | — | 额外放行 IPv4 CIDR 列表（逗号分隔） |
| `NUWA_AUTO` / `NUWA_AUTO_MAX` | `1` / `3` | 自动批开关与每轮并发上限 |
| `NUWA_AUTO_BUDGET_MS` | `90000` | 单批自动执行总时间预算（ms） |
| `NUWA_AUTO_CONCURRENCY` | `1` | 自动批并发度（`recon:ports` 始终独占） |
| `NUWA_EMPTY_LIMIT` | `3` | 无工具空转收口阈值（有工具疑似空转默认 5 轮） |
| `NUWA_MAX_ATTEMPTS` | `3` | 单意图尝试上限（网络失败重试不计入） |
| `NUWA_SCANNER_GUARD` | `1` | `0` 关闭 N-001 |
| `NUWA_REQUIRE_FUJIANG` | `1` | `0` 关闭 N-004 |
| `NUWA_KB_DB` | `/data/nuwa-kb/kb.db` | 本地只读知识库路径 |

## 测试

```bash
# 运行全部 TS 隔离测试（含 v3 核心、Scope/证据、自渗透、Profile/守护器、UI 矩阵）
./run-tests.sh

# 运行 v2/v3 快速门禁（版本一致性 + 无 sapper 契约 + 全量 TS + shell + kb）
./tests/run.sh --v2-only

# 运行完整回归套件（含 v1 兼容测试，缺真实 sapper 时自动 SKIP）
./tests/run.sh
```

更多架构细节见 [`docs/OMP-NATIVE.md`](docs/OMP-NATIVE.md)、[`docs/AUTOPILOT.md`](docs/AUTOPILOT.md) 与 [`docs/UI-DESIGN.md`](docs/UI-DESIGN.md)。
