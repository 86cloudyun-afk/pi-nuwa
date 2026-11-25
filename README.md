# pi-nuwa · 女娲模式 v5.0（全自主安全评估与多领域原生引擎）

把「长任务不会停、证据不造假、范围不越界、认证态自动鉴权差分、漏洞双盲复验与证伪剪枝、经验跨项目自进化、零信任 Sidecar/Egress Proxy 隔离、SARIF 合规证据包与离线基准回归」做成纯 `omp` 原生扩展运行时 + 外层无头守护器。

**女娲模式 v5.0 = 执行纪律（`SKILL.md`）+ 模块化 `omp` 原生运行时（22 个 TS 文件，12 个 `nuwa_*` 工具）+ 随仓便携 SQLite FTS5 知识库（`kb/`）+ 合规双子代理（`fujiang` + `nuwa-verifier`）+ 10 场景离线评测靶场（`benchmarks/`）+ 外层无头守护器（`bin/nuwa-autonomous`）。**
无需外部 `sapper`、无需 `sqlite3` CLI、无需外置私有资产库；支持安全评估（`ctf`/`pentest`/Web 及本地白盒 `audit`）与通用工程运维（`coding`/`ops`）五种领域模式。

## v5.0 核心能力演进

在严格维持 12 个 `nuwa_*` 工具 100% 向后兼容的基础上，v5.0 完成了从工程化底座到自治评估闭环的全面跃升：

1. **认证态攻击面闭环（`omp/session-vault.ts` + `omp/browser-recon.ts` + `omp/auth-diff.ts` + `omp/autoexec.ts`）**：支持 JWT 过期解析、CSRF Cookie 镜像头与 `/nuwa session health` 过期巡检自动派生刷新意图；支持认证态 SPA 懒加载 Chunk 与同源 `.js.map` 隐藏接口提取；内置只读多角色鉴权差分矩阵（`/nuwa authdiff`，确定性识别 `unauth_access` / `vertical_bfla` / `horizontal_bola` 并自动过滤 Soft-404 兜底页）；`nuwa_commit(kind="cred")` 自动派生认证态深挖并支持零明文头文件自动批执行。
2. **零信任常驻 Sidecar、抗 DNS 重绑定 Egress Proxy 与一等 OOB 通道（`omp/sandbox.ts` + `omp/oob.ts` + `docker/Dockerfile.sandbox`）**：支持 `NUWA_SANDBOX=sidecar` 持久只读隔离容器（`N-009`）；内置零依赖 Scoped Egress Proxy（HTTP 正向代理 + HTTPS `CONNECT` 隧道 + 防 DNS 重绑定至云元数据/私网 + 越界 `30x` 拦截）；多阶段 `base`/`lite`/`full` 无 root 沙盒镜像；受 `scope.oobDomains` 白名单门控的一等 OOB Canary 通道（`/nuwa oob`）。
3. **多资产跳板拓扑、跨事实假设图推理与领域 Profile 解耦（`omp/hypothesis.ts` + `omp/profiles.ts`）**：维护主目标、SAN 子域、内网跳板主机与本地代码仓拓扑（`/nuwa assets`）；按 5 类跨事实推理链及收益/成本/置信度评分自动派生高价值假设；双盲驳回前置事实时自动级联失效假设并剪枝未执行 `open` 意图；`audit` 原生支持本地白盒代码目录，且 `coding`/`ops`/本地 `audit` 彻底隔离 Web 扫描器逻辑。
4. **结构化合规导出、离线确定性评测靶场与成本治理（`omp/reporting.ts` + `benchmarks/` + `bin/nuwa-autonomous`）**：`nuwa_report` 与 `/nuwa report` 支持分层 Markdown、JSON、仅含已确认漏洞的 SARIF 2.1.0，以及 `0o700/0o600` 含 SHA-256 `manifest.json` 的脱敏审计证据包（`.nuwa/poc-bundle/`）；内置 10 场景离线评测靶场（`bun benchmarks/run-eval.ts --deterministic`）；守护器新增 `--max-total-tokens`、`--max-usd`（退出码 `3`）、单代/空闲看门狗与脱敏重试 Webhook/死信队列。
5. **双盲复验、纯净账本、自进化 KB 与精准路由（v4.1 加固基线）**：`verify-vuln:<fid>` 强验 `kind="vuln"` 与水位递增实锤执行记录；账本高熵校验 + 专属并发锁 + 自动 Vault 脱敏；经验蒸馏按意图精准归因技术栈 + 90 天半衰期衰减 + 失败避坑回流；按派单精准路由 `fast`/`deep`/`verify` 模型；Scope 护栏区分连接目标与请求载荷并支持 `allowLoopback` / `oobDomains` 策略。

## 模块组成

| 路径 | 职责 |
|---|---|
| `omp/nuwa.ts` | 组装入口（部署为 `index.ts`）：12 个 `nuwa_*` 工具、`/nuwa` 命令、6 类生命周期与护栏事件、全量兼容导出 |
| `omp/types.ts` | 共享类型契约（含 `AssetNode` / `HypothesisNode` / `ScopePolicy`）与版本常量 |
| `omp/storage.ts` | 配置读取、文件锁 `withLock`、原子写、增量 `.json.gz` 快照、journal 恢复、多会话指针与 `.sapper` 迁移 |
| `omp/graph.ts` | 6 阶段种子、图状态机、UCB1 经验提权排序、双盲复验与证伪剪枝流转、SPA/鉴权差分/OOB/资产命令工作流 |
| `omp/lineage.ts` | 主从会话血缘绑定（内存 + 磁盘缓存）与基于派单意图的 `fast`/`deep`/`verify` 动态模型路由器 |
| `omp/scope.ts` | 全工具面（`bash`/`read`/`browser`/`web_search`/`eval`）连接目标 vs 载荷区分范围护栏（`N-007`）、高危拦截（`N-008`）与 `.nuwa/` 防篡改（`N-003`） |
| `omp/evidence.ts` | 可信证据源白名单、单调序列号 + 并发锁 + 高熵校验 `.nuwa/exec-ledger.jsonl` 与工具链能力探针 |
| `omp/autoexec.ts` | Soft-404 基线去噪、内容语义实锤、工具链重武器自适应升档、认证态零明文头文件注入与预算取消控制 |
| `omp/browser-recon.ts` | 认证态 SPA 动态只读无头浏览器感知与静态同源 JS Bundle / 懒加载 Chunk / `.js.map` API 提取层 |
| `omp/auth-diff.ts` | 确定性多角色只读鉴权差分矩阵（Auto-BOLA / BFLA / Unauth + Soft-404 基线过滤 + 全量脱敏） |
| `omp/kb.ts` & `kb/*` | 随仓种子资产、单文件 `DELETE` 模式 `bun:sqlite` 幂等建库器、参数化 FTS5 检索与防污染经验蒸馏引擎 |
| `omp/session-vault.ts` | 多角色会话保险箱（`0o700/0o600`）、JWT 过期解析、CSRF 镜像头、健康巡检刷新与全文本凭据脱敏 |
| `omp/verifier-gate.ts` | 候选漏洞 `candidate → confirmed / rejected` 双盲独立挑刺复验与水位核验闸门 |
| `omp/sandbox.ts` & `docker/` | 零信任 Docker / 常驻 Sidecar 沙盒、精确容器内命令提取、内置抗 DNS 重绑定 Egress Proxy 与多阶段无 root 沙盒镜像 |
| `omp/oob.ts` | 受 `scope.oobDomains` 白名单门控的一等 OOB 外带回调 Canary 管理与轮询入账 |
| `omp/hypothesis.ts` | 多资产与跳板可达拓扑图、5 类跨事实假设图推理（收益/成本评分）与证伪级联剪枝 |
| `omp/reporting.ts` | 分层 Markdown / SARIF 2.1.0（仅已确认漏洞）/ JSON 与 `0o600` SHA-256 脱敏审计证据包导出 |
| `omp/profiles.ts` | 5 种领域 Profile（`ctf`/`pentest`/Web+白盒 `audit`/`coding`/`ops`）全流程种子/派生/兜底/报告解耦 |
| `omp/reincarnate.ts` | 长程无头守护跨世代累计记账、轮转判定与 ≤1500 字交接摘要生成 |
| `omp/ui.ts` / `omp/ui-native.ts` | 三层常驻可视面与 Tern 原生 TSP 组件按能力自动降级层 |
| `agents/*.md` | 便携合规子代理模板：`fujiang.md`（执行取证）与 `nuwa-verifier.md`（独立双盲证伪复验） |
| `benchmarks/` | 10 场景离线确定性评测靶场（`targets.json` + `mock-bench-server.ts` + `run-eval.ts`） |
| `bin/nuwa-autonomous` | 外层无头守护器（跨世代换血、单代/空闲看门狗、Token/USD 成本封顶、脱敏 Webhook/死信队列、`doctor [--json]`） |
| `archive/v1/` & `docs/archive/v1/` | 已归档的 v1 Python 历史模块与早期发布记录（保留 `nuwa/__init__.py` 透明兼容转发） |

## 一键部署与环境体检

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
env -u BUN_OPTIONS ./install.sh                 # 一键部署 22 模块 + 构建便携 kb.db + 安装子代理与守护器
env -u BUN_OPTIONS ./install.sh --force-agents  # 强制刷新已存在的子代理模板
env -u BUN_OPTIONS ./install.sh --clean-kb      # 全新重建纯净 kb.db
./install.sh --rollback                         # 一键回滚至上一版备份

# 部署后一键环境健康体检
~/.local/bin/nuwa-autonomous doctor
~/.local/bin/nuwa-autonomous doctor --json
```

依赖：`omp` ≥ 18.16.0，`bun` ≥ 1.1。随仓自带 `kb/` 种子并通过 `bun:sqlite` 自动构建 `~/.omp/agent/nuwa-kb/kb.db`，开箱即用。

## 快速使用

### 1. 交互式会话命令与工具

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa 审计当前项目源码安全漏洞                 # 本地白盒 audit 模式自动绑定当前目录
/nuwa status                                   # 查看阶段、cand、assets、hyp、roles、sandbox 与 frontier
/nuwa board                                    # 全屏 TUI 看板（q/Esc 关闭）
/nuwa scope [loopback on|off | +oob <domain>]  # 查看或调整 Scope 白名单、回环策略与 OOB 域名
/nuwa session [list|set|health|remove|clear]   # 管理多角色会话保险箱并巡检过期刷新
/nuwa spa                                      # 执行认证态/匿名态只读 SPA 路由、Chunk 与 .js.map 提取
/nuwa authdiff [/api/admin /api/orders/1001]   # 执行多角色只读鉴权差分矩阵（Auto-BOLA / BFLA）
/nuwa oob [list|gen <domain>|poll <url>]       # 管理受白名单门控的一等 OOB Canary 回调
/nuwa assets                                   # 查看多资产跳板拓扑与跨事实假设图
/nuwa report [md|json|sarif|bundle]            # 导出脱敏报告、SARIF 2.1.0 或 SHA-256 审计证据包
/nuwa doctor                                   # 会话内一键组件与环境体检
/nuwa log / why / stop / resume
```

### 2. 长程无头守护（跨世代换血 + 成本封顶 + Sidecar 沙盒 + 脱敏告警）

```bash
nuwa-autonomous \
  --target http://TARGET:PORT \
  --mode pentest \
  --root ./work-target \
  --sandbox sidecar \
  --sandbox-image nuwa-sandbox:latest \
  --fast-model gemini-3.8-flash-high \
  --deep-model gemini-4-neon-xhigh \
  --verify-model gemini-4-carbon-high \
  --max-generations 20 \
  --max-hours 12 \
  --gen-timeout-minutes 45 \
  --max-total-tokens 2000000 \
  --max-usd 10 \
  --webhook https://hooks.example.com/nuwa/notify
```

## 纪律与安全护栏（N-001..N-009）

| 规则 | 拦截行为 |
|---|---|
| N-001 | 主线程直接运行扫描工具 → 必须派发子代理（`NUWA_SCANNER_GUARD=0` 可动态放行） |
| N-002 | 调用已退役的 `bin/nuwa` / `nuwa/cli.py` / `sapper` CLI |
| N-003 | 写入、重定向、删除、读取或脚本篡改 `.nuwa/` 权威状态、账本与 `sessions/vault.json` |
| N-004 | `task` / `eval agent()` 未使用合规子代理（`fujiang` 或 `nuwa-verifier`） |
| N-005 | 子代理越权调用主线程专属记账工具 `nuwa_*` |
| N-006 | `task` 误传 `tools` 字段导致子代理内建工具表被清空 |
| N-007 | 全工具面（`bash`/`read`/`browser`/`web_search`/`eval` + 内置 Egress Proxy）访问授权 Scope 之外的主机、网段、云元数据或外泄内网特征 |
| N-008 | 未显式开启 `allowDestructive` 时执行高危破坏性系统或数据库命令 |
| N-009 | 开启 `NUWA_SANDBOX=docker` 或 `sidecar` 时子代理绕过零信任只读容器沙盒裸跑宿主命令 |

## 测试、评测靶场与门禁

```bash
# 运行全部 TS 隔离测试（19 个套件，覆盖 v2/v3/v4/v4.1/v5 全链路能力）
env -u BUN_OPTIONS ./run-tests.sh

# 运行 10 场景离线确定性评测靶场
env -u BUN_OPTIONS bun benchmarks/run-eval.ts --deterministic --json

# 运行快速契约与原生套件门禁（版本一致性 + 离线构建契约 + 全量 TS + shell + kb）
./tests/run.sh --v2-only

# 运行完整回归套件（含 v1 归档兼容回归与 g0..g4 阶段门禁）
./tests/run.sh
```

更多设计细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`docs/OMP-NATIVE.md`](docs/OMP-NATIVE.md)、[`docs/AUTOPILOT.md`](docs/AUTOPILOT.md)、[`docs/UI-DESIGN.md`](docs/UI-DESIGN.md) 与 [`benchmarks/README.md`](benchmarks/README.md)。
