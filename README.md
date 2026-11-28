# pi-nuwa · 女娲模式 v8.0.0（全方法有状态工作流、现代多协议审计栈、跨文件 RGS 与 L4 演武场引擎）

把「单核合一跨宿主执行、SQLite Schema v2 权威存储、全方法有状态工作流与并发屏障测试、CDP TOTP 交互保活与 GraphQL/WS/RSC/gRPC-Web 多协议审计、跨资产双轨路由与自适应韧性/嵌入式 OOB、7 语言跨文件 RGS 图分析与零明文 `pov-*.ts` 独立脚本生成、只读零写盘与全链路凭据零明文泄露」做成零外部 npm 依赖的 `omp` 原生扩展 + 跨宿主标准 MCP Server + 外层无头守护器。

**女娲模式 v8.0.0 = 单一权威执行核（`core/engine.ts` + `core/engine-helpers.ts`）+ 精简组装入口（`omp/nuwa.ts` `< 1,000` 行，52 个 `omp/*.ts` 无环模块全部严格 `< 2,500` 行，保持 12 个 `nuwa_*` 工具与 31 个 `/nuwa` 子命令）+ 跨宿主 MCP Server（`core/mcp-server.ts` + `bin/nuwa-mcp`）+ KB 2.0 混合语义知识库（`>= 520` 条，`kb/`）+ 5+1 专精特种小队（6 个 `agents/*.md`）+ L1/L2/L3/L4 四层全覆盖评测靶场（`benchmarks/`）+ 外层无头守护器（`bin/nuwa-autonomous` + `core/autonomous-doctor.ts`）。**

## v8.0.0 六大核心能力跃升

1. **反巨石无环模块化与 SQLite Schema v2 平滑演进（Wave 0 Foundation）**：十大超长模块单向无环拆解，全仓 `core/*.ts`、`omp/*.ts`、`kb/*.ts`、`bin/nuwa-autonomous` 均严格 `< 2,500` 行（`omp/nuwa.ts < 1,000` 行）；升级 `SQLITE_SCHEMA_VERSION = 2`，新增 `protocol_frames`、`asset_credentials`、`oob_correlations`、`workflow_runs` 四张扩展表与幂等单事务迁移 `migrateSqliteSchemaV1ToV2`，严守历史 v1 库（含活跃 `-wal` + `-shm`）与遗留纯 `state.json` 目录只读 0 字节写盘。
2. **有状态多方法工作流与并发屏障一致性引擎（`omp/stateful-workflow.ts`）**：支持 `L0`~`L3` 四级请求语义分类、内置 `CookieJar` 与逐跳重定向 Scope 守卫的多步重放（`executeStatefulWorkflowChain`）、未声明字段绑定契约检验（`probeMassAssignment`）、写后读二阶状态回归（`verifySecondOrderWorkflow`）及同步屏障并发探针（`runBarrierRaceProbe`）。
3. **CDP TOTP 交互保活与现代多协议深度审计栈（`omp/cdp-auth.ts` + `omp/cdp-signed-probe.ts` + `omp/protocol-inspector.ts` + `/nuwa proto`）**：内置 RFC 6238 TOTP 生成校验、登录剧本与会话自动刷新（`ensureSessionFresh`）、全方法页面内加签差分、GraphQL 内省/错误提示 Schema 重建、WebSocket 双向帧对比、Next.js RSC Flight 与 gRPC-Web Protobuf 编解码审计。
4. **跨资产双轨路由、网关自适应韧性与嵌入式回调关联器（`omp/asset-router.ts` + `omp/resilience-oob.ts` + `/nuwa pivot`）**：实现跨资产凭据复用检验、公私网双轨防环路由表、网关限流冷却轮换、同构兜底页熔断检测，以及 `127.0.0.1:0` 零端口泄漏的原生 `EmbeddedOobListener` 与 `OobCorrelator`。
5. **7 语言 + SPA Bundle 跨文件 RGS 图分析与零明文独立复核脚本（`omp/rgs-analyzer.ts` + `omp/reporting.ts` + `/nuwa rgs`）**：跨文件追踪 `Route -> Guard -> Service -> Sink` 并识别全局守卫抑制假阳性；`writePocBundle` 自动为 `confirmed` 事实生成零明文独立可运行复核脚本 `pov-<factId>.ts`。
6. **12 场景 L4 真实演武场、`--live-openai-compat` 实网评测与第 9 道门禁（`benchmarks/l4-arena/*` + `tests/gates/g8_v8.sh`）**：同时支持离线确定性 `--deterministic`（12/12 硬门禁）与读取环境变量的 OpenAI 兼容实网 LLM 评测模式。

## v7.0.0 六大核心能力跃升

在 100% 保持 12 个 `nuwa_*` 核心工具名称、参数契约与全部历史导出向后兼容的基础上，v7.0.0 完成了六大架构收敛与实战能力跃升：

1. **单核合一与主入口极致瘦身（`core/engine.ts` + `omp/dispatch-bridge.ts` + `omp/nuwa.ts` + `core/mcp-server.ts`）**：`NuwaUnifiedEngine` 统一承载全部 12 个 `nuwa_*` 工具与 28 个 `/nuwa` 斜杠命令，`omp/nuwa.ts` 瘦身至 `< 1,000` 行，`core/mcp-server.ts` 全面委托单核消除分叉；`DispatchBridgeStore` 零私有全局态闭环 `omp 18.16.0` 异步乱序派单、`taskFile` 与 `eval` 词法安全展开及 `SubagentWatchdog` 精确回收。
2. **SQLite WAL 默认存储转正与双核心不变量（`omp/sqlite-store.ts` + `omp/storage.ts`）**：`NUWA_STORAGE_BACKEND` 未设置时默认返回 `"sqlite"`（保留 `sqlite | json | dual` 显式切换）；严格保证对仅有 `.nuwa/state.json`（无 `nuwa.db`）的遗留目录执行任何只读状态/命令/评估操作时 **零磁盘写入**（不创建 `nuwa.db`/`-wal`/`-shm`），发生写入时自动无损迁移并同步维护 `.nuwa/state.json` 兼容快照。
3. **原生 CDP 流量桥接与页面内借壳加签差分（`omp/cdp-bridge.ts` + `/nuwa cdp`）**：零第三方依赖拉起本机 Headless Chrome 直连 CDP `WebSocket`，拦截层强制 `N-007` Scope 校验（主动 `Fetch.failRequest` 阻断越界外连），实时脱敏写入 `TrafficRecorder` 并同步认证头至 `SessionVault`；在受控同源页面内借壳调用前端原生加签钩子执行纯只读 `GET/HEAD/OPTIONS` 契约差分，免逆向穿透动态 HMAC/时间戳/Nonce 识别 BOLA/BFLA。
4. **多跳攻击链能力合成与有状态验证（`omp/chain-composer.ts` + `/nuwa chains`）**：基于 `provides -> requires` 能力标签在有界深度 `2..4` 跳与严格防环约束下合成组合攻击链，编译为带动态变量提取的只读 `TrafficStep[]` 重放验证；打穿全链自动产出 `candidate` 复合漏洞并触发信念图 `breakthrough_signal`，中间第 `k` 跳受阻精准回灌 `brokenAtStep` 衰减下游分支。
5. **5+1 专精特种小队与 KB 2.0 混合语义治理（`omp/specialist-squad.ts` + `omp/kb-v2.ts` + `/nuwa squad`）**：提供 `nuwa-scout`、`nuwa-spa-reverser`、`nuwa-auth-breaker`、`nuwa-code-auditor`、`nuwa-verifier` + `fujiang` 六大专精模板与校准联合路由；自动摄入 `kb/seed-v7-pack.json` 构建 `>= 520` 条知识库，`nuwa_kb` 默认启用 `hybridKbSearch`（FTS5 + 中英同义扩展 + TF-IDF + N-gram + SimHash），知识蒸馏联动 `governDistilledExperience` 执行反自证优胜劣汰。
6. **L3 真实进程树 SOCKS5h 靶场与第 8 道阶段门禁（`benchmarks/l3-live/*` + `tests/gates/g7_v7.sh`）**：通过 `Bun.spawn` 真实拉起 `bin/nuwa-autonomous` 与内置 TCP `SOCKS5h` 服务器跑通异步派单实锤、硬化零洞封盘防复活与 `/tmp` 停止项目自动迁移接管三大场景。

## 核心模块组成

| 路径 | 职责 |
|---|---|
| `core/engine.ts` / `core/protocol.ts` / `core/mcp-server.ts` | 单一权威执行引擎 `NuwaUnifiedEngine`、12 工具 Schema 协议契约与跨宿主标准 MCP JSON-RPC 2.0 stdio 服务端 |
| `omp/nuwa.ts` / `omp/dispatch-bridge.ts` | 精简组装入口（`< 1,000` 行，部署为 `index.ts`）与零全局态异步派单缓冲/占位符词法展开/看门狗桥接器 |
| `omp/storage.ts` / `omp/sqlite-store.ts` | 默认 SQLite WAL 权威存储（兼容 `json`/`dual`）、遗留只读零写盘守卫、`state.json` 兼容快照同步、FTS5 检索与进程组回收 |
| `omp/cdp-bridge.ts` | 零依赖 Headless Chrome CDP 客户端、拦截层 Scope 阻断、实时流量脱敏录制与页面内借壳动态加签只读鉴权差分（`/nuwa cdp`） |
| `omp/chain-composer.ts` | 前置-后置能力抽取、2～4 跳防环攻击链合成、只读 `TrafficStep[]` 编译、有状态重放验证与 `brokenAtStep` 信念回灌（`/nuwa chains`） |
| `omp/specialist-squad.ts` / `agents/*.md` | 5+1 专精特种小队画像、确定性意图分类与反自证机械战绩联合模型路由器（`/nuwa squad`） |
| `omp/kb-v2.ts` / `omp/kb.ts` / `kb/*` | KB 2.0 大规模种子融合（`>= 520` 条）、中英同义混合语义检索 `hybridKbSearch` 与机械校准驱动经验治理 `governDistilledExperience` |
| `omp/graph.ts` / `omp/graph-planner.ts` / `omp/graph-commands.ts` | 无环三层图状态机（`omp/graph.ts < 2,500` 行）：信念前沿重排、专精角色标注、双盲复验、自主闭环与斜杠命令视图 |
| `omp/belief-search.ts` / `omp/calibration.ts` | 共轭 Beta 信念图 + VoI 搜索剪枝、反自证预测登记与机械核验对账账本（Brier/ECE/FPR/ROI） |
| `omp/traffic-workbench.ts` / `omp/hybrid-audit.ts` | `0o600` 脱敏流量录制重放与只读契约变异、TS/JS/Python/Go/`.js.map` 黑白盒双向审计桥接 |
| `benchmarks/` | L1 10 场景基准（`run-eval.ts`）+ L2 5 场景有状态基准（`run-l2-eval.ts`）+ L3 3 场景真实进程树 SOCKS5h 靶场（`l3-live/run-l3-eval.ts`） |

## 一键部署与快速使用

```bash
env -u BUN_OPTIONS ./install.sh --force-agents --clean-kb  # 一键部署全模块 + nuwa-mcp + 6个专精模板 + 构建 kb.db (>=520条)
~/.local/bin/nuwa-autonomous doctor                        # 环境健康体检（含 V8_EXT_MODULES 与拆解子模块门禁）
~/.local/bin/nuwa-mcp --version                            # 核验跨宿主 MCP Server 版本 (8.0.0)
```

### 常用斜杠命令与 v8.0 新增视图

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa status / board / inspect / query                     # 严格零写盘看板、TUI 与图谱/归档诊断
/nuwa proto [status | frames [limit] | graphql [url]]      # [v8.0] 现代多协议审计栈（只读零写盘状态/帧视图与 GraphQL 探测）
/nuwa pivot [status | routes | verify]                     # [v8.0] 跨资产公私网双轨路由规划、韧性状态与凭据复用校验
/nuwa rgs [status | scan <dir> | plan [dir] | pov <id>]    # [v8.0] 7 语言跨文件 RGS 扫描、意图桥接与零明文独立脚本生成
/nuwa cdp [status | capture [url] | authdiff [paths...]]   # 原生 CDP 桥接状态、实时脱敏抓包与页面内加签差分
/nuwa chains [list [limit] | verify [chainId]]             # 查看可合成 2～4 跳攻击链并执行有状态重放验证
/nuwa squad [role]                                         # 查看 5+1 专精特种小队状态与当前前沿意图联合路由建议
/nuwa belief / calibrate / traffic / hybrid / mcp          # 信念图、校准账本、脱敏流量工作台、黑白盒桥接与 MCP 配置
```

## 测试、四层靶场与九道阶段门禁

```bash
python3 tests/version_check.py --require-install-echo                        # 8.0.0 版本单一事实来源与 install.sh 回显校验
NUWA_REQUIRE_TSC=1 python3 tests/contract_check.py --v2-only                 # 12/12 契约、全仓严格 tsc 与离线构建门禁
env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts --deterministic             # L2 五场景有状态合成靶场 (5/5)
env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts                     # L3 三场景真实进程树与 SOCKS5h 门禁靶场 (3/3)
env -u BUN_OPTIONS bun benchmarks/l4-arena/run-l4-eval.ts --deterministic    # L4 十二场景综合有状态演武场 (12/12)
bash tests/gates/g8_v8.sh                                                    # 单独执行 v8.0 第 9 道阶段门禁
./tests/gates/run.sh                                                   # 执行 g0..g7 全八道历史与当前阶段门禁
```
