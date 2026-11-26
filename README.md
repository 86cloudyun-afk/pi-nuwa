# pi-nuwa · 女娲模式 v7.0.0（单核合一、专精特种小队、原生 CDP 加签差分与多跳攻击链引擎）

把「单核合一跨宿主执行、SQLite WAL 默认并发存储、5+1 专精特种小队联合校准路由、KB 2.0 混合语义与反自证经验治理、原生 CDP 页面借壳加签差分、2～4 跳能力互补攻击链合成验证、只读零写盘与全链路凭据零明文泄露」做成零外部 npm 依赖的 `omp` 原生扩展 + 跨宿主标准 MCP Server + 外层无头守护器。

**女娲模式 v7.0.0 = 单一权威执行核（`core/engine.ts`）+ 精简组装与派单桥接（`omp/nuwa.ts` `< 1,000` 行 + `omp/dispatch-bridge.ts`，35 个 `omp/*.ts` 模块，严格保持 12 个 `nuwa_*` 工具）+ 跨宿主 MCP Server（`core/mcp-server.ts` + `bin/nuwa-mcp`）+ KB 2.0 混合语义知识库（`>= 520` 条，`kb/`）+ 5+1 专精特种小队（6 个 `agents/*.md`）+ L1/L2/L3 全层级评测靶场（`benchmarks/`）+ 外层无头守护器（`bin/nuwa-autonomous`）。**

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
~/.local/bin/nuwa-autonomous doctor                        # 环境健康体检
~/.local/bin/nuwa-mcp --version                            # 核验跨宿主 MCP Server 版本 (7.0.0)
```

### 常用斜杠命令与 v7.0 新增视图

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa status / board / inspect / query                     # 严格零写盘看板、TUI 与图谱/归档诊断
/nuwa cdp [status | capture [url] | authdiff [paths...]]   # [v7.0] 原生 CDP 桥接状态、实时脱敏抓包与页面内加签差分
/nuwa chains [list [limit] | verify [chainId]]             # [v7.0] 查看可合成 2～4 跳攻击链并执行只读有状态重放验证
/nuwa squad [role]                                         # [v7.0] 查看 5+1 专精特种小队状态与当前前沿意图联合路由建议
/nuwa belief / calibrate / traffic / hybrid / mcp          # 信念图、校准账本、脱敏流量工作台、黑白盒桥接与 MCP 配置
```

## 测试、三层靶场与八道阶段门禁

```bash
python3 tests/version_check.py --require-install-echo                  # 7.0.0 版本单一事实来源与 install.sh 回显校验
NUWA_REQUIRE_TSC=1 python3 tests/contract_check.py --v2-only           # 12/12 契约、全仓严格 tsc 与离线构建门禁
env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts --deterministic       # L2 五场景有状态合成靶场 (5/5)
env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts               # L3 三场景真实进程树与 SOCKS5h 门禁靶场 (3/3)
bash tests/gates/g7_v7.sh                                              # 单独执行 v7.0 第 8 道阶段门禁
./tests/gates/run.sh                                                   # 执行 g0..g7 全八道历史与当前阶段门禁
```
