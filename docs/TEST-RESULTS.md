# 测试与阶段门禁验收记录（v6.0.0）

日期：2026-11-26  
环境：Linux 工作区，Bun 1.4.4，Python 3.12.3，TypeScript 5.9.3 / 6.0.3 / 7.0.2（`tsc -p tsconfig.json --noEmit` 全仓零错误），离线零外部网络依赖、零模型 API 成本。

## 一、本地全量 CI 终审总览（`./tests/run.sh`）

终审执行命令：`NUWA_REQUIRE_GATES=1 NUWA_REQUIRE_V1_SAPPER=1 NUWA_REQUIRE_TSC=1 ./tests/run.sh`  
退出码：**0（全部通过）**。

- **版本与架构约束**：
  - `python3 tests/version_check.py --require-install-echo`：`version_check: OK (6.0.0)`
  - 巨石无环拆解：`omp/graph.ts` **2,378 行**（`< 2,500` 行硬红线；`omp/graph-planner.ts` 2,663 行、`omp/graph-commands.ts` 1,223 行）
  - 独立 MCP 服务：`bin/nuwa-mcp --version` 输出 `nuwa-mcp 6.0.0 (mcp 2024-11-05)`
- **双端静态与运行时契约**：
  - `contract(v2)`：**12/12 通过**（12 工具名称与签名不变、子模块零运行时 `./nuwa` 循环依赖、全仓 `tsc -p tsconfig.json --noEmit` 覆盖 `omp`/`kb`/`core`/`benchmarks` 零错误通过、离线 `bun build` 通过、异步插件加载 `RUNTIME_OK:6.0.0:tools=12`）
  - `contract(v1)`：**13/13 一致**（`real='sapper 1.0.0'`）
- **Bun 全量隔离单测（`--isolate` / `./run-tests.sh`）**：
  - **30 个测试文件合计 440 pass / 0 fail（5,327 `expect()` assertions）**（独立 `./run-tests.sh` 复验 65.83s）：`unit` 45/45（85 assertions）、`omp` 128/128（817 assertions）、`isolation` 12/12（33 assertions）、`v3..v6` 255/255（4,392 assertions）
- **Python 协议 / 混沌 / 并发 / E2E / R1–R7 套件**：
  - `shell` 15、`kb` 5（宿主缺省 `~/.nuwa/kb.db` 跳过 2 项；独立便携库在 `v4_kb_memory` 与 `install.sh` 沙盒中 100% 全通）、`chaos` 8、`concurrency` 5、`e2e` 4、`r1core` 41、`r1dispatch` 3、`r1run` 4、`r1multi` 1、`guard` 18、`r2r7` 29 全部通过；`crash_matrix` **16 runs OK**

## 二、多存储后端全链路回归矩阵

| 存储后端模式 | 覆盖套件数 | 用例通过数 | 断言数（`expect()`） | 耗时 | 核心验证点 | 状态 |
|---|---:|---:|---:|---:|---|---|
| 默认模式（`json`） | 30 文件 | **440 pass / 0 fail** | 5,327 | 65.83s | 全量历史、v6 与 Issue #53/#54 & PR #55 回归隔离单测 | PASS |
| `NUWA_STORAGE_BACKEND=sqlite` | 30 文件 | **440 pass / 0 fail** | 5,327 | 101.83s | 全仓 30 套隔离单测切换 SQLite WAL 权威存储：WAL 并发写、纯只读零写盘快照（含跳过脏 `-shm` 仅从 `-wal` 重放及 `0o444`/`0o555` 降权恢复）、活跃 WAL 实时读取、血缘探测、校准/时间线与 Issue #53/#54/PR #55 纯 SQLite 闭环 | PASS |
| `NUWA_STORAGE_BACKEND=dual` | 30 文件 | **440 pass / 0 fail** | 5,327 | 98.48s | 全仓 30 套隔离单测切换 JSON + SQLite 双写模式：双端一致落盘、原子并发锁协同与全链路接线 | PASS |

## 三、v6.0 新增与核心测试套件明细

| 套件 | 覆盖范围 | 状态 |
|---|---|---|
| `tests/v6_sqlite_autoloop.test.ts` | SQLite WAL 10 表初始化、JSON↔SQLite 往返迁移、FTS5 中英文/路径/CVE 检索、4 进程并发写压测、坏库隔离回退、零凭据泄露、自主 AuthDiff 与 OOB 节流闭环 | PASS |
| `tests/v6_belief_calibration.test.ts` | Beta 后验与香农熵/VoI 边界、7 类观测传播、WAF/复验驳回级联剪枝、跃迁信号置顶、反自证拦截、Brier/10-bin ECE 对拍精度 `<= 1e-6`、自适应模型路由 | PASS |
| `tests/v6_traffic_hybrid.test.ts` | `TrafficRecorder` 只读零写盘与 `0o600` 全字段脱敏、`replayTrafficSequence` 多步变量提取与跨源重定向护栏、五类只读契约变异并发 `<= 8`、多语言静态路由与 `.js.map` 双向桥接 | PASS |
| `tests/v6_core_mcp_l2eval.test.ts` | `core/protocol.ts` 12 工具对齐、`core/mcp-server.ts` 双帧格式（Content-Length + NDJSON）与 `bin/nuwa-mcp` 真实子进程 stdio 联调、L2 五场景基准与硬门禁校验 | PASS |
| `tests/v6_integration_wiring.test.ts` | v6.0 全链路总装接线：`NUWA_STORAGE_BACKEND=sqlite|dual` 状态往返、`frontierList` 跨会话持久化信念重排与双盲驳回剪枝、`before_subagent_spawn`→机械门禁反自证结算、批处理收尾自主闭环、5 个新 `/nuwa` 只读视图零写盘与 `omp/graph.ts` 拆解全量兼容导出 | PASS |
| `tests/v6_issues53_54_55_regression.test.ts` | Issue #54 真实 `omp` `tool_call`→`before_subagent_spawn`（无 `task`/`prompt`）→`tool_execution_end` 全链路；Issue #53 `socks5h` 隔离与真实 `Bun.serve` `fetch`、`--model-proxy`/`--no-proxy`、`--resume-stopped`/`--force` 防死循环、`--migrate-workspace` WAL 迁移；PR #55 及 P1–P8 `sealed_negative` 终态不可复活、跨会话只读降级、`buildDirective` / `REPORT.md` / `REPORT.json` 与 `tokens`/`totalTokens` 自动同步 | PASS |
| 存量 `v2`–`v5.1` 全部历史回归套件 | 24 套 TypeScript 单测与全套 Python 契约/回归测试（含 12 工具不变量、N-001..N-009 护栏、沙盒、会话仓、双盲复验、归档与看门狗） | PASS |

## 四、L1 与 L2 离线合成微基准评分卡

### 1. L1 十场景合成靶场（`benchmarks/run-eval.ts --deterministic --json`）

- **场景通过率**：**10/10**（`wallTimeMs = 503`）
- **核心指标**：`passAt1Rate = 1`、`falsePositiveCount = 0`、`verifierCatchRate = 1`、`vaultLeakCount = 0` — **OVERALL PASS**

### 2. L2 五场景有状态全链路靶场（`benchmarks/run-l2-eval.ts --deterministic --json`）

- **`t1-spa-jwt-bola`**：SPA 静态清单提取 + 多角色自主鉴权差分（水平 BOLA + 垂直 BFLA）+ 流量录制变异 + 双盲确认 — **PASS**
- **`t2-waf-soft404-trap`**：HTTP 429 `Retry-After` 识别 + Soft-404 诱饵假阳性自动降级与校准机械结算 + 真实诊断接口确认 — **PASS**
- **`t3-blind-ssrf-oob`**：自主 OOB Canary 规划播撒 + 本机回路收集器节流轮询 + 双盲独立 Canary 二次确认 — **PASS**
- **`t4-hybrid-sourcemap-chain`**：公开 `.js.map` 虚拟源码提取桥接 + `replayTrafficSequence` 两步 `stepToken` 提取重放 + 黑盒发现反向源码定位 — **PASS**
- **`t5-hardened-zero-vuln`**：全加固 RBAC 服务零误报排除 + 信念收敛转向评估 + `11` 轮（`<= 15`）快速收敛至 `sealed_negative` — **PASS**
- **L2 汇总指标与五大硬门禁**（`wallTimeMs = 6310`）：
  - `recallRate = 1`（硬门禁 `=== 1.0`）
  - `falsePositiveRate = 0`（硬门禁 `=== 0`）
  - `vaultLeakCount = 0`（硬门禁 `=== 0`）
  - `hardenedSealTurns = 11`（硬门禁 `<= 15`）
  - `calibrationBrier = 0.0084`（硬门禁 `<= 0.25`），`calibrationEce = 0.0887`
  - `allPassed = true`、`calibrationGate = true` — **OVERALL PASS**

## 五、七道阶段门禁（`tests/gates/run.sh`）与隔离沙盒安装验收

### 1. 阶段门禁（`g0`..`g6`）

| 门禁 | 结果 | 实测详情 |
|---|---|---|
| `g0_baseline` | PASS | 基础契约与历史兼容基线（`contract(v2)` 12/12 + `contract(v1)` 13/13） |
| `g1_r1` | PASS | 日志、锁与恢复核心门禁（`r1core` 41、`r1dispatch` 3、`r1run` 4、`r1multi` 1、`crash_matrix` 16 runs） |
| `g2_r2r7` | PASS | 预算、证据与策略门禁（29 pass） |
| `g3_v4` | PASS | v4 原生扩展、血缘、KB 与沙盒门禁（77 pass / 1,295 `expect()`） |
| `g4_v5` | PASS | v5 会话差分、Sidecar/Egress、OOB、假设图与 L1 10 场景靶场门禁（21 pass / 284 `expect()` + L1 10/10） |
| `g5_v51` | PASS | v5.1 三元组去重、封盘、派单守卫、看门狗与全工具范围护栏门禁（63 pass / 932 `expect()`） |
| `g6_v6` | PASS | v6.0 版本一致性、`tsc -p tsconfig.json --noEmit` 全仓零错误、离线构建、`omp/graph.ts` 2,378 行（`< 2500`）、`nuwa-mcp 6.0.0`、75 pass（1,271 `expect()`）与 L2 五场景硬门禁 |

### 2. 隔离沙盒部署验收（`install.sh`）

- **测试环境**：`/tmp` 独立隔离沙盒 + stub `omp/18.16.0`（耗时 `5.28s`）
- **验收结果**：**全部通过**——`30/30` 扩展模块与 `$AGENT_HOME/nuwa-core/bin/nuwa-mcp`（`6.0.0`）完整就位、运行时冒烟回显 `SMOKE_OK 6.0.0 tools=12`、便携知识库 `kb.db`（394 条，card=36，cve=74）、`doctor --json` 健康体检与 `nuwa-autonomous --egress-proxy socks5h://... --dry-run` 全部通过。
