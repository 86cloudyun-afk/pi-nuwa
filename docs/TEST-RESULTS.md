# 测试与阶段门禁验收记录（v8.0.0 总装预填与历史基线）

> **v8.0.0 总装架构说明（待 Wave 2 全量测试员写入最终实测汇总指标）**：
> - **版本与契约**：`VERSION = "8.0.0"`，`SQLITE_SCHEMA_VERSION = 2`（14 张表），12 个 `nuwa_*` 核心工具与 31 个 `/nuwa` 子命令，`contract(v2): 12/12` + `contract(v1): 13/13`。
> - **反巨石行数红线**：`omp/nuwa.ts < 1,000` 行，全仓所有 `core/*.ts`、`omp/*.ts`、`kb/*.ts`、`bin/nuwa-autonomous` 严格 `< 2,500` 行。
> - **新增门禁与四层靶场**：新增第 9 道门禁 `tests/gates/g8_v8.sh`（覆盖 7 个 `tests/v8_*.test.ts` 套件、0 硬编码密钥扫描、L2 `5/5`、L3 `3/3`、L4 `12/12` `--deterministic` 硬门禁，以及 `benchmarks/l4-arena/run-l4-eval.ts --live-openai-compat` 实网推理评测入口）。

---

## 历史封版基线（v7.0.0 最终封版报告）

日期：2026-11-26  
封版基线：基于 `main@bc9f9f9`（`bc9f9f9a6cd4a2184485ac3bda0adafb614bdbec`）经双路异构 Boost 终审与全量本地 CI 矩阵独立验收定稿。  
环境：Linux 工作区，Bun 运行时，Python 3.12，TypeScript 严格模式（`/opt/q4-relay/node_modules/.bin/tsc -p tsconfig.json --noEmit` 全仓零错误），本机 Headless Chrome + 本地 TCP SOCKS5h 微靶场，零外部网络依赖、零付费 API 成本。

---

## 一、架构收敛硬指标与静态契约校验

- **版本单一事实来源**：
  - `python3 tests/version_check.py --require-install-echo` → `version_check: OK (7.0.0)`
- **全仓严格类型检查与双代契约**：
  - `/opt/q4-relay/node_modules/.bin/tsc -p tsconfig.json --noEmit` → **0 错误**（`2.49s`）
  - `python3 tests/contract_check.py` → **`contract(v2): 12/12 通过`** + **`contract(v1): 13/13 一致`**（含离线 `bun build`、`RUNTIME_OK:7.0.0:tools=12`）
- **单核合一与代码行数红线（精确封版统计）**：
  - `omp/nuwa.ts`：**`932` 行**（严格 `< 1,000` 行硬红线，全面委托 `core/engine.ts` 与 `omp/dispatch-bridge.ts`）
  - `omp/graph.ts`：**`2,439` 行**（严格 `< 2,500` 行硬红线，单向无环三层图架构）
  - `core/mcp-server.ts`：**`579` 行**（`NuwaCoreEngine extends NuwaUnifiedEngine`，彻底消除双核分叉）
  - `core/engine.ts`：**`3,002` 行**（单一权威执行核，统一承载 12 个 `nuwa_*` 工具与 28 个 `/nuwa` 子命令）
  - **向后兼容符号重导出**：相对 `9f0c6dc` 基线的全部 **275 个旧版运行时导出 0 缺失**（现共导出 **382** 个符号）
- **KB 2.0 规模与专精特种小队模板**：
  - `kb/build-kb.ts` 自动幂等摄入 `kb/seed-v7-pack.json`：**`kbItems = 535` 条**（`>= 520` 硬门禁，其中 `card=324, cve=171, technique=40`，`totalRecords=1,324`）
  - `agents/` 5+1 专精特种小队模板：**`6/6` 全部就位**（`fujiang.md`、`nuwa-verifier.md`、`nuwa-scout.md`、`nuwa-spa-reverser.md`、`nuwa-auth-breaker.md`、`nuwa-code-auditor.md`）

---

## 二、全量本地 CI 矩阵（替代 GitHub Actions 等价验收）

### 1. 三存储后端全仓单元测试矩阵（`./run-tests.sh`）

全仓共 **35 个测试文件 / 492 个测试用例 / 11,336 次 `expect()` 断言**：

| 存储后端模式 | 环境变量配置 | 通过 / 失败 | `expect()` 断言数 | 实测耗时 | 结论 |
|---|---|---|---|---|---|
| **默认 SQLite WAL（转正默认）** | 未设置 `NUWA_STORAGE_BACKEND`（自动解析 `"sqlite"`） | **492 pass / 0 fail** | 11,336 | `184.49s` | PASS |
| **显式 JSON 兼容模式** | `NUWA_STORAGE_BACKEND=json` | **492 pass / 0 fail** | 11,336 | `132.15s` | PASS |
| **显式 Dual 双写对账模式** | `NUWA_STORAGE_BACKEND=dual` | **492 pass / 0 fail** | 11,336 | `171.56s` | PASS |

### 2. 严格模式八道阶段门禁（`g0`..`g7`）与全套 `./tests/run.sh`

- **严格模式八道阶段门禁**：
  - 命令：`NUWA_REQUIRE_GATES=1 NUWA_REQUIRE_V1_SAPPER=1 NUWA_REQUIRE_TSC=1 bash tests/gates/run.sh`
  - 结果：`g0_baseline`、`g1_r1`、`g2_r2r7`、`g3_v4`、`g4_v5`、`g5_v51`、`g6_v6`、`g7_v7` **`8/8` 全绿通过**（总耗时 `350.98s`）
  - 其中第 8 道门禁 `g7_v7.sh`：6 个 v7 测试套件 **`59 pass / 0 fail / 6,132 expect()`**，`kbItems = 535 >= 520`，`6/6` 小队模板齐备
- **GitHub Actions 等价全套流水线（`./tests/run.sh`）**：
  - 覆盖 `contract(v1/v2)`、`shell`、`kb`、`chaos`、`concurrency`、`e2e`、`r1*`、`crash`、`guard`、`r2r7`、`omp` 等全部 **27 个阶段** → **`fails=0` 全绿通过**（`1,058.20s`）

### 3. L1 / L2 / L3 三层评测靶场实测指标

| 靶场层级 | 执行入口 | 场景通过率 | 关键实测精度与安全指标 | 结论 |
|---|---|---|---|---|
| **L1 离线确定性十场景靶场** | `benchmarks/run-eval.ts` | **10 / 10** | `passAt1 = 1`、`falsePositiveCount = 0`、`vaultLeakCount = 0` | PASS |
| **L2 有状态五场景合成靶场** | `benchmarks/run-l2-eval.ts --deterministic --json` | **5 / 5** | `recall = 1`、`fp = 0`、`leaks = 0`、`brier = 0.0084`（`<= 0.25`）、`ece = 0.0887` | PASS |
| **L3 真实进程树与 SOCKS5h 靶场** | `benchmarks/l3-live/run-l3-eval.ts --json` | **3 / 3** | `socks5Handshakes = 6`、`socks5DomainReqs = 6`、`modelErrors = 0`、`leaks = 0` | PASS |

---

## 三、双路 Boost 异构终审与隔离临床沙盒专项验收

- **44 路径只读零写盘与防篡改矩阵**：
  - 在遗留仅有 `.nuwa/state.json`（无 `nuwa.db`）且附带语法损坏 `.nuwa/autoexec.json` 的目录中，连续执行 11 次 `omp` 只读工具、29 条 `/nuwa` 只读斜杠命令（含 `cdp`、`chains`、`squad`、`scope show|list`、`session LIST`、`oob LIST`、越界 `cdp capture`）及 3 次 MCP JSON-RPC 只读调用：**`violationCount = 0`、`slashErrorCount = 0`、`nuwaDbExists = false`**（绝不自动创建 `nuwa.db` / `-wal` / `-shm`，绝不回写磁盘）。
  - 在默认 `"sqlite"` 模式下发生状态写入时，同步维护 `.nuwa/state.json` 兼容快照，且二进制扫密确认 `nuwa.db`、`state.json`、`journal.jsonl`、`traffic/index.jsonl`、`exec-ledger.jsonl` 全链路凭据零明文泄露。
- **隔离沙盒安装、体检与回滚验收**：
  - 独立 `/tmp` 沙盒执行 `install.sh --force-agents --clean-kb`：35/35 模块、`core/engine.ts`、6 个小队模板、`kb.db`（`535` 条）一次部署成功；
  - `nuwa-autonomous doctor --json` 返回 `ok = true, criticalPassed = 3/3`（`v7ModulesMissing = []`, `squadMissing = []`）；
  - `nuwa-mcp --version` 返回 `nuwa-mcp 7.0.0 (mcp 2024-11-05)`；`install.sh --rollback` 无损回滚验证通过。
