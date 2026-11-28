# 测试与阶段门禁验收记录（v8.0.0 最终封版报告）

日期：2026-11-28  
封版基线：基于 `main@df37101`（`df37101553b550c0db5dbe71d3b84cd17d3b1164`，生产源码等同 `main@cd1eb72`），经三路异构 Boost 终审（总审 A、总审 B、总审 C 全部 `0 P0 / 0 P1` 签发通过）与全量本地 CI 矩阵 + 实网 LLM 推理评测独立验收定稿。  
环境：Linux 工作区，Bun 1.4.4 运行时，Python 3.12，TypeScript 严格模式（`/opt/q4-relay/node_modules/.bin/tsc -p tsconfig.json --noEmit` 全仓零错误），本机 `sapper 1.0.0`、Headless Chrome、本地 TCP SOCKS5h 微靶场、L4 多协议合成微靶场及 OpenAI 兼容实网推理接口（`deepseek-flash`）。

---

## 一、架构收敛硬指标与静态契约校验

- **版本单一事实来源**：
  - `python3 tests/version_check.py --require-install-echo` → **`version_check: OK (8.0.0)`**
- **全仓严格类型检查与双代契约**：
  - `/opt/q4-relay/node_modules/.bin/tsc -p tsconfig.json --noEmit` → **0 错误**（`4.02s`）
  - `python3 tests/contract_check.py`（对接本机 `sapper 1.0.0`）→ **`contract(v2): 12/12 通过`** + **`contract(v1): 13/13 一致`**（`25.64s`，含离线 `bun build` 与 `RUNTIME_OK:8.0.0:tools=12`）
- **单向无环架构、模块拆解与代码行数红线（精确封版统计）**：
  - `omp/nuwa.ts`：**`952` 行**（严格 `< 1,000` 行硬红线）
  - 全仓 **58 个核心源码文件**（`core/*.ts`、`omp/*.ts`、`kb/*.ts`、`bin/nuwa-autonomous`）**100% 严格 `< 2,500` 行**，全仓除入口外零反向静态循环依赖：
    - `omp/evidence.ts`：`2,455` 行（全仓最高）
    - `omp/rgs-analyzer.ts`：`2,372` 行
    - `omp/sqlite-store.ts`：`2,233` 行
    - `omp/v8-commands.ts`：`967` 行（v8 顶层无环命令与编排入口）
  - **SQLite Schema v2 平滑演进**：`SQLITE_SCHEMA_VERSION = 2`（在原有 10 张表基础上新增 `protocol_frames`、`asset_credentials`、`oob_correlations`、`workflow_runs` 共 14 张表），支持 v1→v2 单事务幂等无损自动迁移，且在旧 v1 库或遗留纯 `state.json` 上只读访问严格 **0 字节写盘**。
  - **工具面、命令面与知识库资产**：
    - 保持 **12 个 `nuwa_*` 工具** 100% 向后兼容，斜杠命令扩展至 **31 个 `/nuwa` 子命令**（新增 `/nuwa proto`、`/nuwa pivot`、`/nuwa rgs`）；
    - 部署扩展模块 **`51/51`**（含 `V8_EXT_MODULES = 8/8` 与 Wave 0 拆解子模块 `8/8`），`agents/` 专精小队模板 **`6/6`**，`kbItems = 535` 条（`>= 520` 硬门禁）；
    - 零第三方 npm 依赖（无 `package.json`），`.github/workflows/` **0 改动**，全仓硬编码密钥正则扫描（`sk-[0-9a-zA-Z]{20,}`）**0 命中**。

---

## 二、全量本地 CI 矩阵与四层评测靶场实测指标

### 1. 三存储后端全仓单元测试矩阵（`./run-tests.sh`）

全仓共 **42 个测试文件 / 615 个测试用例 / 13,379 次 `expect()` 断言**：

| 存储后端模式 | 环境变量配置 | 通过 / 失败 | `expect()` 断言数 | 实测耗时 | 结论 |
|---|---|---|---|---|---|
| **默认 SQLite WAL（Schema v2）** | 未设置 `NUWA_STORAGE_BACKEND`（自动解析 `"sqlite"`） | **615 pass / 0 fail** | 13,379 | `255.16s` | PASS |
| **显式 JSON 兼容模式** | `NUWA_STORAGE_BACKEND=json` | **615 pass / 0 fail** | 13,379 | `192.79s` | PASS |
| **显式 Dual 双写对账模式** | `NUWA_STORAGE_BACKEND=dual` | **615 pass / 0 fail** | 13,379 | `298.90s` | PASS |

### 2. 单次严格等价 GitHub Actions 全量流水线（`./tests/run.sh`）与九道门禁（`g0`..`g8`）

- **执行命令**：
  - `NUWA_REQUIRE_GATES=1 NUWA_REQUIRE_V1_SAPPER=1 NUWA_REQUIRE_TSC=1 env -u BUN_OPTIONS bash ./tests/run.sh`
- **整体结果（实测于 `main@df37101`）**：
  - 全部 **28 个阶段 `0 fail` 全绿通过**（`rc = 0`，总耗时 **`1,463.99s`**）：
    - 基础与契约阶段：`version`（`OK 8.0.0`）、`contract`（`v2 12/12 + v1 13/13`）；
    - TypeScript 隔离测试阶段：`unit`（`45`）、`omp`（`128`, 7 files）、`isolation`（`12`）、`v3`（`430`, 33 files, `242.47s`），合计覆盖 42 个测试文件 **`615 pass / 0 fail`**；
    - Python / Shell / 混沌 / 并发 / R1-R7 套件：`shell`（`15`, `21.62s`）、`kb`（`5`, `OK skipped=2`）、`chaos`（`8`, `31.48s`）、`concurrency`（`5`, `279.48s`）、`e2e`（`4`, `116.21s`）、`r1core`（`41`）、`r1dispatch`（`3`）、`r1run`（`4`）、`r1multi`（`1`）、`crash`、`guard`（`18`）、`r2r7`（`29`）全部 `OK`；
    - **九道阶段门禁 `gates/g0..g8` `9/9` 全绿**：
      - `g0_baseline`：`12/12 + 13/13` 通过
      - `g1_r1`：`41 + 3 + 4 + 1` 通过
      - `g2_r2r7`：`29` 通过
      - `g3_v4`：`77 pass`（5 files）
      - `g4_v5`：`21 pass`（3 files，`15.20s`）
      - `g5_v51`：`63 pass`（5 files）
      - `g6_v6`：`78 pass`（6 files，`60.66s`）
      - `g7_v7`：`59 pass`（6 files，`62.00s`，`kbItems = 535`，L2 `5/5`，L3 `3/3`）
      - `g8_v8`（v8 新增第 9 道门禁）：**`123 pass / 0 fail`**（7 files，`66.21s`，0 硬编码密钥泄露、无 Key 显式快速拒跑、L2 `5/5`、L3 `3/3`、L4 `--deterministic` `12/12`）

### 3. L1 / L2 / L3 / L4 四层基准与实网 `deepseek-flash` L4 推理评测实测指标

| 靶场层级与评测模式 | 执行入口 | 场景通过率 | 关键实测精度、安全与成本指标 | 实测耗时 | 结论 |
|---|---|---|---|---|---|
| **L1 离线确定性十场景靶场** | `benchmarks/run-eval.ts` | **10 / 10** | `passAt1 = 1`、`falsePositiveCount = 0`、`vaultLeakCount = 0` | `1.96s` | PASS |
| **L2 有状态五场景合成靶场** | `benchmarks/run-l2-eval.ts --deterministic --json` | **5 / 5** | `recall = 1`、`fp = 0`、`leaks = 0`、`brier = 0.0084`（`<= 0.25`）、`ece = 0.0887` | `16.70s` | PASS |
| **L3 真实进程树与 SOCKS5h 靶场** | `benchmarks/l3-live/run-l3-eval.ts --json` | **3 / 3** | `socks5Handshakes = 6`、`modelErrors = 0`、`leaks = 0` | `9.54s` | PASS |
| **L4 离线确定性十二场景全谱系靶场** | `benchmarks/l4-arena/run-l4-eval.ts --deterministic --json` | **12 / 12** | `13/13 TP`、`recall = 1`、`fp = 0`、`leaks = 0`、`standalonePovExitZero = true`、`outOfScopeLeakRequests = 0` | `19.91s` | PASS |
| **L4 实网 `deepseek-flash` LLM 推理靶场** | `benchmarks/l4-arena/run-l4-eval.ts --live-openai-compat --json` | **12 / 12** | `recall = 1`、`fp = 0`、`leaks = 0`、`standalonePovExitZero = true`、`outOfScopeLeakRequests = 0`、`llmCalls = 24`、`promptTokens = 4,874`、`completionTokens = 15,005`、`reasoningTokens = 8,920`、`totalTokens = 19,879` | `151.11s` (`wallTimeMs=151110`) | PASS |

---

## 三、三路 Boost 异构终审与隔离临床沙盒专项验收

- **三路异构 Boost 终审结论（`0 P0 / 0 P1` 全部签发放行）**：
  - **总审 A（Schema v2 / 无环拆解 / 零写盘 / 终态守卫）**：确认 v1→v2 单事务幂等迁移、活跃 `-wal/-shm` 隔离快照只读打开、遗留纯 `state.json` 及损坏 `state.json` + `.nuwa/snap` 下 `/nuwa proto|pivot|rgs` 只读视图严格 **0 字节写盘**、终态项目守卫全覆盖。
  - **总审 B（状态工作流 / 多协议检验 / RGS 数据流分析 / L4 实网客户端）**：确认 `SessionVault.retiredSecrets` 覆盖轮换凭据全链路脱敏（`sqlite`/`json`/`dual` 三后端均 `vaultLeaks = 0`）、`rgs-analyzer.ts` 入口 `.nuwa` 路径 `[N-003]` 硬阻断、Live OpenAI 客户端严禁离线回退、4xx 快速失败与错误文本密钥剥离、SSE `usage` 防零覆盖。
  - **总审 C（安全红线 / 跨资产凭据隔离 / 取证包零明文 / 安装体检一致性）**：确认跨资产凭据按 `(scheme, host, port)` 严格源站隔离与越界硬阻断、`writePocBundle` 输出 5 文件（含新增独立可复验脚本 `pov-<factId>.ts`）全量 `0o600` 权限与零明文凭据泄露、`install.sh` / `contract_check.py` / `autonomous-doctor.ts` 模块清单三方严格对齐。
- **独立 `/tmp` 临床沙盒安装、体检、零写盘与回滚验收**：
  - `install.sh --clean-kb`：成功部署 `51/51` 扩展模块、`core/` 核心层、6 个专精小队模板及 `kb.db`（`535` 条），内置运行态冒烟输出 `SMOKE_OK 8.0.0 tools=12`；
  - 跨目录执行 `nuwa-mcp --version` 返回 `nuwa-mcp 8.0.0 (mcp 2024-11-05)`，`nuwa-autonomous doctor --json` 返回 `ok = true, criticalPassed = 3/3, v8Modules = 8/8, submodules = 8/8`；
  - 遗留纯 `state.json` 10 条只读路径与损坏 `state.json` + `.nuwa/snap` 场景零写盘校验通过；
  - `install.sh --rollback`（`rc = 0`）无损回滚验证通过。

---

## 附：历史基线摘要（v7.0.0）

- 封版基线：`main@bc9f9f9`（2026-11-26），`VERSION = "7.0.0"`，35 个测试文件 `492 pass / 0 fail`（`sqlite` / `json` / `dual`），`g0..g7` 8/8 门禁与 `./tests/run.sh` 27 阶段全绿，L1 `10/10`、L2 `5/5`、L3 `3/3` 全绿。
