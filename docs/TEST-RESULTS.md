# 测试与阶段门禁验收记录（v7.0.0）

日期：2026-11-26  
环境：Linux 工作区，Bun 运行时，Python 3.12，TypeScript 严格模式（`tsc -p tsconfig.json --noEmit` 全仓零错误），本机 Headless Chrome + 本地 TCP SOCKS5h 微靶场，零外部网络依赖、零付费 API 成本。

> 说明：本文档记录 Wave 2 总装集成与 `g0..g7` 阶段门禁实测基线；Phase 4 全量本地 CI 矩阵终审数据将在审查闭环后最终归档定稿。

## 一、架构硬指标与静态契约校验

- **版本单一事实来源**：`python3 tests/version_check.py --require-install-echo` → `version_check: OK (7.0.0)`
- **v2 原生契约与全仓严格类型检查**：`NUWA_REQUIRE_TSC=1 python3 tests/contract_check.py --v2-only` → **`12/12` 通过**（含离线 `bun build`、`tsc -p tsconfig.json --noEmit` 零错误、`RUNTIME_OK:7.0.0:tools=12`）
- **单核合一与代码行数红线**：
  - `omp/nuwa.ts`：**`< 1,000` 行**（全面委托 `core/engine.ts` 与 `omp/dispatch-bridge.ts`，全量保留 v4–v7 符号重导出）
  - `omp/graph.ts`：**`< 2,500` 行**（单向无环三层图架构）
  - `core/mcp-server.ts`：全面委托 `NuwaUnifiedEngine`，彻底消除双核分叉
- **KB 2.0 规模与专精小队模板**：
  - `kb/build-kb.ts` 自动摄入 `kb/seed-v7-pack.json`：**`kb_items >= 520` 条**
  - `agents/` 5+1 专精特种小队模板：**6/6 全部就位**（`fujiang.md`、`nuwa-verifier.md`、`nuwa-scout.md`、`nuwa-spa-reverser.md`、`nuwa-auth-breaker.md`、`nuwa-code-auditor.md`）

## 二、v7.0 核心测试套件矩阵

| 套件 | 覆盖范围 | 状态 |
|---|---|---|
| `tests/v7_cdp_bridge.test.ts` | 真实 Headless Chrome 直连 CDP WebSocket、实时 Fetch/XHR 脱敏入 `TrafficRecorder` + 认证态入 `SessionVault`、越界外连 `Fetch.failRequest` 阻断、页面借壳动态 HMAC 加签 BOLA 检出与进程目录零残留 | PASS |
| `tests/v7_chain_composer.test.ts` | 前置-后置能力抽取、2～4 跳防环合成、只读 `TrafficStep[]` 变量提取编译、三跳审批导出链/OOB 链实锤与第 `k` 跳 403 中断 `brokenAtStep` 精准定界及零凭据泄露 | PASS |
| `tests/v7_squad_kb2.test.ts` | 5+1 专精小队画像分类、反自证战绩联合路由、`seed-v7-pack.json` 幂等融合（`>= 520` 条）、中英同义混合语义检索 `hybridKbSearch` 与蒸馏经验 `quarantined`/`promoted` 治理 | PASS |
| `tests/v7_core_unify_l3.test.ts` | `NuwaUnifiedEngine` 12 工具与终态防复活/防降级守卫、`DispatchBridgeStore` 异步乱序/eval/taskFile 词法展开、真实 TCP SOCKS5h 协议握手与 L3 三场景进程树实跑 | PASS |
| `tests/v7_e2e_integration.test.ts` | Wave 2 单核统一路由（`omp` ↔ `MCP`）、SQLite WAL 默认转正与遗留 JSON 只读零写入、KB 2.0 + 5+1 小队 + 攻击链闭环、`/nuwa cdp|chains|squad` 零写盘脱敏与 `install.sh` 隔离沙盒部署验收 | PASS |
| `tests/v6_issues53_54_55_regression.test.ts` | Issue #53/#54 & PR #55 异步派单竞态、SOCKS5h 隔离与终态只读零写盘全量回归 | PASS |

## 三、L1 / L2 / L3 三层靶场与八道阶段门禁（`g0`..`g7`）

- **L1 十场景合成靶场（`benchmarks/run-eval.ts`）**：**10/10 PASS**（`falsePositiveCount = 0`、`vaultLeakCount = 0`）
- **L2 五场景有状态靶场（`benchmarks/run-l2-eval.ts`）**：**5/5 PASS**（`recallRate = 1`、`falsePositiveRate = 0`、`vaultLeakCount = 0`、`calibrationBrier <= 0.25`）
- **L3 三场景真实进程树靶场（`benchmarks/l3-live/run-l3-eval.ts`）**：**3/3 PASS**（`allPassed = true`、`socks5HandshakeCount > 0`、`modelApiErrors = 0`、`vaultLeakCount = 0`）
- **阶段门禁套件（`tests/gates/run.sh`）**：`g0_baseline`、`g1_r1`、`g2_r2r7`、`g3_v4`、`g4_v5`、`g5_v51`、`g6_v6`、`g7_v7` **八道门禁全部通过**。
