# 测试与阶段门禁验收记录（v6.0.0）

日期：2026-11-26
环境：Linux 工作区，Bun 1.4.4，Python 3，离线零外部网络依赖、零模型 API 成本。

## 一、v6.0 新增与核心测试矩阵

| 套件 | 覆盖范围 | 状态 |
|---|---|---|
| `tests/v6_sqlite_autoloop.test.ts` | SQLite WAL 10 表初始化、JSON↔SQLite 往返迁移、FTS5 中英文/路径/CVE 检索、4 进程并发写压测、坏库隔离回退、零凭据泄露、自主 AuthDiff 与 OOB 节流闭环 | PASS |
| `tests/v6_belief_calibration.test.ts` | Beta 后验与香农熵/VoI 边界、7 类观测传播、WAF/复验驳回级联剪枝、跃迁信号置顶、反自证拦截、Brier/10-bin ECE 对拍精度 `<= 1e-6`、自适应模型路由 | PASS |
| `tests/v6_traffic_hybrid.test.ts` | `TrafficRecorder` 只读零写盘与 `0o600` 全字段脱敏、`replayTrafficSequence` 多步变量提取与跨源重定向护栏、五类只读契约变异并发 `<= 8`、多语言静态路由与 `.js.map` 双向桥接 | PASS |
| `tests/v6_core_mcp_l2eval.test.ts` | `core/protocol.ts` 12 工具对齐、`core/mcp-server.ts` 双帧格式（Content-Length + NDJSON）与 `bin/nuwa-mcp` 真实子进程 stdio 联调、L2 五场景基准与硬门禁校验 | PASS |
| `tests/v6_integration_wiring.test.ts` | v6.0 全链路总装接线：`NUWA_STORAGE_BACKEND=sqlite` 状态往返、`frontierList` 信念排序与双盲驳回剪枝、`before_subagent_spawn`→机械门禁反自证结算、批处理收尾自主闭环、5 个新 `/nuwa` 只读视图零写盘与 `omp/graph.ts` 拆解全量兼容导出 | PASS |
| 存量 `v2`–`v5.1` 全部历史回归套件 | 20+ 套 TypeScript 与 Python 契约/回归测试（含 12 工具不变量、N-001..N-009 护栏、沙盒、会话仓、双盲复验、归档与守护器） | PASS |

## 二、L2 离线合成微基准评分卡（`benchmarks/run-l2-eval.ts`）

- **`t1-spa-jwt-bola`**：SPA 静态清单提取 + 多角色自主鉴权差分（水平 BOLA + 垂直 BFLA）+ 流量录制变异 + 双盲确认 — **PASS**
- **`t2-waf-soft404-trap`**：HTTP 429 `Retry-After` 识别 + Soft-404 诱饵假阳性自动降级与校准机械结算 + 真实诊断接口确认 — **PASS**
- **`t3-blind-ssrf-oob`**：自主 OOB Canary 规划播撒 + 本机回路收集器节流轮询 + 双盲独立 Canary 二次确认 — **PASS**
- **`t4-hybrid-sourcemap-chain`**：公开 `.js.map` 虚拟源码提取桥接 + `replayTrafficSequence` 两步 `stepToken` 提取重放 + 黑盒发现反向源码定位 — **PASS**
- **`t5-hardened-zero-vuln`**：全加固 RBAC 服务零误报排除 + 信念收敛转向评估 + `<= 15` 轮快速收敛至 `sealed_negative` — **PASS**
- **五大硬门禁**：`recallRate === 1.0`、`falsePositiveRate === 0`、`vaultLeakCount === 0`、`hardenedSealTurns <= 15`、`calibrationBrier <= 0.25` — **OVERALL PASS**

## 三、阶段门禁（`tests/gates/run.sh`）

| 门禁 | 结果 | 说明 |
|---|---|---|
| `g0_baseline` | PASS | 基础契约与历史兼容基线 |
| `g1_r1` | PASS | 日志、锁与恢复核心门禁 |
| `g2_r2r7` | PASS | 预算、证据与策略门禁 |
| `g3_v4` | PASS | v4 原生扩展、血缘、KB 与沙盒门禁 |
| `g4_v5` | PASS | v5 会话差分、Sidecar/Egress、OOB、假设图与 L1 10 场景靶场门禁 |
| `g5_v51` | PASS | v5.1 三元组去重、封盘、派单守卫、看门狗与全工具范围护栏门禁 |
| `g6_v6` | PASS | v6.0 版本一致性、离线构建、`omp/graph.ts < 2500` 行、`nuwa-mcp`、L2 基准与六大引擎全链路接线门禁 |
