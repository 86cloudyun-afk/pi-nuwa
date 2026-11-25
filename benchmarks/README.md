# pi-nuwa Offline Deterministic Benchmarks / 离线确定性安全评估基准套件

本目录提供 `pi-nuwa` 的 **100% 离线、确定性、零外部依赖** 安全评估回归基准套件。所有 HTTP 交互均运行在本地 `127.0.0.1` 随机空闲端口的良性合成模拟服务（`mock-bench-server.ts`）上，不依赖外部网络或真实 LLM API，可用于 CI 回归门禁与核心算法指标量化对比。

This directory provides a **100% offline, deterministic, zero-dependency** security evaluation benchmark suite for `pi-nuwa`. All HTTP probes run against benign synthetic endpoints served on an ephemeral local `127.0.0.1` port (`mock-bench-server.ts`), making it suitable for CI gates and reproducible metric comparisons.

## 快速运行 / Quick Start

```bash
# 人类可读表格输出 / Human-readable table output
env -u BUN_OPTIONS bun benchmarks/run-eval.ts

# 确定性 JSON 输出（适合 CI 采集与趋势对比）/ Deterministic JSON output for CI
env -u BUN_OPTIONS bun benchmarks/run-eval.ts --deterministic --json

# 仅运行单个场景 / Run a single scenario by ID
env -u BUN_OPTIONS bun benchmarks/run-eval.ts --scenario vault-leak-sarif-redaction
```

退出码 / Exit codes:
- `0`: 所有场景通过且 `vaultLeakCount === 0` / All scenarios passed with zero Vault leaks.
- `1`: 存在失败场景或检测到 Vault 凭据泄露 / One or more scenarios failed or a Vault leak occurred.
- `2`: CLI 参数错误或场景 ID 不存在 / Invalid CLI flag or unknown scenario ID.

## 内置 10 个基准场景 / Included Scenarios (`targets.json`)

| ID | 类别 / Category | 预期判定 / Expected Verdict | 验证模块 / Verified Capabilities |
|---|---|---|---|
| `spa-soft404-trap` | `recon-hygiene` | `no_false_positive` | `parseSoft404Baseline`, `isSoft404Hit` 抑制 SPA 200 兜底页误报 |
| `dual-role-bola-idor` | `authorization` | `confirmed_bola` | `session-vault` 头文件物化、脱敏差分派单与跨用户 BOLA 识别 (`NUWA-BOLA` / `CWE-639`) |
| `vertical-bfla-admin` | `authorization` | `confirmed_bfla` | 低权用户访问管理指标接口垂直越权识别 (`NUWA-AUTH` / `CWE-287`) |
| `auth-spa-bundle-api` | `surface-discovery` | `endpoints_discovered` | `runSpaRecon` 静态 Bundle 解析 (`/api/v2/invoices`, `/graphql`) 与鉴权后管理 Bundle 提取 |
| `waf-429-rate-limit` | `resilience` | `blocked_by_waf` | `classifyAutoFailure` 对 HTTP 429 + `Retry-After` 的限流分类 (`rate-limit`) |
| `blind-ssrf-oob-mock` | `oob-verification` | `confirmed_ssrf_oob` | `oobDomains` 范围白名单放行/拦截与 Interactsh 兼容 OOB 金丝雀回连 (`NUWA-SSRF` / `CWE-918`) |
| `mixed-tech-attribution` | `knowledge-base` | `precise_attribution` | `resolveIntentTechKeys` 与 `distillProjectExperience` 精准归因防污染、跳过 candidate |
| `false-positive-verifier-catch` | `verifier-gate` | `false_positive_rejected` | `shouldStageAsCandidate`、防绕过校验、双盲驳回与 SARIF 严格排除误报 |
| `local-whitebox-audit` | `whitebox-audit` | `ledger_verified` | 本地目录目标归一化、执行账本实质性核验与通用 HTTP 响应头拦截 |
| `vault-leak-sarif-redaction` | `secret-hygiene` | `zero_vault_leaks` | Markdown / JSON / SARIF 2.1.0 / `.nuwa/poc-bundle/` 全量脱敏、`0o700`/`0o600` 权限与 SHA-256 校验 |

## 指标说明 / Metrics Reference

- `totalScenarios` / `passedScenarios`: 运行场景总数与通过数。
- `passAt1Rate`: 首次通过率（`passedScenarios / totalScenarios`，范围 `0..1`）。
- `falsePositiveCount` / `falsePositiveRate`: 误报计数与误报率（理想值为 `0`）。
- `verifierCatchRate`: 双盲复验闸门对刻意注入误报的拦截率（理想值为 `1.0`）。
- `vaultLeakCount`: 在所有报告、派单文本及取证包文件中检出的原始 Vault 敏感凭据泄露次数（**硬性门禁必须为 `0`**）。
- `estimatedTokensPerFinding`: 按确认发现数估算的单漏洞 Token 开销基线。
- `wallTimeMs`: 基准测试总耗时（毫秒）。

## 新增场景 / Adding a Scenario

1. 在 `benchmarks/targets.json` 追加场景元数据（`id`、`name`、`category`、`expectedVerdict`、`description`）。
2. 如需新的本地合成 HTTP 行为，在 `benchmarks/mock-bench-server.ts` 中添加良性 `127.0.0.1` 路由。
3. 在 `benchmarks/run-eval.ts` 的 `RUNNERS` 映射中注册同名执行函数，确保仅使用临时目录并在 `finally` 中自动回收。
4. 运行 `env -u BUN_OPTIONS bun benchmarks/run-eval.ts --deterministic --json` 验证全绿且 `vaultLeakCount === 0`。
