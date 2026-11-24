# 自渗透与自动富化执行器（v3.0）

目标：把「确定性侦察、结构化派生、知识库富化与容错重试」收进 omp 扩展自动闭环，让模型专注需要推理判断的高价值任务。

## 1. 空转的三个形态与治理演进

| 形态 | 现象 | v3.0 治理策略 |
|---|---|---|
| 只想不做 | 模型只输出文本不调工具 | 二维空转闸：无工具且无新事实累计 `emptyRounds`（默认 3 轮）即收口模型批 |
| 长 turn 误杀 | 模型连续多轮查日志/分析暂未 commit | 二维空转闸：有工具活动但无新事实改计 `suspectRounds`（默认 5 轮），避免误伤 |
| 网络抖动耗尽尝试 | 临时断网/超时把 `attempts` 烧光转 blocked | 失败三分类：`network` 释放回 `open` + `nextRunAt` 冷却重试，不消耗 `attempts` |
| 反复试探 / frontier 注水 | 同一意图失败超限或低价值兜底 | `attempts >= NUWA_MAX_ATTEMPTS` 自动 blocked；阶段将尽或 `stall >= 3` 生成战略复盘意图引导 `nuwa_plan` |

## 2. 架构与单轮闭环

```text
session_stop
  ├─ shouldReincarnate   无头守护下 token/genTurns 达标 → 中止/释放自动批 → 写 handoffSummary → 放行换代
  ├─ applyEmptyGuard     二维空转闸（emptyRounds / suspectRounds）
  ├─ autoPlan            复盘(reflect) → 补播 → 事实派生(deriveFromFacts) + KB 富化(deriveKbIntents) → 推进 → 新 episode → 兜底
  ├─ claimAutoBatch      白名单 key（经 canonicalAutoKey 剥离 e<N>:）且冷却到期 → claimed(worker=auto)
  ├─ buildDirective      只给模型判断类任务 + 标明「自动批在跑」
  └─ runAutoBatchManaged 异步受控批次（90s 总预算 + 并发控制 + AbortSignal）
       ├─ exec → parse（产出结构化 meta）
       ├─ 成功：锁内 commitIntent + 立即回灌 deriveFromFacts + deriveKbIntents（写 auto-derive 事件）
       ├─ network 失败：回退 attempts + 设 nextRunAt 冷却 + 累加 runtime.netRetries
       └─ blocked_by_waf / empty：写 blocked 并标注 WAF 或空结果特征
```

开局防抢跑：在 `/nuwa <任务>` 且 `pi.exec` 可用、或显式 `nuwa_init({ autoStart: true })` / `NUWA_AUTO_ON_INIT=1` 时立即拉起首轮自动批；普通 API 初始化（如单测 `nuwa_init -> nuwa_claim("i001")`）不抢跑以保证 100% 向后兼容。

## 3. 内置规则与跨平台升级（Issue #1）

| 规范化 key | 探测方式 | 结构化 `AutoFactMeta` | 超时 |
|---|---|---|---|
| `recon:http` | `curl -k -sS -D - -o body` | `server`, `tech`, `status`, `waf` | 18s |
| `recon:ports` | `python3 -c` 短超时并发 `socket.create_connection`（彻底去除 GNU `timeout` 与 `/dev/tcp`，兼容 macOS/Linux/IPv4/IPv6） | `ports`（同时 `detail` 含 `<port>/tcp`） | 50s |
| `recon:dirs` | 23 条常见路径探测 | `paths`, `status`, `waf` | 45s |
| `recon:tlsjs` | `openssl s_client + x509`（全面 `shellQuote` 与超时保护） | `san`（Scope 内新域名自动派生资产枚举） | 15s |
| `surface:sensitive` | robots/.git/.env/backup/config 等 6 条只读探测 | `paths`, `status`, `waf` | 32s |
| `surface:api` | openapi/swagger/graphql 等 5 条只读探测 | `paths`, `status`, `waf` | 28s |

- **E2+ 轮次归一化**：`canonicalAutoKey("e2:recon:http") === "recon:http"`，第 2 轮及后续扩张生成的种子意图同样可被自动批识别并执行。
- **结构化回灌**：`deriveFromFacts` 优先读取 `fact.meta.ports` / `fact.meta.paths` / `fact.meta.san`（同时兼容正则解析 `title`/`detail`/`output`），并联动 `deriveKbIntents` 自动查询本地知识库派生 `kb:<fid>:<slug>`（`priority=86`, `phase="vuln"`）。

## 4. 外置 JSON 规则热更新（Issue #2）

`loadAutoRules(root?, agentHome?)` 按以下优先级加载规则表，按文件 `mtimeMs` 缓存，修改后无需重启 omp 扩展即刻生效：

1. 项目级：`<root>/.nuwa/autoexec.json`
2. 用户全局：`<agentHome>/nuwa-autoexec.json`
3. 内置默认：`AUTO_RULES`

安全约束：
- 外置 JSON 仅允许绑定内置安全解析器（`parse`: `"http" | "ports" | "dirs" | "tls" | "probe"`），不执行任意外部 JS/TS 代码；
- 若 JSON 格式非法或字段校验失败，自动降级回内置规则，并在返回结果中携带 `error` 告警，同时在 `nuwa_status` 展示 `rules=<source>`。

示例 `.nuwa/autoexec.json`：

```json
{
  "rules": [
    {
      "key": "surface:api",
      "phase": "surface",
      "parse": "probe",
      "timeoutMs": 20000,
      "paths": ["/openapi.json", "/v3/api-docs", "/graphql", "/healthz"]
    }
  ]
}
```

## 5. 失败三分类与冷却重试（Issue #3）

`classifyAutoFailure(res)` 对无产出的自动批执行结果做三分类：

| 类别 | 识别特征 | 处理动作 |
|---|---|---|
| `network` | curl 退出码 `6/7/28`、`killed`、超时、连接重置/拒绝 | 意图释放回 `open`，设置 `nextRunAt = now + retryAfterMs`（默认 `60000ms`），**回退本次 `attempts`**，`runtime.netRetries++`；`pickAuto` 自动跳过未到冷却期的意图 |
| `blocked_by_waf` | HTTP `403`/`406`/`429` 且命中 WAF / challenge / rate-limit 特征 | 标记 `blocked` 并记录 `waf` 特征，触发换路与派生思路 |
| `empty` | 正常通信但无有效命中 | 按常规 `blocked` 收口，避免无意义重试 |

## 6. 预算、并发控制与取消（Issue #5）

`runAutoBatchManaged(ids, st, exec, root, opts)` 解决长批阻塞与停机残留问题：

- **单批总预算**：默认 `NUWA_AUTO_BUDGET_MS=90000`（90 秒），预算耗尽后不再启动剩余规则，未跑意图通过 `onBudgetSkip` 释放回 `open` 并记 `auto_budget` 事件；
- **并发度控制**：默认 `NUWA_AUTO_CONCURRENCY=1`；并发设为 `2` 时，`recon:ports` 依然保持独占执行，避免端口探测与其他规则互相抢占连接与带宽；
- **即时取消**：运行时按 `root` 维护 `AbortController`，触发 `nuwa_stop`、`/nuwa stop`、`session_shutdown` 或世代轮转 `reincarnate` 时立即 `abort()`，释放未完成意图并记 `auto_aborted`。

## 7. 边界与安全护栏联动

- 自动批仅执行只读、秒级、可结构化解析的侦察动作，不替代全端口深度扫描、大字典枚举或复杂业务逻辑分析（这些仍由 `fujiang` 子代理执行）。
- 所有工具执行输出同步记入 `.nuwa/exec-ledger.jsonl`，并受 `omp/scope.ts` 范围策略（`N-007`/`N-008`）保护。

## 8. 配置一览

| 变量 | 默认 | 作用 |
|---|---|---|
| `NUWA_AUTO` | `1` | `0` 关闭自动批（回到纯模型驱动） |
| `NUWA_AUTO_MAX` | `3` | 每轮自动批上限 |
| `NUWA_AUTO_BUDGET_MS` | `90000` | 单批自动执行总时间预算（毫秒） |
| `NUWA_AUTO_CONCURRENCY` | `1` | 自动批并发度（`recon:ports` 始终独占） |
| `NUWA_AUTO_ON_INIT` | `0` | `1` 允许 `nuwa_init` 立即触发首轮自动批 |
| `NUWA_EMPTY_LIMIT` | `3` | 无工具且无新事实的空转收口阈值 |
| `NUWA_SUSPECT_LIMIT` | `5` | 有工具但无新事实的疑似空转收口阈值 |
| `NUWA_MAX_ATTEMPTS` | `3` | 单意图尝试上限（`network` 重试不消耗） |

## 9. 验收

```bash
./run-tests.sh
# 独立测试自渗透与护栏模块：
env -u BUN_OPTIONS bun test --isolate tests/autoexec.test.ts tests/scope_evidence.test.ts tests/nuwa_v3_core.test.ts
```
