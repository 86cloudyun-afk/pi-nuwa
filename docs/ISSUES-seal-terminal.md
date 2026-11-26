# `sealed_negative` 终态不可复活与观测问题全量闭环（PR #55 / P1–P8）

- **来源**：PR #55（`fix/seal-terminal-resume`）及实际运行观测项 P1–P8
- **适用版本**：v6.0.0（同步覆盖 `omp/nuwa.ts`、`omp/graph.ts`、`omp/reporting.ts`、`omp/ui.ts`、`core/mcp-server.ts` 与 `bin/nuwa-autonomous`）
- **严重级**：Critical（负向封盘失效导致永动引擎无法收敛与 episode 空转）
- **状态**：P1–P8 已全部完成闭环修复并通过本地全量测试与多后端门禁验证

## 一、核心问题复现与根因

1. `nuwa_complete(seal=true, reason=…, excluded_surface=[…])` 将项目推进至 `status=sealed_negative`，`state.json` 已写入 `completedAt` 与 `sealMeta`。
2. 引擎续航调用 `nuwa_init(resume=true)`、用户执行 `/nuwa resume` 或 `/nuwa <target>` 时，原有 resume 分支未检查终态，直接覆盖写入：

```ts
s.project.status = "active";
s.project.stopReason = undefined;
s.runtime.status = "active";
```

从而形成“封盘字段仍在、状态却被复活为 active”的半封盘状态，驱动循环开启新一轮空转 episode。

## 二、P1–P8 全量闭环修复清单

| 编号 | 现象描述 | 根因与处置策略 | 状态 |
|---|---|---|---|
| P1 | `nuwa_init(resume=true)` 复活 `sealed_negative` | 在 `omp/nuwa.ts` 与 `core/mcp-server.ts` 中，若项目已处于终态（`sealed_negative` / `completed`），`resume=true` 绝不重置状态字段为 `active`，仅记录原终态并返回不可复活提示 | 已修复 |
| P2 | `/nuwa resume` 复活终态或误触发 `kick` 续航 | 在 `omp/nuwa.ts` `/nuwa resume` 分支增加终态守卫，直接原样返回当前终态，禁止后续 `kick(...)` 续跑 | 已修复 |
| P3 | `/nuwa <target>` 在命中终态目录时重新派生意图 | 在 `/nuwa <target>` 命中已有项目后增加终态检查，`return null` 拒绝新派生意图，提示换 `root` 或使用 `nuwa_init(force=true)` 明确重建 | 已修复 |
| P4 | 跨会话 `nuwa_init(resume=true)` 报“属于其他 omp 会话”导致终态不可查看 | 当 `ownerSessionId !== sid` 且不传 `force=true` 时，若参数包含 `resume=true` 且目标项目为终态（`sealed_negative` / `completed`），自动降级为只读 resume 查看且不覆盖磁盘 `ownerSessionId`（同步覆盖 `omp/nuwa.ts` 与 `core/mcp-server.ts`） | 已修复 |
| P5 | 驱动头 `buildDirective` 仍显示 `status=active`，与 `nuwa_status` 不一致 | `omp/graph.ts` `buildDirective` 将终态语义统一为 `effectiveStatus = rt.status === "sealed_negative" ? "sealed_negative" : p.status`，使指令头与 `nuwa_status` 对齐 | 已修复 |
| P6 | `blockedIntents`（`121→120`）与 `blockedCommits`（`461`）口径差异 | 经代码核对属于预期双口径设计：`blockedIntents` 为当前内存中保留的 blocked 意图数（受 `compactIntents` 默认 120 上限裁剪防内存膨胀），`blockedCommits` 为历史累计 `blocked=true` 提交总次数 | 已核对（按预期设计保留并补充测试校验） |
| P7 | 封盘或完成后 `.nuwa/REPORT.md` 仍停留在旧 `active` 状态 | `omp/reporting.ts` 增加 `sealed_negative` 专属状态展示及 `## 负向封盘说明（Sealed Negative）` 章节；`nuwa_complete`（含 `seal=true`）、`/nuwa seal` 与 MCP `nuwa_complete` 在落盘时自动重写 `.nuwa/REPORT.md`（及已存在的 `REPORT.json` / `REPORT.sarif.json`）并同步更新归档索引 | 已修复 |
| P8 | 封盘或收口时 `runtime.tokens=0` 而 `totalTokens>0` | `nuwa_complete`（及 `/nuwa seal`）在终态结算时从 `ctx.getContextUsage()` 实时写入当前代 `runtime.tokens`（防止未经过 `session_stop` 时最后一轮丢成 `0`），同时 `nuwa_status`、`omp/ui.ts`、`omp/reporting.ts` 与守护器均按 `totalTokens = runtime.totalTokens + runtime.tokens` 汇总暴露，绝不重复计数 | 已修复 |

同时，`bin/nuwa-autonomous` 主循环已同步兼容 `sealed_negative` 终态（含 `waitWhilePaused`、`preState`、`postState`、`finalState` 与 `formatCompletionSummary`），检测到 `sealed_negative` 即干净汇总退出码 `0`，绝不会触发无意义的下一代轮转。
