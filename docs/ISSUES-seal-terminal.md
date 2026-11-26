# sealed_negative 被 resume 复活（封盘不可终止）

- 版本：5.1.0 部署态实测；v6.0.0 `omp/nuwa.ts` 同一代码路径仍存在（三处未加终态守卫）
- 严重级：Critical（负向封盘失效，永动引擎无法收敛，产生 episode 空转）
- 状态：已修（本分支）

## 复现

1. `nuwa_complete(seal=true, reason=…, excluded_surface=[…])`
   → 返回 `ok=true · status=sealed_negative`，`state.json` 写入 `sealMeta` 与 `completedAt`。
2. 引擎续航调用 `nuwa_init(resume=true)`（或手动 `/nuwa resume`、`/nuwa <target>`）。
3. 读盘：

```json
{ "project.status": "active", "runtime.status": "active",
  "project.completedAt": "2026-11-26T06:06:57.031Z",
  "project.sealMeta.sealedAt": "2026-11-26T06:06:57.031Z" }
```

封盘字段存活、状态字段被覆写，形成"半封盘"；驱动随即开启下一 episode。

实测：13 个 episode（E1–E13）反复封盘-复活，`blockedCommits=461`、`flags=0`，
仅在补丁后完成一次有效收口（`turns=124`）。

## 根因

三处 resume 分支无条件重置状态：

```ts
s.project.status = "active";
s.project.stopReason = undefined;
s.runtime.status = "active";
```

未检查 `sealed_negative` 终态。

## 修复

- `nuwa_init(resume=true)`：命中终态仅重绑 `ownerSessionId`，以 `resume-sealed-noop` 落盘后原样返回；
- `/nuwa resume`：命中终态直接返回 `s`，不覆写；
- `/nuwa <target>`：命中终态 `return null` 拒绝派生意图，并给出明确文案（换 root 或 `nuwa_init(force=true)` 重建）。

## 验证

- 重封后连续两次 `nuwa_status` 均为 `sealed_negative`；
- 读盘 `project.status=runtime.status=sealed_negative`，`completedAt=2026-11-26T06:10:10.930Z`；
- `bun build omp/nuwa.ts --target=bun` 通过；
- 补丁在 5.1.0 baseline 上 `patch -p1` 可重放。

## 相关但未在本分支处理的观察

| 编号 | 现象 | 说明 |
|---|---|---|
| P4 | 跨会话 `nuwa_init(resume=true)` 报“属于其他 omp 会话” | 封盘项目无法只读绑定；建议终态时降级为只读 resume |
| P5 | 驱动头 `status=active` 与 `nuwa_status=sealed_negative` 不一致 | P1 修复后收敛 |
| P6 | `blockedIntents 121→120` 而 `blockedCommits` 恒 461 | 计数器口径漂移 |
| P7 | 封盘后 `REPORT.md` 头部仍 `状态: active · 完成: -` | 需再次 `nuwa_report(write=true)`；建议 seal 内自动重写 |
| P8 | `runtime.tokens=0` 而 `totalTokens=2372342` | 统计口径 |
