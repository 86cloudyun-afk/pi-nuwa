# 女娲模式 1.2.1 — 交付审计修复

日期：2026-11-08
审计：codex-cli 0.164.0 / `gpt-6.1-sol` / `model_reasoning_effort=ultra`，只读沙盒
对象：1.2.0 commit `66cdbcb`（基线 `0dbbdb0`）
结论：**block，35/100**（B1–B9 阻断，M1–M8 major）

## 审计指出的根因

1.2.0 把「能跑」当成了「可交付」：journal 的 seq/GC 只在正常路径成立，策略只覆盖了
最朴素的命令/路径形态，URL 入口仍绕过事务提交。审计据此判 block 是对的。

## 逐条关闭

| ID | 问题 | 修复 |
|---|---|---|
| B1 | compact 代号复用，CURRENT 未发布时会覆盖归档 | `_next_gen_locked()` 取 `max(CURRENT, 现有 journal/checkpoint)+1`，rename 前检查目标 |
| B2 | compact 不持锁，append 与 read 可读到半写/换代的混合视图 | `append/compact/gc/read` 共用 `journal.lock`；read 在锁内取稳定快照 |
| B3 | `last_seq` 忽略 checkpoint 高水位，空代 GC 后 seq 回 0 | `_checkpoint_high()` 并入高水位；空代删除后 seq 仍单调 |
| B4 | GC 删掉含未决事务的代，replay/recover 丢依据 | `_pending_floor_locked()` 保护未决代；删除前写 `recovery.json`，`replay_state` 从摘要起算 |
| B5 | 尾读固定 8192 字节，超长记录/UTF-8 切点会返回 0 | 窗口按需翻倍直到行首，编码错误按坏行跳过 |
| B6 | 路径规则只看字面量，`..`、符号链接、反斜杠、相对 cwd 可绕过 | `resolvePath()` 归一（cwd、`..`、file://、realpath/父目录 realpath），递归收集 `files[]/edits[]` 路径字段 |
| B7 | P-006 只认行首/分号，`&&`、管道、`$()`、引号、`\sapper` 可绕过 | 分隔符扩到 `; & | ( ) 换行 空白 引号 反引号`，允许 `\` 与 `$(` |
| B8 | P-007 只保护 `.nuwa/global*.jsonl`，真实账本在 `budget/global.jsonl` | 增加 `budget/*.jsonl` 规则（TS/Python 同步） |
| B9 | URL 入口直接 `sapper dispatch`，绕过 nuwa 事务/账本 | `dispatch_one` 默认走 `nuwa dispatch`；无引擎或 `NUWA_SUBMIT_MODE=sapper` 时回退并记 `dispatch_fallback` |
| M2 | 续跑指令要求 `sapper complete`，与 P-006 冲突 | 新增 `nuwa complete --from <fact>`，校验 kind=flag/vuln/loot；裸 `sapper complete` 仍拦 |
| M3 | `x-nuwa-attempt` 在 CLI 回退 0、dispatch 抛错，两路不一致 | `txn.attempt_of()` 严格非负整数/十进制字符串，两路共用 |
| M4 | `night.verify` 对类型异常崩溃，字符串 `"false"` 被当真 | 严格 schema：数值字段、四个必需判据键、布尔真值 |
| M5 | 旧 REPORT + 旧 COMMIT 可通过，执行期间换提交归属漂移 | REPORT 记录 `started_at/finished_at/duration_seconds`；校验实际时长；`--expect-commit` 绑定提交 |
| M6 | `bin/nuwa` 未转发 `soak-night` / `soak-verify` | 子命令表补齐，并加 `flag` / `complete` |
| M8 | `g1` 返回码取最后一条，早期套件失败可被覆盖 | 逐项 `|| fail=1`，最后统一退出 |

## 次要项

- m1：`gc` 注释改为「keep=2 当前代 + 上一代；keep=1 仅当前代」。
- m3：新增 `nuwa flag`，README 说明 flag 属证据采集、P-006 只约束 done/dispatch/complete。
- m2：`fake-sapper` 的 `FAKE_ENGINE_MODE` 只用于 e2e 反例，RELEASE 明确它是替身行为，
  真实引擎的 malformed 覆盖留在 CI（需真实 sapper）。

## 判据

- 新增反例：空代 GC 高水位、CURRENT 缺失不覆盖、未决事务代保护、recovery 摘要、
  20KB 单条记录、并发 append+compact、路径 `..`/符号链接、`&&`/`sh -c`/`$()`/反斜杠、
  真实账本路径、task context 字段、`complete` 证据闸门、attempt 严格校验、verify 类型/提交绑定。
- 全量测试读数见 `docs/TEST-RESULTS.md`；`contract` 仍因本机无真实 sapper 退出 2。

## 修复后读数（本机）

| 套件 | 用例 | 结果 |
|---|---|---|
| unit | 37 | 全过 |
| shell | 14 | 全过 |
| chaos | 8 | 全过 |
| concurrency | 5 | 全过 |
| e2e | 4 | 全过 |
| r1 core | 23 | 全过 |
| r1 dispatch / run / multi | 2 / 1 / 1 | 全过 |
| crash matrix | 16 runs | 全过 |
| r2–r7 | 28 | 全过 |

合计 123 例 + 16 runs；`contract` 仍因 PATH 中没有真实 sapper 退出 2，`g0_baseline`
随之报缺依赖。URL 入口实测 28 facts 全部带 `[nuwa:sha256:…]` 键。
