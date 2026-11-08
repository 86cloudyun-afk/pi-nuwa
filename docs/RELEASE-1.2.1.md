# 女娲模式 1.2.1 — 交付审计修复

日期：2026-11-08
审计：codex-cli 0.164.0 / `gpt-6.1-sol` / `model_reasoning_effort=ultra`，只读沙盒
第一轮：1.2.0 commit `66cdbcb` → **block，35/100**
第二轮：1.2.1 commit `ef94baa` → **block，45/100**（B1/B3/M6/M8/m1 关闭，其余 partial）
本文件记录第二轮之后的修复；状态按源码实际能力标注，不把 partial 写成 closed。

## 第二轮后的修复

| ID | 第二轮状态 | 本轮处理 | 当前 |
|---|---|---|---|
| B2 | partial：replay 与 GC 半新半旧 | `Journal.snapshot()` 在 `journal.lock` 内一次性取 recovery + 全量记录；`replay_state` 改用 snapshot | closed |
| B4 | partial：`ledger_settle` 未列入未决 | `PENDING_EVENTS` 加 `ledger_settle`；dispatch 失败/拦截/缺 payload 全路径补 `ack` | closed |
| B5 | partial：replace 解码与尾读分裂 | `_iter_records` 改 bytes + 严格 UTF-8，与 `_tail_seq` 同口径；坏行整行跳过 | closed |
| B6 | partial：多级祖先、文件链接、TOCTOU | `resolvePath` 向上找最近存在祖先 realpath + 文件 `readlink`；`apply_patch` 正文目标单独提取 | closed（TOCTOU 仍属宿主写入边界，见下） |
| B7 | partial：全局选项与绝对路径 | `COMMIT_RE` 支持 `(?:\S*/)?sapper` 与 `--store/-s <path>`；`--from` 不再放行 | closed |
| B8 | partial：cap.json 未保护 | `PATH_RULES` 增加 `budget/cap.json`、`budget/freeze.json`、`.nuwa/recovery.json` | closed |
| B9 | partial：回退分支仍绕过 | 默认 `cli`；无 CLI/引擎直接退出 3，不再静默回退；`NUWA_SUBMIT_MODE=sapper` 为显式遗留模式并记 `dispatch_legacy` | closed |
| B10 | 新增：recovery.json 未保护 | 同上路径规则 | closed |
| B11 | 新增：inflight 并集复活终态 | recovery 合并后按 committed 集合剔除 inflight；`replay_state` 从 snapshot 起算 | closed |
| M1 | partial：补丁正文目标遗漏 | `collectPatchTargets` 提取 `*** Add/Update/Delete File:` 与 `+++ b/` 目标 | closed |
| M2 | partial：多 fact 与关联 | `--from` 支持逗号/空白分隔多个 fact，逐个校验 kind；带 `[nuwa:key]` 的证据要求键可回溯 | partial：未强制 fact 必须挂在某个 intent 的 `to` 上 |
| M3 | partial：attempt 锁外读取、键吸收 | `txn.commit(key=None)` 在 `txn.lock` 内生成规范键；已由其他键完成的 intent 直接报冲突，不再吸收 | closed |
| M4 | partial：Infinity/非整数 samples | `_number` 拒绝非有限数与溢出；samples 必须整数 | closed |
| M5 | partial：duration 未交叉核对 | `duration` 与 `finished-started` 误差 >5% 判失败；`--expect-commit` 库层与 CLI 均生效 | closed |
| M9 | 新增：check_prompt 误伤 | `check_prompt` 只查 P-001..P-004；P-006 移到 `check_command`（工具层） | closed |
| M10 | 新增：`complete --from` 绕过 kind | P-006 一律拦 `sapper complete`；完成只走 `nuwa complete` | closed |
| M11 | 新增：gen 字典序 | `_files()` 按代号数字排序 | closed |
| M12 | 新增：URL 循环不 repair | 收工前调用 `nuwa recover --repair` | partial：循环内单条失败仍不即时 repair |
| M13 | 新增：repair 重复结算 | `Ledger.settle` 按 rid 幂等；失败路径写 `ack` | closed |
| M14 | 新增：admit/reserve 分离 | `Ledger.admit_reserve` 在同一把 `global.lock` 内检查并预留 | closed |
| M15 | 新增：关闭表把 partial 写成 closed | 本文件重写为真实状态 | closed |
| m4 | 新增：子命令转发早于 env | case 分支内 exec 前 source `env.sh` | closed |

## 仍然存在的边界

- **TOCTOU**：扩展在 `tool_call` 检查路径，宿主在检查之后才写入。扩展层无法原子锁住文件系统；
  真正的收口在 CLI/宿主写入边界。当前策略把「普通输入可绕过」压到「检查后替换链接」这一类竞态。
- **M2 的 intent 关联**：`sapper flag` 直接采集的 flag 没有 intent 归属，强制关联会误伤；
  当前只校验 kind 与 `[nuwa:key]` 可回溯。
- **M12 的循环内 repair**：URL 循环是并行 shell 子进程，逐条 repair 会与在跑事务抢锁；
  当前在收工前统一 repair。
- **真实 sapper**：`contract_check` 与 real 崩溃组仍需要 PATH 中的真实实现；本机只有替身。

## 判据

新增反例：gen9/gen10 排序、坏 UTF-8 行、recovery inflight 复活、ledger_settle 未决保护、
`--store`/绝对路径 sapper、apply_patch 正文、多级祖先符号链接、`nuwa complete` 放行、
有限数/整数 samples、duration 一致性。

全量读数见 `docs/TEST-RESULTS.md`。
