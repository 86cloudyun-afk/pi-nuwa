# 女娲模式 1.2.1 — 交付审计修复

日期：2026-11-08
审计：codex-cli 0.164.0 / `gpt-6.1-sol` / `model_reasoning_effort=ultra`，只读沙盒

| 轮次 | 对象 | 结果 | 主要残留 |
|---|---|---|---|
| 1 | 1.2.0 `66cdbcb` | block，35/100 | B1–B9、M1–M8 |
| 2 | 1.2.1 `ef94baa` | block，45/100 | B2/B4–B9 partial；新增 B10/B11/M9–M15 |
| 3 | 1.2.1 `4fc3463` | block，50/100 | 新增 B12（预算拒绝虚假结算）、B13（覆写 intent.to）；B5/B6/B7/B11 partial |
| 4 | 1.2.1 `d876cd6` | block，53/100 | B7 回归（`-s PATH`）、B13 快路径、M22–M24 恢复/账本口径 |
| 5 | 1.2.1 `774f517` | 待复审 | 本轮修复见下 |

本文件按第四轮复审前的源码状态标注，不把 partial 写成 closed。

## 第三轮后修复

| ID | 第三轮状态 | 本轮处理 | 当前 |
|---|---|---|---|
| B5 | partial：尾部缺 seq 对象让尾读返回 0 | `_tail_seq` 对缺 seq/非对象记录继续向前，直到找到正整数 seq 或文件头 | closed |
| B6 | partial：bash 重定向/复制完全跳过路径规则 | `collectShellTargets` 提取 `>`/`>>`/`tee`/`cp`/`mv`/`install` 的全部路径参数并走同一套归一化 | partial：检查与写入仍有 TOCTOU |
| B7 | regressed：`-s PATH` 分离形式漏检 | `COMMIT_RE` 改为 `-s(?:\s+\S+|\S*)`；补回归用例 | closed |
| B11 | partial：ack 后 inflight 不清理 | `_summarize`/`replay_state` 在 `ack` 时 pop；recovery 增加 `ended` 集合并剔除 | closed |
| B12 | 新增：预算拒绝后 repair 凭空结算 4000 | 拒绝路径写 `ack`；`repair` 只对 `ledger.has_reserve(rid)` 的预留结算 | closed |
| B13 | partial：dispatch 复用快路径绕过冲突检查 | commit 冲突前置；dispatch 命中 existing 时校验 `intent.to == existing.id` | closed |
| M1 | partial：补丁目标误取时间戳/`/dev/null` | 过滤 `(date)` 后缀、`/dev/null`，增加 `*** Move to:` | closed |
| M2 | partial：键回溯自证、空格列表不识别 | `--from` 改 `nargs="+"`；一次建 facts/intents 映射；带 marker 的证据必须挂在已完成 intent 的 `to` 上 | partial：`sapper flag` 无 marker 仍允许直接入账 |
| M3 | partial：辅助键不参与冲突/查重 | `find_fact_by_key` 读 `x-nuwa-key`；冲突集合并入该字段 | closed |
| M5 | partial：伪造起止仍可通过 | duration 与起止差 >5% 判失败；`--expect-commit` 绑定 | partial：未用独立产物重算 verdict |
| M11 | partial：活动文件先读，旧代覆盖新 ack | `_files()` 改为归档按代号升序 + 当前文件最后 | closed |
| M12 | partial：payload 异常跳过结算；`recovered_crashed` 非终态 | payload 解析包 try 并落 `ledger_settle`+`ack`；`recovered_crashed` 纳入 `TXN_DONE` | closed |
| M16 | 新增：键回溯 O(M×N) | `graph.facts`/`graph.intents` 各读一次建 map | closed |
| M17 | 新增：recover/repair 未接 recovery 摘要 | `_snapshot_state` 读 snapshot 的 committed/ended，pending 先减终态 | closed |
| M18 | partial：末尾固定 `exit 0` 使失败判断失效 | 末尾改 `exit $failed`；legacy 事件前置 | closed |
| M19 | partial：首次 detach 的 `nuwa.log` 触发非空目录拒绝 | 非空检查排除 `nuwa.log`；detach 仍在锁前 | closed |
| M20 | 新增：同 intent 并发各自预留 | dispatch 在预留前检查 inflight 锁 | partial：worker 拿锁后仍未复查 attempt |
| M21 | 新增：关键状态转移缺测试 | 补预算拒绝 repair、ack 摘要、多 fact、其他键冲突、`--store=`、bash 写入、Infinity/分数 samples | partial：并发确定性交错仍缺 |
| M15 | 新增：关闭表夸大 | 本文件按源码能力标注 | closed |

## 第四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| M17 | 摘要未保留 rid/tokens，repair 降为 4000 | `executing_prepare` 写入 rid/tokens；摘要 inflight 保留；repair 取摘要值 |
| M22 | `has_reserve` 忽略 reclaim/重复 reserve | 改成按 rid 的最后一条账本事件判定 |
| M23 | `recovered_crashed` 后未 ack，摘要留幽灵 inflight | 摘要将 `recovered_crashed` 视为终态并 pop |
| M24 | 缺 seq 的 ack 不参与摘要；recover 忽略摘要 inflight | `_summarize` 按文件顺序扫描全部记录；`recover` 从摘要 inflight 起算 |

## 第五轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B5 | `splitlines()` 把 JSON 内的 CR 当换行，尾读拆碎记录 | 尾读改为只按 `\n` 分行 |
| B6 | `cd` 后相对写目标仍按原 cwd；`tee` 只查首个输出 | `shellBaseDir` 解析行首/分隔符后的 `cd`；tee/cp/mv 全部参数入检查 |
| M1 | 统一 diff 的旧路径 `--- a/` 未提取 | 增加 `---` 行解析，过滤 `/dev/null` |
| M3 | 冲突集合只认规范 sha256 键 | 改为任意 `[nuwa:<key>]`，辅助键参与冲突 |
| M5 | verdict 无独立锚点 | verify 读各项目 `.nuwa/journal.jsonl`，要求 `executing_prepare > 0` 且 facts 与 commit_done 差 ≤2 |
| M12 | `txn.commit` 抛异常时跳过结算/ack | commit 包 try，异常落 `ledger_settle`+`ack` |
| M17 | `done_apply` 被当作已完成；摘要缺 tokens | committed 只认 `commit_done`；`executing_prepare` 写 tokens/rid；repair 取摘要值 |
| M20 | attempt 不递增，迟到 worker 无法拒绝 | dispatch 写 `x-nuwa-attempt=attempt+1`；worker 拿锁后比对版本；done intent 直接复用 |
| B13 | validate 失败后 intent 已改盘 | 提交前快照 intent，validate 失败恢复 |

## 第七轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B5 | 尾窗起点落在坏行中间时残片被当合法 seq | 窗口 `start>0` 时跳过第一条不完整行 |
| B6 | `$(cd ...)` 与 `cd x > file` 的 cwd 时序 | `dirBefore` 不进入 `$()`，带重定向的 cd 不应用 |
| B7 | `--store="含空格"` 等号值、连续选项、长空白 | 等号值支持引号；选项组有限重复 `{0,2}` |
| B15 | `validate` 抛异常时不回滚 intent | validate 包 try，异常同样 `_restore_intent` |

## 仍然存在的边界

- **TOCTOU**：扩展在 `tool_call` 检查路径，宿主在检查之后写入；检查后替换链接仍可能绕过。
  真正的原子收口在宿主写入边界，扩展层只能把普通输入绕过压到竞态级别。
- **M2**：`sapper flag` 直接采集的 flag 没有 intent 归属；强制关联会误伤正常采集。
- **M5**：已用各项目 journal 的 `executing_prepare`/`commit_done` 做独立锚点；`verdict` 的 RSS/FD 仍是 soak 自报。
- **M20**：attempt 已持久递增，worker 拿锁后按版本拒绝；同 intent 的并发准入仍靠 inflight 锁，非分布式锁。
- **真实 sapper**：`contract_check` 与 real 崩溃组仍需要 PATH 中的真实实现。

## 判据

新增反例：尾部缺 seq、bash 重定向/复制、`--store=`/`-s`、预算拒绝 repair、ack 摘要、
其他键冲突、多 fact 完成、Infinity/分数 samples。全量读数见 `docs/TEST-RESULTS.md`。
