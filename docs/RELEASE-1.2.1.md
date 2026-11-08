# 女娲模式 1.2.1 — 交付审计修复

日期：2026-11-08
审计：codex-cli 0.164.0 / `gpt-6.1-sol` / `model_reasoning_effort=ultra`，只读沙盒

| 轮次 | 对象 | 结果 | 主要残留 |
|---|---|---|---|
| 1 | 1.2.0 `66cdbcb` | block，35/100 | B1–B9、M1–M8 |
| 2 | 1.2.1 `ef94baa` | block，45/100 | B2/B4–B9 partial；新增 B10/B11/M9–M15 |
| 3 | 1.2.1 `4fc3463` | block，50/100 | 新增 B12（预算拒绝虚假结算）、B13（覆写 intent.to）；B5/B6/B7/B11 partial |
| 4 | 本提交 | 待复审 | — |

本文件按第四轮复审前的源码状态标注，不把 partial 写成 closed。

## 第三轮后修复

| ID | 第三轮状态 | 本轮处理 | 当前 |
|---|---|---|---|
| B5 | partial：尾部缺 seq 对象让尾读返回 0 | `_tail_seq` 对缺 seq/非对象记录继续向前，直到找到正整数 seq 或文件头 | closed |
| B6 | partial：bash 重定向/复制完全跳过路径规则 | `collectShellTargets` 提取 `>`/`>>`/`tee`/`cp`/`mv`/`install` 的全部路径参数并走同一套归一化 | partial：检查与写入仍有 TOCTOU |
| B7 | partial：`--store=` 与 `-s/path` 漏检 | `COMMIT_RE` 支持 `--store[=\s]`、`-s*`、绝对路径前缀 | closed |
| B11 | partial：ack 后 inflight 不清理 | `_summarize`/`replay_state` 在 `ack` 时 pop；recovery 增加 `ended` 集合并剔除 | closed |
| B12 | 新增：预算拒绝后 repair 凭空结算 4000 | 拒绝路径写 `ack`；`repair` 只对 `ledger.has_reserve(rid)` 的预留结算 | closed |
| B13 | 新增：命中其他键时覆写 `intent.to` | 冲突检查前置到 `find_fact_by_key` 之前；`x-nuwa-key` 参与键集合 | closed |
| M1 | partial：补丁目标误取时间戳/`/dev/null` | 过滤 `(date)` 后缀、`/dev/null`，增加 `*** Move to:` | closed |
| M2 | partial：键回溯自证、空格列表不识别 | `--from` 改 `nargs="+"`；一次建 facts/intents 映射；带 marker 的证据必须挂在已完成 intent 的 `to` 上 | partial：`sapper flag` 无 marker 仍允许直接入账 |
| M3 | partial：辅助键不参与冲突/查重 | `find_fact_by_key` 读 `x-nuwa-key`；冲突集合并入该字段 | closed |
| M5 | partial：伪造起止仍可通过 | duration 与起止差 >5% 判失败；`--expect-commit` 绑定 | partial：未用独立产物重算 verdict |
| M11 | partial：活动文件先读，旧代覆盖新 ack | `_files()` 改为归档按代号升序 + 当前文件最后 | closed |
| M12 | partial：payload 异常跳过结算；`recovered_crashed` 非终态 | payload 解析包 try 并落 `ledger_settle`+`ack`；`recovered_crashed` 纳入 `TXN_DONE` | closed |
| M16 | 新增：键回溯 O(M×N) | `graph.facts`/`graph.intents` 各读一次建 map | closed |
| M17 | 新增：recover/repair 未接 recovery 摘要 | `_snapshot_state` 读 snapshot 的 committed/ended，pending 先减终态 | closed |
| M18 | 新增：局部失败被成功退出码覆盖、legacy 事件后置 | 失败写 `.nuwa/dispatch_failed`，战报后非零退出；legacy 事件调用前写 | partial：并行子进程只留汇总标记 |
| M19 | 新增：detach 在锁后重启、参数丢失 | detach 移到项目锁之前；透传 `--no-run`/`--no-loop` | closed |
| M20 | 新增：同 intent 并发各自预留 | dispatch 在预留前检查 inflight 锁 | partial：worker 拿锁后仍未复查 attempt |
| M21 | 新增：关键状态转移缺测试 | 补预算拒绝 repair、ack 摘要、多 fact、其他键冲突、`--store=`、bash 写入、Infinity/分数 samples | partial：并发确定性交错仍缺 |
| M15 | 新增：关闭表夸大 | 本文件按源码能力标注 | closed |

## 仍然存在的边界

- **TOCTOU**：扩展在 `tool_call` 检查路径，宿主在检查之后写入；检查后替换链接仍可能绕过。
  真正的原子收口在宿主写入边界，扩展层只能把普通输入绕过压到竞态级别。
- **M2**：`sapper flag` 直接采集的 flag 没有 intent 归属；强制关联会误伤正常采集。
- **M5**：`verdict` 仍是 soak 自报数据，没有独立探针重算；只能校验自洽与时长。
- **M20**：attempt 没有持久递增，worker 拿锁后无法用版本号拒绝迟到执行；当前靠 inflight 锁缩窗。
- **真实 sapper**：`contract_check` 与 real 崩溃组仍需要 PATH 中的真实实现。

## 判据

新增反例：尾部缺 seq、bash 重定向/复制、`--store=`/`-s`、预算拒绝 repair、ack 摘要、
其他键冲突、多 fact 完成、Infinity/分数 samples。全量读数见 `docs/TEST-RESULTS.md`。
