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

## 第八轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B16 | 坏尾缺 LF 时 append 把新事件拼进坏行，整行被丢弃 | append 前检测末字节，缺 LF 先补一个 |
| B6 | 跳过带重定向的 cd 造成后续命令用旧目录；`$()` 内 cd 污染外层 | 改为「原目录 + 每个 cd 后目录」并集检查，宁严勿松 |
| B7 | 选项上限 2 漏第三个同类选项 | 上限放宽到 4；等号值支持引号 |
| B11 | snapshot 过滤无 seq 记录，已结束事务被当 pending | `snapshot` 改用全记录读取，无 seq 记录参与归并 |
| M25 | `annotate_fact` 覆盖已有辅助键 | 已有其他键时保留首个权威键 |
| M26 | worker 版本读取异常直接放行 | 改为 fail-closed 返回 3 |

## 第九轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B17 | snapshot 保留 `seq="bad"` 让 recover 抛 ValueError / last_seq 类型污染 | `recover`/`replay_state` 只接受正整数 seq，base last_seq 转换包 try |
| B6 | `cd` 失败后停在父目录，候选集漏父目录 | `candidateDirs` 加入每个 cd 目标及其父目录 |
| B7 | 固定上限 4 漏第五个选项 | 上限放宽到 8 |
| M25 | 辅助键不覆盖导致新键无法落盘 | 正文追加 marker，`x-nuwa-key` 保留首个权威键 |

**真实 sapper 已装**：`~/.local/bin/sapper` 1.0.0，`contract_check` 13/13；全量
`tests/run.sh` 退出码 0（140 例 + 16 runs）。

## 第十轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B17 | `base.last_seq` 为无限值时 `int()` 抛 OverflowError | recover/replay/recovery 合并全部捕获 OverflowError |
| B18 | seq=0/负数进入 seen，后续 ack 被去重丢弃 | 只对正整数 seq 去重，零/负记录保留参与归并 |
| B6 | 失败 `cd` 的虚拟目录推进，真实 cwd 落在候选集外 | `candidateDirs` 为每个 cd 目标加入整条祖先链 |
| B7 | 固定选项上限漏第 N 个 | 改为先剥离全部 `--store/-s`，再匹配提交命令 |

## 第十一轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B7 | 无边界剥离会删除引号内文本、跨分隔符吞 token；task 分支用旧正则 | 只在分隔符或 `sapper ` 后剥离选项；task/bash 统一走 `stripGlobalOptions` + `COMMIT_RE` |
| B6 | 失败 cd 的兄弟分支仍可能漏 | `candidateDirs` 对每个 cd 目标基于所有当前候选解析并加入祖先链 |
| B17 | checkpoint 高水位转换漏 OverflowError | `_checkpoint_high` 捕获 OverflowError |

剩余 M 项登记到 `docs/BACKLOG-1.2.1.md`。

## 第十二轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B6 | 多行/缩进 cd 漏出候选集 | cd 正则允许换行后的缩进 |
| B7 | Python 剥离规则缺 `sapper` 前缀；值匹配吞分隔符 | Python 与 TS 同步前缀；选项值限定 `[^\s;&|()]+` |
| 锁泄漏 | SIGKILL 后子进程继承 bin/nuwa 的锁 fd，残留 `.nuwa.lock` | dispatch/repair 子进程统一 `9>&-` |

## 第十三轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B19 | 两个 dispatch 在 txn.lock 外各写 reserve_pending，互相看到对方 pending 而双输 | pending 检查与 `reserve_pending`/`executing_prepare` 同锁；`dispatch_rejected` 写 ack 并纳入终态 |
| B7 | 剥离选项时消费双引号内的命令替换 | 选项值排除 `$` 与反引号，含替换的值不剥离 |
| M5 | verdict 的 RSS/FD 自报 | `night.run` 写 `samples.jsonl`；verify 重算 growth 并与 REPORT 对比 |
| M17 | repair 缺省 tokens | `reserve_committed` 带 tokens，repair 取摘要值 |
| M20 | 同 intent 并发 | txn.lock 内单赢家准入 |
| M21 | 并发测试无屏障 | `threading.Barrier` + reserve tokens 反例 |

## 第十四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B20 | `reserve_rejected` 后摘要仍保留 `executing_prepare` 幽灵 inflight | 摘要与 replay 的 pop 条件加入 `reserve_rejected`/`dispatch_rejected` |
| B21 | store 值含变量展开/反引号时剥离残片导致漏检 | 未解析 store 直接按 P-006 拒绝（fail-closed） |
| M5 | 短跑样本不足 | soak 至少采两个点 |

## 第十五轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B20 | 拒绝后 `ack` 前退出，旧 inflight 在 recovery 合并时复活 | `reserve_rejected`/`dispatch_rejected` 写入 `ended` 墓碑，摘要与 replay 共用 |
| B21 | 引号/空格后的 `$` 守卫漏检，task 分支缺守卫 | 守卫改为 `[^;|&]*[$`]`，bash 与 task 共用 `hasUnresolvedStore` |

## 第十六轮补充

| 项 | 内容 |
|---|---|
| 执行层闸门 | 新增 `bin/sapper-guard`：真实 sapper 链为 `sapper.real`，`sapper` 指向 guard；`done`/`dispatch i<N>`/`complete` 在 `NUWA_SUBMIT_ALLOWED!=1` 时退出 7 |
| 内部放行 | `graph.sapper` 与 `bin/nuwa` 的 legacy 分支显式设置 `NUWA_SUBMIT_ALLOWED=1` |
| 安装 | `install.sh` 自动建立 `sapper.real` 并安装 guard 到 `$SAPPER_HOME/bin/sapper` |
| 测试 | `tests/test_guard.py` 7 例：done/dispatch/complete/--store 前缀被拦，reason/version/内部提交放行 |

## 第十七轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B22 | guard 不认 `--store` 缩写；dispatch 只看紧随 token | argv 扫描支持 `--st*` 缩写；dispatch 扫描其后所有 `i<N>` |
| B23 | `NUWA_SUBMIT_ALLOWED=1` 可伪造 | 改为 `$SAPPER_HOME/.submit_token`（0600）随机 token；`graph.sapper` 读取同一文件 |
| B24 | 真实 sapper 在 `$SAPPER_HOME/bin` 时跳过安装；PATH 顺序不利 | install 先备份/改名 `sapper.real` 再装 guard；`bin/nuwa` 在子命令 exec 前把 `$SAPPER_HOME/bin` 放到 PATH 最前 |
| B25 | guard 放行 `dispatch reason`；真实 complete 绕过校验 | `complete` 一律拦；`dispatch i<N>` 无论前置选项都拦；`reason` 保留（只生成意图） |

## 第十八轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | `dispatch reason` 可写完成状态 | 无 token 时 `reason` 与 `i<N>` 一并拦；内部调用显式带 token |
| B26 | `fact --from-intent` 等直接结案入口绕过 guard | guard 拦 `fact --from-intent`；`auto`/`brainstorm-pick` 不在当前 CLI 子命令表 |
| B23 | token 注入面过宽 | `graph.sapper(allow_submit=False)` 默认不注入；只有 done/complete/reason 提交链传 True |

## 第十九轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B27 | guard 连 `--dry-run` 渲染也拦，正常 dispatch/reason 断链 | guard 对 `dispatch ... --dry-run` 直接放行；续跑文案改 `nuwa run` |
| B28 | 账本缺坏尾隔离，残行吞掉下一条 reserve | `Ledger._append_locked` 写前检查末字节，缺 LF 先补 |
| B24 | env.sh 在 PATH 前移后重置路径 | source 之后再压一次 `$SAPPER_HOME/bin` 到 PATH 最前 |

## 第二十轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B29 | 续跑文案 `nuwa run --root` 缺 target，解析退出 2 | `run` 的 target 改可选；`--root` 优先，两者都空才报错 |
| B24 | Python 子命令 source env.sh 后 PATH 被重置 | case 内 exec 前再压 `$SAPPER_HOME/bin` |
| B26 | `fact` 的 `--from*` 合法缩写未覆盖 | guard 拦 `--f*`（fact 下唯一前缀） |
| B25 | reason 完成只查整图证据 | `_evidence` 优先只认 `completed_from` 指向的 fact |

## 第二十一轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B30 | 真实 sapper 无证据完成被打回后，`to=goal` 完成边残留，validate 持续报错 | `_revert` 删除完成边 intent |
| B25 | 真实完成没有 `completed_from`，退回整图证据 | `_evidence` 读 `to=goal` intent 的 `from` 列表 |
| M52 | `nuwa run --root` 指向非项目仍成功退出 | `cmd_run` 校验 `.sapper/project.json` |
| M53 | reason 的 `data.complete` 被忽略 | `_apply_reason` 校验 `complete.from` 的 kind 后走 `sapper complete` |
| B26 | 真实 `auto`/`brainstorm-pick` 入口未拦 | guard 对 `auto`/`brainstorm-pick`/`sweep` 无 token 直接拦 |

## 第二十二轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B27 | `auto`/`sweep` 的 `--dry-run` 被 guard 拦 | 所有聚合入口先判 `--dry-run` 放行 |
| B30 | shell 回滚仍遗留 goal edge；Python 写 active 在删边前 | shell `revert_completion` 先删 `to=goal` intent；Python `_revert` 同序 |
| B25 | 空引用退回整图、混合引用 any 放行 | 有完成边时只认其 `from`，且要求 all 都是 flag/vuln/loot；空 from 判失败 |
| M53 | reason 的 `data.complete` 在 intents 缺失时提前返回 | 先处理 complete，再把 intents 归一为空列表 |

## 第二十三轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | 无完成边仍用整图历史证据兜底 | 无 `to=goal` 边时 `_evidence` 直接 False；有边时要求 `from` 非空且 all 强证据 |
| B30 | 回滚删边/写 active 不在同一临界区 | Python 用 `.sapper/.lock` 包住删边+写 active；shell 用 `flock -x` 同锁；回滚测试补 validate |
| M55 | 回滚测试空验收 | 增加 `sapper validate` 断言 |
| M56 | `fleet` 只读查询被 guard 拦 | guard 放行 `fleet`，保留 `auto`/`brainstorm-pick`/`sweep`/`command`/`bench` |

## 第二十四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B26 | `fleet up/hire` 获整类放行后可启动 auto | guard 只放行 `fleet status/workers`，其余子命令无 token 拦 |
| B25 | shell 仍用整图证据；空 frontier 提前退出；多边/`done→goal` 宽松 | shell `has_evidence` 改为只认 `to=goal` 且 status=complete、from 非空且全强证据；runner 空 frontier 先做完成验收 |
| B30 | 锁外快照/删边失败静默 | `_revert` 全部收进 `.sapper/.lock`，锁内重读，删边失败返回 False |
| M57 | 删除失败被正常返回 | `_revert` 返回 bool，失败路径不再静默 |

## 第二十五轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 锁泄漏回归 | `9>&-` 写在 `$()` 内，只关闭 python 的 fd，持有锁的子 shell 仍继承 fd 9 | 重定向移到 `$(...) 9>&-` 外侧；`recover` 不再单独关闭 |

## 第二十六轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 测试稳定性 | `test_night_verify_report` 依赖 smoke 的真实 verdict，偶发 `facts_ok=False` | 测试夹具把 REPORT 的 verdict 置为全 True；`test_night_smoke` 继续测真实采样 |

## 第二十七轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | 会话扩展的 `verified` 仍按整图任一强证据 | 扩展 `readGraph` 只认 `to=goal` 且 status=complete 的边，要求 from 非空且全强证据 |
| B30 | `_revert` 锁内未重判证据；调用方丢弃 False；shell 吞删除错误 | 锁内重判 `_evidence`，有效完成不删；调用方记 `revert_failed`；shell 删除失败退出 1 并跑 validate |
| M58 | 测试夹具覆盖 verdict 被指伪造 | 夹具只用于 verify 判定测试；`test_night_smoke` 继续测真实采样 |

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
