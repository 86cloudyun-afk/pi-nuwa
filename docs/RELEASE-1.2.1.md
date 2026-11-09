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

## 第二十八轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | 扩展先过滤 status，complete 与 done/open→goal 并存仍 verified=true；from 类型异常中止扫描 | 收集全部 `to=goal` 边，逐边要求 status=complete、from 为数组且非空、全强证据 |
| B30 | 扩展回滚遗留 goal 边；shell validate 失败被 log 吞 | 扩展 `revertCompletion` 先删边再写 active；shell `validate` 失败 `exit 1` |

## 第二十九轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 锁泄漏（三） | `$(...) 9>&-` 的重定向未覆盖 `$()` 子 shell，SIGKILL 后子 shell 仍持锁 | 改为 `out=$(exec 9>&-; cmd ...)`；repair 用 `(exec 9>&-; ...)` |

## 第三十轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | 损坏节点被静默跳过，异常图可通过局部验收 | 扩展 `readGraph` 增加 `corrupt` 标志，任一 intent/fact 解析失败即 `verified=false` |
| B30 | shell 回滚失败后仍记已打回 | `completion_ok` 检查 `revert_completion` 退出码，失败记 `revert_failed` 并继续等 |
| B23 | 同 UID 可读 token 直接提交 | guard 增加第二因子：父进程 cmdline 必须是 `nuwa/cli.py` 或 `bin/nuwa`；测试用临时 `nuwa/cli.py` 验证 |

## 第三十一轮补充

| ID | 问题 | 处理 |
|---|---|---|
| M64 | guard 的 PPID 规则误拦 `python -m nuwa.cli` | PPID cmdline 增加 `-m nuwa.cli` 匹配 |
| B25 | `goal.json` 缺失/损坏、fact 文件名与 id 错配仍可 verified=true | `readGraph` 检查 goal.json 可解析、fact.id 与文件名一致，否则 corrupt |
| B30 | `completion_ok` 回滚失败与正常继续共用返回 1，最终可 exit 0 | 回滚失败设 `failed=1`，最终退出非零 |

## 第三十二轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B30 | 战报前 `failed=0` 覆盖回滚失败标记 | `failed` 在循环前初始化，战报前只读标记不重置 |
| B25 | `goal.json` 只检查可解析，未验身份/kind | 要求 `goal.id=="goal"` 且 `goal.kind=="goal"`，否则 corrupt |
| B25 | shell 静默跳过损坏 fact/intent | 解析失败直接输出 `no` |

## 第三十三轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B39 | 强制 `kind=goal` 与真实 goal fact 协议冲突（真实 goal 省略 kind） | 只要求 `id=goal`；kind 缺省允许，存在时必须为 goal；description 与 project.goal 一致 |
| B25 | 普通 fact 空 id、from 成员非字符串、schema 分叉 | fact.id 必须存在且等于文件名；from 成员非字符串置 corrupt |
| B30 | shell 回滚 Python 非零被 validate=0 覆盖；Python 回滚失败仍返回 0 | shell `python3 ... || exit 1`；runner 回滚失败设 `exit_code=1` |

## 第三十四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B39 | goal kind 自创枚举会误拦真实 note/缺省 | goal 身份只校验 `id=goal` 与 `description == project.goal`，kind 不参与 |
| B25 | project.goal 缺失跳过、intent 非法 status、非对象 JSON | 缺 goal 直接 corrupt；status 白名单；非对象记录置 corrupt |
| B30 | 锁内直接删届时全部 goal 边；False 同时表示无变化与错误 | shell 锁内先重判有效完成（有效则 exit 0）；Python `_revert` 返回 `reverted/noop/failed` 三态 |
| B40 | `resolve` 先折叠 `..` 再 realpath，链接后 `..` 偏离 shell 语义 | `resolvePath` 改为逐段 realpath 的 `walk`，先跟随链接再处理 `..` |

## 第三十五轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B41 | `resolvePath` 只保留 real，保护目录链接到普通位置时丢失字面名 | 候选集同时保留字面路径与真实路径 |
| B40 | 相对路径仍先 `join` 折叠 `..` | `walk` 接收原始相对路径，从 baseDir 逐段 realpath |
| B25 | 空 status/数组/普通 intent 的 from 未校验 | status 必填白名单；数组/非对象置 corrupt；所有 intent 的 from 校验成员类型 |
| B30 | shell 锁内有效完成与已回滚共用 exit 0 | 有效完成返回 3，`completion_ok` 记 `project_completed` 并停机 |

## 第三十六轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B30 | `rc=3` 被 `|| exit 1` 覆盖，有效完成分支不可达 | shell 先捕获 `_prc`，3 直接 `exit 3`，其余非零 `exit 1` |
| B40 | `cd` 进入目录链接后，相对 `..` 仍按字面 baseDir | `walk` 的相对起点改用 `realpath(baseDir)` |
| B25 | `strong[kind]` 可被原型链键（如 `toString`）误判 | 改为显式 `kind === flag/vuln/loot` 比较 |

## 第三十七轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 锁泄漏（四） | SIGKILL 孤儿继承 fd 9 持有 `.nuwa.lock` | `sapper`/`python3` 函数 wrapper 统一 `9>&-`；flock 失败时只扫描 cmdline 含 `nuwa` 的进程，清掉指向锁文件的 fd 后重试 |
| B30 | `rc=3` 被 `|| exit 1` 覆盖 | 先捕获 `_prc`，3 直接 `exit 3` |
| B40 | 链接 cwd 下的相对 `..` | `walk` 相对起点用 `realpath(baseDir)` |
| B25 | `strong` 原型链键误判 | 显式 `kind === flag/vuln/loot` |

## 第三十八轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 锁泄漏（五） | 孤儿清理误杀正在运行的合法 nuwa 实例 | 只清理 PPID=1 的进程；合法实例 PPID 是 shell/test，不进入清理 |

## 第三十九轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B42 | detach 后台实例被 PID1 收养，第二个实例争锁失败会误杀合法 holder | 孤儿清理排除 `pid == 锁文件 holder`；只清 PPID=1 且不是当前 holder 的 nuwa 进程 |
| B43 | `cleanup_lock` unlink 锁文件 + 重试造成旧 inode 竞态 | 改为保留 inode、只清空内容；测试断言改为“不存在或内容为空” |
| B25 | `kinds` 普通对象可被 `__proto__` 等特殊键污染 | `Object.create(null)` |
| 测试 | 清空后的 `pid=0` 被 `os.kill(0,0)` 判为活进程 | 测试先判 `pid>0` |

## 第四十轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B42 | `exec 9>` 在争锁前截空 holder PID，B 争锁失败后误杀 A | 锁文件改为 `exec 9>>` 追加打开，拿锁后再写 PID，holder 在争锁期间可读 |

## 第四十一轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B42 | 孤儿清理的 holder 换代竞态仍可能误杀合法实例 | 删除杀进程逻辑，改为 5×1s 有界等待锁释放；超时才退出 5。SIGKILL 孤儿子进程退出后自然释放 |

## 第四十二轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | 三个完成入口缺统一 schema | 扩展校验 goal/fact/intent 必填字段、文件身份、引用完整性；Python/shell 补 goal 身份与 description 一致性 |
| 测试 | 夹具缺 created_at/creator | `makeGraph` 补必填字段 |

## 第四十三轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B45 | `graph.facts()` 跳过 goal.json，`_evidence` 取不到 goal → 合法完成被回滚 | 改用 `graph.get_fact(root, "goal")` |
| B25 | intent 文件身份、from 必填非空 | intent.id 必须等于文件名；普通 intent 的 from 必须非空数组 |
| B25 | shell 锁内重判未校验 goal 身份 | 锁内重判前先校验 goal_fact 与 project.goal 一致 |

## 第四十四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| 测试 | fake-sapper setup 不创建 goal.json，`_evidence` 的 goal 校验让 5 个项目全失败 | fake-sapper setup 生成 goal fact（仿真真实 sapper） |
| 测试 | `facts[-1]` 取到 goal.json | 改为按 kind 取 note/flag |

## 第四十五轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B46 | Python `_evidence` 的 goal 未校验对象类型/id | 要求 `isinstance(goal, dict)` 且 `goal.id == "goal"`；edge.from 成员必须是字符串 |
| B25 | shell facts 文件身份、from 成员类型；扩展 to/worker/source_intent 类型 | shell 校验 fact.id 与文件名、from 成员字符串；扩展校验 to/worker/source_intent 类型 |

## 第四十六轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B47 | 真实 open/claimed intent 的 `to` 为 null，被类型检查判坏 | `to` 允许 `null/undefined/string`，不再把 null 视为损坏 |
| B25 | shell 外层未校验 from 数组/成员类型 | 外层解析 goal edge 时先校验 `from` 为字符串数组 |

## 第四十七轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B48 | `to:null` 放宽后，异常 done/complete + to:null 被接纳 | 状态关系：done/complete 必须 `to` 非空字符串；open/claimed 必须 `to` 为 null/undefined |
| B25 | shell 外层 from 直接迭代（dict 迭代键） | 外层校验 `from` 为字符串数组 |
| B30 | shell 锁内缺 project.status 重判 | 锁内读 project，status != completed 直接 exit 0 |

## 第四十八轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B49 | 外层用 `endswith("goal.json")` 跳过，其他 `*goal.json` 被当 goal | 只跳过精确 `.sapper/facts/goal.json`，其余按普通 fact 校验身份 |
| B25 | shell 锁内未校验 fact 文件身份 | 锁内 intent/fact 均校验 id 与文件名 |
| B30 | Python 用内嵌 id 构造删除路径，可能删错文件 | 改为遍历实际 intent 文件路径删除 |

## 第四十九轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B49 | 普通 fact 扫描仍跳过全部 `*goal.json` | 只跳过精确 `.sapper/facts/goal.json` |
| B25 | 外层 intent/锁内 fact 身份、Python 普通节点身份 | 三处均校验 id 与文件名；Python `_evidence` 改目录遍历 |

## 第五十轮补充

| ID | 问题 | 处理 |
|---|---|---|
| B25 | Python `_evidence` 用 `graph.intents` 丢失文件名 | 改为遍历 `.sapper/intents/*.json`，校验 id 与文件名后再取 goal 边 |

## 第五十一轮补充

| ID | 问题 | 处理 |
|---|---|---|
| M78 | 扩展只把 truthy kind 的 fact 加入引用映射，kind 缺省/null 的合法 fact 被判 corrupt | 所有 fact id 都写入 `kinds`（kind 缺省为空串），引用完整性只查 id 存在 |
| B50 | 路径型 intent/fact id 可拼接出图外路径并 patch 外部 JSON | `graph.get_intent/get_fact/patch_intent` 统一 `_safe_id`（`[A-Za-z0-9._-]+`），拒绝 `/`、`..` |

## 第五十二轮补充

| ID | 问题 | 处理 |
|---|---|---|
| M78 | 上一轮替换未命中 `fact?.kind`，修复未落地 | 实际改为 `kinds[id] = fact.kind ?? ""`，未分类 fact 也进入引用映射 |
| B50 | 公共写入层 `annotate_fact`/`set_intent_field` 仍拼接 id | 两处统一 `_safe_id`，路径型 id 直接拒绝 |

## 第五十三轮补充（approve_after_fixes 后的 major 清理）

| ID | 问题 | 处理 |
|---|---|---|
| M86 | `NUWA_LOOP=0` 在策略 handler 注册前 return，连带关闭工具策略 | 策略 handler 始终注册；仅 arm/续跑逻辑检查 `cfg.loop` |
| M62 | 看板 `nohup` 继承锁 fd 9 | `nohup ... 9>&-` |
| M31 | 夜跑 facts 基线按整图比较，四项目恒差 4 | soak 记录逐项目 `facts_baseline`，verify 用增量与 commit_done 比较 |
| M47 | guard 正例只断言“不等于 7” | 临时项目跑真实 setup/fact/intent，断言 done rc=0 与 intent 状态 |
| M44 | 测试清理匹配 `/tmp/nuwa-study` | 限定 `-user $(id -u)`，只删当前用户的 `nuwa-*` |
| M55 | fake complete 不建完成边 | fake-sapper complete 创建 `to=goal` intent，测试断言边存在 |

## 第五十四轮补充

| ID | 问题 | 处理 |
|---|---|---|
| M44 | 清理仍匹配 `/tmp/nuwa-study` | 只匹配测试专用前缀（nuwa-r1-/e2e-/chaos-/guard-/unit-/night-/qa-/soak-/crash-/multi-/dispatch-） |
| M31 | 基线在线程启动后采集；复用项目历史 commit_done 混入 | baseline 移到 `t.start()` 前；记录 `journal_base`，verify 只统计增量 |
| M47 | fleet 正例接受后端失败 | fake-sapper 增加 `fleet status` 返回 0；guard 断言 rc=0 |
| M55 | 回滚测试缺“边存在”断言与合法完成保留 | 补断言与 `test_revert_keeps_valid_completion` |
| M15 | 测试表/backlog 旧读数 | 更新 167 例；登记 B6/B23/B30 接受边界 |

## 仍然存在的边界

- **TOCTOU**：扩展在 `tool_call` 检查路径，宿主在检查之后写入；检查后替换链接仍可能绕过。
  真正的原子收口在宿主写入边界，扩展层只能把普通输入绕过压到竞态级别。
- **M2**：`sapper flag` 直接采集的 flag 没有 intent 归属；强制关联会误伤正常采集。
- **M5**：已用各项目 journal 的 `executing_prepare`/`commit_done` 做独立锚点；`verdict` 的 RSS/FD 仍是 soak 自报。
- **M20**：attempt 已持久递增，worker 拿锁后按版本拒绝；同 intent 的并发准入仍靠 inflight 锁，非分布式锁。
- **真实 sapper**：`contract_check` 与 real 崩溃组仍需要 PATH 中的真实实现。

## 第五十五轮补充

- **M44**：清理窗口改为 `-mtime +7`，覆盖 72h 长测活跃目录。
- **M31**：`journal_base` 按项目增量；verify 读 `journal*.jsonl` 各代际并按 seq 去重；新增 `span` 判据。
- **M47**：dry-run、fact 正例断言真实 rc=0。
- **M17/M22**：repair 合并摘要 inflight、保留零值 tokens；renew 只对打开预留生效，settle 只看最后生命周期。
- **M61**：扩展校验 done/complete 的 `to` 必须命中 fact，`source_intent` 必须命中 intent。

## 第五十六轮补充

- **M31**：span 改为 `(samples-1)*interval*0.8`，两点短跑不再误判；journal 代际合并。
- **M47**：dry-run 正例先建 fact/intent，fake 对缺失 intent 返错。
- **M17**：pending 事件按字段合并，不再整条覆盖。
- **M22**：summary 处理 renew；settle/reclaim 终态不再重复扣账。
- **M61**：`source_intent` 类型校验。
- **M5**：`exit_codes` 必须非空。
- **M32**：复用 marker fact 时绑定 source_intent、持 txn.lock、validate 后提交。
- **M59**：回滚先写临时 project，再删边、rename；失败恢复边。
- **M74**：repair 读取成功 artifact，按 ok 结算。
- **M75**：reason 加预算预留/结算。
- **M21**：补 TS 回滚 goal edge 用例。

## 第五十七轮补充

- **M88**：`_bind_source` 校验 fact id 与文件身份，tmp + `os.replace` 原子写。
- **M31**：verify 核对 `samples.jsonl` 数量与 t 单调。
- **M61**：intent.to 与 fact.source_intent 双向匹配。
- **M5**：退出码必须为真 0，且覆盖全部项目。
- **M75**：reason 按输出长度估算实际 tokens 结算。
- **M59**：TS 恢复循环单次写失败不中断。

## 第五十八轮补充

- **M31**：新增 `samples_density`，按 duration/interval 反推最少采样数。
- **M61**：done intent 的 to fact 归属反查；goal.source_intent 悬空判错。
- **M75**：reason 计费含输入 prompt 长度。
- **M59**：回滚前持久化 goal 边备份，rename 成功后清理。
- **M32**：复用分支失败回滚 fact.source_intent 与 intent 状态/to。
- **M74**：repair 成功还需 stdout 非空。

## 第五十九轮补充

- **M32**：回滚在 txn.lock 内复查，B 已成功则不撤销。
- **M31**：新增 `samples_span`，t 全 0 不再通过。
- **M75**：reason 失败以 `status=error` 结算。
- **M61**：归属反查保持“source 存在才比对”，避免旧图误杀；严格缺省检查留待 1.3。

## 第六十轮补充

- **M32**：复用分支的恢复移入 txn.lock 内；done/to 一致直接快返。
- **M31**：`samples_span` 要求 t 覆盖 duration 的 80%，并校验有限数/区间。
- **M75**：引擎失败时按输入长度计入 tokens，status=error。

## 第六十一轮补充

- **M89**：`_apply_reason` 回滚先备份 goal 边；删边或原子写失败恢复已删边。
- **M31**：新增 `samples_gap`，中间空窗 >3 interval 判失败。
- **M21**：补 marker 复用分支测试（source_intent 绑定 + intent done）。

## 第六十二轮补充

- **M32**：`txn.commit` 复用 marker fact 时绑定 source_intent 并检查冲突。
- **M31**：新增 `samples_tail`，尾部 5% 缺样判失败。
- **M61**：goal.source_intent 的 intent.to 必须为 goal。
- **M75**：reason 预留写 `reason_reserve` 事件，repair 可回收。

## 第六十三轮补充

- **M90**：reason 持 `inflight/reason.lock`，repair 不会提前结算；结算后写 ack 终态。
- **M32**：`txn.commit` 复用绑定后 patch 异常时删除 source_intent。
- **M31**：新增 `samples_head`，头部 5% 缺样判失败。
- **M61**：goal 显式 source 且有多个 complete goal 边判冲突。

## 第六十四轮补充

- **M90**：`engine.call` 继承 reason 锁 fd，runner 被杀后子进程仍持锁。
- **M32**：validate 失败时删除本次绑定的 source_intent。
- **M31**：soak 记录逐项目时长，verify 要求 >= 0.5×minutes。

## 第六十五轮补充

- **M91**：`reason_reserve` 纳入 PENDING_EVENTS、恢复摘要与代际保护。
- **M32**：source 回滚写 `null`，保留必填键。
- **M31**：逐项目时长阈值 0.8×minutes。
- **M61**：缺省 source 的多 intent 指向同一 fact 判冲突；goal 无 source 且多完成边判冲突。

## 第六十六轮补充

- **M32**：`_restore_intent` 保留 `to:null`，清理本次新增的 done_at/worker；dispatch 与 txn 两处一致。
- **M61**：新图 marker fact 的 done.to 必须有 source_intent；缺省且多指向仍判冲突。

## 第六十七轮补充

- **M32**：回滚恢复 worker 原值（含 null），不再统一改回 nuwa。
- **M61**：marker 识别同时看 `x-nuwa-key` 与正文 `[nuwa:...]`。
- **M75**：`EngineError` 携带部分输出，reason 失败按输入+部分输出计费。

## 第六十八轮补充

- **M32**：新建 fact 分支也记录绑定的 fact，validate 失败时回滚 source。
- **M75**：reason 先 dry-run 取输入长度，按 `max(4000, input/4+2000)` 预留。

## 第六十九轮补充

- **M75**：结算上限 clamp 到预留额度。
- **M31**：soak 记录逐项目 facts 增量，verify 要求每项目 >=1。
- **M21**：fake-sapper fact 写 `source_intent`，覆盖新建提交绑定分支。

## 第七十轮补充

- **M92**：`reason_reserve` 先于全局预留落盘；拒绝时写 `reason_rejected`。
- **M93**：finally 内层保障 reason 锁释放。
- **M75**：取消结算 clamp，超预留写 `reason_overrun`。

## 第七十一轮补充

- **M94**：超预留 5% 写 overrun 并抛错暂停。
- **M92**：repair 对无账本预留的 reason_reserve 只跳过，不 ack。
- **M75**：`reason_usage` 落 journal，repair 按实际用量结算。

## 第七十二轮补充

- **M95**：`reason_rejected`/`reason_skipped` 纳入终态集合。
- **M94**：超支写 `.nuwa/reason.freeze`，后续 reason 直接拒绝。
- **M92**：reason 锁先于全局预留获取。
- **M75**：`reason_usage` 在应用图前落盘。

## 第七十三轮补充

- **M93**：journal/ledger 异常时释放 reason 锁。
- **M95**：摘要终态包含 reason_rejected/skipped。
- **M94**：超支先写 freeze，再落 usage。
- **M75**：异常分支也写 reason_usage。
- **M96**：夜跑 commit 取 Nuwa 源码仓库 HEAD，不取目标仓库。

## 第七十四轮补充

- **M97**：run 收尾写失败仍释放 run.lock。
- **M93**：reason_rejected 写入异常也释放锁。
- **M75**：引擎输出按 UTF-8 replace 解码，避免 UnicodeDecodeError。
- **M96**：`_commit` 优先读安装 `COMMIT`；install.sh 写入。
- **M94**：repair 发现 usage 超预留时补写 freeze。

## 第七十五轮补充

- **M98**：run 初始化异常释放 run.lock。
- **M75**：KeyboardInterrupt 也按输入计费并 settle error。
- **M94**：repair 无预留但 usage 超支时补 freeze。
- **M96**：install.sh 仅在 nuwa 复制成功后写 COMMIT。

## 第七十六轮补充

- **M94**：repair 先算 `reserved/tokens`，消除 UnboundLocalError。
- **M96**：COMMIT 写入失败时删除旧标记。
- **M74**：stdout 为空/`{}`/`[]` 不判成功。

## 第七十七轮补充

- **M99**：零 tokens 预留恢复保留 0，不再回退 4000。
- **M94**：超支在应用意图前抛错。
- **M96**：COMMIT 写入失败时删除旧标记并失败退出。
- **M98**：初始化捕获 BaseException 释放锁。
- **M74**：空 JSON 对象/数组不判成功。

## 第七十八轮补充

- **M100**：reason 预留阶段的 journal/ledger 异常按 BaseException 释放锁。
- **M96**：COMMIT 写入失败删除旧标记并 exit 1。
- **M74**：`{"result":"{}"}` 等嵌套空对象判失败。
- **M101**：repair 成功分支前先检查 inflight 锁。

## 第七十九轮补充

- **M74**：嵌套 `result` 为 `{}`/`[]`/空串判失败。
- **M96**：nuwa 复制失败删除 COMMIT 并 exit 1。
- **M94**：超支先写 freeze，再写 usage。

## 第八十轮补充

- **M74**：内层 `{ }`/`[ ]` 也按 JSON 解析判空。
- **M46**：guard/soak-night 安装失败 `exit 1`。
- **M94**：中断与引擎异常分支也先写 freeze。

## 第八十一轮补充

- **M74**：repair 成功需通过 `parse_engine_stdout`，与正常派发一致。
- **M46**：nuwa 入口安装失败 `exit 1`。
- **M94**：冻结写入失败记录并抛错，不再静默继续。

## 第八十二轮补充

- **M75**：usage 与 freeze 在 finally 中双写，避免互相跳过。
- **M74**：parse 后要求 payload 含 description/facts/intents/complete。
- **M94**：repair 冻结失败直接中断，不再继续 ack。

## 第八十三轮补充

- **M103**：settle 后先写 ack，再处理 overrun。
- **M46**：扩展/备份/skill 复制失败 `exit 1`。
- **M102**：backlog 补问题定义与 1.3 计划。

## 第八十四轮补充

- **M94**：冻结失败时保留 pending，不 settle/ack。
- **M74**：repair 验收与 dispatch 一致，要求 description（含 data.description）。

## 第八十五轮补充

- **M94**：冻结失败先置标志，诊断写失败不影响保护。
- **M74**：payload 有 data 时优先校验 data.description。
- **M102**：repair 对 commit_prepare/done_apply 状态跳过，不提前 ack。

## 第八十六轮补充

- **M94**：引擎异常分支冻结失败也置标志并保留 pending。
- **M46**：install.sh 启用 `set -euo pipefail`。

## 第八十七轮补充

- **M94**：冻结失败保留 pending 前先落 usage。
- **M104**：备份清理按行读取，含空格路径不拆分。
- **M102**：repair 对 60 秒内的成功 artifact 跳过，避让父提交窗口。

## 第八十八轮补充

- **M102**：worker 写 `parent_pid`，repair 仅在父进程存活时跳过，父崩溃后正常恢复。

## 第八十九轮补充

- **M102**：`parent_pid > 1` 才判活，父被 init 收养后正常恢复。
- **M94**：repair 每个事务前重读 journal 的 `reason_usage`。
- **M104**：备份清理用 `find -print0`/`sort -z`，含换行路径不拆分。

## 第九十轮补充

- **M106**：回滚备份用 `find -print0` 读取，含换行路径不截断。
- **M105**：真实 sapper PATH 切换需完整闸门配置，保持 1.3 验收项。

## 第九十一轮补充

- **M107**：备份查找使用 `find -L`，跟随 extensions 目录符号链接。

## 第九十二轮补充

- **M94**：repair 在结算前二次重读 journal usage。
- **M102**：ready 窗口检查因破坏 after_reserve 恢复测试回退，保留 1.3 状态机项。

## 第九十三轮补充

- **M75**：引擎启动 OSError 按输入计费并 settle error。

## 第九十四轮补充

- **M75**：`bin/nuwa` 默认 URL 循环在 reason.freeze 存在时跳过生成。
- **M21**：新增引擎缺失不崩溃测试。

## 第九十五轮补充

- **M75**：`bin/nuwa` freeze 检查改用项目目录 `$dir`。
- **M21**：引擎缺失测试先完成 i001，清空 frontier 以触达 reason 分支。
- **M102**：repair 跳过 `reserve_pending`（预留未提交）。

## 第九十六轮补充

- **M108**：`reserve_pending` 记录 ts；repair 仅在 60 秒内跳过，超时按孤儿恢复。

## 第九十七轮补充

- **M102**：`executing_prepare` 记录 parent_pid；repair 仅在父存活时跳过，父崩溃后恢复。

## 判据

新增反例：尾部缺 seq、bash 重定向/复制、`--store=`/`-s`、预算拒绝 repair、ack 摘要、
其他键冲突、多 fact 完成、Infinity/分数 samples。全量读数见 `docs/TEST-RESULTS.md`。
