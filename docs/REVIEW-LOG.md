# 路线图评审记录

评审员：Codex CLI 0.164.0，模型 `gpt-6.1-sol`，推理 `max`，只读沙盒。
被评审对象：`docs/ROADMAP.md`。
判定规则：`score >= 85` 且 `blocking` 为空才算通过。

## Round 1 — 2026-11-08

- 结论：**fail**，63/100
- 评分：measurable 8 / sequencing 6 / acceptance 5 / risk 6 / scope 8 / compatibility 5
- 阻塞 6 项：
  - B1 run.json 缺少在途派发与提交协议，"跳过已完成 intent" 存在执行完成、done 未落盘的窗口
  - B2 把 registry 缓存与预算账本、执行进度混为一类，"损坏重建" 会丢失消费与历史
  - B3 tokens/wall/dispatches 三类额度统一按 dispatch 记账，5% 超支的单位与分母不明
  - B4 evidence 强制在 R3，迁移却在 R6，0.6–0.8 旧 fact 处理缺失；图 schema 基线不清
  - B5 重放 + 哈希只能证明输出一致，仍可搭配错误结论；五类幻觉缺判定机制
  - B6 72h 门禁只有资源增长，现有 soak 允许提前退出，延长脚本会假通过
- 主要修订：
  - 新增第 3 节「状态权威与恢复矩阵」
  - R1 增加幂等键与三段提交协议
  - R2 拆分三类预算口径
  - R3 增加 evidence 结构、目标绑定、断言、新鲜度、五类样本表
  - R6 增加 schema 清单，按实际版本迁移
  - R7 增加专用长测协议
  - 风险表补触发信号与恢复验证
  - R5 增加两条执行路径的策略覆盖矩阵
  - R6/R7 增加回滚配套

## Round 2 — 2026-11-08

- 结论：**fail**，68/100
- 评分：measurable 8 / sequencing 6 / acceptance 5 / risk 8 / scope 9 / compatibility 5
- 阻塞 5 项：
  - B1 P2「无 fact 就重派」与「重复 dispatch = 0」冲突；commit 三次写入缺中间崩溃恢复；done 补 ack 会漏账本结算
  - B2 共享预算只有项目级账本，两个项目可各自依据余额预留同一份全局额度；p95 预留未处理超额
  - B3 R3 哈希依赖 R5 脱敏规则，但顺序上 R5 在后；R5 升级会改写已验收证据的身份
  - B4 schema v3 未指明迁移对象；图、会话、run、registry、ledger 五类版本混称
  - B5 回滚用旧版 `nuwa status` 与 0.3.0 实现冲突；恢复快照会回退升级后新增的 facts/进度/消费
- 主要修订：
  - 日志分层为 `journal.jsonl`（权威）与 `events.jsonl`（诊断）
  - 全局账本 `global.jsonl` 成为唯一权威，预留/结算/回收/透支四类条目
  - 哈希规范 v1 只做归一化不做脱敏；脱敏只作用于派生副本
  - 版本拆成 graph/fact/loop/run/registry/ledger 六个命名空间
  - 回滚改为「快照 + 增量导出/导入」，不再依赖旧版 status
  - 公平性分母改为活跃区间并集之和
  - 证据增加 artifact 与截断规则
  - 长测补采样间隔、PID 范围、FD 算法、facts 增长窗口
  - 增补 `contract_check.py` 交付归属、CI 固定 ref、E2E 禁止静默回退
  - 置信度边界改为 `<0.6` / `[0.6,0.8)` / `≥0.8`

## Round 3 — 2026-11-08

- 结论：**fail**，70/100
- 阻塞 5 项：R1 恢复依赖 R2/R3 的能力（依赖倒置）；执行结果到 executed 之间的崩溃窗口；checkpoint 缺去重水位；快照跨项目一致性；72h 长测缺回归指标与统计窗口
- 修订：R1 内置最小账本与结果 artifact；R6 承担快照回滚；checkpoint 补 intents/dispatch_keys/unresolved；长测补 RSS 斜率、FD 算法、滚动窗口

## Round 4 — 2026-11-08

- 结论：**fail**，80/100
- 阻塞 5 项：fact 已建、intent 未更新的窗口；tokens 计费与"失败不计 tokens"冲突；快照持 global.lock 等待结算造成自锁；快照缺 checkpoint 与 artifact；门禁绕过 tests/run.sh 与 gates
- 修订：commit 改 saga；tokens 在 executed 计费；快照改两阶段冻结；快照清单补 checkpoint/artifact；CI 与 suite 统一入口

## Round 5 — 2026-11-08

- 结论：**fail**，70/100
- 阻塞 6 项：done 后写幂等键的窗口；spawn 前写 pid；Bloom 误命中跳过新事务；崩溃未写 executed 导致漏计费；快照缺 global.jsonl 全量与 artifact 字节；0.3.1 无账本读取能力却要求降级验证
- 修订：幂等标记写进 fact description；executing_prepare/executing 两段式 + pid_starttime；精确索引 dispatch_keys.idx；任何 spawn 必写 executed；快照复制 global.jsonl 与 artifact；降级基线改为 0.9.0

## Round 6 — 2026-11-08

- 结论：**fail**，75/100
- 阻塞 6 项：spawn 成功到 executing 落盘之间的重叠执行；前 8 位键碰撞；intent_verify 缺恢复动作、crashed/timeout 与 commit 分支冲突；per_task_cap 未受全局余量约束；快照缺共同写入栅栏；门禁只校验清单存在不校验阶段脚本
- 修订：inflight flock 作为存活唯一依据；完整 64 hex 键写进 description；恢复表补 intent_verify 与 crashed 分支；per_task_cap 取四者最小并压到 reserve×1.05；快照改为冻结+结算队列栅栏并移入 R6；门禁改为 expected 清单 + 非空校验
- 同步：契约扩到 11 项（正向结案、未知字段保留、版本字符串记录）

## Round 7 — 2026-11-08

- 结论：**fail**，82/100
- 阻塞 5 项：父进程建锁、子进程后加锁的窗口；子进程已产出 artifact 但未写 executed 的恢复缺失；reserve 与 cap 互相定义导致两项目合计超全局；置信度 rubric 缺取值与示例；freeze 未拦 commit 路径
- 修订：`nuwa-worker-lock` 先加锁再 exec；恢复表补「锁空闲且有 artifact → executed(ok)」；`reserve` 作为唯一硬上限、准入按预留总和；置信度给出三维取值表与三个示例；freeze 拦 commit 全路径 + 项目锁 barrier + pre/post seq 校验
- 同步：会话状态改为「先迁移、失败才重置」；HMAC 密钥与旧账本接管规则

## Round 8 — 2026-11-08

- 结论：**fail**，77/100
- 阻塞 6 项：保留 `sapper done`/`sapper dispatch` 旧路径导致无键 fact；事务锁不能阻止暂停后苏醒的旧 wrapper；done 的两次写入之间崩溃只补 to 不补 status；reserve 取 p95×1.05 实际超 5.94%；置信度示例算术错误；freeze 等待 commit 队列为空造成死锁
- 修订：R1 改为提交所有权（`nuwa dispatch/commit` 独占 fact 创建，禁直连）；改为**意图级锁** + wrapper 内 attempt_seq 复核；intent 修复必须写全 status/to/done_at/worker；预留即硬上限、超支以预留为分母、timeout 与 token 上限分离；置信度示例改为 1.00/0.65/0.35 并注明硬拒绝；freeze 只等 executed，队列解冻后按新 seq 归入增量
- 同步：R2 验收不再依赖 R6 快照；门禁加入不可删核心锚点；快照打包会话缓存/HMAC 密钥/组件版本；补加权公平与模型路由验收；TESTING 文档与固定顺序执行器对齐

## Round 9 — 2026-11-08

- 结论：**fail**，78/100
- 阻塞 4 项：executed(crashed) 后再次崩溃会跳过结算；超支口径同时写"恒为 0"与"允许 5%"；项目锁与全局锁获取顺序相反形成死锁；增量导出用单一 cut_seq 裁切两个独立序列
- 修订：executed 增加 `settled/rid`，恢复先结算再重派；tokens/dispatches 以预留为分母、wall 以 wall_cap 为分母；全系统固定锁序 global→project；快照记录 `global_cut_seq` 与每项目 `cut_seq[p]`
- 同步：wrapper 写 `result.json` 完成标记；公平性加 2:1:1 权重容差；R5 矩阵改 `nuwa dispatch`；契约加 dry-run 零写入（13 项）

## Round 10 — 2026-11-08

（待填）
