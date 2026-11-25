# Changelog

## 5.1.0 — 2026-11-26

实战长程自治闭环与工程化深度加固大版本（Epic #20，子议题 #21–#52 / NW-01–NW-32，共 33 个 Issues 全部闭环）：在严格保持 12 个 `nuwa_*` 工具名称 100% 不变的前提下，彻底根治实战 208 轮跑批暴露的零新事实死循环、无封盘终态、出口未注入假阴性、假阳性未复核升格、模板化回包、批派单截断、只读诊断缺失、子代理超时卡死、残留孤儿进程组、`/tmp` 易失工作区丢失与跨运行时内联脚本越界等全部痛点。

### 四大工程化闭环（覆盖 #20–#52 / NW-01–NW-32）

- **状态机收敛、表面分域三元组去重、免票据记账与全量只读观测（#21, #22, #25, #29, #30, #31, #34, #35, #38, #41, #43, #45, #49）**：
  - **#21 (NW-01) & #43 (NW-23)**：引入持久化已尝试过滤器 `attempted(kind, targetKey)` 与规范化三元组去重键 `(expectedKind, normalizeTargetKey(target), hintHash)`，冷却窗内自动抑制 `blocked` 目标重派生，`nuwa_plan` / `nuwa_expand` 输出结构化 `rejectedReasons`（`duplicate_key` / `blocked_cooldown` / `inflight`），状态看板实时输出 `repeat_ratio` / `repeatRatio`。
  - **#22 (NW-02) & #41 (NW-21)**：新增合法终态 `status="sealed_negative"`（`sealEngagement`、`shouldRecommendSeal`），`nuwa_complete(seal=true, reason, excluded_surface, coverage)` 与 `/nuwa seal` 支持硬化目标负向封盘收口；`completionRejects >= 1` 时自动生成 `buildConvergenceAdvice` 引导收敛至 `report` / `seal`。
  - **#25 (NW-05)**：显式划分攻击面域 `surfaceDomain: "port" | "path" | "host"`（`inferSurfaceDomain`、`canDeriveCrossSurface`），隔离端口级与路径级 `blocked` 状态，跨层派生强制校验有效前置事实。
  - **#29 (NW-09) & #31 (NW-11)**：`Intent` 自动推断并记录 `expectedKind`，`nuwa_commit` 省略 `kind` 时自动继承；导出 `commitFreeFact` 并支持 `nuwa_commit` 省略 `id` / `free_note=true` 及 `/nuwa note` 免票据直接落账。
  - **#30 (NW-10) & #45 (NW-25)**：`Runtime` 追踪语义停滞 `noveltyStall`（`blocked=true` 提交绝不重置，仅新非 `blocked` 事实归零）；导出 `resolveReportPhaseTransition` / `finalizeReportPhase` 修复 `report` 阶段零正向漏洞时的死锁循环。
  - **#34 (NW-14)、#35 (NW-15)、#38 (NW-18) & #49 (NW-29)**：`nuwa_status` 支持 `raw`/`offset`/`limit`/`format="text"|"json"` 不截断输出（`renderFullStatus`）及 `inspect_intent`/`query_status`/`target_key`（`/nuwa inspect`、`/nuwa query`）严格零磁盘写入只读诊断（`inspectGraph`）；UI 与状态栏呈现 `last_ok`、`blocked_ratio` 边缘受阻标记，并明确区分当前 `blockedIntents` 与累计 `blockedCommits`。
- **派单守卫、假阳性与真实性门禁、证据落盘及跨轮结构化归档（#24, #26, #27, #28, #39, #42, #50, #51, #52）**：
  - **#24 (NW-04)**：`evaluatePositiveEvidenceGate` / `verifyPositiveConclusion` / `buildFalsePositiveNote` 拦截仅凭 `HTTP 200` + `<64B` 微小错误壳、Soft-404 或与负向基线同哈希的误报升格，返回 `falsePositive: true` 并支持自动降级为 `note` 记账。
  - **#26 (NW-06) & #39 (NW-19)**：`validateDeliverableRealism` 拦截 `[TARGET]`/`[BOOL_DELTA]` 占位符、未展开 `TARGET`/`HOST`/`$U` 与无状态码纯脚本回包；`buildDispatchPacket` 自动注入 `resolved_host` 与目标 URL；`validateHitEvidenceFields` 与 `agents/{fujiang,nuwa-verifier}.md` 强制五项 `curl -w` 命中证据指标。
  - **#27 (NW-07)、#28 (NW-08) & #50 (NW-30)**：`before_subagent_spawn` 与 `task` 接入 `validateSubagentDispatch` 及 `DispatchReceiptRegistry` 拦截空任务并标记 `requeue`；`chunkBatchTasks` 对超过 `6000`B 的批派单自动分片或溢写 `.nuwa/dispatches/batch-<id>.json`；`InflightTargetRegistry` 与 `coalesceProbesByTarget` 实现跨子代理在途目标去重与同目标探针合并。
  - **#42 (NW-22)、#51 (NW-31) & #52 (NW-32)**：`nuwa_commit` 接入 `parseAgentResult`（兼容 JSON / Markdown fenced JSON / 5 行回执）与 `saveFactEvidenceLog`（`0o600` 脱敏落盘 `.nuwa/evidence/<factId>.log` 生成 `evidence_ref`）；`nuwa_report(format="timeline")` 与 `/nuwa export` 导出 Episode 时间线（`exportEpisodeTimeline`），`writeEpisodeArchiveIndex` / `searchArchiveIndexes` 生成并检索 `.nuwa/archive/episode-<N>.{json,md}` 结构化归档。
- **出口注入、多出口熔断池、端点分类与合规浏览器挑战门识别（#23, #32, #33, #36, #37）**：
  - **#23 (NW-03) & #36 (NW-16)**：`injectEgressEnv` / `buildCurlProxyArgs` / `injectEgressIntoScript` 随任务强制透传出口配置，`preflightEgressCheck` 在 Gate URL 被边缘防火墙统一拦截时快速失败标记 `egress_blocked`（杜绝业务路径假阴性）；`EgressPoolManager` 统计 TTFB/403/5xx/重置率并执行自动熔断故障转移与最少负载/轮询分池。
  - **#32 (NW-12) & #33 (NW-13)**：`classifyEndpointResponse` 精确区分 `exists_requires_auth`（401/鉴权 403/带 `Allow` 405）与 `not_found` 并记录 SHA-256 `bodyHash`/`bodyBytes`；`detectSoft404` / `sampleSoft404Baseline` 识别随机路径基线、Next.js RSC Flight `NEXT_HTTP_ERROR_FALLBACK;404` 及多语言 404 文案。
  - **#37 (NW-17)**：`buildChromiumLaunchConfig` 支持持久化 `--user-data-dir` 与可配 `headless`/`useXvfb`/`display`；`detectChallengeGate` 确定性识别 Cloudflare Turnstile 等挑战门并立即停止盲目重试返回 `challenge_gated`，支持通过 `session-vault`（`loadHumanSessionFromVault`/`saveHumanSessionToVault`）复用人工合法会话凭据（零验证码破解/绕过代码）。
- **孤儿进程组回收、免确认软暂停、子代理看门狗、持久化工作区与跨运行时网络守卫（#40, #44, #46, #47, #48）**：
  - **#40 (NW-20) & #46 (NW-26)**：`ProcessGroupTracker` 与 `cleanupTrackedProcesses` 在 `nuwa_stop`、`session_shutdown` 与信号退出时按 `-pgid` 安全级联回收派生子进程组（严格校验 PID/PGID 边界防误杀）；`SubagentWatchdog` 追踪 `startedAt`/`lastReqAt`/`lastOutputAt`，超空闲（300s）或硬超时（900s）自动终止回收并释放并发槽位。
  - **#44 (NW-24)**：`nuwa_stop` 显式暴露 `confirm="STOP"`（硬停机）与 `pause=true`（免确认即时软暂停），配合 `/nuwa pause`、`/nuwa resume` 与 `setPausedState`/`isPausedState` 实现优雅挂起与即时恢复。
  - **#47 (NW-27) & #48 (NW-28)**：默认状态与工作区迁出易失 `/tmp`（优先 `$NUWA_STATE_DIR` / `~/.local/state/nuwa`），`verifyWorkspaceIntegrity` 持续巡检工作区与 `.git` 元数据完好性；`omp/scope.ts` 统一拦截 `python -c`、`node -e`、`bun -e`、`ruby -e`、`perl -e`、`php -r` 内联脚本越界请求，所有 `N-007` 阻断消息显式携带 `[layer=shell-guard|egress-proxy|sandbox-net]`，并为 `bin/nuwa-autonomous` 外部探活施加短超时保护；新增 `tests/gates/g5_v51.sh` 阶段门禁。

## 5.0.0 — 2026-11-25

架构跃升与自主评估闭环大版本（Issues #16–#19）：全面贯通认证态攻击面自动化、零信任常驻 Sidecar 沙盒与抗 DNS 重绑定出向代理、一等 OOB 回调通道、多资产跳板拓扑与跨事实假设图推理、全流程 Profile 领域解耦、企业级 SARIF 2.1.0 / 脱敏审计证据包、守护器成本封顶与告警，以及 10 场景离线确定性评测靶场；严格维持 12 个 `nuwa_*` 工具 100% 向后兼容。

### 四大核心升级

- **认证态攻击面闭环与自动化鉴权差分（Issue #16）**：
  - `omp/session-vault.ts` 扩展角色元数据（`expiresAt`、`checkUrl`、`csrfHeader`、`csrfCookie`、`loginHint`），新增 `decodeJwtExpiryIso`、`getRoleHeadersMap`（自动镜像 CSRF Cookie 至请求头）、`checkRoleHealth`（JWT 本地过期 + 401/403/登录页 302 探活）与 `buildRefreshIntentSpec`；支持 `/nuwa session health` 自动巡检并派生 `session-refresh:<role>` 刷新意图。
  - `omp/browser-recon.ts` 支持携带会话保险箱认证头执行认证态 SPA 侦察（Playwright `extraHTTPHeaders` + 静态抓取注入），新增懒加载 Chunk 与同源 `.js.map` SourceMap 隐藏 API 发现；`nuwa_commit(kind="cred")` 收纳新角色后自动派生 `post-auth:recon:<role>` 认证态侦察意图。
  - 新增 `omp/auth-diff.ts`（`runAuthDiffMatrix`）与 `/nuwa authdiff [paths...]`：严格只读 `GET` 多角色对照（匿名 vs 管理员 vs 同级普通用户），结合双随机路径 Soft-404 过滤与 JSON 结构键 Jaccard 相似度，确定性检出 `unauth_access` / `vertical_bfla` / `horizontal_bola`（BOLA 与 BFLA 精确分层无串扰），自动暂存 `verifyStage="candidate"` 并派发双盲复验；`omp/autoexec.ts` 新增 `injectAuthHeaderFileIntoScript` 零明文 `-H @"$NUWA_AUTH_HEADER_FILE"` 认证态自动批执行。
- **零信任常驻 Sidecar、抗 DNS 重绑定 Egress Proxy 与一等 OOB 通道（Issue #17）**：
  - `omp/sandbox.ts` 扩展 `SandboxMode = "none" | "docker" | "sidecar"`，新增项目级常驻只读 Sidecar 生命周期（`sidecarContainerName`、`buildSidecarStartArgs`、`buildSidecarExecArgs`、`wrapCommandInSidecarSandbox`、`isCompliantSidecarCommand`、`extractSandboxInnerCommand`、`ensureProjectSidecar`、`execInProjectSidecar`、`stopProjectSidecar`），与 `N-009` 钩子深度集成且精确校验容器内实际命令，消除预检脚本与代理环境变量引发的回环误报。
  - 内置零依赖抗 DNS 重绑定出向代理 `startScopedEgressProxy` / `validateEgressTarget`：支持 HTTP 正向代理与 HTTPS `CONNECT` 隧道，直连已校验 IP 阻断 DNS 重绑定至云元数据（`169.254.0.0/16`）/ 未授权私网 / 回环，拦截越界 `30x` 重定向（返回 `403 nuwa-egress N-007`），并提供 `onTraffic` 响应预览回流；`docker/Dockerfile.sandbox` 升级为 `base` / `lite` / `full` 多阶段无 root 镜像。
  - 新增 `omp/oob.ts` 与 `/nuwa oob [list|gen|poll]`：一等外带回调 Canary 通道，严格受 `ScopePolicy.oobDomains` 白名单门控，支持 `0o600` 持久化、Interactsh/通用回调解析与候选证据入账。
- **多资产跳板拓扑、跨事实假设图推理与领域 Profile 解耦（Issue #18）**：
  - 新增 `omp/hypothesis.ts` 与 `/nuwa assets`：维护主资产、SAN 子域、内网/跳板主机与本地代码仓多资产拓扑（`AssetNode`）；内置 5 类跨事实推理链（SSRF+内网、文件读取+配置/上传、认证态/凭据+特权面、白盒汇点+存活端点、非 HTTP 服务+CVE/配置）按收益/成本/置信度确定性排序（`HypothesisNode`）；双盲复验驳回前置事实时自动执行 `propagateFactRejection` 级联失效关联假设并剪枝未执行 `open` 意图。
  - `omp/profiles.ts` 与 `omp/storage.ts` 解耦全流程领域派生与兜底逻辑：`audit` 支持本地源码目录白盒审计（`requireHttpTarget: false` + 6 阶段白盒种子），`coding`/`ops`/本地 `audit` 的自动派生与兜底意图彻底隔离渗透扫描器指令。
- **离线评测靶场、SARIF 2.1.0 / 脱敏证据包与守护器成本告警（Issue #19）**：
  - 新增 `omp/reporting.ts`：`nuwa_report` 保持原有工具契约并扩展 `format="md"|"json"|"sarif"` 与 `bundle=true`（同步开放 `/nuwa report [md|json|sarif|bundle]`），支持仅含已确认漏洞的 SARIF 2.1.0 导出、结构化 JSON、分层 Markdown，以及 `0o700/0o600` 权限含 `manifest.json` SHA-256 校验与全量 Vault 凭据脱敏的 `.nuwa/poc-bundle/` 审计取证包。
  - `bin/nuwa-autonomous` 新增 `--sandbox sidecar`、`--max-total-tokens`、`--max-usd`、`--usd-per-1m-tokens`（触发硬封顶优雅退出码 `3`）与 `--webhook`（脱敏载荷 + URL 掩码 + 3 次重试 + `0o600` `.nuwa/webhook-deadletter.jsonl` 死信队列）。
  - 新增 `benchmarks/` 离线确定性评测靶场（10 场景覆盖 Soft-404、认证态 SPA、BOLA/BFLA、双盲误报驳回、账本防幻觉、Sidecar/Egress Proxy、OOB、假设剪枝、本地白盒、SARIF/证据包零泄露）与 `tests/gates/g4_v5.sh` 阶段门禁。

## 4.1.0 — 2026-11-25

安全闭环加固与运行时可靠性升级版本（Issues #11–#15）：封堵双盲复验与执行账本绕过面、消除自进化记忆跨技术栈误污染、修复动态模型路由串台、补齐跨世代累积记账与无头守护单代卡死看门狗，并显著提升 Scope 护栏（N-007）的载荷识别精度。

### 核心加固与修复

- **双盲复验闸门与执行账本加固（Issue #11）**：
  - `omp/verifier-gate.ts` 新增 `validateVerificationCommit` 与 `partitionFactsByVerifyStage`：`verify-vuln:<fid>` 非 blocked 提交强制要求 `kind="vuln"`，禁止以默认 `kind="note"` 绕过执行账本核验直接升格；候选漏洞落盘记录当前账本序列号水位 `evidenceSeq`，复验提交须核验严格晚于该水位的实质性新增执行记录。
  - `omp/evidence.ts` 新增单调递增 `seq`、`agentName` 归属、`getLatestLedgerSeq`、`isLowEntropyGenericLine` 与专属锁文件 `.nuwa/exec-ledger.lock`（消除多子代理并发写竞态），落盘前自动执行 `redactVaultSecrets` 脱敏并以 `0o600` 原子写入；`verifyExecutionEvidence` 拦截仅含 `HTTP/1.1 200 OK`、`Content-Type` 等通用低熵响应头的伪造放行。
  - `omp/scope.ts` 与 `omp/graph.ts` 封堵经由 `bash`（`cat`/`jq`/`grep`/`python3`/`node`/`curl -d @` 等）、`read`/`read_file`、`eval` 与写工具对 `.nuwa/sessions/vault.json` 的读取与篡改（N-003）。
  - `reportMarkdown` 按 `verifyStage` 分层输出「漏洞（已确认）」「待复验候选漏洞（Candidate）」「已驳回误报（Rejected）」，结论仅统计已确认实锤漏洞。
- **自进化经验蒸馏防污染与失败回流（Issue #12）**：
  - `omp/kb.ts` 将被双盲驳回的 `rejected` 漏洞记为 `negative` 避坑经验并跳过未复验 `candidate`；新增 `resolveIntentTechKeys` 按意图键与关联事实精准归因技术栈（彻底消除项目级笛卡尔积污染）；`computeExperiencePriorityBoost` 引入 90 天半衰期时间衰减；`nuwa_stop` / `/nuwa stop` 触发 `negativeOnly: true` 失败避坑蒸馏。
- **动态模型路由串台修复（Issue #13）**：
  - `omp/lineage.ts` 新增 `resolveTaskIntentContext`，优先从派单正文 `[女娲派单 iNNN]` 解析当前任务对应的具体意图与阶段；`before_subagent_spawn` 不再因队列中存在任意 `open` 态 `verify-vuln` 意图而误将所有常规 `fujiang` 子代理路由至 `verifyModel`，并在 `journal.jsonl` 记录 `model_route` 轨迹。
- **无头守护器与跨世代记账加固（Issue #14）**：
  - `omp/types.ts` / `omp/storage.ts` / `omp/reincarnate.ts` / `omp/nuwa.ts` 持久化 `projectStartedAt`、`totalTurns`、`totalTokens`，`nuwa_init(resume=true)`、`/nuwa resume` 与跨代换血不再清零项目累计轮次与起始时间。
  - `bin/nuwa-autonomous` 同步 `CORE_EXT_MODULES` 补齐 `storage.ts` 与 `graph.ts` 校验，新增 `--gen-timeout-minutes`（默认 45 分钟 / `NUWA_GEN_TIMEOUT_MS`）与 `--idle-timeout-minutes`（`NUWA_DAEMON_IDLE_MS`）子进程看门狗（`SIGTERM` → `SIGKILL` 兜底并受总 `maxHours` 剩余时长封顶）。
- **Scope 护栏（N-007）精度优化与回环策略收紧（Issue #15）**：
  - `omp/scope.ts` 升级为按命令形态区分连接目标与请求载荷：忽略 `-d`/`--data`/`--json`/`-H`/`-F`/`-b`/`-e`/`-A` 等载荷与头中的 SSRF 测试 URL，同时严格捕获 `-x`/`--proxy`/`--resolve`/`--connect-to` 及 `$()` 命令替换中的真实外连目标。
  - 新增 `ScopePolicy.allowLoopback`（远程 `pentest`/`audit` 默认 `false`，`ctf`/`coding`/`ops` 或本机靶标默认 `true`，支持 `NUWA_SCOPE_ALLOW_LOOPBACK` 与 `/nuwa scope loopback on|off`）与 `ScopePolicy.oobDomains`（支持 `NUWA_SCOPE_OOB_DOMAINS` 与 `/nuwa scope +oob/-oob`）。

## 4.0.1 — 2026-11-25

热修复与部署门禁加固版本：彻底根治 SQLite WAL 模式在冷启动/缺失伴生文件时只读打开失败缺陷，全面隔离单测环境变量杜绝污染宿主机知识库，并强化 `install.sh` 一键安装与 `doctor` 体检门禁。

### 关键缺陷修复与加固

- **根治 SQLite WAL 模式无 `-shm` 伴生文件时只读打开抛 `SQLITE_CANTOPEN`**：
  - `kb/schema.sql` 切换为 `PRAGMA journal_mode = DELETE; PRAGMA synchronous = NORMAL;`，确保便携知识库以单文件模式落盘，零 `-shm` / `-wal` 伴生文件依赖。
  - `kb/build-kb.ts`、`omp/kb.ts`（`ensureBundledKb` 与 `distillProjectExperience`）在写事务收尾关闭前显式执行 `PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;`，将已有设备上的旧版 WAL 知识库原地无损转回 `DELETE` 模式（100% 保护既有 `experience` 自进化记录）。
  - `omp/kb.ts`、`kb/build-kb.ts` 与 `bin/nuwa-autonomous`（`doctor`）统一接入健壮只读打开器 `openReadonlyKbDb`：优先以 `{ readonly: true }` + `PRAGMA busy_timeout = 3000` 并经 `sqlite_master` 探针验证可读；若遇外部遗留 WAL 库缺失 `-shm` 伴生文件，自动安全回退为普通连接并立即锁定 `PRAGMA query_only = ON`。
  - `tests/v4_kb_memory.test.ts` 新增强删 `-shm` / `-wal` 冷启动及强制遗留 WAL 库只读回退与原地自愈回归测试，覆盖 `kbLookupSafe`、`getKbStats`、`computeExperiencePriorityBoost`、`build-kb.ts --stats-only` 与 `nuwa-autonomous doctor`。
- **单测环境双重硬隔离（杜绝污染宿主机 `~/.omp/agent/nuwa-kb/kb.db`）**：
  - 为 `tests/omp_extension.test.ts`、`tests/omp_nuwa.test.ts`、`tests/nuwa_forever.test.ts`、`tests/nuwa_v3_core.test.ts` 等全部测试套件及 `run-tests.sh` / `tests/run.sh` 补齐临时沙盒 `PI_AGENT_HOME` 与 `NUWA_KB_DB` 隔离，确保任何单测执行绝不向宿主机真实知识库或缓存写入测试数据。
- **`install.sh` 部署与验收加固**：
  - 新增 `--clean-kb` 选项支持一键全新重建纯净 `kb.db`；`[5/5] 验收` 阶段使用独立临时会话目录隔离冒烟测试状态、清理临时产物、显式移除 `-shm`/`-wal` 后实测 `nuwa_kb` 冷启动命中及 `nuwa-autonomous doctor` 真实表记录数校验。

## 4.0.0 — 2026-11-25

三期工程化全量总装升级：模块化分层解耦、主从会话血缘与动态模型路由、全工具面安全护栏与纯净证据账本、Soft-404 校准与 SPA 前端感知、随仓便携 SQLite FTS5 知识库与跨项目自进化记忆、多角色会话保险箱、候选漏洞双盲独立复验闸门、零信任 Docker 容器沙盒以及外部设备一键全量部署。

### 核心架构与模块总装

- **巨石拆分解耦与离线严格构建门禁**：
  - 将原 4,391 行 `omp/nuwa.ts` 拆分为 `omp/storage.ts`（配置、文件锁、原子写、增量 `.json.gz` 快照、journal 恢复、多会话指针与 `.sapper` 迁移）、`omp/graph.ts`（六阶段种子、状态机、经验提权排序、双盲复验流转与纪律策略）与精简入口 `omp/nuwa.ts`（静态无后缀 ESM 导入、100% 向后兼容 re-export、12 个 `nuwa_*` 工具、`/nuwa` 命令与事件钩子）。
  - 新增自包含离线类型声明 `omp/env.d.ts` 与根目录严格 `tsconfig.json`，无需外置 `node_modules` 即可通过 `bun build` 全模块静态构建。
- **主从会话血缘追踪与动态模型分流（`omp/lineage.ts`）**：
  - 新增 `registerActiveSession`、`bindSubagentSpawn`、`resolveLineageRoot`（进程内缓存 + `<agentHome>/cache/nuwa-lineage.json` 原子持久化），接入 `nuwa_init`、`/nuwa`、`session_start`、`before_subagent_spawn`、`tool_call` 与 `tool_execution_end`，彻底根治 `task` 子代理独立 `subSessionId` 下护栏与证据账本断层。
  - 新增 `routeSubagentModel`：按角色（`fujiang` / `nuwa-verifier`）、阶段、待复验与战略复盘特征在 `NUWA_MODEL_FAST` / `NUWA_MODEL_DEEP` / `NUWA_MODEL_VERIFY` 间动态分流。
- **全工具面范围护栏与纯净执行账本（`omp/scope.ts` + `omp/evidence.ts`）**：
  - 新增 `checkToolScopeAndRisk` 覆盖 `read`、`browser`（`http/https/ws/wss`、`allowed_domains`、禁非 `coding` 本地文件访问）、`web_search`（拦截靶标私网 IP 与内网特征外泄）与 `eval` 代码 URL/防篡改检查。
  - 新增 `TRUSTED_EVIDENCE_TOOLS` 与 `isTrustedEvidenceEvent`，在 `tool_execution_end` 与 `recordToolExecution` 双层屏蔽 `task`/`eval`/`todo`/`think`/`ask` 编排输出进入 `exec-ledger.jsonl`，并在有执行历史时对 `vuln`/`cred`/`flag` 强验真实回显。
  - 新增便携合规子代理模板 `agents/fujiang.md` 与 `agents/nuwa-verifier.md`。
- **Soft-404 基线去噪、语义实锤、工具链升档与 SPA 感知（`omp/autoexec.ts` + `omp/browser-recon.ts`）**：
  - `dirsRule` 与 `probePaths` 引入双随机路径 Soft-404 基线校准（状态码 + 体积容差 + HTML title 去噪）与内容级语义指纹实锤，`.env` 密钥自动掩码脱敏，杜绝 SPA HTML 兜底页误报敏感泄漏。
  - 按 `st.project.toolchain` 自适应升档 `nmap`、`ffuf -ac`、`katana` 与合规非破坏性 `nuclei`（仅限 `tech,exposure,misconfig` 标签）。
  - 新增 `omp/browser-recon.ts`（`runSpaRecon`）：支持受控只读 Playwright 动态拦截模式与零外部依赖静态 JS Bundle（最多 8 个同源包 + 受控跳转范围校验）回退模式，融入自动批与 `/nuwa spa` 工作流。
- **随仓便携知识库与跨项目自进化经验回流（`kb/*` + `omp/kb.ts`）**：
  - 随仓内置 `kb/schema.sql`、36 张技术栈防御审计卡、74 条公开 CVE、30 条 ATT&CK 技术与纯 `bun:sqlite` 幂等建库脚本 `kb/build-kb.ts`（保护既有 `experience` 表不清空）。
  - `nuwa_kb` 与 `deriveKbIntents` 全面切换至全参数化防注入 `kbLookupSafe`，彻底移除 `sqlite3` CLI 外部依赖与 SQL 拼接；`nuwa_init` / `session_start` 支持懒初始化建库。
  - `nuwa_complete` 验收成功时自动调用 `distillProjectExperience` 强脱敏沉淀成败经验（零 URL/IP/端口/凭据/Flag 残留），`frontierList` 接入 `computeExperiencePriorityBoost` 基于 UCB1 实现跨项目自适应提权与避坑降权。
- **多角色会话保险箱、双盲独立复验闸门与零信任容器沙盒（`omp/session-vault.ts` + `omp/verifier-gate.ts` + `omp/sandbox.ts`）**：
  - 新增 `0o700/0o600` 原子持久化会话保险箱：`/nuwa session [list|set|remove|clear]` 管理多角色凭据，`nuwa_commit(kind="cred")` 自动收纳并对落盘事实与报告执行 `redactVaultSecrets` 全量脱敏；`nuwa_claim` 对鉴权相关意图自动物化头文件并注入零明文差分重放指引。
  - 新增双盲复验闸门：手动/子代理提交的 `vuln` 默认暂存为 `verifyStage="candidate"` 并自动派生 P96 `verify-vuln:<fid>` 独立挑刺正负对照意图；`nuwa_complete` 调用 `filterConfirmedProofs` 阻断仅凭未复验候选漏洞过早结案。
  - 新增零信任 Docker 沙盒包裹器（`--read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=256`，仅挂载 `/tmp/nuwa/<projectId>`，阻断宿主敏感目录与 API Key 透传，附容器内 `ScopePolicy` 前置白名单校验与 `docker/Dockerfile.sandbox`）；`tool_call(bash)` 在 `NUWA_SANDBOX=docker` 时强制校验（`N-009`）。
  - `bin/nuwa-autonomous` 新增 `--sandbox`/`--sandbox-image`/`--fast-model`/`--deep-model`/`--verify-model` 及 `doctor [--json]` 一键体检子命令；会话内同步新增 `/nuwa doctor`。
- **v1 遗产归档与一键全量部署升级**：
  - 旧版 Python 模块归档至 `archive/v1/nuwa/`（由 `nuwa/__init__.py` 透明兼容转发，历史测试全绿），历史发布纪要归档至 `docs/archive/v1/`。
  - `install.sh` 升级为一键安装全部 18 个扩展模块、`kb/`、`config/`、自动构建 `kb.db`、无损安装子代理模板（支持 `--force-agents`）并执行含 KB 查询与子代理血缘拦截的异步插件冒烟验收。

## 3.0.1 — 2026-11-24

彻底根治 Issue #10（ESM 异步插件运行时加载问题）并对齐 Issues #1–#9 全部细节判据：

- **静态 ESM 导入消除加载断裂（Issue #10）**：移除 `omp/nuwa.ts` 中的 `createRequire`、`loadSibling` 桥接与顶层 `await import().catch(() => null)` 静默吞错机制，改为零 Top-Level Await 的标准静态 ESM 导入（`./scope`、`./evidence`、`./profiles`、`./autoexec`、`./reincarnate`），同时删除 360+ 行冗余 fallback 桩代码。
- **部署与契约增加异步 `Bun.plugin` 冒烟门禁（Issue #10）**：`install.sh` 末尾与 `tests/contract_check.py` 均挂载模拟 `omp` 异步 `onLoad` 插件的 `Bun.plugin` 加载 `index.ts` / `nuwa.ts` 并实测调用 `nuwa_init` 与 `nuwa_status`，确保同步 `require` 类故障绝不流入部署态。
- **规则来源命名与异常事件对齐（Issue #2）**：将全局规则来源 `source` 统一为 `"project" | "global" | "builtin"`，`nuwa_status` 实时检测 `.nuwa/autoexec.json` 热更新并去重写入 `autoexec_config_invalid` 日志事件。
- **失败分类与空转闸文案精确对齐（Issue #3 / #4）**：自动批 `empty` 类失败 `note` 标注 `已测面`，二维空转闸有工具活动超限收口 `note` 标注 `有工具无产出`。
- **Tern 验证记录与版本对齐（Issue #6 / #9）**：`docs/UI-DESIGN.md` 补充实测日期与 `omp 18.16.0` / `bun 1.4.4` 环境记录，并发布 `v3.0.1`。

## 3.0.0 — 2026-11-24

女娲自治闭环与多领域引擎全面升级：外层无头世代轮转、知识库自动富化与战略复盘、真实执行账本防幻觉、靶标范围护栏、工具链探针自适配、多领域 Profile 解耦，以及 2.6.0 全部遗留 Issues（#1–#9）清零。

### 六大核心升级

- **升级 1 · 外层无头守护与跨世代自动换血**：
  - 新增 `bin/nuwa-autonomous`（`#!/usr/bin/env bun`）：自动注入 `NUWA_LOOP=1`、`NUWA_INFINITE=1`、`NUWA_HEADLESS_DAEMON=1`、`NUWA_STRICT_EVIDENCE=1`、`NUWA_REINCARNATE_TOKENS`、`NUWA_REINCARNATE_TURNS`、`NUWA_PROJECT` 及范围环境变量，支持 `--target`/`--mode`/`--goal`/`--root`/`--max-generations`/`--max-hours`/`--allow-subdomains`/`--allow-cidr`/`--model`/`--omp-bin`/`--dry-run`；自动读取 `.nuwa/state.json` 接力拉起下一代会话，子进程非零退出（API 429/5xx 断流或崩溃）按指数退避重启并从磁盘接续。
  - 新增 `omp/reincarnate.ts`：`readReincarnatePolicy` / `shouldReincarnate` / `buildHandoffSummary`（≤1500 字精炼交接摘要）/ `prepareNextGeneration`；`session_stop` 命中换代阈值时自动释放并中止在途自动批、写入 `handoffSummary` 并优雅放行，由外层守护器拉起全新上下文。
- **升级 2 · 知识库自动富化与战略复盘规划**：
  - 新增 `omp/profiles.ts` 中的 `extractTechKeywords` / `deriveKbIntents` / `buildReflectIntentSpec`：自动从 `service`/`endpoint`/`vuln` 提取技术栈（nginx/apache/tomcat/php/spring/fastjson/thinkphp/shiro/redis/mysql/postgres/grafana/gitlab/jenkins/wordpress/graphql/swagger 等）与 `CVE-YYYY-NNNN`，安全查库并派生 `key=kb:<fid>:<slug>`（`phase=vuln`, `priority=86`, `from=[fid]`）核验意图（缺 KB 库静默降级）。
  - 阶段将尽或连续 `stall >= 3` 时自动生成 `reflect:e<ep>:<phase>:<bucket>` 战略复盘意图，要求模型综合已知事实与阻塞原因调用 `nuwa_plan(intents=[...])` 构建带 `from` 依赖链的新假设。
- **升级 3 · 执行账本真实证据复验（防幻觉）**：
  - 新增 `omp/evidence.ts`：`tool_execution_end` 自动记录执行输出至内存环形缓冲与 `.nuwa/exec-ledger.jsonl`（滚动保留最近 200 条摘要及 SHA1）；`nuwa_flag` 与 `nuwa_commit(kind="vuln"|"cred"|"flag")` 调用 `verifyExecutionEvidence` 核验关键行是否真实出现在近期执行流或 `/tmp/nuwa/<projectId>/` 产物中（`NUWA_STRICT_EVIDENCE=0` 可关闭）。
- **升级 4 · 靶标范围护栏与 `.nuwa` 防篡改**：
  - 新增 `omp/scope.ts`：`defaultScopeForTarget` / `extractCommandTargets` / `isHostInScope` / `checkNuwaDirTamper` / `checkScopeAndRisk`。
  - 工具层新增 `N-007`（越界外链/非授权主机拦截，支持黑名单优先、精确主机、`*.domain`、IPv4 CIDR 掩码与回环地址策略）、`N-008`（默认拦截 `rm -rf`/`mkfs`/`dd if=`/`shutdown`/`reboot`/`DROP TABLE`/`TRUNCATE` 等破坏性命令），并强化 `N-003` 拦 `rm`/`mv`/`cp`/`sed -i`/`truncate` 与脚本写入 `.nuwa/` 权威状态。
  - `/nuwa scope` 支持运行时查看与调整范围；`nuwa_init` 支持 `scope`、`autoStart` 参数；修复 `NUWA_SCANNER_GUARD=0` 在 `checkBashPolicy` 中动态生效。
- **升级 5 · 本地武器库能力探针与指令自适配**：
  - `omp/evidence.ts` 新增 `probeToolchain`（检测 `curl`/`openssl`/`nmap`/`ffuf`/`nuclei`/`sqlmap`/`whatweb`/`hydra`/`python3`/`nc`/`sqlite3`）与 `adaptPacketForToolchain`，`nuwa_init` 探测并记录工具链快照，`nuwa_claim` 对缺失工具自动附加本地可用工具的合规替代建议。
- **升级 6 · 多领域 Profile 引擎解耦**：
  - 新增 `omp/profiles.ts` 与 `omp/types.ts`：`ProfileMode` 扩展为 `ctf` / `pentest` / `audit` / `coding` / `ops`；`coding` 与 `ops` 支持本地目录/服务标识目标（`requireHttpTarget: false`），提供软件工程与自动化运维 6 阶段内置种子，验收证据支持 `loot`/`note`。

### 自渗透引擎重构与 Issues #1–#9 修复

- **Issue #1（自动批回灌派生 + 跨平台 + E2+ key）**：`omp/autoexec.ts` 新增 `canonicalAutoKey` 归一化 `e<N>:` 前缀；`portsRule` 彻底去除 GNU `timeout` 与 `/dev/tcp`，改用 `python3` 短超时并发 `socket.create_connection` 并全面 `shellQuote`（兼容 macOS/Linux）；`AutoFact` 增加结构化 `meta`（`ports/paths/server/tech/status/san/waf`），每次自动批提交后锁内立即回灌 `deriveFromFacts` + `deriveKbIntents`。
- **Issue #2（规则表外置 JSON 热更新）**：`loadAutoRules` 按 `<root>/.nuwa/autoexec.json` > `<agentHome>/nuwa-autoexec.json` > 内置顺序加载，支持 `mtimeMs` 缓存热更新，仅允许绑定内置 `parse`（`http|ports|dirs|tls|probe`），非法 JSON 自动降级回内置。
- **Issue #3（失败三分类与冷却重试）**：`classifyAutoFailure` 区分 `network`（不消耗 `attempts`，设置 `nextRunAt` 冷却重试并计入 `runtime.netRetries`）、`blocked_by_waf`（403/406/429 特征标注并换路）、`empty`。
- **Issue #4（二维空转硬闸）**：`applyEmptyGuard` 区分无工具活动（`emptyRounds`）与有工具活动但无新事实（`suspectRounds`，默认阈值 5），避免长 turn 误杀。
- **Issue #5（预算、并发与取消）**：`runAutoBatchManaged` 支持单批总预算 `NUWA_AUTO_BUDGET_MS`（默认 90s）、并发度控制（`recon:ports` 仍独占）与 `AbortSignal` 取消；`nuwa_stop` / `/nuwa stop` / `session_shutdown` 立即中止在途自动批并释放未完成意图回 `open`。
- **Issue #6（Tern `describe()` 验证矩阵）**：`tests/ui_native.test.ts` 补齐 `table`/`tree`/`progress`+`meter`/`badge`+`kv`、16 组可选原语开关矩阵及 40 列窄宽度断言，完整记录于 `docs/UI-DESIGN.md`。
- **Issue #7（v1/v2 契约与 CI 治理）**：`tests/contract_check.py` 与 `tests/run.sh` 新增 `--v2-only` 模式，缺真实 `sapper` 时优雅 `SKIP`；`.github/workflows/test.yml` 拆分为 `v2-fast` 与 `full-suite`，`soak.yml` 移除无人值守 `schedule`；修复 `NightTest` 时长校验与多会话 `armPump` 隔离。
- **Issue #8（state 容量控制与增量快照）**：新增 `compactFacts` 保留近期 200 条未引用 `note`；`saveState` 改为每 10 次或关键节点（`init/flag/complete/stop/reincarnate`）才写全量 `.json.gz` 快照，超过 2MB 告警；`statusBoard` 展示 `state=xxKB`、`rules=<source>`、`net-retry=<n>`、`gen=<g>`。
- **Issue #9（版本一致性门禁与安装器对齐）**：新增 `tests/version_check.py` 校验 `omp/nuwa.ts`、`CHANGELOG.md`、`install.sh` 一致；`install.sh` 部署全部 9 个 `omp/*.ts` 模块与 `bin/nuwa-autonomous`，动态提取 `VERSION` 并在结尾回显 `installed version = 3.0.0`。

## 2.6.0 — 2026-11-15

omp 驱动的自渗透：确定性侦察由扩展直接执行，模型只做判断类意图。

从 ARTEX 抄的三条：

- **调度与执行分离**：ARTEX 的 scheduler 决定批次、worker 执行；女娲此前把两者都交给模型，
  模型"只思考不动手"就空转。现在扩展自己 claim 自动批、自己跑命令、自己入账。
- **空转硬闸**：ARTEX 对"只有思考、无正文无工具"的回合注入续跑并设上限（每意图 2 次）；
  女娲改为按 facts 增长判定，连续 `NUWA_EMPTY_LIMIT` 轮无新事实就把模型批全部收口、强制换面。
- **意图尝试上限**：ARTEX 的限额不随重启/换版本重置；女娲 `attempts >= NUWA_MAX_ATTEMPTS`
  的意图在 `autoPlan` 里自动转 blocked，不再占 live 位。

新增 `omp/autoexec.ts`：

- 6 条确定性规则：`recon:http`（状态/Server/标题）、`recon:ports`（29 端口 TCP 连通）、
  `recon:dirs`（23 条常见路径）、`recon:tlsjs`（证书/SAN）、`surface:sensitive`
  （robots/.git/.env/backup）、`surface:api`（openapi/swagger/graphql）。
  `bash -lc` 执行，8–50s 超时，解析器纯函数。
- `pickAuto` / `claimAutoBatch`：白名单 key、依赖满足、attempts 未超限；标 `worker="auto"`。
- `runAutoBatch`：锁外执行、锁内 `commitIntent`；成功记 `auto` 事件，失败写 `blocked(note="auto: …")`。
- 模型 directive 会单独列出"自动批在跑，不要 claim/commit"。

配置：

| 变量 | 默认 | 作用 |
|---|---|---|
| `NUWA_AUTO` | `1` | `0` 关闭自动批 |
| `NUWA_AUTO_MAX` | `3` | 每轮自动批上限 |
| `NUWA_EMPTY_LIMIT` | `3` | 连续无新事实轮数触发空转闸 |
| `NUWA_MAX_ATTEMPTS` | `3` | 单意图尝试上限 |

`install.sh` 部署 `autoexec.ts` 并自检；新增 `tests/autoexec.test.ts` 18 例。

### 历史版本号说明：关于 2.5.0–2.5.2（Issue #9）

2.4.0 发布后，原计划用于 2.5.0–2.5.2 的若干扩展稳定性与交互小修直接并入 2.6.0 一同发布，未单独切出 `2.5.0–2.5.2` 发布标签与变更条目，导致版本号由 `2.4.0` 直接跳升至 `2.6.0`。自 `3.0.0` 起已引入 `tests/version_check.py` 作为 CI 门禁，确保 `omp/nuwa.ts` 的 `VERSION`、`CHANGELOG.md` 顶部条目与 `install.sh` 的版本回显严格保持单一事实来源。

## 2.4.0 — 2026-11-13

Tern 原生渲染：手写 TSP 节点，不引入 `@oh-my-pi/pi-tui` 依赖。

- 实测 `import("@oh-my-pi/pi-tui")` 在扩展目录失败：包入口 `src/index.ts` 依赖
  `@oh-my-pi/pi-natives` 原生模块，bun 解析到源码而非 omp 内置 bundle。改为直接构造 TSP 节点
  （纯 JSON），组件只暴露 `render()` / `describe()`。
- 新增 `omp/ui-native.ts`：
  - `buildWidgetNode`：`card` > `row`（badge / progress / episode）+ `kv`（批/claim/facts/blocked/rate）
    + `row`（meter / turns）；缺 `progress`/`meter` 时降级 `text`。
  - `buildBoardNode`：`card` > `kv` + `section`（`table` 阶段表）+ frontier `list`
    + 攻击链 `tree` + 事件 `list`；缺 `table`/`tree` 时降级 `text`/`list`。
  - `createWidgetComponent` / `createBoardComponent`：`describe()` 缓存同一节点引用，
    `render()` 走字符串回退，board 保留 `q`/Esc 关闭。
- `refreshUi` 优先组件工厂；`NUWA_UI_NATIVE=0` 回退字符串数组；`setWidget` 的工厂返回同一实例，
    避免每帧重建。
- `install.sh` 部署 `ui.ts` + `ui-native.ts` 并自检；`tests/ui_native.test.ts` 7 例
    （节点结构、supports 降级、describe 缓存、q 关闭），`omp_extension` 增 1 例回退。
- 测试 120 例全绿（TS 109 + shell 15 + kb 5，shell/kb 见下）。

## 2.3.0 — 2026-11-13

可视化：状态栏 + mini 看板 + `/nuwa board` 覆盖层。

- 新增 `omp/ui.ts`：`buildSnapshot` 纯函数、`renderStatusLine` / `renderWidgetLines` /
  `renderBoardLines`、`clipAnsi`（ANSI/CJK 感知截断）、`sparkline`、`commitRate`、`parseJournalTail`。
- 状态栏：`女娲 ● vuln 12/32 · 派单 2 · E1 · ∞`，≤ 48 列。
- mini 看板：编辑器上方 3 行（`NUWA_UI_LINES=5` 追加 commit 趋势与扩张/停滞读数），宽度按终端截断。
- `/nuwa board`：覆盖层只读面板（阶段表 + frontier + 攻击链 + 事件流），`q`/Esc 关闭；
  宿主无 UI 通道时回退 `notify` 文本。
- 刷新点：`nuwa_init` / `commit` / `flag` / `complete` / `expand` / `stop` / `status`、
  `session_start`、`session_stop`；250ms 节流 + sig 缓存；`session_shutdown` 清理
  `setWidget`/`setStatus`。
- 开关：`NUWA_UI=0` 全关，`NUWA_UI_WIDGET=0` 只留状态栏，`NUWA_UI_LINES=3|5`，
  `NUWA_UI_BOARD_MAX` 控制 board 意图行数。
- 设计取舍：不 import `@oh-my-pi/pi-tui`，全部字符串/ANSI——扩展目录没有 node_modules，
  包解析失败会拖垮整个扩展；Tern 下走 `ansi`/`rows` 回退，颜色保留。
  原生组件（card/table/tree/progress）留 2.4.0，见 `docs/UI-DESIGN.md`。
- `install.sh` 复制 `ui.ts` 并自检；新增 `tests/ui.test.ts` 13 例，`omp_extension` 增 2 例
  （init 后状态栏/widget 写入、shutdown 清理）。

## 2.2.0 — 2026-11-13

永动模式：目标未完成前不停机，攻击面自动扩张到下一轮、下一层、下一个面。

根因（2.1.3 为什么总会停）：

- `session_stop` 在 `blockStreak > NUWA_BLOCK_STREAK` 时返回 `{continue:true}`。omp 只对非 `decision:block`
  的续跑计数，`continue` 上限 8（`dist/cli.js` 中 `_as=8`，日志 `session_stop continuation cap reached`）；
  第 9 次放行后会话真正 settle，表现为「跑几轮就停」。
- `stopReason` 有 5 个硬闸：turns 200 / minutes 480 / tokens 4M / stall 12 / idle 4，任一触发即
  `status=stopped`，之后 hook 直接 return。
- frontier 为空时指令引导 agent 调 `nuwa_stop`；阶段链走到 report 即终止，没有扩张层。
- 压缩/异常路径下 stop hook 被跳过时没有兜底驱动。

修复：

- 续跑只返回 `decision:"block"`（omp 不计数），删除 `continue:true` 分支与所有放行路径；
  `blockStreak` 降级为升级文案。frontier 空也照常续跑。
- `NUWA_INFINITE=1`（默认）：`stopReason` 只在 completed/stopped 返回；预算降级为 `budgetPressure`，
  压力 ≥90% 时并行降到 2，推进不减速。`NUWA_INFINITE=0` 保留旧硬闸。
- 新增扩张引擎：
  - `deriveFromFacts`：service→按端口深挖、endpoint→参数/方法/认证审计、vuln→利用+横向、
    cred→复用、asset→枚举、loot→复盘；按 fact id 去重，幂等。
  - `seedEpisode`：六阶段 32 条种子按 `e<N>:` 前缀重播，优先级随轮次衰减。
  - `addFallbackIntent`：无面可扩时生成强制深挖意图，保证队列非空。
  - `autoPlan`：live → 补播当前阶段 → 事实派生 → 逐阶段推进 → 新 episode → 兜底，一步保证 frontier 非空。
- report 全终态后自动 `episode+1` 回到 recon；`NUWA_MAX_EPISODES=0` 默认无限。
- `compactIntents`：blocked 超过 120 条回收最旧，state 不会无限膨胀。
- 新增 `nuwa_expand` 工具（第 12 个）；`nuwa_stop` 在永动模式下必须 `confirm="STOP"`，模型自行停机一律拒绝；
  `nuwa_status` 增加 `pressure / ep / expand` 读数。
- 看门狗：`session_start` 启动心跳（`NUWA_TICK_MS`，默认 60s），stop hook 被压缩/异常跳过时
  用 `sendUserMessage` 兜底续跑。
- `normalizeState`：旧 state 缺 runtime/facts/intents 时补齐，不再因半截 state 抛错。
- 根因补充（现场实测）：`extensions/` 下同时存在 `nuwa-omp.bak-*` 与退役的 `nuwa-loop.*` 时，
  omp 会把每个含 `index.ts` 的目录都当扩展加载；旧版 `session_stop` 仍按 `continue` 放行，与新扩展抢跑。
  `install.sh` 现在把备份/退役目录移到 `$AGENT_HOME/backups/`，安装末尾自检 `extensions/` 下除
  `nuwa-omp` 外无其它 `nuwa-*` 目录；`--rollback` 同步从新位置取备份。
- install.sh 工具自检补 `nuwa_expand`；退役的 sapper 安装断言同步到 v2 契约。

测试（全绿）：omp_extension 7、omp_nuwa 34、nuwa_forever 20、nuwa_command 11、nuwa_isolation 12、
shell 14、kb 5。新增关键用例：连续 30 轮 `stop_hook_active` 仍全部 `decision:block`；
连续 60 轮零事实产出 frontier 仍非空；report 后自动进 E2；预算全超限 `stopReason=null`。

## 2.1.3 — 2026-11-12

修复共享根被旧项目占用时 `/nuwa` 第 1 轮报「未找到女娲项目」：

- `findRoot` 在共享根命中别的会话 owner 时不再直接返回空，继续落到本会话指针；目标不同同样走新根。
- 场景：`/tmp` 留有旧项目（owner 为已结束会话），新会话 `/nuwa <新目标>` 已建好 `cache/nuwa-projects/...` 并写指针，但 `nuwa_frontier` 从 `/tmp` 解析时被旧 owner 挡住。
- 新增 1 例：共享根被 sess-other 占用，sess-A 仍能解析到自己的指针项目；无指针会话返回空。
- 测试：v2 62 例全绿（omp_extension 5 + omp_nuwa 34 + nuwa_command 11 + nuwa_isolation 12）。

## 2.1.2 — 2026-11-12

补完多任务隔离的「同根换目标」缺口：

- `findRoot` / `findLocalRoot` 增加 target 过滤：同目录已是 A 目标时，B 目标不再并入 A 的图；共享根（`/tmp`、home、`/`、`/data/workspace`、`NUWA_SHARED_CWDS`）的项目不向子目录继承。
- `/nuwa <任务>` 有目标时按目标选根：同目标复用，不同目标新建 `cache/nuwa-projects/<target>-<sessionHash>`；非共享 cwd 的第二个目标落到 `<cwd>/.nuwa-tasks/<target>-<sessionHash>`。
- `nuwa_init` 走同一套根选择；显式 `root` 与目标不一致时要求 `force=true`，避免静默覆盖。
- 会话指针只对非共享项目根跨 cwd 生效；共享根只服务恰好位于该目录的会话。
- 崩溃接管：`nuwa_init(root="<旧根>", resume=true, force=true)` 显式改 owner 并保留 facts（15 事实项目实测 owner 变更、facts 15→15）；`force` 不带 `resume` 仍是重建。
- 新增 5 例：共享根不向子目录继承、同会话换目标开新根、同目标复用、非共享第二目标落 `.nuwa-tasks`、`nuwa_init` 不覆盖旧项目。
- 测试：v2 61 例全绿（omp_extension 5 + omp_nuwa 34 + nuwa_command 11 + nuwa_isolation 11）。

## 2.1.1 — 2026-11-12

修复多女娲任务互相污染：

- 指针按 `sessionId` 分文件写入 `cache/nuwa-current.d/`；具名会话不再读写全局 legacy 指针，最后写入者不再覆盖别人的项目。
- `findRoot` 只接管 `ownerSessionId` 匹配的 state；其他会话的项目直接拒绝，不向父目录借用图。
- 共享 cwd（`/tmp`、home、`/data/workspace`）默认项目根落到 `cache/nuwa-projects/<target>-<sessionHash>`，不再共用 `/tmp/.nuwa/state.json`。
- `/nuwa <task>` 在非共享 cwd 优先当前目录项目；只有共享 cwd 才用本会话指针兜底，避免把新任务并进旧项目。
- 新增 `tests/nuwa_isolation.test.ts` 6 例：指针隔离、legacy 拒绝、owner 冲突、共享 cwd 根分离、真实 init 不写 `/tmp/.nuwa`。

## 2.1.0 — 2026-11-12

`/nuwa <任务>` 一键开工：自然语言进，自动抽 target/mode，init 完立即起跑。

- 命令 `/nuwa <任务>`：抽目标（URL → IPv4[:port] → 主机名[:port] → `NUWA_TARGET`/`TARGET`），
  按语义选模式（审计/渗透/ctf）；无项目则 `newState` + `seedPhase(recon)`，有项目则把任务并入
  `priority=95` 的 custom intent；随后 `sendUserMessage(kickPrompt)` 触发第 1 轮，之后交给
  `session_stop` 续跑。
- `/nuwa stop [原因]`、`/nuwa resume` 落成命令；`/nuwa`、`/nuwa log [n]`、`/nuwa why` 保留。
- 新增 `findLocalRoot`：任务模式只认 cwd 树里的 `.nuwa`，不接管指针指向的其它项目（避免串台）。
- 新增 `tests/nuwa_command.test.ts` 11 例：extractTarget（URL/IP/域名/文件名排除/环境变量）、
  pickMode、一句话开工、任务并入、stop/resume/看板、无目标提示、流式回退。
- 测试 50 pass（39 旧 + 11 新）。

## 2.0.0 — 2026-11-12

纯 omp 运行时重构：移除 CLI、Python、sapper 依赖，状态机与续跑循环收进扩展进程。

- 新增 `omp/nuwa.ts`：11 个 `nuwa_*` 工具（init/plan/frontier/claim/commit/flag/complete/status/report/stop/kb），
  单文件状态 `.nuwa/state.json`，journal 完整快照回放，`state.lock` 单写者锁。
- 新增六阶段 32 条内置 playbook；`recon/surface/vuln/exploit/post/report`，阶段清空自动推进。
- 新增证据闸门：非 note 事实必须带 command+output，echo/printf 不算证据，flag output 必须含完整值；
  commit 与 flag 双层幂等（attempt 键 / value 哈希）。
- 新增 `session_stop` 续跑：turns/minutes/tokens/stall/idle 五重预算，block 链超限切 continue；
  directive 内置 claim→task(fujiang)→commit 协议与换路提示。
- 新增工具层纪律 N-001..N-005：主线程禁扫描、CLI 退役、状态文件保护、task 必须 fujiang、子代理禁记账。
- 新增 `.sapper` 迁移：`nuwa_init(migrate=true)` 重编号事实/意图并保持 from/to 引用。
- 新增 `tests/omp_nuwa.test.ts`（34 例）与 `tests/omp_extension.test.ts`（5 例）；合计 39 pass。
- `install.sh` 重写：只装 `nuwa-omp` + skill，退役 `nuwa-loop`，旧 CLI 改名 `nuwa.legacy`，支持 `--rollback`。
- 文档重写：`docs/OMP-NATIVE.md`、`README.md`、`skills/nuwa-pentest/SKILL.md`。

## 1.2.2 — 2026-11-11

- 修复 P-006：`hasUnresolvedStore` 不再把 `/root/sapper-lab/bin/nuwa` 等路径误判为 `sapper` 命令；仅匹配真正的 `sapper` 子命令加变量展开。
- `session_stop` 增加 `stop_no_root` / `stop_no_graph` 诊断事件，避免“找不到图”时静默停机。
- 补充两条 TS 策略回归：`sapper-lab` 路径放行、`sapper` 命令带变量仍拦截。
- 全量 170 例 + 16 runs，45 TS 单测，EXIT=0。

## 1.2.1 — 2026-11-08

codex `gpt-6.1-sol` ultra 三轮交付审计（35 → 45 → 50，均 block）后的修复：

- journal：compact 代号不覆盖、统一锁、seq 并入 checkpoint 高水位、未决事务代保护、
  recovery 摘要与 snapshot 原子读、尾读扩窗、严格 UTF-8、gen 数字排序（B1–B5、B11、M11）
- 策略：路径归一（cwd/`..`/多级祖先/符号链接/反斜杠）+ `files[]`/`apply_patch` 正文；
  P-006 覆盖 `&&`/管道/`$()`/引号/反斜杠/`--store`/绝对路径；P-007 覆盖 `budget/global.jsonl`、
  `cap.json`、`freeze.json`、`.nuwa/recovery.json`（B6–B8、B10、M1）
- 入口：URL 默认走 `nuwa dispatch` 事务提交；无 CLI/引擎 fail-closed；
  `NUWA_SUBMIT_MODE=sapper` 为显式遗留模式；`bin/nuwa` 转发 flag/complete/soak-night/soak-verify；
  收工前 `recover --repair`（B9、M6、M12）
- 完成：`nuwa complete --from` 支持多 fact、kind 校验、`[nuwa:key]` 回溯；裸 `sapper complete` 一律拦（M2、M10）
- 一致：`txn.commit(key=None)` 锁内生成规范键并拒绝其他键冲突（M3）；
  `night.verify` 严格 schema、有限数、整数 samples、duration 一致性、`--expect-commit`（M4/M5）；
  `check_prompt` 与 `check_command` 分离，避免提示误伤（M9）；`g1` 逐项聚合（M8）
- 第三轮补充：尾部缺 seq、bash 重定向/复制路径、`--store=`/`-s`、预算拒绝不虚假结算、
  其他键冲突前置、ack 终结 inflight、补丁目标过滤、recover/repair 接 recovery 摘要
- 文档：`RELEASE-1.2.1.md` 按真实状态标注 closed/partial；`TEST-RESULTS.md` 更新到 1.2.1；
  剩余 M 项登记到 `docs/BACKLOG-1.2.1.md`
- 测试：扩展 42、journal 23、r1core 39、r2r7 29、guard 17，合计 164 例 + 16 runs；真实 sapper 1.0.0 下 contract 13/13、总退出码 0
- 执行层：`bin/sapper-guard` 拦截 done/dispatch i/complete，内部调用凭 `NUWA_SUBMIT_ALLOWED=1` 放行

## 1.2.0 — 2026-11-08

- journal 代际：`compact()` 在归档前取 seq（原先归档后取到 0，checkpoint 丢基线）；
  `last_seq()` 跨代取最大值，压缩后新记录不再与归档代撞号；新增 `gc(keep)`，
  默认保留 2 代，`NUWA_JOURNAL_KEEP=0` 关闭自动 GC
- 工具面策略：扩展新增 `checkTool`，bash / task / write / edit / multi_edit / apply_patch
  统一拦截；新增 P-005（写图目录）、P-006（绕开 nuwa 直接提交）、P-007（写权威状态）、
  P-009（直接改 project.json），`nuwa/policy.py` 同步 `check_path`
- 提交所有权：`buildDirective` 与 `SKILL.md` 不再 instruct `sapper done`，子代理只回结论，
  主线程用 `nuwa commit --key auto` 收口；`auto` 按 `sha256(project|intent|attempt)` 生成规范键
- 夜跑：`nuwa soak-verify <base>` 校验 `REPORT.json / MODE / COMMIT` 一致且判据全绿
- 测试：扩展 30 例（新增 8 条工具策略）、journal 3 例（跨代 seq / GC / 环境变量）、
  txn 1 例（auto 键幂等）、夜跑 2 例（报告校验 / 缺失报告）
- 替身：`fake-sapper` 识别 `FAKE_ENGINE_MODE` 的 noop / hallucinate / malformed，
  E2E 三种反例从 1/4 恢复到 4/4

## 1.1.0 — 2026-11-08

- 扩展侧命令拦截：`nuwa-loop` 的 `tool_call` 对 bash 执行 deny 规则（P-001..P-004），
  命中即 `block` 并写 `policy_block`；`NUWA_POLICY_ENFORCE=0` 可关
- 夜跑长测：`nuwa soak-night --base DIR --minutes 4320 --projects 4`，可续跑，
  输出 `REPORT.json / MODE / COMMIT`
- 崩溃矩阵：`tests/crash_matrix.py`，7 个提交点，支持 `--full`（20/5）
- 单测：扩展 22 例（新增 4 条命令策略）
- 安装器：新增 `nuwa-soak-night` 入口

## 1.0.0 — 2026-11-08

- R1 补齐：journal 归档压缩（`journal.<gen>.jsonl` + checkpoint + CURRENT）、崩溃注入 4 点、repair 恢复
- R5：渲染提示注入门（`policy.check_prompt`），命中 deny 规则即阻断 dispatch 并记 `policy_block`
- R6：`loop_schema 2→3` 写入迁移 + 自动备份，`migrate --dry-run/--write`
- 压力测试：16 项目 × 3 分钟并发，读数见 `docs/RELEASE-1.0.md`
- 门禁：g1 增加崩溃注入，g2 含迁移测试

## 1.0.0-rc1 — 2026-11-08

- R2：`nuwa fairness` 加权调度、账本准入、超支口径
- R3：`nuwa/evidence.py` 五类拒绝（10–14）与置信度 rubric、`nuwa verify`
- R4：`nuwa metrics --json`、`nuwa report` 离线 HTML、webhook 告警
- R5：`nuwa policy check/redact`、HMAC 签名校验
- R6：`nuwa/plugins.py`（api_version 校验）、`nuwa migrate --dry-run`
- R7：`nuwa soak` 多项目采样与判据
- 测试：R2–R7 模块 17 例；门禁 `g2_r2r7`
- 发布说明：`docs/RELEASE-1.0.md`（GA 缺口清单）

## 0.4.0-dev — 2026-11-08

R1 运行时（Python 包 `nuwa/`）：

- `journal.py`：append-only 权威事件流、并发 seq、checkpoint + CURRENT 指针、重放摘要
- `ledger.py`：全局账本 `global.jsonl`、reserve/renew/reclaim/settle/opening_balance、准入与剩余额度
- `locks.py`：`run.lock` / `txn.lock` / `inflight/<intent>.lock`，flock 封装与存活探测
- `txn.py`：幂等键、`commit`（key 扫描 + sapper done + intent 修补 + validate）、`repair`、`adopt`
- `worker.py`：先加锁、写 ready、fork+wait、写 result，锁 fd 随子进程保留
- `dispatch.py`：渲染提示 → 引擎 → executed → 解析 payload → 幂等提交 → 结算
- `runner.py`：round 循环、reason 批量幂等、并行 dispatch、证据闸门、run.json、resume 计数
- `cli.py`：`ls / status / attach / budget / commit / dispatch / run / recover / adopt`
- 测试：core 11 + dispatch 2 + run 1 + multi 1 = 15 例，全部在 us3 通过
- 门禁：`g1_r1.sh` 接入 `tests/run.sh` 与 `gates/expected`

## 0.3.1 — 2026-11-08

- `bin/nuwa --version`
- `tests/contract_check.py`：真实 sapper 与 fake-sapper 的 13 项契约对照（含正向结案、未知字段保留、dry-run 零写入、版本记录）
- `tests/gates/run.sh`：阶段门禁入口，按 `g*.sh` 聚合退出码
- E2E 在真实 sapper 缺失时拒绝静默回退（`NUWA_ALLOW_FAKE_SAPPER=1` 才允许）
- CI 固定 sapper 到 `c91881dc`

## 0.3.0 — 2026-11-08

测试机制补齐。五套测试 + 两个替身 + 八类靶场 + 小长测，全部在沙盒机执行。

### 新增测试

- `tests/unit.test.ts`（18 项）：`findRoot` / `readGraph` / `buildDirective` / `revertCompletion` / `readCfg`。
- `tests/test_chaos.py`（8 项）：损坏图、陈旧锁、活锁、SIGKILL 恢复、只读目录、1000 intent 性能、缺 python3。
- `tests/test_concurrency.py`（5 项）：同项目单赢家、跨项目并行、锁清理（正常/SIGTERM）、无重复派发。
- `tests/test_e2e_deterministic.py`（4 项）：零模型成本的完整链路、幻觉完成拦截、空 reason、非 JSON 引擎。
- `tests/soak.py`：小长测采样器，判 RSS 斜率 / FD 增长 / 状态文件体积。

### 新增替身

- `tests/fake-sapper`：sapper-v2 协议级替身，逐字复刻输出与参数约束。
- `tests/fake-claude`：确定性 claude 兼容引擎，模式 `normal` / `noop` / `hallucinate` / `malformed` / `slow`。

### 靶场扩展（沙盒）

从 4 类扩到 8 类：static / dvwa / slow / deny / redirect / basicauth / notfound / gzip。

### 修复（测试驱动）

- **完成闸门出口缺口**：frontier 为空时提前 break，绕过证据闸门 → 现在预算用尽、frontier 为空、循环末尾三个出口统一调 `completion_ok`。
- **SIGTERM 不退出**：`trap ... INT TERM` 只清锁不退出 → 改为 `on_signal` 清锁 + 收子进程 + `exit 143`。
- **损坏图未拦截**：`.sapper/project.json` 非法 JSON 时直接跑 → 现在前置校验并退出 2。
- **项目目录语义**：有 `.sapper` 即复用，非空且无图才拒绝（退出 4）。

## 0.2.0 — 2026-11-08

运行时正确性与可观测性大修。基于三层沙盒（协议仿真 / 真实靶场 / headless 会话）验证。

### P0 阻断修复

- `bin/nuwa` 增加依赖闸门：`sapper` / `python3` / `curl` 缺失时以退出码 3 立即退出，不再空转。
- `bin/nuwa` 的 frontier 取值改为 `grep -E '^i[0-9]+' | cut -f1`，不再把 `(no ready intents)` 当成 intent id。
- `buildDirective` 的 `sapper claim` 补上 `--worker`（sapper 的必填项）。
- `buildDirective` 的 `sapper doc` 补上 `--set`，避免子代理打开 `$EDITOR` 挂起。
- `install.sh` 在缺 `sapper` 时 `exit 1`，不再只打印提示。
- `install.sh` 生成 `$SAPPER_HOME/bin/omp-claude` 执行引擎。

### P1 运行时修复

- `findRoot` 删除「扫 `$SAPPER_HOME` 下 mtime 最新 active 图」兜底，改为 `cwd 向上` + `NUWA_PROJECT` + JSON 指针，指针带 `sessionId` 校验。
- 新增项目级互斥锁 `.nuwa.lock`（`flock`），退出时按 pid 清理。
- 触发词收紧为 `女娲模式|女娲渗透|开图|接入 sapper|sapper 模式`。
- `tool_call` 改为结构化判定：`bash.command` 匹配 `\bsapper\b`，或 `task.agent === "fujiang"`。
- `stall` 判据改用「有效推进」签名（排除 `note` 噪声）。
- `NUWA_MAX_TURNS` / `NUWA_MAX_STALL` / `NUWA_MAX_TOKENS` / `NUWA_IDLE_LIMIT` / `NUWA_GUARD_HOURS` 全部做数值校验，非法值回落默认。
- `session_stop` 在 block 链过长时切 `continue`，降低与其他 handler 的抢占。
- `dispatch` 超时继承 `SAPPER_TIMEOUT`，每轮按剩余预算收敛。
- URL 无 scheme 时补 `https://`，解析失败以退出码 2 退出。
- 默认项目名加 pid 后缀，同名目录冲突以退出码 4 退出。

### P2 可观测

- `events.jsonl`：每轮 `round_start` / `dispatch_start` / `dispatch_end` / `budget_exhausted` / `stall_stop` / `project_completed` / `completion_rejected`。
- `nuwa-loop` 日志 `cache/nuwa-loop/log/<sid>.jsonl`，每轮一行。
- `/nuwa-loop` 子命令：`off` / `on` / `log [n]` / `why` / `reset` / `budget <tokens>`。
- token 预算闸门（`NUWA_MAX_TOKENS`，默认 2M）。
- 空转检测（`NUWA_IDLE_LIMIT`，默认 3）。
- 状态文件带 `schema: 2`，路径用 `sha1(sessionId)` 前 16 位。
- `install.sh` 安装前备份扩展，支持 `--rollback`。

### 新增防御（沙盒实测驱动）

- **完成证据闸门**：`status=completed` 但没有任何 `flag/vuln/loot` 事实时，`bin/nuwa` 与 `nuwa-loop` 都会把状态打回 `active` 并写 hint，最多打回 3 次。解决 reason 阶段模型幻觉直接"完成任务"。
- **bash 循环 stall 熔断**：`NUWA_MAX_STALL`（默认 5）轮无有效推进即停机。noop 场景从 61.8s / 405 次 dispatch 降到 10.4s / 38 次。
- **锁清理**：`trap cleanup_lock EXIT INT TERM`，只删自己持有的锁文件。

### 沙盒

- `layer-a/`：`fake-sapper` 协议仿真 + 14 项验收测试（`tests/test_nuwa_shell.py`）。
- `layer-b/`：4 目标 Docker 靶场（静态 flag / DVWA / 慢响应 / 全 403）。
- `layer-c/`：omp headless 会话，验证 `armed` → `block` → directive 注入。
- `bin/stress.py`：并发压力测试，支持 `empty_frontier` / `noop` / `slow` / `error` 注入。
- `bin/analyze.py`：把压力、靶场访问、会话日志合成 `ANALYSIS.md`。
