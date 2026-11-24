# 架构设计：女娲 v4.0 原生全自主运行时

## 1. 架构总览

女娲 v4.0 采用**纯 `omp` 进程内模块化原生扩展 + 极薄外层无头换血守护器**的双层架构，彻底消除了早期 v1 四层外部脚本拼接（已归档至 `archive/v1/`）带来的状态分裂与环境耦合。

```text
bin/nuwa-autonomous (外层守护：跨世代接力 / 指数退避恢复 / 模型与沙盒策略透传 / doctor 体检)
  └── omp 会话进程 (加载 ~/.omp/agent/extensions/nuwa-omp/index.ts)
        ├── 组装与事件层: omp/nuwa.ts (12 个 nuwa_* 工具 + /nuwa 命令 + 6 类事件钩子)
        ├── 图与规划层:   omp/graph.ts + omp/profiles.ts + omp/reincarnate.ts
        ├── 状态存储层:   omp/storage.ts + omp/types.ts (withLock + 原子写 + 增量 .json.gz 快照)
        ├── 血缘与护栏层: omp/lineage.ts + omp/scope.ts + omp/sandbox.ts
        ├── 证据与复验层: omp/evidence.ts + omp/verifier-gate.ts + omp/session-vault.ts
        ├── 侦察与感知层: omp/autoexec.ts + omp/browser-recon.ts
        └── 知识与进化层: omp/kb.ts + kb/{schema.sql, seed-*.json, build-kb.ts}
```

**硬性模块依赖约束**：所有子模块仅单向引用 `./types` 或下层基础模块，**严禁运行时反向 `import "./nuwa"`**，且入口文件保持纯静态无后缀 ESM 导入（零 `createRequire`、零顶层 `await import`），确保在 `omp` 异步 `Bun.plugin` 加载器与离线 `bun build` 下 100% 稳定运行。

## 2. 六大闭环机制

### 2.1 永动续跑与跨世代换血（`session_stop` + `reincarnate.ts`）
- `omp` 对 `continue: true` 设有硬上限（8 次），而 `decision: "block"` 不计入该上限。`session_stop` 在目标未达成前持续返回 `{ decision: "block", reason: directive }` 驱动下一轮。
- 在无头守护模式（`NUWA_HEADLESS_DAEMON=1`）下，当单代 token 或轮次触及阈值时，`session_stop` 自动中止并释放在途自动批，生成 ≤1500 字结构化交接摘要写入 `.nuwa/state.json` 后返回 `undefined` 优雅退出，由 `bin/nuwa-autonomous` 拉起全新上下文的第 `G+1` 代会话无缝接力。

### 2.2 主从会话血缘与全工具面安全护栏（`lineage.ts` + `scope.ts` + `sandbox.ts`）
- 主代理在 `nuwa_init`、`/nuwa`、`session_start` 注册活跃会话，并在 `before_subagent_spawn`（及 `task` 调用前）将父子血缘原子持久化至 `<agentHome>/cache/nuwa-lineage.json`，同时通过 `routeSubagentModel` 按角色（`fujiang` / `nuwa-verifier`）与阶段动态分配 `fast`/`deep`/`verify` 模型。
- 子代理即便运行于独立 `subSessionId`，`tool_call` 与 `tool_execution_end` 也能经 `resolveLineageRoot` 100% 还原父项目根，强制执行 `N-001..N-009` 全工具面范围护栏（覆盖 `bash`/`read`/`browser`/`web_search`/`eval`/`write`）及零信任只读 Docker 沙盒校验。

### 2.3 纯净证据账本与候选漏洞双盲复验（`evidence.ts` + `verifier-gate.ts`）
- `tool_execution_end` 经 `isTrustedEvidenceEvent` 严格过滤，拒绝 `task`/`eval`/`todo`/`think`/`ask` 等编排工具输出进入 `.nuwa/exec-ledger.jsonl`，从源头阻断子代理口头幻觉污染账本。
- 非自动批提交的 `vuln` 默认标记为 `verifyStage="candidate"`，并自动派生 P96 `verify-vuln:<fid>` 意图，引导独立审查子代理 `nuwa-verifier` 执行正负对照实验；未升格为 `confirmed` 前，`nuwa_complete` 通过 `filterConfirmedProofs` 拒绝收口结案。

### 2.4 Soft-404 去噪、工具链升档与 SPA 表面感知（`autoexec.ts` + `browser-recon.ts`）
- 自动批探测前先请求随机不存在路径建立 Soft-404 基线（状态码 + 体积容差 + 标题签名），并对 `.git/HEAD`、`.env`、`openapi.json` 做内容语义指纹校验与密钥脱敏，彻底消除单页应用假 200 误报。
- 根据 `st.project.toolchain` 自动将轻量探针升档至 `nmap`、`ffuf -ac`、`katana` 及非破坏性 `nuclei`；针对前端 SPA 自动调用 `runSpaRecon`（Playwright 只读拦截或静态同源 JS Bundle 解析）提取隐藏 API 路由并同轮派生端点审计意图。

### 2.5 多角色会话保险箱（`session-vault.ts`）
- 以 `0o700` 目录与 `0o600` 文件权限将多角色 Cookie / Bearer / 凭据存储于 `.nuwa/sessions/vault.json`；`nuwa_commit(kind="cred")` 自动收纳角色并对全部落盘事实与报告执行 `redactVaultSecrets` 掩码脱敏；`nuwa_claim` 在鉴权类意图上自动物化 `/tmp/nuwa/<projectId>/sessions/<role>.headers` 供零明文差分重放。

### 2.6 便携知识库与跨项目自进化记忆（`kb.ts` + `kb/*`）
- 随仓提供完整 SQLite FTS5 Schema 与安全基线种子，全量采用 `?` 参数化绑定防注入查询；每次项目通过 `nuwa_complete` 验收后，`distillProjectExperience` 自动剥离靶标敏感信息将技术栈成败规律写回 `experience` 表，供后续同类项目在 `frontierList` 中通过 UCB1 公式动态提权高胜率路径。
