# pi-nuwa · 女娲模式 v4.0（全自主安全评估与多领域原生引擎）

把「长任务不会停、证据不造假、范围不越界、漏洞双盲复验、经验跨项目自进化、零信任沙盒可隔离、任意新机一键部署」做成纯 `omp` 原生扩展运行时 + 外层无头守护器。

**女娲模式 v4.0 = 执行纪律（`SKILL.md`）+ 模块化 `omp` 原生运行时（18 个 TS 文件，12 个 `nuwa_*` 工具）+ 随仓便携 SQLite FTS5 知识库（`kb/`）+ 合规双子代理（`fujiang` + `nuwa-verifier`）+ 外层无头守护器（`bin/nuwa-autonomous`）。**
无需外部 `sapper`、无需 `sqlite3` CLI、无需外置私有资产库；支持安全评估（`ctf`/`pentest`/`audit`）与通用工程运维（`coding`/`ops`）五种领域模式。

## v4.0 核心能力演进

在保留 12 个 `nuwa_*` 工具 100% 向后兼容的基础上，v4.0 完成了工程化三期全量闭环：

1. **巨石解耦与离线严格构建（`omp/types.ts` + `omp/storage.ts` + `omp/graph.ts` + `omp/nuwa.ts` + `omp/env.d.ts`）**：单向无环模块架构，零 `node_modules` 依赖即可通过 `bun build` 全模块静态构建与异步 `Bun.plugin` 加载。
2. **主从会话血缘追踪与动态模型分流（`omp/lineage.ts`）**：`before_subagent_spawn` 持久化父子血缘至 `<agentHome>/cache/nuwa-lineage.json`，根治子代理独立 `subSessionId` 下护栏与证据账本断层；按角色/阶段/复验/复盘自动路由 `fast` / `deep` / `verify` 模型。
3. **全工具面 Scope 护栏与纯净证据账本（`omp/scope.ts` + `omp/evidence.ts`）**：范围拦截从 `bash` 扩展至 `read`/`browser`/`web_search`/`eval`；`isTrustedEvidenceEvent` 彻底屏蔽 `task`/`eval` 等编排输出污染 `exec-ledger.jsonl`，杜绝伪造回显。
4. **Soft-404 校准、工具链重武器升档与 SPA 感知（`omp/autoexec.ts` + `omp/browser-recon.ts`）**：双随机探针自动过滤 SPA 假 200 HTML 兜底页，内容级语义指纹实锤并掩码脱敏 `.env`；自适应升档 `nmap`/`ffuf -ac`/`katana`/合规 `nuclei`；内置 Playwright 只读拦截与静态 JS Bundle 双模 SPA 路由提取（`/nuwa spa`）。
5. **便携知识库与跨项目自进化记忆（`kb/*` + `omp/kb.ts`）**：随仓内置 36 张审计卡、74 条 CVE、30 条 ATT&CK 技术，纯 `bun:sqlite` 参数化防注入查询；`nuwa_complete` 验收后自动强脱敏蒸馏成败经验，`nuwa_frontier` 基于 UCB1 算法对同类项目自适应提权与避坑降权。
6. **多角色会话保险箱、双盲独立复验与零信任容器沙盒（`omp/session-vault.ts` + `omp/verifier-gate.ts` + `omp/sandbox.ts`）**：`0o600` 加密掩码管理多角色会话并生成零明文差分重放指引；新发现 `vuln` 先入 `candidate` 并自动派生 `verify-vuln:<fid>` 交由 `nuwa-verifier` 正负对照复验，未升格 `confirmed` 前阻断过早收口；支持零信任只读 Docker 沙盒包裹执行（`N-009`）与 `nuwa-autonomous doctor` 一键体检。

## 模块组成

| 路径 | 职责 |
|---|---|
| `omp/nuwa.ts` | 组装入口（部署为 `index.ts`）：12 个 `nuwa_*` 工具、`/nuwa` 命令、6 类生命周期与护栏事件、全量兼容导出 |
| `omp/types.ts` | 共享类型契约与常量定义 |
| `omp/storage.ts` | 配置读取、文件锁 `withLock`、原子写、增量 `.json.gz` 快照、journal 恢复、多会话指针与 `.sapper` 迁移 |
| `omp/graph.ts` | 6 阶段种子、图状态机、UCB1 经验提权排序、双盲复验门禁流转、SPA 工作流与纪律校验策略 |
| `omp/lineage.ts` | 主从会话血缘绑定（内存 + 磁盘缓存）与子代理 `fast`/`deep`/`verify` 动态模型路由器 |
| `omp/scope.ts` | 全工具面（`bash`/`read`/`browser`/`web_search`/`eval`）靶标范围策略（`N-007`）、高危拦截（`N-008`）与防篡改（`N-003`） |
| `omp/evidence.ts` | 可信证据源白名单（屏蔽编排幻觉）、`.nuwa/exec-ledger.jsonl` 强复验与工具链能力探针 |
| `omp/autoexec.ts` | Soft-404 基线去噪、内容语义实锤、工具链重武器自适应升档、外置规则热更新与预算取消控制 |
| `omp/browser-recon.ts` | SPA 动态只读无头浏览器感知与零依赖静态同源 JS Bundle API 提取层 |
| `omp/kb.ts` & `kb/*` | 随仓种子资产、纯 `bun:sqlite` 幂等建库器、参数化 FTS5 检索与跨项目强脱敏经验蒸馏引擎 |
| `omp/session-vault.ts` | 多角色认证会话保险箱（`0o700/0o600`）、全文本凭据掩码脱敏与零明文鉴权差分重放指引 |
| `omp/verifier-gate.ts` | 候选漏洞 `candidate → confirmed / rejected` 双盲挑刺复验闸门 |
| `omp/sandbox.ts` & `docker/` | 零信任 Docker 容器隔离包裹器与非 root 标准评估沙盒镜像定义 |
| `omp/profiles.ts` | 5 种领域 Profile（`ctf`/`pentest`/`audit`/`coding`/`ops`）、技术栈提取与战略复盘生成 |
| `omp/reincarnate.ts` | 长程无头守护跨世代轮转判定与 ≤1500 字交接摘要生成 |
| `omp/ui.ts` / `omp/ui-native.ts` | 三层常驻可视面与 Tern 原生 TSP 组件按能力自动降级层 |
| `agents/*.md` | 便携合规子代理模板：`fujiang.md`（执行取证）与 `nuwa-verifier.md`（独立双盲证伪复验） |
| `bin/nuwa-autonomous` | 外层无头守护器（跨世代换血、模型路由透传、容器沙盒透传、`doctor [--json]` 一键体检） |
| `archive/v1/` & `docs/archive/v1/` | 已归档的 v1 Python 历史模块与早期发布记录（保留 `nuwa/__init__.py` 透明兼容转发） |

## 一键部署与环境体检

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
env -u BUN_OPTIONS ./install.sh                 # 一键部署 18 模块 + 构建便携 kb.db + 安装子代理与守护器
env -u BUN_OPTIONS ./install.sh --force-agents  # 强制刷新已存在的子代理模板
./install.sh --rollback                         # 一键回滚至上一版备份

# 部署后一键环境健康体检
~/.local/bin/nuwa-autonomous doctor
~/.local/bin/nuwa-autonomous doctor --json
```

依赖：`omp` ≥ 18.16.0，`bun` ≥ 1.1。随仓自带 `kb/` 种子并通过 `bun:sqlite` 自动构建 `~/.omp/agent/nuwa-kb/kb.db`，开箱即用。

## 快速使用

### 1. 交互式会话命令与工具

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa status                 # 查看阶段、待复验 cand、Vault 角色 roles、kb 状态与 frontier
/nuwa board                  # 全屏 TUI 看板（q/Esc 关闭）
/nuwa scope                  # 查看或动态调整靶标 Scope 白名单/子域策略
/nuwa session list           # 查看多角色会话保险箱摘要（全量掩码脱敏）
/nuwa session set admin cookie="sid=..."
/nuwa spa                    # 执行受控只读 SPA 前端路由与同源 JS Bundle 接口提取
/nuwa doctor                 # 会话内一键组件与环境体检
/nuwa log / why / stop / resume
```

### 2. 长程无头守护（跨世代换血 + 动态模型分流 + 零信任容器沙盒）

```bash
nuwa-autonomous \
  --target http://TARGET:PORT \
  --mode pentest \
  --root ./work-target \
  --sandbox docker \
  --sandbox-image nuwa-sandbox:latest \
  --fast-model gemini-3.8-flash-high \
  --deep-model gemini-4-neon-xhigh \
  --verify-model gemini-4-carbon-high \
  --max-generations 20 \
  --max-hours 12
```

## 纪律与安全护栏（N-001..N-009）

| 规则 | 拦截行为 |
|---|---|
| N-001 | 主线程直接运行扫描工具 → 必须派发子代理（`NUWA_SCANNER_GUARD=0` 可动态放行） |
| N-002 | 调用已退役的 `bin/nuwa` / `nuwa/cli.py` / `sapper` CLI |
| N-003 | 写入、重定向、删除或脚本篡改 `.nuwa/` 权威状态与账本文件 |
| N-004 | `task` / `eval agent()` 未使用合规子代理（`fujiang` 或 `nuwa-verifier`） |
| N-005 | 子代理越权调用主线程专属记账工具 `nuwa_*` |
| N-006 | `task` 误传 `tools` 字段导致子代理内建工具表被清空 |
| N-007 | 全工具面（`bash`/`read`/`browser`/`web_search`/`eval`）访问授权 Scope 之外的主机、网段或外泄内网特征 |
| N-008 | 未显式开启 `allowDestructive` 时执行高危破坏性系统或数据库命令 |
| N-009 | 开启 `NUWA_SANDBOX=docker` 时子代理绕过零信任只读容器沙盒裸跑宿主命令 |

## 测试与门禁

```bash
# 运行全部 TS 隔离测试（16 个套件，覆盖 v2/v3/v4 全链路能力）
env -u BUN_OPTIONS ./run-tests.sh

# 运行快速契约与原生套件门禁（版本一致性 + 离线构建契约 + 全量 TS + shell + kb）
./tests/run.sh --v2-only

# 运行完整回归套件（含 v1 归档兼容回归与 g0..g3 阶段门禁）
./tests/run.sh
```

更多设计细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`docs/OMP-NATIVE.md`](docs/OMP-NATIVE.md)、[`docs/AUTOPILOT.md`](docs/AUTOPILOT.md) 与 [`docs/UI-DESIGN.md`](docs/UI-DESIGN.md)。
