# pi-nuwa · 女娲模式 v6.0.0（下一代自主认知安全评估与跨宿主原生引擎）

把「长任务不会停、证据不造假、范围不越界、信念与信息增益驱动搜索、反自证机械校准路由、认证态/OOB 自主闭环、结构化流量重放变异、黑白盒双向混合审计、SQLite WAL 并发持久化与跨宿主 MCP 标准协议」做成零外部 npm 依赖的 `omp` 原生扩展 + 独立跨宿主 MCP Server + 外层无头守护器。

**女娲模式 v6.0.0 = 执行纪律（`SKILL.md`）+ 模块化原生运行时（30 个 `omp/*.ts` 模块，严格保持 12 个 `nuwa_*` 工具）+ 独立核心与跨宿主 MCP Server（`core/` + `bin/nuwa-mcp`）+ 随仓便携 SQLite FTS5 知识库（`kb/`）+ 合规双子代理（`fujiang` + `nuwa-verifier`）+ L1/L2 离线合成评测靶场（`benchmarks/`）+ 外层无头守护器（`bin/nuwa-autonomous`）。**

## v6.0.0 核心能力跃升

在 100% 保持 12 个 `nuwa_*` 核心工具名称与既有行为向后兼容的基础上，v6.0.0 完成了六大认知与工程引擎升级：

1. **SQLite WAL 权威状态存储与全文检索（`omp/sqlite-store.ts` + `omp/storage.ts`）**：支持 `NUWA_STORAGE_BACKEND=json|sqlite|dual` 无缝切换，10 张规范表 + WAL 多连接并发写入无锁超时 + 坏库自动隔离/回退保护 + `queryFactsByText` 中英文/路径/CVE 全文检索，自动保留 `state.json` 兼容快照且全库零明文凭据泄露。
2. **不确定性感知信念图与预期信息增益（VoI）前沿搜索（`omp/belief-search.ts` + `omp/graph-planner.ts`）**：对每个事实/意图/假设维护共轭 Beta 后验、香农熵与一步预期熵减（VoI）；发现 `.js.map` 源码泄露、`cred` 凭据或确认漏洞时自动触发关联子树先验跃升重排，双盲复验驳回或 WAF 阻断时沿拓扑级联衰减剪枝低收益分支，并输出收敛与 `sealed_negative` 封盘建议（`/nuwa belief`）。
3. **反自证机械对账校准核与自适应模型路由（`omp/calibration.ts` + `omp/lineage.ts`）**：硬性拦截任何模型/代理自评结算（`SELF_CERTIFICATION_FORBIDDEN`），仅接受 `verifier-gate`、`exec-ledger`、`autoexec`、`benchmark`、`human` 机械核验源单次结算；实时核算 Brier Score、10-bin ECE、误报率与 Token ROI，在冷启动保护与严格白名单边界内自动降权高误报模型（`/nuwa calibrate`）。
4. **自主 AuthDiff / OOB 闭环驱动（`omp/auto-loops.ts` + `omp/graph.ts`）**：批处理收尾自动检测多角色/新凭据触发只读鉴权差分（Auto-BOLA/BFLA -> `candidate` -> 双盲复验），并在配置 `scope.oobDomains` 时自动识别盲 SSRF/XXE/SSTI/反序列化高危面播撒去重 Canary、按 30s 节流轮询回收回调实锤。
5. **结构化 HTTP 流量工作台与黑白盒混合审计（`omp/traffic-workbench.ts` + `omp/hybrid-audit.ts`）**：内置 `0o600` 全字段脱敏 `TrafficRecorder`、支持 Cookie Jar 与变量提取替换的多步重放 `replayTrafficSequence`、并发 `<= 8` 的五类纯只读契约探针 `runStructuredMutations`（`/nuwa traffic`）；零外部依赖静态提取 TS/JS/Next.js/Python/Go 与 `.js.map` 路由鉴权及危险汇点，双向桥接黑盒核验意图与源码行号锚点（`/nuwa hybrid`）。
6. **图引擎无环拆解、跨宿主 MCP Server 与 L2 基准门禁（`omp/graph*.ts` + `core/*` + `bin/nuwa-mcp` + `benchmarks/run-l2-eval.ts`）**：原巨石 `omp/graph.ts` 无环拆解为 `graph-planner.ts`、`graph-commands.ts`、`graph.ts`（`< 2,500` 行）；`bin/nuwa-mcp` 基于标准 JSON-RPC 2.0 over stdio 向 Claude Code / Cursor / Codex 等任意宿主暴露完整 12 工具与护栏（`/nuwa mcp`）；配套 L2 五场景离线合成靶场与 `g6_v6.sh` 硬门禁。

## 模块组成

| 路径 | 职责 |
|---|---|
| `omp/nuwa.ts` | 组装入口（部署为 `index.ts`）：12 个 `nuwa_*` 工具、`/nuwa` 全量斜杠子命令、生命周期与护栏钩子、v6 全量兼容导出 |
| `omp/types.ts` | 共享类型契约与单一版本常量 `NUWA_VERSION = "6.0.0"` |
| `omp/storage.ts` / `omp/sqlite-store.ts` | JSON / SQLite WAL / Dual 双模存储底座、文件锁、FTS5 全文检索、进程组回收、软暂停、子代理看门狗与工作区完整性校验 |
| `omp/graph.ts` / `omp/graph-planner.ts` / `omp/graph-commands.ts` | 无环三层图状态机：6 阶段种子、三元组去重、信念前沿排序、双盲复验与剪枝、机械校准结算、自主闭环与斜杠命令视图 |
| `omp/belief-search.ts` | 共轭 Beta 信念图、预期信息增益（VoI）排序、拓扑级联衰减剪枝、跃迁信号提权与收敛/封盘推荐 |
| `omp/calibration.ts` | 反自证预测登记与机械核验对账账本、Brier/ECE/FPR/ROI 统计与自适应模型路由决策器 |
| `omp/auto-loops.ts` | 冷却防重自主多角色鉴权差分闭环与受 `scope.oobDomains` 门控的自主 OOB Canary 播撒/节流轮询闭环 |
| `omp/traffic-workbench.ts` | `0o600` 零明文泄露流量录制检索、多步状态变量提取重放与五类只读契约差分变异探针 |
| `omp/hybrid-audit.ts` | TS/JS/Python/Go 与 `.js.map` 静态路由及风险汇点提取、白盒→黑盒核验意图桥接、黑盒发现→源码行锚点反向关联 |
| `core/protocol.ts` / `core/mcp-server.ts` / `bin/nuwa-mcp` | 宿主无关核心引擎 `NuwaCoreEngine` 与跨宿主标准 MCP JSON-RPC 2.0 stdio 服务端（支持 Content-Length 与 NDJSON） |
| `omp/lineage.ts` | 主从会话血缘绑定、派单守卫、6KB 批派单分片溢写、在途目标去重与校准驱动动态模型路由 |
| `omp/scope.ts` / `omp/sandbox.ts` / `docker/` | 跨运行时范围护栏（`N-007` 含内联脚本拦截与层标签）、零信任 Docker/Sidecar 沙盒（`N-009`）、抗 DNS 重绑定 Egress Proxy 与出口熔断池 |
| `omp/evidence.ts` / `omp/verifier-gate.ts` | 单调序列可信执行证据账本、五项命中指标与假阳性复核门禁、双盲独立复验闸门 |
| `omp/autoexec.ts` / `omp/browser-recon.ts` | 出口注入与 Gate 预检、Soft-404 多语言/RSC 去噪、持久化浏览器挑战门识别停机与 SPA 接口感知 |
| `omp/session-vault.ts` / `omp/auth-diff.ts` / `omp/oob.ts` | `0o600` 多角色会话保险箱与凭据掩码脱敏、多角色只读鉴权差分矩阵、一等 OOB 回调通道 |
| `omp/kb.ts` / `omp/hypothesis.ts` / `omp/reporting.ts` | 随仓 SQLite FTS5 便携知识库与经验蒸馏、多资产假设图推理、Markdown/JSON/SARIF 2.1.0/时间线归档/PoC 脱敏证据包导出 |
| `omp/profiles.ts` / `omp/reincarnate.ts` / `omp/ui*.ts` | 五领域 Profile 解耦、跨世代换血交接、三层常驻可视面与原生 TUI 看板 |
| `benchmarks/` | L1 10 场景确定性基准（`run-eval.ts`）+ v6.0 L2 5 场景合成靶场与校准评分卡（`run-l2-eval.ts` + `l2-range/`） |
| `bin/nuwa-autonomous` | 外层无头守护器（跨世代换血、看门狗、Token/USD 封顶、脱敏 Webhook/死信队列、`doctor [--json]`） |

## 一键部署与跨宿主接入

```bash
git clone https://github.com/86cloudyun-afk/pi-nuwa.git
cd pi-nuwa
env -u BUN_OPTIONS ./install.sh                 # 一键部署 30 模块 + nuwa-mcp + 构建便携 kb.db + 子代理与守护器
env -u BUN_OPTIONS ./install.sh --force-agents  # 强制刷新已存在的子代理模板
env -u BUN_OPTIONS ./install.sh --clean-kb      # 全新重建纯净 kb.db
./install.sh --rollback                         # 一键回滚至上一版备份

# 部署后环境体检与 MCP 版本核验
~/.local/bin/nuwa-autonomous doctor
~/.local/bin/nuwa-mcp --version
```

## 快速使用

### 1. 交互式会话命令与 v6.0 新增只读视图

```text
/nuwa 打 http://TARGET:PORT 拿 flag
/nuwa 审计当前项目源码安全漏洞                 # 本地白盒 audit 模式自动绑定当前目录
/nuwa status / board / inspect / query         # 只读看板、全屏 TUI 与零写入图谱/归档检索
/nuwa belief [limit]                           # [v6.0] 查看贝叶斯信念图、Top VoI 排序、剪枝节点与收敛转向建议
/nuwa calibrate [category]                     # [v6.0] 查看反自证校准账本（Brier/ECE/FPR/ROI）与自适应路由评估
/nuwa traffic [limit] [host=...] [status=200]  # [v6.0] 只读检索结构化脱敏 HTTP 流量工作台
/nuwa hybrid [dirOrMap | plan [dirOrMap]]      # [v6.0] 提取白盒/SourceMap 路由风险并双向关联黑盒发现
/nuwa mcp                                      # [v6.0] 查看跨宿主 nuwa-mcp 状态与 mcpServers 接入配置
/nuwa scope / session / spa / authdiff / oob / assets
/nuwa report [md|json|sarif|timeline|bundle] / export / seal / pause / resume / stop / doctor
```

### 2. 跨宿主 MCP Server（Claude Code / Cursor / Codex）

```json
{
  "mcpServers": {
    "pi-nuwa": {
      "command": "/root/.local/bin/nuwa-mcp",
      "args": ["--project", "/path/to/workspace"]
    }
  }
}
```

## 测试、评测靶场与阶段门禁

```bash
python3 tests/version_check.py --require-install-echo  # 单一版本事实来源与 install.sh 回显一致性校验
python3 tests/contract_check.py --v2-only              # 30 模块无环契约、12 工具不变量与离线 bun build 门禁
env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts       # 运行 v6.0 L2 五场景合成靶场与五大硬门禁评分卡
./run-tests.sh                                         # 全量单元/集成测试与 g0..g6 阶段门禁一键回归
bash tests/gates/g6_v6.sh                              # 单独执行 v6.0 阶段门禁
```
