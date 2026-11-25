# 女娲 v3.0.1 实战跑批问题全集（rggo5269.com · E1–E6 · 208 轮）

- 日期：2026-11-25 / 26
- 目标：`http://rggo5269.com:80`（CTF，取 shell/root）
- 版本：女娲 v3.0.1，`rules=builtin`，`budget=∞`，`phase=report(E6)`
- 终态：`turns=208`、`1560min`、`tokens≈850k`、`facts=49`、`done=49`、`blocked=123`、`expand=62`、`rejects=1`、`flag=0`、`loot=0`
- 人工介入：第 190 轮起由操作者手动切断环路，第 208 轮 **停止全部任务** 并提交本文件

本文件合并两版：第 183 轮初版 12 项 + 第 208 轮新增 10 项，共 **22 项**。每项含「现象 / 证据 / 根因 / 修法」。

---

# A. 调度与循环（P0）

## NW-01（P0）零新事实循环：blocked 不抑制同键重派生

**现象**：第 168–183 轮共 16 轮，`facts` 恒为 32，`blocked` 120→121，`expand` 52→60（命中 0）。

**证据**：
- 路径集合恒为 8 条：`/admin` `/login` `/api` `/api/v1` `/swagger-ui.html` `/swagger/index.html` `/openapi.json` `/robots.txt`
- 端口集合恒为 8 个：`21/22/23/53/80/110/111/135`
- `/admin` 被审计 ≥6 次（i011→i756–i780→i796–i799），端口 21 被关 ≥3 次（i742→i750→i786）

**根因**：派生器只以 facts 为输入；`blocked` 不参与去重键（应为 `(kind, target_key)`，如 `endpoint:/admin`、`port:rggo5269.com:23`），commit 只改账本不改派生空间。

**修法**：`attempted(target_key)` 过滤器 + 候选集 set 去重；`nuwa_status` 增 `repeat_ratio = 1 - distinct/total`。

## NW-02（P0）`nuwa_complete` 无"封盘"出口 → 硬化目标无限续跑

**现象**：`flag=0 / loot=0` 时 complete 必被拒（`rejects=1`），而引擎"每轮自动续跑"，对不可攻破目标无终止条件。本跑批在 `facts` 停滞的 40+ 轮里持续消耗。

**修法**：新增 `nuwa_seal(reason, excluded_surface[], coverage)` → `status=sealed_negative`；gate 放宽为 `flag OR sealed_negative`；加 `max_turns / max_tokens / no_new_fact_rounds>=K` 自动建议封盘。

## NW-03（P0）出口未随任务下发 → 批量假阴性

**现象**：6 个子代理交付 `403 / 4549B` 并当作阴性上报。

**证据**：

| 任务 | 失效形态 |
|---|---|
| SqliProbe | 正文全 `[TARGET]` `[BOOL_DELTA]` 占位符，脚本从未运行 |
| SstiProbe | 实际请求 `http://TARGET:3000/...`，主机不存在 |
| NextCve | 只回脚本，`U=https://TARGET`，零响应 |
| RewriteProbe | 闸门 `/zh-tw` 即 403/4561 |
| ImageOpt | 五组全 403/4549，被读成"优化器未启用" |
| CmdInjReal | 18 次全 403/4549 |

**根因**：dispatch 只传目标 URL，不传已验证出口；该站对数据中心/VPN 出口是 ASN 级硬阻断，仅 `socks5h://127.0.0.1:7890` 可过。

**修法**：dispatch 强制注入 `EGRESS`；worker 首步自检 `GET /zh-tw == 200`，否则 fail-fast 且**不产生任何结论**。

## NW-04（P0）假阳性未复核即上报

**现象**：`MwBypass` 报 `x-middleware-subrequest: pages/_middleware` 使 `/api/v1/member/activityDailyDrawInfo` 从 `401/33B` 变 `200/63B`，判为 CVE-2025-29927 绕过。

**复核**：`VerifyBypass` 重放 —— 基线 `404/82B`，带头 `404/82B`，body md5 逐字节相同；页面 `/member` 三头值均 307；该路由根本未注册，Next 16.3.3 已忽略该头。

**根因**：未设"阳性必须含业务数据"判据。`200 + 63B` 与错误信封同量级，仅凭状态码判定。

**修法**：阳性判定要求 `body` 含业务字段（`data[]`/用户对象），否则强制复核；复核不通过写入 `note(false_positive)`。

## NW-05（P1）端口级与路径级 surface 共用 blocked 逻辑

端口层判定全假阳性后仍派生路径审计，路径 403 后又回头重派端口（i741–i750 与 i756–i799 交替）。**修法**：surface 分域（port/path/host），跨域派生需显式前置。

---

# B. 委派与交付质量

## NW-06（P1）子代理交付模板化 / 目标未解析

**证据**：`SqliProbe` 回包含 `[BOOL_DELTA]B`、`[TIME_DELTA]s`；`NextCve` 回包是整段 shell 而无可执行输出。

**判据（任一命中即拒收，不落账）**：
```
a) 正文出现 \[[A-Z_]+\] 占位符
b) 命令里出现 TARGET / HOST / DOMAIN / $U 字面量
c) 无 remote_ip / cf-ray / %{http_code} 实际输出
d) 只有脚本或变量赋值，没有 HTTP/ 或状态码
```
**修法**：dispatch 注入 resolved_host；worker 回包强制 `-w '%{http_code} %{size_download} %{remote_ip}'`。

## NW-07（P1）派单内容丢失：job 已 spawn，agent 侧无 task

**证据**：`PathTraversal` 状态 `no assigned task in context; awaiting work item`，空转 25 分钟。

**修法**：spawn 后回读 agent 首条 context，校验长度 > 0 才计入 `open`；否则立即重派。

## NW-08（P1）`task` 批派单 ~6.5KB 上限，无分片保护

**证据**：6 条 packet（约 10KB）提交时被截断，返回 `Error: Expected ';' or '}'`，任务静默丢失；改每批 2–3 条恢复。

**修法**：`len(json) > 6000` 自动分片；或提供 `tasks_file` 走磁盘引用。

## NW-09（P2）`nuwa_commit` 不从 `claim` 继承 `kind`

packet 已声明 `kind=vuln/service`，commit 仍须手填，主线程只能推断。**修法**：claim 时把 kind 写入 ticket，commit 缺省继承。

---

# C. 观测与账本

## NW-10（P1）`stall/idle/pressure` 对语义停滞失明

16 轮零新事实期间 `stall=0 idle=0 pressure=0%` —— 三个指标都基于"有动作/有 commit/有 token 消耗"，不基于 facts 增量，且被 blocked 记账喂饱。

**修法**：新增 `novelty_stall = 连续无新 fact 轮数`，阈值 8 即置 stall 并触发换路/封盘。

## NW-11（P1）无免费 intent 时事实无法落账

**现象**：第 199–207 轮间，`facts` 停滞而实际已有 5 条确证（Next.js 16.3.3、buildManifest 五前缀、`/callback/download`、SSTI 阴性、CVE 假阳性）。`nuwa_plan` 与 `nuwa_expand` 均返回"新增 0 条"，只能等 `i806/i803` 收口。

**修法**：facts 落账不应占用 intent；提供 `nuwa_note(kind, title, detail, evidence)` 独立写事实通道。

## NW-12（P1）端点清单高估：401 与 404 混淆

**证据**：member 面 15 条中，实际只有 `profile`、`bank` 存在（405 `allow: POST`），其余 13 条为 `404/6586B` 同页；早期把 401 与 404 混算，导致清单虚高到 63 条。

**修法**：端点事实必须区分 `exists_requires_auth(401/405)` 与 `not_found(404)`，并记录响应体指纹。

## NW-13（P1）软 404 与真实页面同码

**证据**：`/zh-tw/m/{login,game,deposit,withdraw,register}` 全 `200` 但正文是「找不到此頁面」；`/zh-tw/admin` 返回 200，flight 内是 `E{"digest":"NEXT_HTTP_ERROR_FALLBACK;404"}`。

**修法**：以 body 指纹 + 体积基线判真页；RSC 响应需检查 `NEXT_HTTP_ERROR_FALLBACK`。

## NW-14（P2）`nuwa_status` 单行 768B 截断

需读 `artifact://` 才能看全。**修法**：`raw=true` 或分页；或输出结构化 JSON 摘要。

## NW-15（P2）无只读诊断接口

主线程禁写 `.nuwa/*`，但 blocked 明细不可查（`state=261KB`）。**修法**：`nuwa_inspect(intent_id)` / `nuwa_query(status=blocked, target_key=...)`。

---

# D. 工具链与运行环境

## NW-16（P1）出口劣化无自愈，多 agent 抢同一链路

**证据**：`ProxyCheck` 六次对照 —— `101.36.104.239:10808` 第 1 次 200/110,674B/82.79s（TTFB 39s），第 2 次 reset（exit 97），第 3 次 CONNECT 拒绝（exit 7），完整成功率 1/6；`127.0.0.1:7890` 200/110,674B/4.28s。

**修法**：出口健康度探针 + 自动降级；任务按出口分池，避免并发抢占同一 socks 节点。

## NW-17（P1）browser/Turnstile 能力缺口

**证据**：sitekey 已取得，headless Chromium 反复 `ERR_FAILED`；`--user-data-dir` 未落地，token 无复用；后台残留 chromeproxy 服务需人工清理。

**修法**：支持持久化 profile + Xvfb 有头模式；"取 token"独立为可重试步骤。

## NW-18（P2）stage 状态与真实进展不符

**证据**：多个 agent 显示 `proxy 已定位`、`probing endpoints`，实际全部 403；状态文本无法区分"在探测"与"被墙"。

**修法**：stage 串需带最后一次成功状态码，`last_ok=200|none`。

## NW-19（P2）子代理不附带命中证据

回包常缺 `remote_ip` / `cf-ray` / `time_total`，无法区分"边缘拦截"与"源站响应"（4549B vs 4561B 只是页脚 IP 族差异）。

**修法**：输出契约强制三字段；缺字段判未执行。

## NW-20（P2）任务停止后残留服务

`chromeproxy`、`chromium-cdp`、`omp.browser.headless` 由子代理拉起，任务取消后仍在运行，需人工 `proc://…/kill`。

**修法**：任务级 cgroup/进程组回收；取消时级联清理。

## NW-21（P2）rejects 计数不足以触发策略变更

`rejects=1` 之后系统仍按原策略续跑，没有"连续拒绝→降级"路径。**修法**：rejects≥1 即强制进入 report/seal 分支。

## NW-22（P2）日志与账本分离，复盘成本高

本次复盘需从 208 轮 transcript 中人工拼出 22 项问题；账本只记 `blocked=true`。

**修法**：commit 支持 `evidence_ref`，指向落盘文件；提供 `nuwa_export(episode)` 导出时间线。

---

# 修复优先级

| 序 | 项 | 理由 |
|---|---|---|
| 1 | NW-03 出口注入 | 一条修好，可消除本次 60% 假阴性 |
| 2 | NW-04 阳性复核 | 防止假漏洞污染 facts（比假阴性更贵） |
| 3 | NW-01/02 去重与封盘 | 直接决定 ∞ budget 下能否收敛 |
| 4 | NW-06/07/08 交付校验 | 减少无效 token 消耗 |
| 5 | NW-10/11 观测与落账 | 让"停滞"和"已确证"都能被看见 |

---

# 附录：目标侧已确认事实（供封盘复用）

| 面 | 结论 | 依据 |
|---|---|---|
| 栈 | Next.js **16.3.3** + React 19.3.0-canary + Turbopack；后端 Laravel；前置 Cloudflare | f040 |
| RSC | `RSC:1` → 200/87,815B `text/x-component`；Server Actions **0 个** | f040/f047 |
| 中间件绕过 | CVE-2025-29927 **假阳性**（头被忽略，307 未变） | f043 |
| 路径穿越 | 32 组 + 190 组全 400/403，无文件读取 | i804 |
| 图片优化器 | 启用但白名单，`file://`/远端 → 400；SSRF 关闭 | f042 |
| SSTI | 阴性（载荷只进 flight searchParams） | f044 |
| Swagger/OpenAPI/GraphQL | 全无 | i811/i812/i819/i820 |
| source map | 24/24 全 404 | f046 |
| `/config` | 仅 `appleIcon.webp` 可读 | f039/f049 |
| 反代前缀 | `/api` `/file` `/liveapi` `/bkapi` `/r2imgs`（后三条未测通） | f041 |
| 未鉴权 POST 接口 | `web/news`、`web/activity`、`web/carousel`、`web/customLink/list`、`setting/gamePlat`、`setting/metaPixel`、`setting/captcha` | f048 + MobileTree |
| 需 token | `member/profile`、`member/bank`、`game/*` | f045 |
| 注册 | 真实面 `PUT /api/v1/member/signup`，需短信码 + Turnstile 双门；零账号创建 | RegisterFlow |
| 后台 | `/zh-tw/rest/admin/*` 前端页存在（31KB 级），`/api/v1/admin/*` 命名空间不存在；78 个模块键 | AdminModules |

---

# 第二批（第 213 轮复盘补充，NW-23 – NW-29）

| ID | 级别 | 问题 | 关键证据 |
|---|---|---|---|
| NW-23 | P1 | 派生去重键错误：新面被拒、死面重复 | 四条新提示 `nuwa_plan` 全「新增 0 条」；端口 21/22/23/53/110/111 被判死 3–4 轮；frontier 空时 expand 反出 11 条 |
| NW-24 | P2 | 停机路径不可发现 | `nuwa_stop` 三次调用才成功：schema 错 → 「永动模式只有目标完成才停」→ 需 `confirm="STOP"` |
| NW-25 | P1 | phase 机卡死 | `phase=report(E6)` 连续 60+ 轮；vuln done=4/blocked=76，exploit 0/1，post 0/1 |
| NW-26 | P1 | 子代理无超时无看门狗 | CmdInjProbe 1h54m、PathTraversal 1h54m、RegisterFlow 1h47m、MemberEnum 1h27m，全程 running |
| NW-27 | P1 | 运行期工作区丢失 | 第 183 轮 commit 61f9c95 成功后，第 208 轮 `/tmp/nuwa-study/.git` 不存在，目录只剩 docs/ |
| NW-28 | P1 | 工具层网络策略不一致 | bash: `nuwa N-007 靶标越界 (api.github.com)`；python urlopen → 200；gh auth 挂死 80s |
| NW-29 | P2 | blocked 计数与实际提交不一致 | 第 203–213 轮每轮 4 次 blocked commit，状态长期 `blocked=120` |

合计 **29 项**（含首批 22 项）。远端对应：总表 #20，子 issue #21–#49。
