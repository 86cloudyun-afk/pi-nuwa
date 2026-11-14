# 自渗透执行器（2.6.0）

目标：把「确定性侦察」从模型手里拿走，让 omp 扩展自己跑、自己记账，模型只处理需要判断的节点。

## 1. 空转的三个形态

| 形态 | 现象 | 旧行为 |
|---|---|---|
| 只想不做 | 模型输出计划/总结，不调工具 | `idle++`，下一轮继续给同样的 directive |
| 反复试探 | 同一条 intent claim → blocked → 重领 | `attempts` 涨，没人止损 |
| frontier 注水 | fallback 生成低价值意图 | 模型做不动，循环烧预算 |

ARTEX 的对应做法：

- scheduler 决定批次，worker 执行；不把调度权交给模型。
- 「只有思考、无正文无工具」的回合注入续跑，每意图上限 2 次（`engine.go` `emptyTurnNudge`）。
- 限额属于意图总量，重启/换版本不重置（`llmretry.go` `emptyTurnNudgeLimit`）。

## 2. 架构

```text
session_stop
  ├─ applyEmptyGuard   连续 N 轮 facts 不涨 → 模型批 blocked + 清零
  ├─ autoPlan          补播 → 派生 → 推进 → 新 episode → 兜底
  ├─ claimAutoBatch    白名单意图标 claimed(worker=auto)
  ├─ buildDirective    只列判断类；单列「自动批在跑」
  └─ runAutoBatch      异步：pi.exec → parse → commitIntent
```

下一轮 `session_stop` 读到的就是已入账的事实。

## 3. 规则

| key | 命令 | 产出 | 超时 |
|---|---|---|---|
| `recon:http` | `curl -D - -o body -w FINAL` | `service`：状态/Server/X-Powered-By/标题/跳转 | 18s |
| `recon:ports` | `/dev/tcp` 29 端口 | `service`：开放端口聚合 | 50s |
| `recon:dirs` | 23 条常见路径 HEAD | `endpoint`：200/301/401/403/500 | 45s |
| `recon:tlsjs` | `openssl s_client + x509` | `service`：subject/issuer/SAN | 15s |
| `surface:sensitive` | robots/.git/.env/backup 等 6 条 | `vuln`（.git/.env）或 `endpoint` | 32s |
| `surface:api` | openapi/swagger/graphql 5 条 | `endpoint`：文档暴露 | 28s |

脚本用 `bash -lc`，参数 `shellQuote` 单引号转义；解析器是纯函数（`tests/autoexec.test.ts` 直接喂 stdout）。

## 4. 边界

不覆盖：

- `nmap` 全端口、`ffuf` 大字典、任何写操作、exploit 链、payload 构造。
- 需要看响应体语义的面（SQLi/XSS/SSTI 判定）。
- 这些仍由 `fujiang` 子代理或模型完成。

原因：扩展内 `pi.exec` 是同步阻塞的，长任务会卡住 settle；只放秒级、可解析、低风险的侦察。

## 5. 空转闸

```text
facts 数 == lastFacts ? emptyRounds++ : (emptyRounds=0, lastFacts=facts)
emptyRounds >= NUWA_EMPTY_LIMIT
  → 所有 claimed 且 worker != "auto" 的意图 blocked(note="空转: 连续 N 轮无新事实")
  → emptyRounds=0
  → 下一行 autoPlan 换面
```

自动批不参与：`worker="auto"` 的 claimed 不会被收口，避免网络慢时误杀。

## 6. 尝试上限

`autoPlan` 开头：`open|claimed` 且 `attempts >= NUWA_MAX_ATTEMPTS` → `blocked(note="尝试上限")`。
自动批 claim 时 `attempts += 1`，同一条规则最多跑 3 次。

## 7. 配置

| 变量 | 默认 | 作用 |
|---|---|---|
| `NUWA_AUTO` | `1` | `0` 关闭自动批（回到纯模型驱动） |
| `NUWA_AUTO_MAX` | `3` | 每轮自动批上限 |
| `NUWA_EMPTY_LIMIT` | `3` | 连续无新事实轮数 |
| `NUWA_MAX_ATTEMPTS` | `3` | 单意图尝试上限 |

## 8. 验收

```bash
cd tests
NUWA_WORK=/tmp/nuwa-study bun test autoexec.test.ts      # 18 例
NUWA_WORK=/tmp/nuwa-study bun test omp_nuwa.test.ts omp_extension.test.ts \
  nuwa_forever.test.ts ui.test.ts ui_native.test.ts       # 104 例
```

真实冒烟：本地 `127.0.0.1:18081` 静态站 → `nuwa_init` → 第一轮结束 →
`journal` 出现 `auto` 事件、`facts` 增长、`state.intents` 里自动批从 claimed 转 done。

## 9. 后续（2.7.0 候选）

- 自动批结果回来后派生下一层：开放端口 → 服务指纹，路径 → 参数枚举。
- 把 `runAutoBatch` 的规则表外置成 JSON，允许项目级扩展，不重启扩展。
- 自动批失败分类：网络不可达 / WAF 403 / 超时，分别走「重试 / 换面 / 降级」。
