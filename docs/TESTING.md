# 测试矩阵

六类测试，全部可在无模型、无外网的条件下重复执行。

| 套件 | 文件 | 用例数 | 跑多久 | 回答什么 |
|---|---|---|---|---|
| 单元 | `tests/unit.test.ts` | 18 | ~0.2s | 纯函数对不对 |
| 协议 | `tests/test_nuwa_shell.py` | 14 | ~12s | CLI 契约对不对 |
| 混沌 | `tests/test_chaos.py` | 8 | ~16s | 坏状态会不会挂 |
| 并发 | `tests/test_concurrency.py` | 5 | ~90s | 锁与并行对不对 |
| 端到端 | `tests/test_e2e_deterministic.py` | 4 | ~2min | 整条链路通不通 |
| 小长测 | `tests/soak.py` | 1 | 可配 | 有没有慢性泄漏 |

## 单元（bun）

```bash
cd tests && NUWA_WORK=<repo> bun test unit.test.ts
```

覆盖 `findRoot` / `readGraph` / `buildDirective` / `revertCompletion` / `readCfg`：
指针 JSON 的 sessionId 校验、坏 JSON、note 噪声、证据判定、四个 sapper 动作的参数、stall/idle 升级、非法环境变量回落。

## 协议（fake-sapper）

`tests/fake-sapper` 是 sapper-v2 的协议级替身，逐字复刻输出与参数约束：

- `frontier` 空图输出 `(no ready intents)`
- `claim` 的 `--worker` 必填，缺了 `exit 2`
- `done` 的 `--fact` 必填
- `dispatch <id>` 自动 `conclude_with_new_fact`
- 所有调用写 `.sapper/calls.jsonl`

故障注入：`FAKE_EMPTY_FRONTIER` / `FAKE_STALL` / `FAKE_ERROR` / `FAKE_SLOW` / `FAKE_COMPLETE_AFTER` / `FAKE_NOOP_DISPATCH`。

## 混沌

| 用例 | 期望 |
|---|---|
| 损坏的 `project.json` | 退出 2，不抛 traceback |
| 陈旧锁（死 pid） | 忽略并接管 |
| 活锁（真的持有 flock） | 退出 5 |
| 非 sapper 非空目录 | 退出 4，不覆盖 |
| SIGKILL 后重启 | 可接管 |
| 1000 条 intent | 建图 < 30s |
| 只读项目目录 | 优雅失败 |
| 缺 python3 | 退出 3 |

## 并发

| 用例 | 期望 |
|---|---|
| 同一项目 5 实例 | 恰好 1 个跑，4 个退出 5 |
| 5 个不同项目 | 全部成功 |
| 正常退出 | 锁被清理 |
| SIGTERM | 锁被清理，下次可接管 |
| 单实例 `--parallel 4` | 同一 intent 不重复派发 |

## 端到端（确定性引擎）

`tests/fake-claude` 顶替模型：有 `--append-system-prompt` 判为 explore，否则判为 reason，产出合法的 sapper payload。零模型成本、完全确定。

模式：`normal` / `noop` / `hallucinate` / `malformed` / `slow`。

| 用例 | 期望 |
|---|---|
| 全链路 | reason → intents → dispatch → facts，`sapper validate` 通过 |
| 幻觉完成 | 无 flag/vuln/loot 的 `completed` 被打回 `active` + hint |
| 空 reason | frontier 为空，干净退出 |
| 非 JSON 输出 | 业务错误，不崩 |

## 小长测

```bash
python3 tests/soak.py --minutes 10 --interval 5 --instances 2
```

每 5 秒采样：主进程 RSS、FD、子进程数、facts 数、图 JSON 总字节、事件行数。
跳过前 20% 预热样本后算最小二乘斜率。判定口径：

- 退出码：0 或 143（采样器主动收工）
- RSS：< 2 MB/min（只算主进程，避免短命子进程干扰）
- FD：≤ 2/min
- 状态体积：< 4 KB/fact（图随事实增长是正常的，按每 fact 计）
- 事件日志：< 512 KB/min

## 多类型同时压测（matrix）

```bash
# 仓库内：脚本在 sandbox/bin/matrix.py，部署后位于 /srv/nuwa-sandbox/bin/matrix.py
python3 sandbox/bin/matrix.py --replicas 2 --minutes 1
python3 sandbox/bin/matrix.py --skip-orchestration --http-workers 4 --http-seconds 10
```

两段：

- **编排矩阵**：8 类目标 × N 副本同时起 `nuwa`（fake-sapper），断言退出码全 0、无残留锁、每类目标都有 dispatch。
- **HTTP 矩阵**：每类目标开 C 个并发 worker 打 D 秒，按类型断言状态码（static 200 / deny 403 / redirect 302 / basicauth 401 / notfound 404 / gzip 200 / slow 超时 / dvwa 200 或 302），统计 p50/p95 与匹配率。

## 总编排

```bash
./tests/run.sh                      # 契约 + 五套 + 门禁（固定顺序，无参数）
# 沙盒层（C 层、靶场、矩阵、小长测）
/srv/nuwa-sandbox/bin/sandbox.sh suite --soak-minutes 5
```

每段输出 `PASS/FAIL` 与耗时，报告落在 `reports/run-all-<ts>/`。

## 靶场（B 层）

8 个目标覆盖 8 类响应面：

| 端口 | 类型 | 断言 |
|---|---|---|
| 18081 | static | `/flag` 返回 200 + flag |
| 18082 | dvwa | 登录页 200/302 |
| 18083 | slow | 3s 客户端超时 |
| 18084 | deny | 403 |
| 18085 | redirect | 302 → `/a` 循环 |
| 18086 | basicauth | 401，带凭据 200 |
| 18087 | notfound | 404 |
| 18088 | gzip | 200 + `content-encoding: gzip` |

```bash
./layer-b/range-up.sh
./layer-b/range-status.sh
./layer-b/range-reset.sh
```


## 沙盒层（可选）

B 层（Docker 靶场）与 C 层（omp headless）不在仓库内，放在测试沙盒：

- `layer-b/range-up.sh`：8 个目标（static / dvwa / slow / deny / redirect / basicauth / notfound / gzip）
- `layer-c/run-headless.sh`：`omp -p -e extensions/nuwa-loop/index.ts` 验证 `armed` → `block`
- `bin/run-all.sh`：把五套测试 + 靶场断言 + 小长测串成一条命令
