# 沙盒：三层验证

女娲模式的验证不依赖真实目标。三层沙盒各自回答一个问题：

| 层 | 回答什么 | 成本 | 位置 |
|---|---|---|---|
| A 协议仿真 | `bin/nuwa` 与 `nuwa-loop` 在边界条件下行为对不对 | 毫秒级 | `layer-a/` |
| B 真实靶场 | 真实 HTTP 目标上链路通不通 | 秒级 | `layer-b/` |
| C 会话沙盒 | `session_stop` 的 block 到底有没有发生 | 一次模型调用 | `layer-c/` |

## A 层：fake-sapper

`layer-a/fake-sapper` 是 sapper-v2 CLI 的协议级替身。它的目标不是"像"，而是"在 nuwa 会调用的每个面上逐字一致"：

- `frontier` 空图时输出 `(no ready intents)`
- `claim` 的 `--worker` 是必填项，缺了 `exit 2`
- `done` 的 `--fact` 是必填项
- `dispatch <id>` 会 `conclude_with_new_fact`，intent 自动 done、facts+1
- 所有调用写 `.sapper/calls.jsonl`，供断言"nuwa 到底传了什么"

故障注入：

| 变量 | 效果 |
|---|---|
| `FAKE_EMPTY_FRONTIER=1` | frontier 永远为空 |
| `FAKE_STALL=1` | reason 只产出同一个 intent |
| `FAKE_ERROR=1` | dispatch/claim/done 退出 1 |
| `FAKE_SLOW=<sec>` | dispatch 前睡眠 |
| `FAKE_COMPLETE_AFTER=<n>` | 第 n 次 reason 后 completed |
| `FAKE_NOOP_DISPATCH=1` | dispatch 不写 fact（模拟空转） |

跑测试：

```bash
cd layer-a/tests
NUWA_WORK=<repo> python3 test_nuwa_shell.py
```

14 项测试全部对应一个缺陷编号（P0-0.1 至 P2-2.6）。改造前 11 项失败，改造后全绿。

## B 层：Docker 靶场

四个目标覆盖四类响应：

| 容器 | 端口 | 类型 | 用途 |
|---|---|---|---|
| `nuwa-t1` | 18081 | 静态 flag | 正常链路 |
| `nuwa-t2` | 18082 | DVWA | 真实漏洞面 |
| `nuwa-t3` | 18083 | 30s 延迟 | 超时与预算 |
| `nuwa-t4` | 18084 | 全 403 | 无进展与 stall |

```bash
cd layer-b
./range-up.sh      # 起全部
./range-status.sh  # 看端口与请求数
./range-reset.sh   # 清日志重建
./range-down.sh    # 停
```

每个目标的请求写 `logs/<container>/access.jsonl`（时间、IP、方法、路径、UA）。

## C 层：headless 会话

```bash
cd layer-c
NUWA_C_TURNS=3 ./run-headless.sh
```

脚本会建一张 `.sapper` 图，用 `omp -p -e extensions/nuwa-loop/index.ts` 跑一个会话，然后检查：

- 日志出现 `armed`
- 日志出现 `block`，`turn` 递增
- 注入的 directive 里有 `claim --worker` / `doc --set`

## 压力与数据

```bash
python3 bin/stress.py --instances 4 --minutes 1
python3 bin/stress.py --instances 3 --minutes 1 --inject noop
python3 bin/analyze.py
```

`analyze.py` 输出 `reports/ANALYSIS.md`：退出码分布、耗时 p50/p95、dispatch 总数、靶场请求 RPS、会话 block 轮数。
