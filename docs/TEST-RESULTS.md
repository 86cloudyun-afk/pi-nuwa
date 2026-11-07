# 测试结果（0.3.0）

日期：2026-11-08
环境：us3，8 核 / 19G，Docker 29.1.3，Python 3.12.3，bun 1.4.4
原则：全部在沙盒机执行，不占本机负载。

## 一、五套测试

| 套件 | 用例 | 结果 | 耗时 |
|---|---|---|---|
| 单元 `unit.test.ts` | 18 | 18 pass / 0 fail | 0.11s |
| 协议 `test_nuwa_shell.py` | 14 | 14 pass | 10.8s |
| 混沌 `test_chaos.py` | 8 | 8 pass | 16.3s |
| 并发 `test_concurrency.py` | 5 | 5 pass | 150.2s |
| 端到端 `test_e2e_deterministic.py` | 4 | 4 pass | 78.4s |

基线对照：协议套件在 0.2.0 改造前是 **11 fail / 3 pass**，现在 14/14。

混沌覆盖：损坏 `project.json`、陈旧锁、活锁（真 flock）、非 sapper 非空目录、SIGKILL 恢复、1000 intent 性能、只读目录、缺 python3。

并发覆盖：同项目 5 实例单赢家（1×0 / 4×5）、5 个不同项目全成功、正常退出清锁、SIGTERM 清锁可接管、`--parallel 4` 无重复派发。

## 二、编排矩阵（8 类目标同时起）

| 指标 | 值 |
|---|---|
| 实例 | 8（t1–t8 各 1） |
| 成功 | 8/8 |
| 墙钟 | 63.3s |
| 每类 dispatch 调用 | 80–86 |
| 残留锁 | 0 |

## 三、HTTP 矩阵（4 worker × 6s × 8 目标）

| 目标 | 类型 | 请求 | 匹配 | p50 | p95 |
|---|---|---|---|---|---|
| t1 | static | 3283 | 100% | 2.3ms | 59.8ms |
| t2 | dvwa | 1117 | 100% | 7.6ms | 73.1ms |
| t3 | slow | 12 | 100%（超时） | 2004.2ms | 2004.8ms |
| t4 | deny | 3474 | 100% | 2.3ms | 61.4ms |
| t5 | redirect | 390 | 100% | 81.4ms | 89.4ms |
| t6 | basicauth | 3597 | 100% | 2.2ms | 62.2ms |
| t7 | notfound | 3123 | 100% | 2.4ms | 64.2ms |
| t8 | gzip | 3719 | 100% | 2.2ms | 61.8ms |

合计 18,715 次请求，八类响应面全部符合预期。

## 四、小长测（3 分钟 × 2 实例）

| 指标 | 值 | 判定 |
|---|---|---|
| 退出码 | 143 / 143（采样器主动收工） | PASS |
| RSS 斜率 | 0.33 KB/min | PASS（< 2048） |
| FD 斜率 | -0.165 /min | PASS（≤ 2） |
| facts 峰值 | 400 | — |
| 每 fact 状态体积 | 808 B | PASS（< 4096） |
| 事件日志 | 37.7 KB/min | PASS（< 512） |

采样 34 次，跳过前 6 个预热样本后做最小二乘。

## 五、本轮测试驱动修出的缺陷

| 缺陷 | 现象 | 修复 |
|---|---|---|
| 完成闸门出口缺口 | frontier 为空时提前 break，无证据完成不被拦截 | 预算用尽 / frontier 为空 / 循环末尾三个出口统一 `completion_ok` |
| SIGTERM 不退出 | `trap ... INT TERM` 只清锁，进程继续等子进程 | `on_signal` 清锁 + 收子进程 + `exit 143` |
| 损坏图未拦截 | `project.json` 非法 JSON 仍继续跑 | 前置校验，退出 2 |
| 项目目录语义 | 显式同名会被静默改名 | 有 `.sapper` 即复用，非空且无图才拒绝（退出 4） |
| 小长测口径 | SIGTERM 算失败、子进程 RSS 污染、图增长当泄漏 | 只测主进程、跳过预热、按每 fact 计 |

## 六、复现

```bash
cd <repo> && ./tests/run.sh                 # 五套，约 5 分钟
./bin/run-all.sh --soak-minutes 5           # 加靶场断言 + 矩阵 + 小长测
./bin/matrix.py --replicas 2 --minutes 1    # 单独跑矩阵
```

## 七、仓库布局复跑

从干净 checkout 直接跑 `./tests/run.sh`（不依赖沙盒目录结构）：

| 套件 | 结果 |
|---|---|
| unit | 18 pass / 0 fail |
| shell | 14 pass |
| chaos | 8 pass |
| concurrency | 5 pass |
| e2e | 4 pass |

CI 工作流 `.github/workflows/test.yml` 在每次 push 时复跑这五套（bun + python3 + 临时安装 sapper CLI）。

## 八、最终完整编排（8/8 PASS）

`./bin/run-all.sh --soak-minutes 3`，报告目录 `reports/run-all-20261107-175833`：

| 段 | 结果 | 耗时 |
|---|---|---|
| unit | PASS | ~0.1s |
| shell | PASS | ~11s |
| chaos | PASS | ~16s |
| concurrency | PASS | ~150s |
| e2e | PASS | ~78s |
| targets | PASS | ~18s |
| matrix | PASS | ~112s |
| soak | PASS | ~183s |

总墙钟 571s，全部在沙盒机执行。
