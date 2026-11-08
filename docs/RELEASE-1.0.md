# 女娲模式 1.0.0 发布说明

日期：2026-11-08
基线提交：见 git tag `v1.0.0`

## 交付范围

| 阶段 | 能力 | 状态 |
|---|---|---|
| R1 | 多项目注册表、journal/checkpoint、run/txn/inflight 锁、幂等提交、dispatch、run、resume、adopt、repair | 已实现 |
| R2 | 全局账本、准入与预留、加权公平调度模拟、超支口径 | 已实现 |
| R3 | 证据采集/校验（五类拒绝）、置信度 rubric | 已实现 |
| R4 | `metrics --json`、离线 HTML、webhook 告警 | 已实现 |
| R5 | 命令 allow/deny、脱敏、HMAC 签名校验、渲染提示注入门 | 已实现 |
| R6 | 插件加载（api_version）、`loop_schema 2→3` 写入迁移 | 已实现 |
| R7 | `nuwa soak` 多项目采样与判据 | 已实现 |

## 测试读数（us3）

- R1 core 11、dispatch 2、run 1、multi 1
- R2–R7 模块 17
- 契约 13
- 门禁 g0/g1/g2 全部通过
- 完整 `tests/run.sh`（契约/单元/协议/混沌/并发/端到端/R1/R2–R7/门禁）退出码 0

### 16 项目 × 3 分钟压力测试（us3，fake 引擎）

| 指标 | 读数 | 判定 |
|---|---|---|
| 项目 | 16 | — |
| dispatch | 444 | — |
| facts | 460 | PASS |
| RSS 增长 | 4188 KB | PASS |
| FD 增长（稳态最小值） | 0 | PASS |
| 退出码 | 16/16 = 0 | PASS |

### 2 分钟 × 4 项目长测（us3，fake 引擎）

| 指标 | 读数 | 判定 |
|---|---|---|
| 样本 | 24（5s 间隔） | — |
| facts | 438 | PASS |
| RSS 增长 | 1524 KB | PASS |
| FD 增长（稳态最小值） | +2 | PASS |
| 退出码 | 4/4 = 0 | PASS |

## 已知缺口（GA 前必须关闭）

1. **72 小时长测未跑**：`nuwa soak` 已具备采样与判据，259200 秒需自托管 runner，本轮只做了 3 分钟压力测试。
2. **R5 子代理工具级强制**：已实现渲染提示注入门与检查器；会话内 `task` 子代理的 `tool_call` 拦截仍需扩展侧接线。
3. **崩溃注入规模**：已覆盖 4 个提交点各 1 次；路线图的 6×20 + 4×5 全量矩阵未跑。
4. **journal 压缩为归档式**：`journal.<gen>.jsonl` 保留历史，磁盘随运行增长；真正的截断/回滚未做。
5. **图 schema 归 sapper 管**：nuwa 只迁移自身状态，不做图迁移。

## 升级方式

```bash
git fetch --tags && git checkout v1.0.0-rc1
./install.sh          # 安装 CLI + nuwa 包 + 扩展 + skill
./tests/run.sh        # 仓库内测试
```

## 回滚

`./install.sh --rollback` 恢复扩展备份；状态文件按 `.nuwa/` 目录单独备份。
