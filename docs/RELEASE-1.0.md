# 女娲模式 1.0.0-rc1 发布说明

日期：2026-11-08
基线提交：见 git tag `v1.0.0-rc1`

## 交付范围

| 阶段 | 能力 | 状态 |
|---|---|---|
| R1 | 多项目注册表、journal/checkpoint、run/txn/inflight 锁、幂等提交、dispatch、run、resume、adopt、repair | 已实现 |
| R2 | 全局账本、准入与预留、加权公平调度模拟、超支口径 | 已实现 |
| R3 | 证据采集/校验（五类拒绝）、置信度 rubric | 已实现 |
| R4 | `metrics --json`、离线 HTML、webhook 告警 | 已实现 |
| R5 | 命令 allow/deny、脱敏、HMAC 签名校验 | 已实现（检查器） |
| R6 | 插件加载（api_version）、迁移 dry-run | 已实现（最小） |
| R7 | `nuwa soak` 多项目采样与判据 | 已实现 |

## 测试读数（us3）

- R1 core 11、dispatch 2、run 1、multi 1
- R2–R7 模块 17
- 契约 13
- 门禁 g0/g1/g2 全部通过

### 2 分钟 × 4 项目长测（us3，fake 引擎）

| 指标 | 读数 | 判定 |
|---|---|---|
| 样本 | 24（5s 间隔） | — |
| facts | 438 | PASS |
| RSS 增长 | 1524 KB | PASS |
| FD 增长（稳态最小值） | +2 | PASS |
| 退出码 | 4/4 = 0 | PASS |

## 已知缺口（GA 前必须关闭）

1. **72 小时长测未跑**：`nuwa soak` 已具备采样与判据，但 259200 秒的有效运行需自托管 runner，本轮未执行。
2. **R5 强制点未接入执行链**：策略检查器与脱敏可用，但 bash 循环与会话子代理的实际拦截尚未接线；当前是“可检查”而非“强制”。
3. **R6 迁移只做 dry-run**：`loop_schema 2→3` 的写入迁移未实现。
4. **checkpoint 压缩未截断 journal**：只写 checkpoint 与 CURRENT，未做代际截断/回滚。
5. **十点崩溃注入**：已有 repair 与单点用例，未跑 6×20 + 4×5 全量。

## 升级方式

```bash
git fetch --tags && git checkout v1.0.0-rc1
./install.sh          # 安装 CLI + nuwa 包 + 扩展 + skill
./tests/run.sh        # 仓库内测试
```

## 回滚

`./install.sh --rollback` 恢复扩展备份；状态文件按 `.nuwa/` 目录单独备份。
