# 女娲模式 1.1.0 发布说明

日期：2026-11-08
基线：1.0.0

## 新增

| 项 | 内容 |
|---|---|
| 扩展命令拦截 | `nuwa-loop` 的 `tool_call` 对 bash 命中 P-001..P-004 时返回 `block`，写 `policy_block`；`NUWA_POLICY_ENFORCE=0` 关闭 |
| 夜跑长测 | `nuwa soak-night --base DIR --minutes 4320 --projects 4 --interval 30`，可续跑，输出 `REPORT.json / MODE / COMMIT` |
| 崩溃矩阵 | `tests/crash_matrix.py`：7 个提交点，快速 2/1，`--full` 为 6×20 + 4×5 |
| 安装器 | 新增 `nuwa-soak-night` 入口 |

## 测试读数（us3）

- 扩展单测：22 例（新增 4 条命令策略）
- 崩溃矩阵快速组：16 runs 全过（每点崩溃后 repair + 重派只产生一个 fact）
- 夜跑冒烟：4 项目 / 6 秒，24 facts，RSS +792KB，FD +0，四项判据全 PASS
- 门禁 g0/g1/g2：见本轮 `tests/gates/run.sh` 退出码

## 仍待办

- 72h 夜跑需自托管 runner 实际执行；本轮只验证了入口与 6 秒冒烟
- 会话内 `task` 子代理的工具拦截依赖扩展已接线（bash 已覆盖），非 bash 工具尚未逐类拦截
- journal 仍为归档式压缩，未做历史代际删除
