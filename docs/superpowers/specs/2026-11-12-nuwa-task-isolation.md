# 女娲任务隔离 G1 规格

日期：2026-11-12
基线：`ec839d8`（2.1.0）+ 本工作树已有 KB 未提交改动（保留，不动）
范围：`omp/nuwa.ts`、`tests/nuwa_isolation.test.ts`、`tests/run.sh`

## Goal

同一台机器上并行运行多个女娲任务时，项目状态、会话指针和 session_stop 续跑目标不互相串台。

1. **会话语义指针**：`writePointer` 按 `sessionId` 写独立文件；具名会话不读取无 sessionId 的 legacy 指针；`findRoot` 不把 `sessionId=""` 当作通配。
2. **共享 cwd 项目根隔离**：`/tmp`、home、`/data/workspace` 等共享目录下，新建项目默认落到 `AGENT_HOME/cache/nuwa-projects/<target>-<sessionHash>`，不复用共享 `.nuwa/state.json`。
3. **state 归属**：新建/恢复项目写入 `project.ownerSessionId`；`findRoot`/`findLocalRoot` 遇到其他会话的 owner 直接拒绝，不向父目录借用图。
4. **任务模式 cwd 优先**：`/nuwa <task>` 在非共享 cwd 优先当前目录项目；只有共享 cwd 才用本会话指针兜底。
5. **同根换目标**：同一目录/共享根已有 A 目标时，B 目标必须开隔离根（共享 cwd → `AGENT_HOME/cache/nuwa-projects`，非共享 cwd → `<cwd>/.nuwa-tasks`），不得并入 A 的 facts/intents。
6. **共享根不向下继承**：`/tmp` 等项目根只服务恰好位于该目录的会话，其子目录不再解析到该根。

## Non-goals

- 修改既有 `.tmp/nuwa-shuffle` 任务数据或清空历史 `.sapper` 事实。
- 修复 1.x 遗留测试套件（`test_install_*`、E2E tests/sapper 替身）与 2.x 不兼容的 known-red。
- 改变外部 CLI `bin/nuwa`、`nuwa/*.py` 的既有语义（工作树已有其他会话的 KB 改动）。

## Acceptance

```bigtask-checks
{"checks":[
  {"id":"v2-tests","argv":["bun","test","tests/omp_extension.test.ts","tests/omp_nuwa.test.ts","tests/nuwa_command.test.ts","tests/nuwa_isolation.test.ts"],"cwd":".","expected_exit":0},
  {"id":"isolation","argv":["bun","test","tests/nuwa_isolation.test.ts"],"cwd":".","expected_exit":0},
  {"id":"install","argv":["bash","-n","install.sh"],"cwd":".","expected_exit":0}
]}
```

## Rollback

- 源码：`git revert <本次提交>`；工作树 KB 改动不纳入提交。
- 运行时：备份 `~/.omp/agent/extensions/nuwa-omp/index.ts`，回滚时复制回并重启 omp 会话。
- 共享指针：`~/.omp/agent/cache/nuwa-current.json` 保留为 legacy 备份，新代码对具名会话忽略它。
