# 女娲任务隔离 G2 计划

1. **T1 会话语义指针**
   - 文件：`omp/nuwa.ts`、`tests/nuwa_isolation.test.ts`
   - RED：legacy 空 sessionId 指针被具名会话接管；两个 session 指针互相覆盖。
   - GREEN：`writePointer` 写 `nuwa-current.d/<sha(sessionId)>.json`；`findRoot` 具名会话只读本会话指针；无 sessionId 才读 legacy。
   - 验收：隔离测试前 3 例。

2. **T2 共享 cwd 根隔离**
   - 文件：`omp/nuwa.ts`、`tests/nuwa_isolation.test.ts`
   - RED：`nuwa_init` 在 `/tmp` 写 `/tmp/.nuwa/state.json`；两个 session 同 target 共用。
   - GREEN：`isSharedCwd` + `defaultProjectRoot`；`nuwa_init`/`/nuwa` 在共享 cwd 用 `nuwa-projects`。
   - 验收：隔离测试后 2 例，包含真实 `nuwa_init` 不写 `/tmp/.nuwa`。

3. **T3 owner 与命令根选择**
   - 文件：`omp/nuwa.ts`、`tests/nuwa_command.test.ts`、`tests/nuwa_isolation.test.ts`
   - RED：其他 session 的 state 被向父目录借用；`/nuwa` 在非共享新 cwd 并入旧项目。
   - GREEN：`project.ownerSessionId`；`rootForSession` 直接 reject；`/nuwa` 非共享 cwd 优先 cwd。
   - 验收：v2 55+ 例全绿；全量 known-red 只保留 1.x 遗留项。

4. **T4 同根换目标隔离（2.1.2）**
   - 文件：`omp/nuwa.ts`、`tests/nuwa_isolation.test.ts`
   - RED：共享根已有 A 项目时，同一会话 `/nuwa B` 把 B 并进 A；`findRoot` 从子目录继承共享根的 A。
   - GREEN：`findRoot`/`findLocalRoot` 按 target 过滤；共享根不向下继承；`defaultProjectRoot` 为同根第二目标开隔离根（共享 cwd → `cache/nuwa-projects`，非共享 cwd → `.nuwa-tasks`）。
   - 验收：isolation 第 7–11 例。

5. **T5 入口一致与装机**
   - `nuwa_init`、`/nuwa` 共用根选择；`VERSION=2.1.2`；装机后 `sha256(index.ts) == sha256(omp/nuwa.ts)`。
   - 验收：v2 61 例全绿、`bash -n install.sh`、装机哈希一致、双会话指针目录各写各的。

6. **T6 共享根被占用的指针回落（2.1.3）**
   - RED：`/tmp` 有旧 owner 项目时，`findRoot("/tmp", 新会话)` 被 reject 直接置空，`nuwa_frontier` 报「未找到女娲项目」。
   - GREEN：reject / 目标不符只终止向上扫描，继续落到本会话指针。
   - 验收：isolation 第 12 例 + 实盘 `nuwa_frontier` 返回 6 条 recon。

## 回滚点

每个任务一个本地 commit；失败回到上一个绿测。安装前备份已安装扩展。
