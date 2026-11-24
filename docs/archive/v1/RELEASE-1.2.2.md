# 女娲模式 1.2.2 — 续跑与 P-006 修复

## 修复
- P-006 的 `hasUnresolvedStore` 原用 `\bsapper\b`，会把 `/root/sapper-lab/bin/nuwa` 这类路径当成 `sapper` 命令；后续出现 `$PATH` 时整条 bash 被拦，模型无法执行续跑指令。
- 改为只匹配真正的 `sapper` 子命令（`sapper\s+`）后的变量展开。
- `session_stop` 找不到图时写 `stop_no_root` / `stop_no_graph`，不再静默返回。

## 激活实测
- 补指针 `~/.omp/agent/cache/nuwa-current -> /tmp/nuwa-shuffle` 后：
  - `armed` -> `block turn=1` -> 注入下一批 i011/i012；
  - `NUWA_MAX_TURNS=1` 时按预算 `stop max_turns`，属预期。
- P-006 修复后，新 omp 执行 `PATH=... /root/sapper-lab/bin/nuwa --version` 返回 `nuwa 1.2.2`。

## 验证
- 170 例 + 16 runs，contract 13/13，EXIT=0。
- TS 单测 45 pass。
