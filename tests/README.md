# 测试

本目录是仓库自带的五套测试。B 层靶场与 C 层会话需要 Docker / omp，见 [`../docs/TESTING.md`](../docs/TESTING.md)。

```bash
./tests/run.sh
```

## 套件

| 文件 | 用例 | 依赖 | 说明 |
|---|---|---|---|
| `unit.test.ts` | 18 | bun | `findRoot` / `readGraph` / `buildDirective` / `revertCompletion` / `readCfg` |
| `test_nuwa_shell.py` | 14 | python3 | CLI 契约，对应 P0/P1/P2 每个缺陷编号 |
| `test_chaos.py` | 8 | python3 + flock | 坏图、陈旧锁、活锁、SIGKILL、只读目录、大图性能 |
| `test_concurrency.py` | 5 | python3 + flock | 同项目单赢家、跨项目并行、锁清理、无重复派发 |
| `test_e2e_deterministic.py` | 4 | python3 | 用 `fake-claude` 跑完整链路，零模型成本 |

## 两个替身

- `fake-sapper`：sapper-v2 CLI 的协议级替身，逐字复刻输出格式与参数约束（`claim --worker` 必填、`done --fact` 必填、空图输出 `(no ready intents)`）。
- `fake-claude`：claude 兼容引擎，有 `--append-system-prompt` 判为 explore，否则判为 reason，产出合法 sapper payload。模式 `normal` / `noop` / `hallucinate` / `malformed` / `slow`。

## 环境变量

| 变量 | 默认 | 用途 |
|---|---|---|
| `NUWA_WORK` | 仓库根 | 被测代码所在目录 |
| `NUWA_BIN` | `$NUWA_WORK/bin/nuwa` | 被测入口 |
| `NUWA_EXT` | `$NUWA_WORK/extensions/nuwa-loop/index.ts` | 被测扩展 |
| `FAKE_ENGINE_MODE` | `normal` | `fake-claude` 的行为 |
| `FAKE_EMPTY_FRONTIER` 等 | — | `fake-sapper` 的故障注入 |

## 判定标准

每套测试都遵循「改造前必须 FAIL、改造后必须 PASS」。基线报告在沙盒的 `reports/baseline.txt`：14 项协议测试里有 11 项失败。
