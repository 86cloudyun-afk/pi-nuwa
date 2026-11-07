# 女娲模式 0.2.0 交付报告

日期：2026-11-08
仓库：`86cloudyun-afk/pi-nuwa`
提交：`11f9178`（父提交 `752f438`）
验证主机：测试沙盒机（8 核 / 19G / Docker 29.1.3 / Python 3.12.3 / bun 1.4.4）

---

## 一、任务

对 `pi-nuwa`（女娲模式）做维护升级：修复运行时缺陷、补齐可观测性、建立可重复利用的测试沙盒、做真实压力测试与数据分析。

规划见上一轮尸检报告（P0 6 条 / P1 10 条 / P2 7 条）。本轮全部落地，并额外修了沙盒实测中发现的 3 个新缺陷。

---

## 二、沙盒

### A 层：协议仿真（`layer-a/`）

`fake-sapper` 是 sapper-v2 CLI 的协议级替身，逐字复刻：

- `frontier` 空图输出 `(no ready intents)`
- `claim` 的 `--worker` 必填（缺了 `exit 2`）
- `done` 的 `--fact` 必填
- `dispatch <id>` 自动 `conclude_with_new_fact`
- 所有调用写 `.sapper/calls.jsonl`

故障注入：`FAKE_EMPTY_FRONTIER` / `FAKE_STALL` / `FAKE_ERROR` / `FAKE_SLOW` / `FAKE_COMPLETE_AFTER` / `FAKE_NOOP_DISPATCH`。

验收：`layer-a/tests/test_nuwa_shell.py`，14 项。

### B 层：真实靶场（`layer-b/`）

| 容器 | 端口 | 类型 |
|---|---|---|
| nuwa-t1 | 18081 | 静态 flag |
| nuwa-t2 | 18082 | DVWA |
| nuwa-t3 | 18083 | 30s 延迟 |
| nuwa-t4 | 18084 | 全 403 |

网络 `nuwa-range`（172.28.0.0/24），请求日志 `logs/<container>/access.jsonl`。

### C 层：headless 会话（`layer-c/`）

`omp -p -e extensions/nuwa-loop/index.ts` 跑真实会话，检查 `armed` / `block` / directive 参数。

### 总控

```bash
/srv/nuwa-sandbox/bin/sandbox.sh up|down|status|test|stress|session|report|reset
```

---

## 三、修复与验证

### P0（6/6）

| 编号 | 修复 | 验证 |
|---|---|---|
| 0.1 | 依赖闸门，缺 sapper/python3/curl 退出码 3 | `test_missing_sapper_exits_fast` PASS |
| 0.2 | frontier 只取 `^i[0-9]+` | `test_empty_frontier_does_not_dispatch_garbage` PASS；empty_frontier 压力 2.3s 干净退出 |
| 0.3 | directive 的 claim 带 `--worker` | `test_directive_claim_has_worker` PASS + 反向证明 `test_claim_without_worker_really_fails` PASS |
| 0.4 | directive 的 doc 带 `--set` | `test_directive_doc_has_body` PASS |
| 0.5 | install.sh 缺 sapper 硬失败 | `test_install_hard_fails_without_sapper` PASS |
| 0.6 | 生成 omp-claude 引擎 | `test_install_creates_engine` PASS |

### P1（10/10）

| 编号 | 修复 | 验证 |
|---|---|---|
| 1.1 | findRoot 去 mtime 兜底 + JSON 指针 + sessionId 校验 | `test_pointer_isolation` PASS |
| 1.2 | `.nuwa.lock` + flock + trap 清理 | 压力测试 `lock_left=0` |
| 1.3 | tool_call 结构化判定 | 源码审查 + C 层 armed 实测 |
| 1.4 | 触发词收紧 | 源码审查 |
| 1.5 | stall 用 effective 签名 | `test_stall_not_reset_by_note_facts` PASS |
| 1.6 | 环境变量数值校验 | `test_invalid_max_turns` PASS |
| 1.7 | stop_hook_active 处理 | 源码审查 |
| 1.8 | 超时继承 SAPPER_TIMEOUT + 剩余预算收敛 | 源码审查 |
| 1.9 | URL 规范化 | `test_url_without_scheme` PASS |
| 1.10 | 项目名防撞 | `test_same_minute_two_projects` PASS |

### P2（7/7）

| 编号 | 修复 | 验证 |
|---|---|---|
| 2.1 | JSONL 日志 | `test_jsonl_log` PASS + 压力事件统计 |
| 2.2 | `/nuwa-loop log/why/budget/reset` | 源码审查 |
| 2.3 | token 预算闸门 | 源码审查 |
| 2.4 | 空转检测 | 源码审查 |
| 2.5 | 看板联动 | 源码审查 |
| 2.6 | statePath 哈希 + schema | `test_state_schema` PASS |
| 2.7 | install 备份回滚 | 源码审查 |

### 新增防御（沙盒实测驱动，3 条）

| 缺陷 | 现象 | 修复 | 验证 |
|---|---|---|---|
| reason 幻觉直接 complete | B 层第一次跑，模型编造"已访问 /flag 拿到 flag"，项目变 completed，实际零请求 | 完成证据闸门：无 flag/vuln/loot 的 completed 打回 active + hint，最多 3 次 | 源码 + B 层复跑 |
| bash 循环无 stall 熔断 | noop 场景 61.8s / 405 次无效 dispatch | `graph_sig` + `NUWA_MAX_STALL`（默认 5） | **10.4s / 38 次**，事件 `stall_stop` |
| 锁文件残留 | 13 个实例留下 13 个 `.nuwa.lock` | `trap cleanup_lock EXIT INT TERM` | 复跑 `lock_left=0` |

---

## 四、压力与数据

### 正常 4 并发

| 指标 | 值 |
|---|---|
| 实例 | 4 |
| 成功 | 4/4 |
| 墙钟 | 61.7s |
| dispatch | 386 |
| 平均耗时 | 61.5s |

### 故障注入

| 场景 | 实例 | 墙钟 | dispatch | 结论 |
|---|---|---|---|---|
| empty_frontier | 3 | 2.3s | 3 | 空图干净退出，无垃圾 dispatch |
| error | 3 | 2.4s | 3 | 快速失败 |
| noop（修复前） | 3 | 61.8s | 405 | 烧满预算 |
| noop（修复后） | 2 | **10.4s** | **38** | `stall_stop` 生效 |

### 靶场真实流量

| 目标 | 请求数 | 唯一路径 | RPS |
|---|---|---|---|
| nuwa-t1 | 556 | 3 | 0.12 |
| nuwa-t3 | 51 | 2 | 0.38 |
| nuwa-t4 | 296 | 42 | 0.80 |

### 真实链路（B 层）

- `sapper dispatch reason` 调 deepseek-flash 成功（44s）
- `sapper dispatch i001 --claim` 真实执行 curl，写入 flag fact：`flag{nuwa-t4-deny}`
- sapper 内部拒绝重复 executor 结果（`already concluded`）

---

## 五、交付物

### 仓库

- `bin/nuwa`：328 行变更
- `extensions/nuwa-loop/index.ts`：442 行变更
- `install.sh`：111 行变更
- `README.md` / `docs/ARCHITECTURE.md` 重写
- 新增 `CHANGELOG.md`、`docs/SANDBOX.md`

### 沙盒（us3 `/srv/nuwa-sandbox/`）

```
bin/{sandbox.sh,stress.py,analyze.py,omp-claude}
layer-a/{fake-sapper,sapper,fixtures,tests/test_nuwa_shell.py}
layer-b/{range-up.sh,range-down.sh,range-status.sh,range-reset.sh,targets/server.js}
layer-c/run-headless.sh
reports/{baseline.txt,ANALYSIS.md,summary.json,stress-*}
logs/nuwa-t*/access.jsonl
```

---

## 六、复现

```bash
# 1. A 层验收（14 项，约 12s）
/srv/nuwa-sandbox/bin/sandbox.sh test

# 2. B 层靶场
/srv/nuwa-sandbox/bin/sandbox.sh up
/srv/nuwa-sandbox/bin/sandbox.sh status

# 3. 压力
/srv/nuwa-sandbox/bin/sandbox.sh stress 4 1
/srv/nuwa-sandbox/bin/sandbox.sh stress 3 1 noop

# 4. 会话
/srv/nuwa-sandbox/bin/sandbox.sh session

# 5. 报告
/srv/nuwa-sandbox/bin/sandbox.sh report
```

---

## 七、已知边界

1. **C 层 headless 的续跑链只跑一轮**：`omp -p` 在 hidden continuation 后受 `--max-time` 约束；`block` 本身已被验证，但多轮续跑在 print 模式下不稳定。交互式 TUI 不受此限。
2. **`sapper dispatch reason` 仍可能幻觉**：证据闸门只能拦截"无证据完成"，拦不住模型在 fact 里写不实描述。需要在 SKILL 层要求"每条 fact 带可复现命令"。
3. **token 预算为估算口径**：用上下文 tokens 增量累加，compaction 后会低估。
4. **B 层 t2 DVWA 未做全量回归**：只验证了登录页 200，未跑完整漏洞面。
