#!/usr/bin/env bash
# C 层：omp headless 会话沙盒。
#
# 验证的不是"模型会不会打靶"，而是"nuwa-loop 会不会在 session_stop 时把 turn 顶回去"。
# 断言点：
#   1) 日志出现 armed
#   2) 日志出现 block，且 turn 递增
#   3) 注入的 reason 里带 claim --worker / doc --set / done --fact
#   4) 达到 NUWA_MAX_TURNS 后出现 stop 事件
#
# 用法：
#   ./run-headless.sh              # 本地或 us3 均可
#   NUWA_C_TURNS=3 ./run-headless.sh
set -uo pipefail

SANDBOX="${NUWA_SANDBOX:-/srv/nuwa-sandbox}"
WORK="${NUWA_WORK:-$SANDBOX/work}"
AGENT_HOME="$SANDBOX/state/agent-c"
LAB="$SANDBOX/state/lab-c"
PROJ="$SANDBOX/state/c-project"
LOGS="$SANDBOX/logs/c"
MODEL="${NUWA_C_MODEL:-deepseek/deepseek-flash}"
MAXT="${NUWA_C_TURNS:-4}"

export PATH="$SANDBOX/layer-a:$PATH"
export PI_AGENT_HOME="$AGENT_HOME"
export SAPPER_HOME="$LAB"
export NUWA_LOOP=1
export NUWA_MAX_TURNS="$MAXT"
export NUWA_MAX_STALL=3
export NUWA_IDLE_LIMIT=2
export NUWA_GUARD_HOURS=1

mkdir -p "$AGENT_HOME/cache" "$LAB" "$LOGS"
rm -rf "$PROJ"
mkdir -p "$PROJ"
cd "$PROJ" || exit 1

echo "[c] 建图"
sapper setup --goal "C 层会话续跑验证" --agents >/dev/null
sapper fact "靶标可达 http://127.0.0.1:18081" -t "靶标确认" -k host \
  -d ip=127.0.0.1 -d port=18081 -d url=http://127.0.0.1:18081 >/dev/null
sapper dispatch reason --model deepseek-flash >/dev/null
sapper frontier | head -3

# 指针：sessionId 留空，扩展会按 cwd 优先找到这张图
python3 - "$AGENT_HOME/cache/nuwa-current" "$PROJ" <<'PY'
import json, os, sys, time
with open(sys.argv[1] + ".tmp", "w") as f:
    json.dump({"root": os.path.abspath(sys.argv[2]), "sessionId": "", "ts": int(time.time()*1000)}, f)
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
PY
rm -rf "$AGENT_HOME/cache/nuwa-loop"

# us3 上没有 omp 命令时，直接用挂载的运行时
if command -v omp >/dev/null 2>&1; then
  OMP_CMD=(omp)
else
  OMP_CMD=(bun /srv/omp-sandbox/runtime/pi-coding-agent/dist/cli.js)
fi

echo "[c] 启动 omp headless（max-turns=$MAXT，engine=${OMP_CMD[0]}）"
PROMPT='女娲模式。先执行一次 bash: cd '"$PROJ"' && sapper status，然后直接回复 DONE-1，不要做别的。'
timeout 380 "${OMP_CMD[@]}" -p --no-extensions \
  -e "$WORK/extensions/nuwa-loop/index.ts" \
  --model "$MODEL" --max-time 300 \
  --cwd "$PROJ" -- "$PROMPT" >"$LOGS/omp-stdout.txt" 2>"$LOGS/omp-stderr.txt"
RC=$?
echo "[c] omp exit=$RC"

SIDLOG="$(ls -t "$AGENT_HOME"/cache/nuwa-loop/log/*.jsonl 2>/dev/null | head -1)"
echo "[c] 状态日志: ${SIDLOG:-（无）}"

python3 - "$SIDLOG" "$LOGS/result.json" "$MAXT" <<'PY'
import json, sys, pathlib
log, out, maxt = sys.argv[1], sys.argv[2], int(sys.argv[3])
recs = []
if log and pathlib.Path(log).exists():
    for line in pathlib.Path(log).read_text().splitlines():
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
events = [r.get("event") for r in recs]
blocks = [r for r in recs if r.get("event") == "block"]
stops = [r for r in recs if r.get("event") == "stop"]
turns = [r.get("turn") for r in blocks]
result = {
    "records": len(recs),
    "events": events,
    "armed": "armed" in events,
    "blocks": len(blocks),
    "turns": turns,
    "turn_increasing": turns == sorted(turns) and len(set(turns)) == len(turns),
    "stopped": len(stops) > 0,
    "stop_reason": stops[0].get("why") if stops else None,
    "reached_max_turns": bool(turns and max(turns) >= maxt),
}
pathlib.Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2))
print(json.dumps(result, ensure_ascii=False, indent=2))
PY

echo "[c] 检查注入指令的关键参数"
if grep -q -- '--worker' "$LOGS/omp-stdout.txt" 2>/dev/null; then echo "  claim --worker: OK"; else echo "  claim --worker: 未在 stdout 出现（看日志）"; fi
if grep -q -- '--set' "$LOGS/omp-stdout.txt" 2>/dev/null; then echo "  doc --set: OK"; else echo "  doc --set: 未在 stdout 出现（看日志）"; fi

exit 0
