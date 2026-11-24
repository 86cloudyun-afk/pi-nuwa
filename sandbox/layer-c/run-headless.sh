#!/usr/bin/env bash
# C 层：omp headless 会话沙盒。
#
# 默认验证 v2/v3（omp/nuwa.ts + bin/nuwa-autonomous 无头续跑与世代轮转），
# 保留 --v1 兼容选项以验证旧版 extensions/nuwa-loop/index.ts + sapper。
#
# 用法：
#   ./run-headless.sh                  # 默认 v2/v3 无头验证
#   ./run-headless.sh --autonomous     # 启用 bin/nuwa-autonomous 外层守护实跑
#   ./run-headless.sh --v1             # 兼容旧版 v1 sapper + nuwa-loop 验证
#   NUWA_C_TURNS=3 ./run-headless.sh
set -uo pipefail

MODE="v2"
USE_AUTONOMOUS="${NUWA_C_AUTONOMOUS:-0}"
for arg in "$@"; do
  case "$arg" in
    --v1) MODE="v1" ;;
    --v2) MODE="v2" ;;
    --autonomous) USE_AUTONOMOUS=1 ;;
    -h|--help)
      cat <<'EOF'
用法: ./run-headless.sh [--v2|--v1] [--autonomous]
  --v2          默认模式，验证 omp/nuwa.ts 与 bin/nuwa-autonomous 无头续跑
  --v1          兼容模式，验证旧版 extensions/nuwa-loop/index.ts + sapper
  --autonomous  配合 --v2 使用，直接通过 bin/nuwa-autonomous 拉起无头守护进程
EOF
      exit 0
      ;;
    *)
      echo "[c] 未知参数: $arg" >&2
      exit 2
      ;;
  esac
done

SANDBOX="${NUWA_SANDBOX:-/srv/nuwa-sandbox}"
WORK="${NUWA_WORK:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
AGENT_HOME="$SANDBOX/state/agent-c"
LAB="$SANDBOX/state/lab-c"
PROJ="$SANDBOX/state/c-project"
LOGS="$SANDBOX/logs/c"
MODEL="${NUWA_C_MODEL:-deepseek/deepseek-flash}"
MAXT="${NUWA_C_TURNS:-4}"

export PI_AGENT_HOME="$AGENT_HOME"
export NUWA_LOOP=1
export NUWA_MAX_TURNS="$MAXT"
export NUWA_MAX_STALL=3
export NUWA_IDLE_LIMIT=2
export NUWA_GUARD_HOURS=1

mkdir -p "$AGENT_HOME/cache" "$LAB" "$LOGS"
rm -rf "$PROJ"
mkdir -p "$PROJ"
cd "$PROJ" || exit 1

run_with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
  else
    python3 -c '
import subprocess, sys
secs = int(sys.argv[1])
try:
    p = subprocess.run(sys.argv[2:], timeout=secs)
    sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
' "$secs" "$@"
  fi
}

# us3 上没有 omp 命令时，直接用挂载的运行时
if command -v omp >/dev/null 2>&1; then
  OMP_CMD=(omp)
else
  OMP_CMD=(bun /srv/omp-sandbox/runtime/pi-coding-agent/dist/cli.js)
fi

if [[ "$MODE" == "v1" ]]; then
  export PATH="$SANDBOX/layer-a:$PATH"
  export SAPPER_HOME="$LAB"
  echo "[c:v1] 建图"
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

  echo "[c:v1] 启动 omp headless（max-turns=${MAXT}，engine=${OMP_CMD[0]}）"
  PROMPT='女娲模式。先执行一次 bash: cd '"$PROJ"' && sapper status，然后直接回复 DONE-1，不要做别的。'
  run_with_timeout 380 "${OMP_CMD[@]}" -p --no-extensions \
    -e "$WORK/extensions/nuwa-loop/index.ts" \
    --model "$MODEL" --max-time 300 \
    --cwd "$PROJ" -- "$PROMPT" >"$LOGS/omp-stdout.txt" 2>"$LOGS/omp-stderr.txt"
  RC=$?
  echo "[c:v1] omp exit=$RC"

  SIDLOG="$(ls -t "$AGENT_HOME"/cache/nuwa-loop/log/*.jsonl 2>/dev/null | head -1)"
  echo "[c:v1] 状态日志: ${SIDLOG:-（无）}"

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
    "mode": "v1",
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

  echo "[c:v1] 检查注入指令的关键参数"
  if grep -q -- '--worker' "$LOGS/omp-stdout.txt" 2>/dev/null; then echo "  claim --worker: OK"; else echo "  claim --worker: 未在 stdout 出现（看日志）"; fi
  if grep -q -- '--set' "$LOGS/omp-stdout.txt" 2>/dev/null; then echo "  doc --set: OK"; else echo "  doc --set: 未在 stdout 出现（看日志）"; fi
  exit 0
fi

# ---------------------------------------------------------------- v2/v3 默认模式
EXT_ENTRY="$WORK/omp/nuwa.ts"
AUTO_BIN="$WORK/bin/nuwa-autonomous"
if [[ ! -f "$EXT_ENTRY" ]]; then
  echo "[c:v2] ERROR: 缺少 $EXT_ENTRY" >&2
  exit 1
fi

export NUWA_PROJECT="$PROJ"
rm -rf "$AGENT_HOME/cache/nuwa-current"* "$AGENT_HOME/cache/nuwa-projects"

AUTONOMOUS_CHECK="absent"
if [[ -x "$AUTO_BIN" ]]; then
  echo "[c:v2] 预检 bin/nuwa-autonomous --dry-run"
  if "$AUTO_BIN" --target "http://127.0.0.1:18081" --mode ctf --root "$PROJ" \
      --max-generations 2 --reincarnate-turns "$MAXT" \
      --omp-bin "${OMP_CMD[0]}" --dry-run >"$LOGS/autonomous-dryrun.txt" 2>&1; then
    AUTONOMOUS_CHECK="dry_run_ok"
  else
    AUTONOMOUS_CHECK="dry_run_failed"
  fi
fi

if [[ "$USE_AUTONOMOUS" -eq 1 && -x "$AUTO_BIN" ]]; then
  echo "[c:v2] 通过 bin/nuwa-autonomous 启动无头守护（max-generations=2, turns=${MAXT}）"
  run_with_timeout 380 "$AUTO_BIN" \
    --target "http://127.0.0.1:18081" \
    --mode ctf \
    --goal "C 层 v2/v3 无头守护验证" \
    --root "$PROJ" \
    --max-generations 2 \
    --reincarnate-turns "$MAXT" \
    --model "$MODEL" \
    --omp-bin "${OMP_CMD[0]}" >"$LOGS/omp-stdout.txt" 2>"$LOGS/omp-stderr.txt"
  RC=$?
  AUTONOMOUS_CHECK="live_rc_$RC"
else
  echo "[c:v2] 启动 omp headless（max-turns=${MAXT}，ext=${EXT_ENTRY}，engine=${OMP_CMD[0]}）"
  PROMPT='女娲模式。先调用 nuwa_init(target="http://127.0.0.1:18081", mode="ctf", goal="C 层 v2 会话续跑验证")，再调用 nuwa_status，然后直接回复 DONE-1，不要做别的。'
  run_with_timeout 380 "${OMP_CMD[@]}" -p --no-extensions \
    -e "$EXT_ENTRY" \
    --model "$MODEL" --max-time 300 \
    --cwd "$PROJ" -- "$PROMPT" >"$LOGS/omp-stdout.txt" 2>"$LOGS/omp-stderr.txt"
  RC=$?
fi
echo "[c:v2] headless exit=$RC"

JLOG="$PROJ/.nuwa/journal.jsonl"
SPATH="$PROJ/.nuwa/state.json"
echo "[c:v2] 状态日志: ${JLOG}"

python3 - "$JLOG" "$SPATH" "$LOGS/result.json" "$MAXT" "$AUTONOMOUS_CHECK" <<'PY'
import json, pathlib, sys
jlog, spath, out, maxt, auto_chk = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
recs = []
if pathlib.Path(jlog).exists():
    for line in pathlib.Path(jlog).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
state = {}
if pathlib.Path(spath).exists():
    try:
        state = json.loads(pathlib.Path(spath).read_text(encoding="utf-8"))
    except Exception:
        state = {}
events = [r.get("type") or r.get("event") for r in recs]
blocks = [r for r in recs if (r.get("type") or r.get("event")) == "block"]
stops = [r for r in recs if (r.get("type") or r.get("event")) in ("stop_budget", "stop", "reincarnate")]
turns = [r.get("turn") for r in blocks if isinstance(r.get("turn"), int)]
proj_status = (state.get("project") or {}).get("status")
last_dir = (state.get("runtime") or {}).get("lastDirective") or ""
result = {
    "mode": "v2",
    "records": len(recs),
    "events": events,
    "armed": "init" in events or len(blocks) > 0,
    "blocks": len(blocks),
    "turns": turns,
    "turn_increasing": turns == sorted(turns) and len(set(turns)) == len(turns),
    "stopped": len(stops) > 0 or proj_status in ("stopped", "completed"),
    "stop_reason": (stops[0].get("why") if stops else None) or (state.get("project") or {}).get("stopReason"),
    "reached_max_turns": bool(turns and max(turns) >= maxt),
    "autonomous": auto_chk,
    "has_nuwa_claim_directive": "nuwa_claim" in last_dir,
    "has_nuwa_commit_directive": "nuwa_commit" in last_dir,
}
pathlib.Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2))
PY

echo "[c:v2] 检查 v2 工具与无头指令"
if grep -q 'nuwa_claim' "$LOGS/omp-stdout.txt" "$SPATH" 2>/dev/null; then echo "  nuwa_claim: OK"; else echo "  nuwa_claim: 未出现（看日志）"; fi
if grep -q 'nuwa_commit' "$LOGS/omp-stdout.txt" "$SPATH" 2>/dev/null; then echo "  nuwa_commit: OK"; else echo "  nuwa_commit: 未出现（看日志）"; fi
echo "  autonomous: $AUTONOMOUS_CHECK"

exit 0
