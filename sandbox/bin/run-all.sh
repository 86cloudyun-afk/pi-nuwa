#!/usr/bin/env bash
# 女娲测试总编排：五类测试 + 小长测，一条命令跑完。
#
#   ./run-all.sh                     # 全部（小长测 5 分钟）
#   ./run-all.sh --soak-minutes 15   # 小长测 15 分钟
#   ./run-all.sh --only shell,chaos  # 只跑指定段
#
# 段名：unit shell chaos concurrency e2e targets matrix soak
set -uo pipefail

SANDBOX="${NUWA_SANDBOX:-/srv/nuwa-sandbox}"
WORK="${NUWA_WORK:-$SANDBOX/work}"
export NUWA_SANDBOX="$SANDBOX" NUWA_WORK="$WORK"

SOAK_MIN="${SOAK_MINUTES:-5}"
ONLY=""
while (( $# )); do
  case "$1" in
    --soak-minutes) SOAK_MIN="${2:-5}"; shift 2 ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "未知参数 $1" >&2; exit 2 ;;
  esac
done

want() {
  [[ -z "$ONLY" ]] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

mkdir -p "$SANDBOX/reports"
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="$SANDBOX/reports/run-all-$STAMP"
mkdir -p "$REPORT"

declare -a NAMES=() CODES=()
run_section() {
  local name="$1"; shift
  want "$name" || return 0
  printf '\n========== %s ==========\n' "$name"
  local t0; t0=$(date +%s)
  "$@" >"$REPORT/$name.log" 2>&1
  local rc=$?
  local dt=$(( $(date +%s) - t0 ))
  tail -n 6 "$REPORT/$name.log" | sed 's/^/  /'
  printf '  → %s: %s (%ss)\n' "$name" "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" "$dt"
  NAMES+=("$name"); CODES+=("$rc")
}

run_unit() {
  cd "$SANDBOX/layer-a/tests" || return 1
  bun test unit.test.ts
}

run_shell() {
  cd "$SANDBOX/layer-a/tests" || return 1
  python3 test_nuwa_shell.py
}

run_chaos() {
  cd "$SANDBOX/layer-a/tests" || return 1
  python3 test_chaos.py
}

run_concurrency() {
  cd "$SANDBOX/layer-a/tests" || return 1
  python3 test_concurrency.py
}

run_e2e() {
  cd "$SANDBOX/layer-a/tests" || return 1
  python3 test_e2e_deterministic.py
}

run_matrix() {
  python3 "$SANDBOX/bin/matrix.py" --replicas 1 --minutes 1 --http-workers 4 --http-seconds 6 \
    --out "$REPORT/matrix"
}

run_targets() {
  "$SANDBOX/layer-b/range-up.sh" || return 1
  local fail=0
  # 每个目标用 curl 做一次类型断言
  local code
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/flag)
  [[ "$code" == "200" ]] || { echo "t1 flag: $code"; fail=1; }
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18084/)
  [[ "$code" == "403" ]] || { echo "t4 deny: $code"; fail=1; }
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18085/)
  [[ "$code" == "302" ]] || { echo "t5 redirect: $code"; fail=1; }
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18086/)
  [[ "$code" == "401" ]] || { echo "t6 basicauth: $code"; fail=1; }
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18087/)
  [[ "$code" == "404" ]] || { echo "t7 notfound: $code"; fail=1; }
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' -H 'Accept-Encoding: gzip' http://127.0.0.1:18088/)
  [[ "$code" == "200" ]] || { echo "t8 gzip: $code"; fail=1; }
  # curl 超时本身会打印 000，再 `|| echo 000` 会拼成 000000
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18083/ 2>/dev/null || true)
  [[ "$code" == "000" || -z "$code" ]] || { echo "t3 slow 应超时，实际 $code"; fail=1; }
  return $fail
}

run_soak() {
  python3 "$SANDBOX/bin/soak.py" --minutes "$SOAK_MIN" --interval 5 --instances 2 \
    --out "$REPORT/soak"
}

run_section unit run_unit
run_section shell run_shell
run_section chaos run_chaos
run_section concurrency run_concurrency
run_section e2e run_e2e
run_section targets run_targets
run_section matrix run_matrix
run_section soak run_soak

printf '\n========== 汇总 ==========\n'
FAIL=0
for i in "${!NAMES[@]}"; do
  rc="${CODES[$i]}"
  printf '  %-14s %s\n' "${NAMES[$i]}" "$([[ $rc -eq 0 ]] && echo PASS || echo "FAIL($rc)")"
  [[ $rc -ne 0 ]] && FAIL=1
done
printf '  报告目录: %s\n' "$REPORT"
exit $FAIL
