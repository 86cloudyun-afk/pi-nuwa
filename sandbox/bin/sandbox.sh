#!/usr/bin/env bash
# 女娲沙盒总控：一条命令拉起/验证/压测/出报告。
#
#   ./sandbox.sh up        起 B 层靶场 + 检查 A/C 依赖
#   ./sandbox.sh down      停靶场
#   ./sandbox.sh status    三层状态
#   ./sandbox.sh test      A 层 14 项验收
#   ./sandbox.sh stress    [instances] [minutes] [inject]
#   ./sandbox.sh session   C 层 headless
#   ./sandbox.sh matrix    多类型同时压测（编排矩阵 + HTTP 矩阵）
#   ./sandbox.sh suite     五套测试 + 靶场 + 矩阵 + 小长测（调 run-all.sh）
#   ./sandbox.sh report    生成 ANALYSIS.md
#   ./sandbox.sh reset     清状态与日志后重建
set -uo pipefail

SANDBOX="${NUWA_SANDBOX:-/srv/nuwa-sandbox}"
WORK="${NUWA_WORK:-$SANDBOX/work}"
export NUWA_SANDBOX="$SANDBOX" NUWA_WORK="$WORK"

say() { printf '[sandbox] %s\n' "$*"; }

case "${1:-status}" in
  up)
    "$SANDBOX/layer-b/range-up.sh" || exit 1
    command -v bun >/dev/null 2>&1 || { say "bun 缺失，C 层会退化为 node"; }
    command -v sapper >/dev/null 2>&1 || say "sapper 未安装：bash $SANDBOX/vendor/sapper-v2/install.sh --cli-only"
    say "A 层: $SANDBOX/layer-a/fake-sapper"
    say "C 层: $SANDBOX/layer-c/run-headless.sh"
    ;;
  down)
    "$SANDBOX/layer-b/range-down.sh"
    ;;
  status)
    say "=== B 层 ==="
    "$SANDBOX/layer-b/range-status.sh"
    say "=== A 层 ==="
    [[ -x "$SANDBOX/layer-a/fake-sapper" ]] && say "fake-sapper OK" || say "fake-sapper 缺失"
    say "=== C 层 ==="
    [[ -f "$SANDBOX/layer-c/run-headless.sh" ]] && say "run-headless OK" || say "run-headless 缺失"
    say "=== 图 ==="
    ls -d "$SANDBOX"/state/*/.sapper 2>/dev/null | wc -l | xargs -I{} echo "  {} 张图"
    ;;
  test)
    cd "$SANDBOX/layer-a/tests" || exit 1
    python3 test_nuwa_shell.py
    ;;
  stress)
    I="${2:-4}"; M="${3:-1}"; INJ="${4:-}"
    args=(--instances "$I" --minutes "$M" --out "$SANDBOX/reports/stress-$(date +%H%M%S)")
    [[ -n "$INJ" ]] && args+=(--inject "$INJ")
    python3 "$SANDBOX/bin/stress.py" "${args[@]}"
    ;;
  session)
    "$SANDBOX/layer-c/run-headless.sh"
    ;;
  matrix)
    shift || true
    python3 "$SANDBOX/bin/matrix.py" "$@"
    ;;
  suite)
    shift || true
    "$SANDBOX/bin/run-all.sh" "$@"
    ;;
  report)
    python3 "$SANDBOX/bin/analyze.py"
    say "报告: $SANDBOX/reports/ANALYSIS.md"
    ;;
  reset)
    "$SANDBOX/layer-b/range-reset.sh"
    rm -rf "$SANDBOX"/state/* "$SANDBOX"/logs/*
    say "状态与日志已清空"
    ;;
  *)
    sed -n '2,14p' "$0"
    exit 2
    ;;
esac
