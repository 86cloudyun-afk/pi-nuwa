#!/usr/bin/env bash
# 阶段门禁：执行 tests/gates/g*.sh，聚合退出码。
# 阶段脚本自行负责前置检查（环境变量、沙盒可达性）。
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
shopt -s nullglob
scripts=(gates/g*.sh)
if (( ${#scripts[@]} == 0 )); then
  echo "gates: 暂无阶段脚本（R1 起逐步加入）"
  exit 0
fi

for s in "${scripts[@]}"; do
  printf '\n== %s ==\n' "$s"
  bash "$s" || fail=1
done
exit $fail
