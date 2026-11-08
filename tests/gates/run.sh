#!/usr/bin/env bash
# 阶段门禁：核心锚点 + expected 清单 + 非空校验 + 执行。
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# 已交付阶段清单：只增不减。新增阶段时把门禁名加入此数组与 expected。
DELIVERED=(0_baseline)
EXPECTED="gates/expected"

fail=0
declare -a names=()

if [[ ! -f "$EXPECTED" ]]; then
  echo "gates: 缺少 $EXPECTED" >&2
  exit 1
fi

while IFS= read -r line; do
  [[ -z "${line// }" || "${line:0:1}" == "#" ]] && continue
  names+=("$line")
done <"$EXPECTED"

if (( ${#names[@]} == 0 )); then
  echo "gates: expected 为空" >&2
  exit 1
fi

# 已交付门禁必须在清单中
for c in "${DELIVERED[@]}"; do
  found=0
  for n in "${names[@]}"; do
    [[ "$n" == "$c" ]] && found=1
  done
  if (( found == 0 )); then
    echo "gates: 已交付门禁 $c 不在 expected 中" >&2
    fail=1
  fi
done

# 每个清单项必须有非空脚本
for n in "${names[@]}"; do
  f="gates/g${n}.sh"
  if [[ ! -s "$f" ]]; then
    echo "gates: 缺少或为空: $f" >&2
    fail=1
  fi
done

# 执行所有实际存在的脚本
shopt -s nullglob
for f in gates/g*.sh; do
  printf '\n== %s ==\n' "$f"
  [[ -s "$f" ]] || { echo "gates: 空脚本 $f" >&2; fail=1; continue; }
  bash "$f" || fail=1
done

exit $fail
