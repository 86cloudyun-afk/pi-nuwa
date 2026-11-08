#!/usr/bin/env bash
# 阶段门禁：按 expected 清单校验脚本存在且非空，再逐个执行。
# expected 每行一个门禁名（不含 g 前缀与 .sh 后缀），例如 baseline。
# 新增阶段时，同一 PR 内把门禁名加入 expected。
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

EXPECTED="gates/expected"
fail=0
declare -a names=()

if [[ -f "$EXPECTED" ]]; then
  while IFS= read -r line; do
    [[ -z "${line// }" || "${line:0:1}" == "#" ]] && continue
    names+=("$line")
  done <"$EXPECTED"
else
  echo "gates: 缺少 $EXPECTED" >&2
  exit 1
fi

if (( ${#names[@]} == 0 )); then
  echo "gates: expected 为空" >&2
  exit 1
fi

for n in "${names[@]}"; do
  f="gates/g${n}.sh"
  if [[ ! -s "$f" ]]; then
    echo "gates: 缺少或为空: $f" >&2
    fail=1
  fi
done

# 额外脚本也执行（不在 expected 里的，不强制）
shopt -s nullglob
for f in gates/g*.sh; do
  printf '\n== %s ==\n' "$f"
  [[ -s "$f" ]] || { echo "gates: 空脚本 $f" >&2; fail=1; continue; }
  bash "$f" || fail=1
done

exit $fail
