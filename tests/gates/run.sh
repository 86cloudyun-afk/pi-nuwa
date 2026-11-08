#!/usr/bin/env bash
# 阶段门禁：已发布历史 + 已交付清单 + 非空校验 + 执行。
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# 本版本已交付的阶段门禁：只增不减
DELIVERED=(0_baseline)
EXPECTED="gates/expected"
RELEASED="gates/released.json"

fail=0
declare -a names=()

[[ -f "$EXPECTED" ]] || { echo "gates: 缺少 $EXPECTED" >&2; exit 1; }
[[ -f "$RELEASED" ]] || { echo "gates: 缺少 $RELEASED" >&2; exit 1; }

while IFS= read -r line; do
  [[ -z "${line// }" || "${line:0:1}" == "#" ]] && continue
  names+=("$line")
done <"$EXPECTED"

(( ${#names[@]} > 0 )) || { echo "gates: expected 为空" >&2; exit 1; }

has_name() {
  local needle="$1" n
  for n in "${names[@]}"; do [[ "$n" == "$needle" ]] && return 0; done
  return 1
}

# 1) 本版本已交付清单必须在 expected 中
for c in "${DELIVERED[@]}"; do
  has_name "$c" || { echo "gates: 已交付门禁 $c 不在 expected 中" >&2; fail=1; }
done

# 2) 历史发布过的门禁必须在 expected 中（删除需改 released.json，属发布变更）
gate_tmp="$(mktemp)"
python3 - "$RELEASED" >"$gate_tmp" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"gates: released.json 解析失败: {exc}", file=sys.stderr)
    sys.exit(2)
if not isinstance(d, dict) or not all(isinstance(v, list) for v in d.values()):
    print("gates: released.json 结构必须是 {version: [gate]}", file=sys.stderr)
    sys.exit(3)
for gates in d.values():
    for g in gates:
        print(g)
PY
rc=$?
if (( rc != 0 )); then
  fail=1
fi
while IFS= read -r g; do
  [[ -z "$g" ]] && continue
  has_name "$g" || { echo "gates: 历史门禁 $g 缺失" >&2; fail=1; }
done <"$gate_tmp"
rm -f "$gate_tmp"

# 3) 每个清单项必须有非空脚本
for n in "${names[@]}"; do
  f="gates/g${n}.sh"
  [[ -s "$f" ]] || { echo "gates: 缺少或为空: $f" >&2; fail=1; }
done

# 4) 执行所有实际存在的脚本
shopt -s nullglob
for f in gates/g*.sh; do
  printf '\n== %s ==\n' "$f"
  [[ -s "$f" ]] || { echo "gates: 空脚本 $f" >&2; fail=1; continue; }
  bash "$f" || fail=1
done

exit $fail
