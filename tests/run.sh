#!/usr/bin/env bash
# 仓库内测试：单元 / 协议 / 混沌 / 并发 / 确定性 E2E。
# B 层靶场与 C 层会话在沙盒环境跑，见 docs/TESTING.md。
set -uo pipefail
cd "$(dirname "$0")" || exit 1
export NUWA_WORK="${NUWA_WORK:-$(cd .. && pwd)}"

fail=0
run() {
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  "$@" || { echo "  → FAIL"; fail=1; }
}

run unit bun test unit.test.ts
run shell python3 test_nuwa_shell.py
run chaos python3 test_chaos.py
run concurrency python3 test_concurrency.py
run e2e python3 test_e2e_deterministic.py

printf '\n== 汇总 ==\n'
[[ $fail -eq 0 ]] && echo "全部通过" || echo "有失败用例"
exit $fail
