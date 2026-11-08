#!/usr/bin/env bash
# 仓库内测试：单元 / 协议 / 混沌 / 并发 / 确定性 E2E。
# B 层靶场与 C 层会话在沙盒环境跑，见 docs/TESTING.md。
set -uo pipefail
cd "$(dirname "$0")" || exit 1
export NUWA_WORK="${NUWA_WORK:-$(cd .. && pwd)}"
# 清理一天前的 nuwa 测试临时目录，避免 /tmp 越跑越乱
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -user "$(id -u)" \
  \( -name 'nuwa-r1-*' -o -name 'nuwa-e2e-*' -o -name 'nuwa-chaos-*' \
     -o -name 'nuwa-guard-*' -o -name 'nuwa-unit-*' -o -name 'nuwa-night-*' \
     -o -name 'nuwa-qa-*' -o -name 'nuwa-soak-*' -o -name 'nuwa-crash-*' \
     -o -name 'nuwa-multi-*' -o -name 'nuwa-dispatch-*' \) \
  -mtime +1 -exec rm -rf {} + 2>/dev/null || true

fail=0
run() {
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  "$@" || { echo "  → FAIL"; fail=1; }
}

run contract python3 contract_check.py
run unit bun test unit.test.ts
run shell python3 test_nuwa_shell.py
run chaos python3 test_chaos.py
run concurrency python3 test_concurrency.py
run e2e python3 test_e2e_deterministic.py
run r1core python3 test_r1_core.py
run r1dispatch python3 test_r1_dispatch.py
run r1run python3 test_r1_run.py
run r1multi python3 test_r1_multi.py
run crash python3 crash_matrix.py --fake-repeat 2 --real-repeat 1
run guard python3 test_guard.py
run r2r7 python3 test_r2_r7.py
run gates bash gates/run.sh

printf '\n== 汇总 ==\n'
[[ $fail -eq 0 ]] && echo "全部通过" || echo "有失败用例"
exit $fail
