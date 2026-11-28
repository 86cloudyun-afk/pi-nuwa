#!/usr/bin/env bash
# 仓库内测试：版本一致性 / 契约 / bun 隔离测试 / 混沌 / 并发 / 确定性 E2E / R1-R7 / 门禁。
# B 层靶场与 C 层会话在沙盒环境跑，见 docs/TESTING.md。
set -uo pipefail
cd "$(dirname "$0")" || exit 1
export NUWA_WORK="${NUWA_WORK:-$(cd .. && pwd)}"
# 避免宿主 shell 预设 BUN_OPTIONS=--preload 干扰 bun test 子命令解析
unset BUN_OPTIONS

V2_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --v2-only) V2_ONLY=1 ;;
    -h|--help)
      echo "用法: $0 [--v2-only]"
      exit 0
      ;;
    *)
      echo "未知参数: $arg" >&2
      exit 2
      ;;
  esac
done

# 清理一周前的 nuwa 测试临时目录，避免 /tmp 越跑越乱
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -user "$(id -u)" \
  \( -name 'nuwa-r1-*' -o -name 'nuwa-e2e-*' -o -name 'nuwa-chaos-*' \
     -o -name 'nuwa-guard-*' -o -name 'nuwa-unit-*' -o -name 'nuwa-night-*' \
     -o -name 'nuwa-qa-*' -o -name 'nuwa-soak-*' -o -name 'nuwa-crash-*' \
     -o -name 'nuwa-multi-*' -o -name 'nuwa-dispatch-*' \) \
  -mtime +7 -exec rm -rf {} + 2>/dev/null || true

fail=0
run() {
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  "$@" || { echo "  → FAIL"; fail=1; }
}

run_shell_suite() {
  if command -v flock >/dev/null 2>&1; then
    python3 test_nuwa_shell.py
  else
    echo "[skip] 缺少 flock，跳过 3 个依赖 bin/nuwa flock 的用例 (P0_FrontierGuard/P1_UrlNormalize/P1_ProjectCollision)"
    python3 -m unittest -v \
      test_nuwa_shell.P0_ClaimWorker \
      test_nuwa_shell.P0_DocSet \
      test_nuwa_shell.P0_DependencyCheck \
      test_nuwa_shell.P0_InstallGuard \
      test_nuwa_shell.P0_EngineWrapper \
      test_nuwa_shell.P1_FindRootIsolation \
      test_nuwa_shell.P1_StallSignal \
      test_nuwa_shell.P1_EnvValidation \
      test_nuwa_shell.P2_StateSchema \
      test_nuwa_shell.P2_Logging
  fi
}

run_guard_suite() {
  if [[ -r /proc/self/cmdline ]]; then
    python3 test_guard.py
  else
    echo "[skip] 非 Linux（无 /proc/*/cmdline），跳过 2 个 procfs 守卫用例"
    python3 - <<'PY'
import sys, unittest
suite = unittest.defaultTestLoader.loadTestsFromName("test_guard")
filtered = unittest.TestSuite()
skip = {"test_allows_internal_commit", "test_allows_reason_internal"}
for grp in suite:
    for t in grp:
        if t._testMethodName not in skip:
            filtered.addTest(t)
res = unittest.TextTestRunner(verbosity=2).run(filtered)
sys.exit(0 if res.wasSuccessful() else 1)
PY
  fi
}

run version python3 version_check.py
if (( V2_ONLY )); then
  run contract python3 contract_check.py --v2-only
else
  run contract python3 contract_check.py
fi

_NUWA_TS_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/nuwa-ts-sandbox.XXXXXX")"
trap 'rm -rf "$_NUWA_TS_SANDBOX"' EXIT
run_bun_isolated() {
  env -u NUWA_KB_DB \
    PI_AGENT_HOME="$_NUWA_TS_SANDBOX/agent" \
    bun test --isolate --timeout 60000 "$@"
}

run unit run_bun_isolated unit.test.ts
run omp run_bun_isolated \
  omp_nuwa.test.ts \
  omp_extension.test.ts \
  nuwa_forever.test.ts \
  nuwa_command.test.ts \
  ui.test.ts \
  ui_native.test.ts \
  autoexec.test.ts
run isolation run_bun_isolated nuwa_isolation.test.ts

v3_tests=()
for f in nuwa_v3_core.test.ts scope_evidence.test.ts profiles_daemon.test.ts; do
  [[ -f "$f" ]] && v3_tests+=("$f")
done
for f in *.test.ts; do
  case "$f" in
    unit.test.ts|omp_nuwa.test.ts|omp_extension.test.ts|nuwa_forever.test.ts|nuwa_command.test.ts|ui.test.ts|ui_native.test.ts|autoexec.test.ts|nuwa_isolation.test.ts|nuwa_v3_core.test.ts|scope_evidence.test.ts|profiles_daemon.test.ts)
      ;;
    *)
      [[ -f "$f" ]] && v3_tests+=("$f")
      ;;
  esac
done
if (( ${#v3_tests[@]} > 0 )); then
  run v3 run_bun_isolated "${v3_tests[@]}"
fi

run shell run_shell_suite
run kb python3 test_kb.py

if (( V2_ONLY )); then
  printf '\n== 汇总 (--v2-only) ==\n'
  [[ $fail -eq 0 ]] && echo "全部通过" || echo "有失败用例"
  exit $fail
fi

if command -v flock >/dev/null 2>&1; then
  run chaos python3 test_chaos.py
  run concurrency python3 test_concurrency.py
else
  printf '\n== chaos ==\n  → SKIP (缺少 flock，跳过 v1 Linux 锁测试)\n'
  printf '\n== concurrency ==\n  → SKIP (缺少 flock，跳过 v1 Linux 锁测试)\n'
fi

run e2e python3 test_e2e_deterministic.py
run r1core python3 test_r1_core.py
run r1dispatch python3 test_r1_dispatch.py
run r1run python3 test_r1_run.py
run r1multi python3 test_r1_multi.py
run crash python3 crash_matrix.py --fake-repeat 2 --real-repeat 1
run guard run_guard_suite
run r2r7 python3 test_r2_r7.py
run gates bash gates/run.sh

printf '\n== 汇总 ==\n'
[[ $fail -eq 0 ]] && echo "全部通过" || echo "有失败用例"
exit $fail
