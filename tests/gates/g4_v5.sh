#!/usr/bin/env bash
# g4：v5.0 全量工程化门禁（版本一致性 / 离线构建契约 / v4.1 加固 / 认证态攻击面 / Sidecar+Egress+OOB / 假设图+SARIF+成本封顶 / 10场景离线确定性评测）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0
python3 tests/version_check.py --require-install-echo || fail=1
python3 tests/contract_check.py --v2-only || fail=1
env -u BUN_OPTIONS bun test --isolate --timeout 60000 \
  tests/v41_hardening.test.ts \
  tests/v5_auth_sandbox_oob.test.ts \
  tests/v5_hypothesis_report_bench.test.ts || fail=1
env -u BUN_OPTIONS bun benchmarks/run-eval.ts --deterministic --json >/dev/null || fail=1

exit $fail
