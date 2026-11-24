#!/usr/bin/env bash
# g3：v4.0 全量工程化门禁（版本一致性 / 离线构建契约 / 血缘护栏 / SPA 反噪 / 便携 KB 记忆 / 会话仓双盲沙盒）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0
python3 tests/version_check.py --require-install-echo || fail=1
python3 tests/contract_check.py --v2-only || fail=1
env -u BUN_OPTIONS bun test --isolate \
  tests/nuwa_v3_core.test.ts \
  tests/v4_lineage_guard.test.ts \
  tests/v4_recon_browser.test.ts \
  tests/v4_kb_memory.test.ts \
  tests/v4_vault_verifier_sandbox.test.ts || fail=1

exit $fail
