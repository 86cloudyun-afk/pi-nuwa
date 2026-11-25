#!/usr/bin/env bash
# g5：v5.1.0 全量工程化门禁（版本一致性 / 12工具与离线构建契约 / 图封盘去重 / 派单证据归档 / 出口探测合规浏览器 / 进程回收看门狗作用域 / 端到端总装集成）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0
python3 tests/version_check.py --require-install-echo || fail=1
python3 tests/contract_check.py --v2-only || fail=1

_G5_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/nuwa-g5-sandbox.XXXXXX")"
trap 'rm -rf "$_G5_SANDBOX"' EXIT

env -u BUN_OPTIONS -u NUWA_KB_DB PI_AGENT_HOME="$_G5_SANDBOX/agent" bun test --isolate \
  tests/v51_graph_seal_dedup.test.ts \
  tests/v51_dispatch_evidence_archive.test.ts \
  tests/v51_egress_recon_browser.test.ts \
  tests/v51_runtime_watchdog_scope.test.ts \
  tests/v51_nuwa_e2e_integration.test.ts || fail=1

exit $fail
