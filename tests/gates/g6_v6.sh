#!/usr/bin/env bash
# g6：v6.0.0 全量工程化门禁（版本一致性 / 离线静态构建与12工具契约 / graph.ts 巨石拆解行数上限 / 跨宿主 nuwa-mcp CLI / L2 离线合成五场景基准与校准硬门禁 / 六大新引擎与全链路接线集成测试）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0

echo "[g6] 1/5 版本单一事实来源与 install.sh 动态回显校验"
python3 tests/version_check.py --require-install-echo || fail=1

echo "[g6] 2/5 契约、全仓 TypeScript 静态类型检查与离线静态构建校验"
python3 tests/contract_check.py --v2-only || fail=1

echo "[g6] 3/5 omp/graph.ts 巨石拆解行数门禁 (< 2500 行) 与无环导入校验"
GRAPH_LINES="$(wc -l < omp/graph.ts | tr -d ' ')"
if (( GRAPH_LINES >= 2500 )); then
  echo "FAIL: omp/graph.ts 行数超限 (${GRAPH_LINES} >= 2500)" >&2
  fail=1
else
  echo "PASS: omp/graph.ts 行数 = ${GRAPH_LINES} (< 2500)"
fi

echo "[g6] 4/5 跨宿主 MCP Server (bin/nuwa-mcp) 与 L2 离线微基准硬门禁验收"
EXPECTED_VER="$(sed -nE "s/^export[[:space:]]+const[[:space:]]+VERSION[[:space:]]*=[[:space:]]*[\"']([^\"']+)[\"'].*/\1/p" omp/nuwa.ts | head -n 1)"
MCP_VER="$(env -u BUN_OPTIONS ./bin/nuwa-mcp --version 2>&1 || true)"
if [[ -z "$EXPECTED_VER" || "$MCP_VER" != *"$EXPECTED_VER"* ]]; then
  echo "FAIL: bin/nuwa-mcp --version 异常: $MCP_VER (expected $EXPECTED_VER)" >&2
  fail=1
else
  echo "PASS: bin/nuwa-mcp --version -> $MCP_VER"
fi

L2_JSON="$(env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts --json --deterministic)" || fail=1
python3 - "$L2_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
gates = data.get("gates", {})
metrics = data.get("metrics", {})
if not gates.get("allPassed"):
    print(f"FAIL: L2 硬门禁未通过: {gates}", file=sys.stderr)
    sys.exit(1)
if not gates.get("calibrationGate"):
    print(f"FAIL: L2 校准门禁未通过: brier={metrics.get('calibrationBrier')}", file=sys.stderr)
    sys.exit(1)
print(
    f"PASS: L2 五场景全绿 recall={metrics.get('recallRate')} fp={metrics.get('falsePositiveRate')} "
    f"leaks={metrics.get('vaultLeakCount')} sealTurns={metrics.get('hardenedSealTurns')} "
    f"brier={metrics.get('calibrationBrier')}"
)
PY

echo "[g6] 5/5 v6.0 全量引擎单测与端到端全链路接线测试"
_G6_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/nuwa-g6-sandbox.XXXXXX")"
trap 'rm -rf "$_G6_SANDBOX"' EXIT

env -u BUN_OPTIONS -u NUWA_KB_DB PI_AGENT_HOME="$_G6_SANDBOX/agent" bun test --isolate \
  tests/v6_sqlite_autoloop.test.ts \
  tests/v6_belief_calibration.test.ts \
  tests/v6_traffic_hybrid.test.ts \
  tests/v6_core_mcp_l2eval.test.ts \
  tests/v6_integration_wiring.test.ts \
  tests/v6_issues53_54_55_regression.test.ts || fail=1

exit $fail
