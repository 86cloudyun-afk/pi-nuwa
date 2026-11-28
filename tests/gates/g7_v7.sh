#!/usr/bin/env bash
# g7：v7.0.0 全量工程化门禁（版本一致性 7.0.0 / tsc+12工具契约 12/12 / nuwa.ts<1000行 & graph.ts<2500行 / KB 2.0 >=520条 / 6个专精小队模板 / 5+1个v7测试套件 / L2 5/5 & L3 3/3 靶场全绿）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0

echo "[g7] 1/7 版本单一事实来源与 install.sh 动态回显校验 (7.0.0)"
VER_OUT="$(python3 tests/version_check.py --require-install-echo 2>&1)"
rc=$?
echo "$VER_OUT"
if (( rc != 0 )) || [[ "$VER_OUT" != *"version_check: OK ("* ]]; then
  echo "FAIL: version_check 未通过" >&2
  fail=1
fi

echo "[g7] 2/7 v2 契约检查、全仓 TypeScript 严格类型检查与离线构建 (12/12)"
CONTRACT_OUT="$(NUWA_REQUIRE_TSC=1 python3 tests/contract_check.py --v2-only 2>&1)"
rc=$?
echo "$CONTRACT_OUT"
if (( rc != 0 )) || [[ "$CONTRACT_OUT" != *"contract(v2): 12/12 通过"* ]]; then
  echo "FAIL: contract_check --v2-only 未达成 12/12 通过" >&2
  fail=1
fi

echo "[g7] 3/7 单核收敛瘦身硬指标校验 (omp/nuwa.ts < 1000 行 & omp/graph.ts < 2500 行)"
NUWA_LINES="$(wc -l < omp/nuwa.ts | tr -d ' ')"
GRAPH_LINES="$(wc -l < omp/graph.ts | tr -d ' ')"
if (( NUWA_LINES >= 1000 )); then
  echo "FAIL: omp/nuwa.ts 行数超限 (${NUWA_LINES} >= 1000)" >&2
  fail=1
else
  echo "PASS: omp/nuwa.ts 行数 = ${NUWA_LINES} (< 1000)"
fi
if (( GRAPH_LINES >= 2500 )); then
  echo "FAIL: omp/graph.ts 行数超限 (${GRAPH_LINES} >= 2500)" >&2
  fail=1
else
  echo "PASS: omp/graph.ts 行数 = ${GRAPH_LINES} (< 2500)"
fi

echo "[g7] 4/7 5+1 专精特种小队模板 (6 个 agents/*.md) 与 KB 2.0 (>= 520 条) 校验"
for ag in fujiang.md nuwa-verifier.md nuwa-scout.md nuwa-spa-reverser.md nuwa-auth-breaker.md nuwa-code-auditor.md; do
  if [[ ! -s "agents/$ag" ]]; then
    echo "FAIL: 缺少或为空的专精代理模板 agents/$ag" >&2
    fail=1
  else
    echo "  OK  agents/$ag"
  fi
done

_G7_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/nuwa-g7-sandbox.XXXXXX")"
trap 'rm -rf "$_G7_SANDBOX"' EXIT

KB_STATS_JSON="$(env -u BUN_OPTIONS bun kb/build-kb.ts --out "$_G7_SANDBOX/kb.db" --stats)" || fail=1
python3 - "$KB_STATS_JSON" <<'PY' || fail=1
import json, sys
stats = json.loads(sys.argv[1])
kb_items = int(stats.get("kbItems", 0))
if kb_items < 520:
    print(f"FAIL: kb.db kbItems={kb_items} < 520", file=sys.stderr)
    sys.exit(1)
print(f"PASS: kb.db 构建成功 kbItems={kb_items} (>= 520), cards={stats.get('cards')}, cves={stats.get('cves')}, techniques={stats.get('techniques')}")
PY

echo "[g7] 5/7 全量 5+1 个 v7 测试套件隔离回归验收"
env -u BUN_OPTIONS -u NUWA_KB_DB PI_AGENT_HOME="$_G7_SANDBOX/agent" bun test --isolate \
  tests/v7_cdp_bridge.test.ts \
  tests/v7_chain_composer.test.ts \
  tests/v7_squad_kb2.test.ts \
  tests/v7_core_unify_l3.test.ts \
  tests/v7_e2e_integration.test.ts \
  tests/v6_issues53_54_55_regression.test.ts || fail=1

echo "[g7] 6/7 L2 五场景有状态合成靶场 (5/5) 硬门禁验收"
L2_JSON="$(env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts --json --deterministic)" || fail=1
python3 - "$L2_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
gates = data.get("gates", {})
metrics = data.get("metrics", {})
scenarios = data.get("scenarios", [])
passed = sum(1 for s in scenarios if s.get("passed"))
if passed != 5 or len(scenarios) != 5 or not gates.get("allPassed") or not gates.get("calibrationGate"):
    print(f"FAIL: L2 靶场未达成 5/5 全绿: passed={passed}/{len(scenarios)} gates={gates}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: L2 5/5 全绿 recall={metrics.get('recallRate')} fp={metrics.get('falsePositiveRate')} leaks={metrics.get('vaultLeakCount')} brier={metrics.get('calibrationBrier')}")
PY

echo "[g7] 7/7 L3 真实进程树与 SOCKS5h 门禁靶场 (3/3) 验收"
L3_JSON="$(env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts --json)" || fail=1
python3 - "$L3_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
scenarios = data.get("scenarios", [])
passed = sum(1 for s in scenarios if s.get("passed"))
if (
    passed != 3
    or len(scenarios) != 3
    or not data.get("allPassed")
    or int(data.get("socks5HandshakeCount", 0)) <= 0
    or int(data.get("modelApiErrors", -1)) != 0
    or int(data.get("vaultLeakCount", -1)) != 0
):
    print(f"FAIL: L3 靶场门禁未通过: {data}", file=sys.stderr)
    sys.exit(1)
print(
    f"PASS: L3 3/3 全绿 socks5Handshakes={data.get('socks5HandshakeCount')} "
    f"domainReqs={data.get('socks5DomainRequests')} modelErrors={data.get('modelApiErrors')} leaks={data.get('vaultLeakCount')}"
)
PY

exit $fail
