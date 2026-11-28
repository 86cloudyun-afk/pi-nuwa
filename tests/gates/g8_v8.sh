#!/usr/bin/env bash
# g8：v8.0.0 全量工程化门禁（版本一致性 8.0.0 / tsc+12工具契约 12/12 / 全模块反巨石行数红线 / 源码零密钥硬编码 / SQLite Schema v2 + 7个v8套件隔离回归 / L2 5/5 + L3 3/3 + L4 12/12 靶场全绿）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
unset BUN_OPTIONS

fail=0

echo "[g8] 1/6 版本单一事实来源与 install.sh 动态回显校验 (8.0.0)"
VER_OUT="$(python3 tests/version_check.py --require-install-echo 2>&1)"
rc=$?
echo "$VER_OUT"
if (( rc != 0 )) || [[ "$VER_OUT" != *"version_check: OK (8.0.0)"* ]]; then
  echo "FAIL: version_check 未通过或版本非 8.0.0" >&2
  fail=1
fi

echo "[g8] 2/6 v2 契约检查、全仓 TypeScript 严格类型检查与离线构建 (12/12)"
CONTRACT_OUT="$(NUWA_REQUIRE_TSC=1 python3 tests/contract_check.py --v2-only 2>&1)"
rc=$?
echo "$CONTRACT_OUT"
if (( rc != 0 )) || [[ "$CONTRACT_OUT" != *"contract(v2): 12/12 通过"* ]]; then
  echo "FAIL: contract_check --v2-only 未达成 12/12 通过" >&2
  fail=1
fi

echo "[g8] 3/6 反巨石行数红线核验 (omp/nuwa.ts < 1000 行 & 全部 core/*.ts, omp/*.ts, kb/*.ts, bin/nuwa-autonomous < 2500 行)"
python3 - <<'PY' || fail=1
from pathlib import Path
import sys

nuwa_lines = Path("omp/nuwa.ts").read_bytes().count(b"\n")
if nuwa_lines >= 1000:
    print(f"FAIL: omp/nuwa.ts 行数超限 ({nuwa_lines} >= 1000)", file=sys.stderr)
    sys.exit(1)

targets = (
    sorted(Path("core").glob("*.ts"))
    + sorted(Path("omp").glob("*.ts"))
    + sorted(Path("kb").glob("*.ts"))
    + [Path("bin/nuwa-autonomous")]
)
over = []
max_file = ("", 0)
for p in targets:
    n = p.read_bytes().count(b"\n")
    if n > max_file[1]:
        max_file = (str(p), n)
    if n >= 2500:
        over.append((str(p), n))
if over:
    print(f"FAIL: 存在 >= 2500 行的代码文件: {over}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: omp/nuwa.ts={nuwa_lines} (<1000), 检查 {len(targets)} 个核心文件全部 < 2500 行 (最高 {max_file[0]}={max_file[1]})")
PY

echo "[g8] 4/6 仓库源码 API 密钥硬编码零泄漏扫描 (sk-[0-9a-zA-Z]{20,})"
python3 - <<'PY' || fail=1
from pathlib import Path
import re, sys

secret_re = re.compile(r"\bsk-[0-9a-zA-Z]{20,}\b")
scan_dirs = ["core", "omp", "kb", "bin", "benchmarks", "tests", "scripts"]
leaks = []
for d in scan_dirs:
    base = Path(d)
    if not base.exists():
        continue
    for f in base.rglob("*"):
        if not f.is_file() or f.suffix in {".db", ".png", ".jpg", ".pyc"}:
            continue
        txt = f.read_text(encoding="utf-8", errors="ignore")
        for m in secret_re.finditer(txt):
            leaks.append((str(f), m.group(0)[:10] + "***"))
for root_file in ["install.sh", "README.md", "CHANGELOG.md"]:
    p = Path(root_file)
    if p.is_file():
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for m in secret_re.finditer(txt):
            leaks.append((root_file, m.group(0)[:10] + "***"))
if leaks:
    print(f"FAIL: 检测到疑似硬编码 API 密钥泄漏: {leaks}", file=sys.stderr)
    sys.exit(1)
print("PASS: 全仓源码扫描 0 处 sk-[0-9a-zA-Z]{20,} 硬编码密钥泄漏")
PY

_G8_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/nuwa-g8-sandbox.XXXXXX")"
trap 'rm -rf "$_G8_SANDBOX" .nuwa-l3-tmp-persist' EXIT

echo "[g8] 5/6 SQLite Schema v2 迁移/零写盘与全部 7 个 v8 测试套件隔离回归验收"
env -u BUN_OPTIONS -u NUWA_KB_DB PI_AGENT_HOME="$_G8_SANDBOX/agent" bun test --isolate --timeout 45000 \
  tests/v8_foundation_schema.test.ts \
  tests/v8_stateful_workflow.test.ts \
  tests/v8_cdp_protocols.test.ts \
  tests/v8_pivot_resilience.test.ts \
  tests/v8_rgs_analyzer.test.ts \
  tests/v8_l4_arena.test.ts \
  tests/v8_e2e_integration.test.ts || fail=1

echo "[g8] 6/6 L2 (5/5) + L3 (3/3) + L4 (12/12) 全层级评测演武场硬门禁验收"
L2_JSON="$(env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts --json --deterministic)" || fail=1
python3 - "$L2_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
gates = data.get("gates", {})
scenarios = data.get("scenarios", [])
passed = sum(1 for s in scenarios if s.get("passed"))
if passed != 5 or len(scenarios) != 5 or not gates.get("allPassed") or not gates.get("calibrationGate"):
    print(f"FAIL: L2 未达成 5/5 全绿: passed={passed}/{len(scenarios)} gates={gates}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: L2 5/5 全绿 recall={data.get('metrics', {}).get('recallRate')} fp={data.get('metrics', {}).get('falsePositiveRate')}")
PY

L3_JSON="$(env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts --json)" || fail=1
python3 - "$L3_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
scenarios = data.get("scenarios", [])
passed = sum(1 for s in scenarios if s.get("passed"))
if passed != 3 or len(scenarios) != 3 or not data.get("allPassed") or int(data.get("vaultLeakCount", -1)) != 0:
    print(f"FAIL: L3 未达成 3/3 全绿: {data}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: L3 3/3 全绿 socks5Handshakes={data.get('socks5HandshakeCount')} leaks={data.get('vaultLeakCount')}")
PY

L4_JSON="$(env -u BUN_OPTIONS bun benchmarks/l4-arena/run-l4-eval.ts --json --deterministic)" || fail=1
python3 - "$L4_JSON" <<'PY' || fail=1
import json, sys
data = json.loads(sys.argv[1])
gates = data.get("gates", {})
scenarios = data.get("scenarios", [])
passed = sum(1 for s in scenarios if s.get("passed"))
if (
    passed != 12
    or len(scenarios) != 12
    or not data.get("allPassed")
    or not gates.get("allPassed")
    or float(data.get("recallRate", 0)) != 1.0
    or float(data.get("falsePositiveRate", -1)) != 0.0
    or int(data.get("vaultLeakCount", -1)) != 0
):
    print(f"FAIL: L4 未达成 12/12 全绿: passed={passed}/{len(scenarios)} gates={gates}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: L4 12/12 全绿 recall={data.get('recallRate')} fp={data.get('falsePositiveRate')} leaks={data.get('vaultLeakCount')}")
PY

exit $fail
