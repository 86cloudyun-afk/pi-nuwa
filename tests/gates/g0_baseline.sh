#!/usr/bin/env bash
# g0：基线门禁。契约检查必须与真实 sapper 一致。
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
python3 tests/contract_check.py
