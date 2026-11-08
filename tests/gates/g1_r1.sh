#!/usr/bin/env bash
# g1：R1 状态机 / 账本 / dispatch / run 验收
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
python3 tests/test_r1_core.py
python3 tests/test_r1_dispatch.py
python3 tests/test_r1_run.py
python3 tests/test_r1_multi.py
python3 tests/crash_matrix.py --fake-repeat 2 --real-repeat 1
