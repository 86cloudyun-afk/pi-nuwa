#!/usr/bin/env bash
# g2：R2-R7 模块验收（公平/证据/指标/策略/插件/长测）
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
python3 tests/test_r2_r7.py
