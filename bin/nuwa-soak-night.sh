#!/usr/bin/env bash
# 夜跑入口：nuwa soak-night --base DIR --minutes 4320 --projects 4
set -euo pipefail
_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$_DIR/../nuwa/cli.py" soak-night "$@"
