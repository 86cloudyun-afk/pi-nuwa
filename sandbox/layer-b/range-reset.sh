#!/usr/bin/env bash
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/range-down.sh"
rm -f /srv/nuwa-sandbox/logs/nuwa-t*/access.jsonl
"$DIR/range-up.sh"
