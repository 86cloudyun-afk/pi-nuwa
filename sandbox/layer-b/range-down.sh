#!/usr/bin/env bash
set -uo pipefail
for c in nuwa-t1 nuwa-t2 nuwa-t3 nuwa-t4; do
  docker rm -f "$c" >/dev/null 2>&1 && echo "[range] removed $c"
done
docker network rm nuwa-range >/dev/null 2>&1 || true
echo "[range] down"
