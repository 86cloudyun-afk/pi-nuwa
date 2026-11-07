#!/usr/bin/env bash
# B 层状态：8 个目标的端口、类型、请求数
set -uo pipefail
declare -A TYPE=(
  [18081]=static [18082]=dvwa [18083]=slow [18084]=deny
  [18085]=redirect [18086]=basicauth [18087]=notfound [18088]=gzip
)
for p in 18081 18082 18083 18084 18085 18086 18087 18088; do
  code=$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/" 2>/dev/null || true)
  [[ -z "$code" ]] && code=000
  printf 'port %-6s %-10s → %s\n' "$p" "${TYPE[$p]}" "$code"
done
echo "--- 日志行数 ---"
for d in /srv/nuwa-sandbox/logs/nuwa-t*; do
  [[ -d "$d" ]] || continue
  printf '%-12s %s\n' "$(basename "$d")" "$(wc -l < "$d/access.jsonl" 2>/dev/null || echo 0)"
done
