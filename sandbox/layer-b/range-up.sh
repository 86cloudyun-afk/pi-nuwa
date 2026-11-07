#!/usr/bin/env bash
# B 层靶场：8 个目标，覆盖 8 类响应面。
#
#   18081 static     正常 200 + flag
#   18082 dvwa       真实漏洞面
#   18083 slow       30s 延迟
#   18084 deny       全 403
#   18085 redirect   302 循环
#   18086 basicauth  401 + WWW-Authenticate
#   18087 notfound   全 404
#   18088 gzip       gzip 压缩响应
#
# 用法：./range-up.sh [--only t1,t3]
set -uo pipefail
NET=nuwa-range
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="${NUWA_LOGS:-/srv/nuwa-sandbox/logs}"
ONLY=""
[[ "${1:-}" == "--only" ]] && ONLY="${2:-}"
say() { printf '[range] %s\n' "$*"; }

docker network inspect "$NET" >/dev/null 2>&1 || {
  docker network create --subnet 172.28.0.0/24 "$NET" >/dev/null
  say "created network $NET"
}

want() {
  [[ -z "$ONLY" ]] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

start_one() {
  local tag="$1" name="$2" ip="$3" host_port="$4"; shift 4
  want "$tag" || return 0
  docker rm -f "$name" >/dev/null 2>&1
  mkdir -p "$LOGS/$name"
  docker run -d --name "$name" --network "$NET" --ip "$ip" \
    -p "127.0.0.1:${host_port}:8000" \
    -v "$DIR/targets/server.js:/app/server.js:ro" \
    -v "$LOGS/$name:/logs" \
    "$@" node:22-bookworm-slim node /app/server.js >/dev/null || return 1
  say "$name → 127.0.0.1:${host_port} (${ip})"
}

start_one t1 nuwa-t1 172.28.0.11 18081 -e MODE=static    -e FLAG='flag{nuwa-t1-static}'
start_one t3 nuwa-t3 172.28.0.13 18083 -e MODE=slow      -e DELAY_MS=30000 -e FLAG='flag{nuwa-t3-slow}'
start_one t4 nuwa-t4 172.28.0.14 18084 -e MODE=deny      -e FLAG='flag{nuwa-t4-deny}'
start_one t5 nuwa-t5 172.28.0.15 18085 -e MODE=redirect  -e FLAG='flag{nuwa-t5-redirect}'
start_one t6 nuwa-t6 172.28.0.16 18086 -e MODE=basicauth -e FLAG='flag{nuwa-t6-basic}'
start_one t7 nuwa-t7 172.28.0.17 18087 -e MODE=notfound  -e FLAG='flag{nuwa-t7-404}'
start_one t8 nuwa-t8 172.28.0.18 18088 -e MODE=gzip      -e FLAG='flag{nuwa-t8-gzip}'

if want t2; then
  docker rm -f nuwa-t2 >/dev/null 2>&1
  docker run -d --name nuwa-t2 --network "$NET" --ip 172.28.0.12 \
    -p 127.0.0.1:18082:80 vulnerables/web-dvwa >/dev/null \
    && say "nuwa-t2 → 127.0.0.1:18082 (DVWA，启动约 10s)"
fi

say "等待健康检查..."
for i in $(seq 1 40); do
  ok=0; total=0
  for p in 18081 18083 18084 18085 18086 18087 18088; do
    want "t$((${p#1808} - 0))" >/dev/null 2>&1 || true
    total=$((total + 1))
    curl -fsS -m 1 -o /dev/null "http://127.0.0.1:$p/health" 2>/dev/null && ok=$((ok + 1))
  done
  if want t2; then
    total=$((total + 1))
    curl -fsS -m 1 -o /dev/null "http://127.0.0.1:18082/login.php" 2>/dev/null && ok=$((ok + 1))
  fi
  (( ok >= total )) && { say "全部就绪 ($ok/$total)"; exit 0; }
  sleep 1
done
say "部分目标未就绪，用 range-status.sh 查看"
exit 1
