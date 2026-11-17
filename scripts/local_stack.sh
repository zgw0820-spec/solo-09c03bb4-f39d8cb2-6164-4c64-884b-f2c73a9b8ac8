#!/usr/bin/env bash
# 无 Docker 环境下本地起整套服务，用于真实验证（nginx + watcher + FastAPI）。
# 用法: scripts/local_stack.sh up|down|restart-web|status
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${LOCAL_WORK:-/tmp/certops-local}"
NGINX_BIN="${NGINX_BIN:-/tmp/nginxpkg/root/usr/sbin/nginx}"
WEB_PORT="${WEB_PORT:-8080}"
TLS_PORT="${TLS_PORT:-8443}"
HTTP_PORT="${HTTP_PORT:-8081}"
DELAY="${ACTIVATE_DELAY_AFTER_WRITE:-0}"
RUN="$WORK/run"
NGX="$WORK/nginx"

write_nginx_conf() {
  mkdir -p "$NGX/logs" "$NGX/tmp" "$NGX/html" "$RUN"
  [ -f "$NGX/html/index.html" ] || echo '<h1>demo.internal intranet site</h1>' > "$NGX/html/index.html"
  cat > "$NGX/nginx.conf" <<EOF
pid $RUN/nginx.pid;
error_log $NGX/logs/error.log warn;
worker_processes 1;
events { worker_connections 256; }
http {
  access_log $NGX/logs/access.log;
  default_type text/html;
  client_body_temp_path $NGX/tmp/body;
  proxy_temp_path $NGX/tmp/proxy;
  fastcgi_temp_path $NGX/tmp/fastcgi;
  uwsgi_temp_path $NGX/tmp/uwsgi;
  scgi_temp_path $NGX/tmp/scgi;
  server {
    listen 127.0.0.1:$HTTP_PORT;
    root $NGX/html;
  }
  server {
    listen 127.0.0.1:$TLS_PORT ssl;
    server_name demo.internal;
    ssl_certificate     $WORK/live/fullchain.pem;
    ssl_certificate_key $WORK/live/privkey.pem;
    location / { root $NGX/html; }
  }
}
EOF
}

start_nginx() {
  write_nginx_conf
  RELOAD_DIR="$WORK/reload" LIVE_DIR="$WORK/live" NGINX_BIN="$NGINX_BIN" \
    NGINX_ARGS="-p $NGX -c $NGX/nginx.conf" \
    nohup sh "$ROOT/nginx/reload-watcher.sh" > "$WORK/watcher.log" 2>&1 &
  echo $! > "$RUN/watcher.pid"
}

start_web() {
  SITE_DOMAIN=demo.internal \
  DATA_DIR="$WORK/data" LIVE_DIR="$WORK/live" RELOAD_DIR="$WORK/reload" \
  NGINX_PROBE_HOST=127.0.0.1 NGINX_PROBE_PORT="$TLS_PORT" \
  RECEIPT_TIMEOUT=6 VERIFY_TIMEOUT=10 PENDING_TTL=20 STARTUP_PROBE_TIMEOUT=20 \
  ACTIVATE_DELAY_AFTER_WRITE="$DELAY" \
  nohup python3 -m uvicorn app.main:app --app-dir "$ROOT/web" \
    --host 127.0.0.1 --port "$WEB_PORT" > "$WORK/web.log" 2>&1 &
  echo $! > "$RUN/web.pid"
}

wait_web() {
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$WEB_PORT/api/status" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "web 未就绪，日志:"; tail -20 "$WORK/web.log"; return 1
}

wait_tls() {
  for _ in $(seq 1 60); do
    if openssl s_client -connect "127.0.0.1:$TLS_PORT" -servername demo.internal </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
      return 0
    fi
    sleep 0.5
  done
  echo "nginx TLS 未就绪，日志:"; tail -20 "$NGX/logs/error.log" 2>/dev/null; return 1
}

case "${1:-}" in
  up)
    mkdir -p "$WORK/data" "$WORK/live" "$WORK/reload" "$RUN"
    start_nginx
    start_web
    wait_web
    wait_tls
    echo "UP  web=http://127.0.0.1:$WEB_PORT  tls=https://127.0.0.1:$TLS_PORT"
    ;;
  down)
    for p in watcher web; do
      [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null || true
    done
    [ -f "$RUN/nginx.pid" ] && kill "$(cat "$RUN/nginx.pid")" 2>/dev/null || true
    sleep 0.5
    echo "DOWN"
    ;;
  restart-web)
    kill "$(cat "$RUN/web.pid")" 2>/dev/null || true
    sleep 0.5
    start_web
    wait_web
    echo "WEB RESTARTED (delay=$DELAY)"
    ;;
  kill-web)   # 模拟崩溃：SIGKILL
    kill -9 "$(cat "$RUN/web.pid")" 2>/dev/null || true
    echo "WEB KILLED"
    ;;
  status)
    curl -s "http://127.0.0.1:$WEB_PORT/api/status" | python3 -m json.tool | head -40
    ;;
  *)
    echo "usage: $0 up|down|restart-web|kill-web|status" >&2; exit 2;;
esac
