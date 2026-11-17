#!/bin/sh
# 与 web 侧约定：web 向 $RELOAD_DIR/REQUEST 追加一行令牌，
# 本脚本检测到新行后执行 nginx -t && nginx -s reload（平滑重载，旧连接自然完成），
# 并把结果以 "令牌 ok|fail 原因" 追加到 $RELOAD_DIR/RESULT。
set -u

RELOAD_DIR="${RELOAD_DIR:-/reload}"
LIVE_DIR="${LIVE_DIR:-/etc/nginx/certs/live}"
NGINX_BIN="${NGINX_BIN:-nginx}"
NGINX_ARGS="${NGINX_ARGS:-}"
REQ="$RELOAD_DIR/REQUEST"
RES="$RELOAD_DIR/RESULT"

mkdir -p "$RELOAD_DIR"
touch "$REQ" "$RES"

# 首次启动时等待 web 侧生成证书文件
n=0
while [ ! -s "$LIVE_DIR/fullchain.pem" ] || [ ! -s "$LIVE_DIR/privkey.pem" ]; do
  n=$((n + 1))
  if [ "$n" -gt 600 ]; then
    echo "reload-watcher: 等待证书文件超时" >&2
    exit 1
  fi
  sleep 0.5
done

# shellcheck disable=SC2086
$NGINX_BIN $NGINX_ARGS || exit 1
echo "reload-watcher: nginx started, watching $REQ" >&2

last_count=$(wc -l < "$REQ" | tr -d ' ')
while :; do
  sleep 0.3
  cur_count=$(wc -l < "$REQ" 2>/dev/null | tr -d ' ' || echo 0)
  case "$cur_count" in ''|*[!0-9]*) cur_count=0 ;; esac
  [ "$cur_count" -le "$last_count" ] && continue

  # shellcheck disable=SC2086
  if $NGINX_BIN $NGINX_ARGS -t >/tmp/nginx-t.err 2>&1; then
    # shellcheck disable=SC2086
    if $NGINX_BIN $NGINX_ARGS -s reload >/tmp/nginx-r.err 2>&1; then
      result="ok"
    else
      result="fail reload: $(tail -n 1 /tmp/nginx-r.err)"
    fi
  else
    result="fail test: $(tail -n 1 /tmp/nginx-t.err)"
  fi

  # 同一批新行共享本次重载结果（后写文件的操作先于重载落盘，语义安全）
  sed -n "$((last_count + 1)),${cur_count}p" "$REQ" | while read -r token _; do
    [ -n "$token" ] && echo "$token $result" >> "$RES"
  done
  last_count=$cur_count
done
