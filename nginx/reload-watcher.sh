#!/bin/sh
# 与 web 侧约定：web 向 $RELOAD_DIR/REQUEST 追加一行令牌，
# 本脚本检测到新行后执行 nginx -t && nginx -s reload（平滑重载，旧连接自然完成），
# 并把结果以 "令牌 ok|fail 原因" 追加到 $RELOAD_DIR/RESULT。
set -u

RELOAD_DIR="${RELOAD_DIR:-/reload}"
LIVE_DIR="${LIVE_DIR:-/etc/nginx/certs/live}"
NGINX_BIN="${NGINX_BIN:-nginx}"
NGINX_ARGS="${NGINX_ARGS:-}"
NGINX_PID="${NGINX_PID:-/var/run/nginx.pid}"
REQ="$RELOAD_DIR/REQUEST"
RES="$RELOAD_DIR/RESULT"

mkdir -p "$RELOAD_DIR"
touch "$REQ" "$RES"

start_nginx() {
  # shellcheck disable=SC2086
  $NGINX_BIN $NGINX_ARGS
}

# 启动 nginx：等待 web 侧生成证书文件；若现有文件是混搭/损坏
# （例如断电留下的 fullchain 与 privkey 不同版本），nginx 会拒绝启动，
# 此处持续重试，等 web 按已确认的在用版本修复 live 后再成功启动。
n=0
while :; do
  if [ -s "$LIVE_DIR/fullchain.pem" ] && [ -s "$LIVE_DIR/privkey.pem" ]; then
    if start_nginx; then
      break
    fi
    n=$((n + 1))
    if [ "$n" -eq 1 ] || [ $((n % 20)) -eq 0 ]; then
      echo "reload-watcher: nginx 暂无法启动（第 $n 次），等待证书修复后重试" >&2
    fi
  fi
  sleep 0.5
done
echo "reload-watcher: nginx started, watching $REQ" >&2

last_count=$(wc -l < "$REQ" | tr -d ' ')
while :; do
  sleep 0.3
  cur_count=$(wc -l < "$REQ" 2>/dev/null | tr -d ' ' || echo 0)
  case "$cur_count" in ''|*[!0-9]*) cur_count=0 ;; esac
  if [ "$cur_count" -le "$last_count" ]; then
    # 空闲时巡检：master 意外退出则重新拉起（证书已不成对时重试直到修复）
    if [ ! -f "$NGINX_PID" ] || ! kill -0 "$(cat "$NGINX_PID" 2>/dev/null)" 2>/dev/null; then
      start_nginx || true
    fi
    continue
  fi

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
