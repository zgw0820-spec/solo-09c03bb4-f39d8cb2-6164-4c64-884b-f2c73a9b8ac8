#!/usr/bin/env bash
# 中断/崩溃恢复实测：
#  A. 启用中途（已写文件、未请求重载）kill -9 web -> 重启后应回退到可确认旧版本
#  B. 启用中途（已请求重载）kill -9 web       -> 重启后应核实新证书已生效
#  C. live 文件被带外篡改后重启 web           -> 应恢复为在用版本并重载
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK=/tmp/certops-local
WEB=http://127.0.0.1:8080
STACK="bash $ROOT/scripts/local_stack.sh"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL  $1 $2"; }

jqv() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
live_fp() { openssl x509 -in "$WORK/live/fullchain.pem" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
served_fp() { openssl s_client -connect 127.0.0.1:8443 -servername demo.internal </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
mkcert() { python3 "$ROOT/scripts/make_cert.py" --data-dir "$WORK/data" --out-dir "$1" >/dev/null; }
upload() { curl -s -F "cert_file=@$1/chain.pem" -F "key_file=@$1/key.pem" "$WEB/upload" | jqv "d['version_id']"; }
activate_async() { curl -s -F "version_id=$1" -F "base_version_id=$2" "$WEB/activate" > /tmp/act_result.json & echo $!; }

echo "=== 场景 A：写文件后、请求重载前崩溃 ==="
$STACK down >/dev/null 2>&1; rm -rf $WORK
ACTIVATE_DELAY_AFTER_WRITE=5 $STACK up >/dev/null || { echo "stack up failed"; exit 1; }
V1FP=$(served_fp)
mkcert /tmp/ic-a; V2=$(upload /tmp/ic-a)
V2FP=$(openssl x509 -in /tmp/ic-a/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
CPID=$(activate_async "$V2" 1)
# 等 live 文件被换成 v5（此时 web 在崩溃窗口内睡眠）
for i in $(seq 1 100); do [ "$(live_fp)" = "$V2FP" ] && break; sleep 0.05; done
[ "$(live_fp)" = "$V2FP" ] && ok "A: 崩溃窗口已进入（live 文件已切换）" || bad "A: 未能进入崩溃窗口"
$STACK kill-web >/dev/null
wait $CPID 2>/dev/null
$STACK restart-web >/dev/null || { echo "restart failed"; exit 1; }
ST=$(curl -s $WEB/api/status)
ACTIVE=$(echo "$ST" | jqv "d['active_version_id']")
OPSTATE=$(echo "$ST" | jqv "d['latest_op']['state']")
CONS=$(echo "$ST" | jqv "d['consistency']")
[ "$ACTIVE" = "1" ] && ok "A: 重启后在用版本回退为 #1" || bad "A: 在用版本" "active=$ACTIVE"
[ "$OPSTATE" = "failed" ] && ok "A: 崩溃操作标记为 failed" || bad "A: 操作状态" "state=$OPSTATE"
[ "$(live_fp)" = "$V1FP" ] && ok "A: live 文件已恢复为旧证书" || bad "A: live 文件未恢复"
[ "$CONS" = "match" ] && [ "$(served_fp)" = "$V1FP" ] && ok "A: 实测指纹与在用一致" || bad "A: 一致性" "cons=$CONS"

echo "=== 场景 B：请求重载后崩溃 ==="
ACTIVATE_DELAY_AFTER_WRITE=5 $STACK restart-web >/dev/null || { echo "restart failed"; exit 1; }
mkcert /tmp/ic-b; V3=$(upload /tmp/ic-b)
V3FP=$(openssl x509 -in /tmp/ic-b/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
REQ_LINES_BEFORE=$(wc -l < $WORK/reload/REQUEST)
CPID=$(activate_async "$V3" 1)
# 等 REQUEST 出现新行（重载已请求），立即 SIGKILL
for i in $(seq 1 150); do
  L=$(wc -l < $WORK/reload/REQUEST)
  [ "$L" -gt "$REQ_LINES_BEFORE" ] && break
  sleep 0.05
done
$STACK kill-web >/dev/null
wait $CPID 2>/dev/null
ACTIVATE_DELAY_AFTER_WRITE=0 $STACK restart-web >/dev/null || { echo "restart failed"; exit 1; }
sleep 2  # 等后台核实
ST=$(curl -s $WEB/api/status)
ACTIVE=$(echo "$ST" | jqv "d['active_version_id']")
OPSTATE=$(echo "$ST" | jqv "d['latest_op']['state']")
[ "$ACTIVE" = "$V3" ] && ok "B: 重启后核实新证书生效，在用版本 #$V3" || bad "B: 在用版本" "active=$ACTIVE want=$V3"
[ "$OPSTATE" = "succeeded" ] && ok "B: 崩溃操作经核实标记 succeeded" || bad "B: 操作状态" "state=$OPSTATE"
[ "$(served_fp)" = "$V3FP" ] && ok "B: openssl 实测为 v3 证书" || bad "B: 实测指纹不符"

echo "=== 场景 C：live 文件带外篡改后重启 ==="
mkcert /tmp/ic-c
cp /tmp/ic-c/chain.pem $WORK/live/fullchain.pem   # 带外替换（未触发重载）
$STACK restart-web >/dev/null
sleep 2
[ "$(live_fp)" = "$V3FP" ] && ok "C: live 文件已恢复为在用版本" || bad "C: live 文件未恢复"
[ "$(served_fp)" = "$V3FP" ] && ok "C: 实测指纹恢复为在用版本" || bad "C: 实测指纹" "served=$(served_fp)"

echo "=== 场景 D：断电留下混搭 live 目录，Web 与 Nginx 一起重启 ==="
# 模拟事故现场：live 是实目录（旧部署形态），fullchain 已被换成新证书，
# privkey 仍是已确认在用的旧私钥 —— nginx 会因 "key values mismatch" 拒绝启动。
mkcert /tmp/ic-d
V3KEY_BACKUP=$(mktemp)
openssl pkey -in "$WORK/live/privkey.pem" -out "$V3KEY_BACKUP" 2>/dev/null
$STACK down >/dev/null 2>&1
rm -f "$WORK/live"
mkdir -p "$WORK/live"
cp /tmp/ic-d/chain.pem "$WORK/live/fullchain.pem"
cp "$V3KEY_BACKUP" "$WORK/live/privkey.pem"
rm -f "$V3KEY_BACKUP"
# 先确认这确实是一个 nginx 无法加载的混搭状态
if "${NGINX_BIN:-nginx}" -p "$WORK/nginx" -c "$WORK/nginx/nginx.conf" -t >/dev/null 2>&1; then
  bad "D: 前置" "混搭文件竟通过 nginx -t"
else
  ok "D: 前置：混搭文件确实令 nginx -t 失败"
fi
# 整栈重启：watcher 会等 web 按已确认在用版本修复文件后才成功启动 nginx
$STACK up >/dev/null 2>&1 || { bad "D: 整栈重启失败"; }
for i in $(seq 1 60); do [ "$(served_fp)" = "$V3FP" ] && break; sleep 0.5; done
# /api/status 的实测指纹有 2s 缓存，轮询到一致性收敛（或超时）
for i in $(seq 1 40); do
  ST=$(curl -s $WEB/api/status)
  CONS=$(echo "$ST" | jqv "d['consistency']")
  [ "$CONS" = "match" ] && break
  sleep 0.5
done
ACTIVE=$(echo "$ST" | jqv "d['active_version_id']")
PAIROK=$(echo "$ST" | jqv "d['live_pair_ok']")
[ "$ACTIVE" = "$V3" ] && ok "D: 在用版本仍为已确认的 #$V3" || bad "D: 在用版本" "active=$ACTIVE want=$V3"
[ "$PAIROK" = "True" ] && ok "D: live 已恢复为成对证书" || bad "D: live 不成对"
[ -L "$WORK/live" ] && ok "D: live 已改为原子符号链接" || bad "D: live 非符号链接"
[ "$(served_fp)" = "$V3FP" ] && ok "D: 站点恢复可连接，握手为已确认在用证书" || bad "D: 站点不可用/指纹不符" "served=$(served_fp)"
[ "$CONS" = "match" ] && ok "D: 一致性为 match" || bad "D: 一致性" "cons=$CONS"
# 恢复完成后应可重新接单
mkcert /tmp/ic-d2; V5=$(upload /tmp/ic-d2)
CODE=$(curl -s -o /tmp/ic-d2.json -w '%{http_code}' -F "version_id=$V5" -F "base_version_id=$V3" "$WEB/activate")
D2STATE=$(jqv "d['op']['state']" < /tmp/ic-d2.json)
[ "$CODE" = "200" ] && [ "$D2STATE" = "succeeded" ] && ok "D: 恢复后重新接单成功" || bad "D: 重新接单" "code=$CODE state=$D2STATE"

echo ""
echo "== interrupt: $PASS passed, $FAIL failed =="
$STACK down >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
