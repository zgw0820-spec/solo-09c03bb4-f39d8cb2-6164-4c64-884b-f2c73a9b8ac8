#!/usr/bin/env python3
"""端到端验证：对运行中的本地栈执行真实检查。

前置：scripts/local_stack.sh up 已运行。
覆盖：页面/指纹一致性、上传校验、启用生效（以 openssl s_client 实测为准）、
过期提交拒绝、并发重复提交只成功一次、已有连接自然完成。
"""
import http.client
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

WEB = os.environ.get("WEB", "http://127.0.0.1:8080")
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
WORK = os.environ.get("LOCAL_WORK", "/tmp/certops-local")

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}")


def api(path):
    with urllib.request.urlopen(WEB + path, timeout=10) as r:
        return json.load(r)


def post_form(path, data=None, files=None):
    """最小 multipart/form-data POST，返回 (status, json)。"""
    boundary = "----e2eboundary"
    body = b""
    for k, v in (data or {}).items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (fname, content) in (files or {}).items():
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; '
            f'filename="{fname}"\r\nContent-Type: application/x-pem-file\r\n\r\n'
        ).encode() + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        WEB + path, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def openssl_fp():
    out = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{TLS_PORT}",
         "-servername", "demo.internal"],
        input="", capture_output=True, text=True, timeout=10,
    ).stdout
    cert = subprocess.run(
        ["openssl", "x509", "-fingerprint", "-sha256", "-noout"],
        input=out, capture_output=True, text=True,
    ).stdout.strip()
    return cert.split("=")[1].replace(":", "").lower()


def make_cert(out_dir):
    subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), "make_cert.py"),
         "--data-dir", f"{WORK}/data", "--out-dir", out_dir],
        check=True, capture_output=True,
    )
    with open(f"{out_dir}/chain.pem", "rb") as f:
        chain = f.read()
    with open(f"{out_dir}/key.pem", "rb") as f:
        key = f.read()
    return chain, key


def wait_served(fp, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = api("/api/status")
        if st["served_fingerprint"] == fp:
            return True
        time.sleep(0.5)
    return False


def main():
    # 1. 初始状态：页面可访问，指纹三方一致（DB 在用 / API 实测 / openssl 实测）
    with urllib.request.urlopen(WEB + "/", timeout=10) as r:
        html = r.read().decode()
    check("GET / 200 且包含状态区", "当前状态" in html and "实测指纹" in html)
    st = api("/api/status")
    v1_fp = st["active"]["fingerprint"]
    check("初始在用版本 #1", st["active_version_id"] == 1)
    check("API 实测指纹 == 在用版本指纹", st["served_fingerprint"] == v1_fp)
    check("openssl 实测指纹 == 在用版本指纹", openssl_fp() == v1_fp)

    # 2. 上传新证书（v2）
    chain2, key2 = make_cert("/tmp/e2e-cert2")
    code, resp = post_form("/upload", files={
        "cert_file": ("chain.pem", chain2), "key_file": ("key.pem", key2)})
    v2 = resp.get("version_id")
    check("上传 v2 成功", code == 200 and v2 == 2, f"code={code} resp={resp}")

    # 2b. 负面上传：密钥不匹配应被拒
    chain3, _ = make_cert("/tmp/e2e-cert3")
    _, key_other = make_cert("/tmp/e2e-cert-other")
    code, resp = post_form("/upload", files={
        "cert_file": ("chain.pem", chain3), "key_file": ("key.pem", key_other)})
    check("密钥不匹配的上传被拒(400)", code == 400 and "不匹配" in resp.get("err", ""))

    # 3. 过期提交：错误的 base_version_id
    code, resp = post_form("/activate", data={"version_id": v2, "base_version_id": 99})
    check("过期版号提交被拒(409)", code == 409, f"code={code}")
    st = api("/api/status")
    check("过期提交未影响在用证书", st["active_version_id"] == 1
          and st["served_fingerprint"] == v1_fp)

    # 4. 正常启用 v2：以 openssl 实测新指纹为准
    code, resp = post_form("/activate", data={"version_id": v2, "base_version_id": 1})
    op = resp.get("op", {})
    check("启用 v2 返回成功", code == 200 and op.get("state") == "succeeded",
          f"code={code} op={op.get('state')} {op.get('detail')}")
    st = api("/api/status")
    v2_fp = [v for v in st["versions"] if v["id"] == v2][0]["fingerprint"]
    check("启用后 API 实测指纹 == v2", st["served_fingerprint"] == v2_fp)
    check("启用后 openssl 实测指纹 == v2", openssl_fp() == v2_fp)
    check("一致性状态 match", st["consistency"] == "match")

    # 5. 重复提交同一表单（幂等/防重）
    code, resp = post_form("/activate", data={"version_id": v2, "base_version_id": 1})
    check("重复提交被拒(409)", code == 409, f"code={code}")

    # 6. 并发重复提交：8 线程同时启用 v3，仅一个成功
    chain3, key3 = make_cert("/tmp/e2e-cert3b")
    code, resp = post_form("/upload", files={
        "cert_file": ("chain.pem", chain3), "key_file": ("key.pem", key3)})
    v3 = resp.get("version_id")
    results = []

    def worker():
        results.append(post_form("/activate",
                                 data={"version_id": v3, "base_version_id": v2}))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = [r for r in results if r[0] == 200]
    conflict = [r for r in results if r[0] == 409]
    check("并发 8 提交仅 1 个成功", len(ok) == 1 and len(conflict) == 7,
          f"ok={len(ok)} conflict={len(conflict)}")
    st = api("/api/status")
    v3_fp = [v for v in st["versions"] if v["id"] == v3][0]["fingerprint"]
    check("并发后 openssl 实测指纹 == v3", openssl_fp() == v3_fp)
    check("并发后仅登记 2 个操作", len(st["ops"]) == 2, f"ops={len(st['ops'])}")

    # 7. 已有连接自然完成：重载前建立的 TLS 连接在重载后仍可完成请求
    chain4, key4 = make_cert("/tmp/e2e-cert4")
    code, resp = post_form("/upload", files={
        "cert_file": ("chain.pem", chain4), "key_file": ("key.pem", key4)})
    v4 = resp.get("version_id")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    import socket
    old_sock = ctx.wrap_socket(
        socket.create_connection(("127.0.0.1", TLS_PORT), timeout=5),
        server_hostname="demo.internal")
    old_fp = old_sock.getpeercert(binary_form=True)
    code, resp = post_form("/activate", data={"version_id": v4, "base_version_id": v3})
    check("启用 v4 成功", code == 200 and resp.get("op", {}).get("state") == "succeeded")
    old_sock.sendall(b"GET / HTTP/1.0\r\nHost: demo.internal\r\n\r\n")
    resp_old = old_sock.recv(4096)
    old_sock.close()
    check("旧连接在重载后自然完成请求", b"200" in resp_old.split(b"\r\n")[0],
          resp_old.split(b"\r\n")[0].decode(errors="replace"))
    st = api("/api/status")
    v4_fp = [v for v in st["versions"] if v["id"] == v4][0]["fingerprint"]
    check("v4 启用后 openssl 实测一致", openssl_fp() == v4_fp)

    print(f"\n== e2e: {len(passed)} passed, {len(failed)} failed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
