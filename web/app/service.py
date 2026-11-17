"""证书启用核心逻辑。

设计要点：
- 启用请求带"页面所见版号"(base_version_id)，在 BEGIN IMMEDIATE 事务内
  比较-交换，过期提交与并发重复提交直接拒绝，不会覆盖在用证书。
- 启用成功以"Nginx 新建 TLS 连接返回新证书指纹"为唯一判据；
  重载回执失败 -> 回滚文件并保持旧版本在用；
  回执不明/无法探测 -> 置"待核实"，由后台核实循环继续处理。
- 任何落库/写文件动作前都检查"自己是否仍是最新操作"，
  旧操作不得覆盖后来提交。
- 进程重启时按 Nginx 实际服务的指纹对账，恢复到可确认的在用版本。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass

from . import certutil
from .db import DB

log = logging.getLogger("certops")

UTC = dt.timezone.utc


def now_iso() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


class Conflict(Exception):
    """409：版号过期或已有操作在进行。"""


class BadRequest(Exception):
    """400：请求内容不合法。"""


class NotFound(Exception):
    """404：目标不存在。"""


class ProbeError(Exception):
    """无法与 Nginx 建立 TLS 连接。"""


@dataclass
class Config:
    site_domain: str = "demo.internal"
    data_dir: str = "/data"
    live_dir: str = "/certs/live"
    reload_dir: str = "/reload"
    probe_host: str = "nginx"
    probe_port: int = 443
    receipt_timeout: float = 6.0      # 等待重载回执的秒数
    verify_timeout: float = 10.0      # 启用后探测新证书的秒数
    pending_ttl: float = 45.0         # 待核实操作的宽限秒数，超时回退
    probe_interval: float = 0.5
    startup_probe_timeout: float = 15.0
    restore_interval: float = 30.0    # 无在途操作时一致性修复的最小间隔
    activate_delay_after_write: float = 0.0  # 测试钩子：写完文件后人为延迟

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "certops.db")

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ
        return cls(
            site_domain=e.get("SITE_DOMAIN", "demo.internal"),
            data_dir=e.get("DATA_DIR", "/data"),
            live_dir=e.get("LIVE_DIR", "/certs/live"),
            reload_dir=e.get("RELOAD_DIR", "/reload"),
            probe_host=e.get("NGINX_PROBE_HOST", "nginx"),
            probe_port=int(e.get("NGINX_PROBE_PORT", "443")),
            receipt_timeout=float(e.get("RECEIPT_TIMEOUT", "6")),
            verify_timeout=float(e.get("VERIFY_TIMEOUT", "10")),
            pending_ttl=float(e.get("PENDING_TTL", "45")),
            startup_probe_timeout=float(e.get("STARTUP_PROBE_TIMEOUT", "15")),
            activate_delay_after_write=float(e.get("ACTIVATE_DELAY_AFTER_WRITE", "0")),
        )


def tls_fingerprint(host: str, port: int, server_name: str, timeout: float = 3.0) -> str:
    """新建一条 TLS 连接，返回对端叶子证书的 SHA-256 指纹。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except OSError as exc:
        raise ProbeError(str(exc)) from exc
    return hashlib.sha256(der).hexdigest()


class FileReloadChannel:
    """经共享目录与 nginx 侧 watcher 通信：REQUEST 追加令牌，RESULT 回收回执。"""

    def __init__(self, reload_dir: str):
        self.req_path = os.path.join(reload_dir, "REQUEST")
        self.res_path = os.path.join(reload_dir, "RESULT")

    def request(self, token: str) -> None:
        with open(self.req_path, "a", encoding="utf-8") as f:
            f.write(f"{token} {now_iso()}\n")
            f.flush()
            os.fsync(f.fileno())

    def wait(self, token: str, timeout: float) -> str | None:
        """等到 'ok' / 'fail ...'；超时返回 None（回执不明）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(self.res_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(" ", 1)
                        if len(parts) == 2 and parts[0] == token:
                            return parts[1]
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        return None


class RealControl:
    """生产用 Nginx 控制面：文件通道触发平滑重载 + 真实 TLS 探测。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.channel = FileReloadChannel(cfg.reload_dir)

    def probe(self) -> str:
        return tls_fingerprint(
            self.cfg.probe_host, self.cfg.probe_port, self.cfg.site_domain
        )

    def request_reload(self, token: str) -> None:
        self.channel.request(token)

    def wait_receipt(self, token: str, timeout: float) -> str | None:
        return self.channel.wait(token, timeout)


class CertService:
    def __init__(self, cfg: Config, control=None):
        self.cfg = cfg
        for d in (cfg.data_dir, cfg.live_dir, cfg.reload_dir):
            os.makedirs(d, exist_ok=True)
        self.db = DB(cfg.db_path)
        self.control = control or RealControl(cfg)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._probe_cache: tuple[float, str | None] = (0.0, None)
        self._last_restore = 0.0

    # ------------------------------------------------------------ 生命周期

    def startup(self, background: bool = True) -> None:
        self.db.init_schema()
        with self.db.txn() as c:
            empty = c.execute("SELECT COUNT(*) n FROM versions").fetchone()["n"] == 0
        if empty:
            self._seed()
        # 上次进程退出时遗留的"启用中"操作一律转为待核实
        with self.db.txn() as c:
            c.execute(
                "UPDATE ops SET state='pending_verify',"
                " detail='进程重启，启用结果待核实', updated_at=?"
                " WHERE state='activating'",
                (now_iso(),),
            )
        served = self._probe_with_grace(self.cfg.startup_probe_timeout)
        with self.db.txn() as c:
            op = self._latest_inflight(c)
        if op:
            target = self._version(op["version_id"])
            if served is not None and served == target["fingerprint"]:
                self._finalize_success(op["seq"], note="重启后核实：新证书已生效")
            elif served is not None:
                self._recover_to_confirmable(served)
                self._finalize_fail(
                    op["seq"], "进程重启，启用结果未确认，已恢复到可确认的在用版本"
                )
            else:
                log.warning("startup: 无法探测 Nginx，操作 #%s 保持待核实", op["seq"])
        else:
            self._ensure_live_matches_active(served)
        if background:
            self._thread = threading.Thread(
                target=self._reconcile_loop, name="reconciler", daemon=True
            )
            self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.db.close()

    def _seed(self) -> None:
        """首次启动：生成演示 CA 与"旧证书"，作为版本 1 在用。"""
        ca_cert, ca_key = certutil.generate_ca()
        chain, key = certutil.generate_server_cert(
            self.cfg.site_domain, ca_cert, ca_key,
            days_valid=330, not_before_days_ago=300,
        )
        info = certutil.validate_upload(chain, key, self.cfg.site_domain)
        ca_dir = os.path.join(self.cfg.data_dir, "ca")
        os.makedirs(ca_dir, exist_ok=True)
        with open(os.path.join(ca_dir, "ca.pem"), "wb") as f:
            f.write(ca_cert)
        with open(os.path.join(ca_dir, "ca-key.pem"), "wb") as f:
            f.write(ca_key)
        with self.db.txn() as c:
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain.decode(), key.decode(),
                    "active", now_iso(),
                ),
            )
            vid = cur.lastrowid
            c.execute("UPDATE state SET active_version_id=?", (vid,))
        self._write_live(self._version(vid))
        log.info("seeded demo cert version #%s fp=%s", vid, info.fingerprint[:16])

    # ------------------------------------------------------------ 上传

    def upload(self, chain_pem: bytes, key_pem: bytes):
        info = certutil.validate_upload(chain_pem, key_pem, self.cfg.site_domain)
        with self.db.txn() as c:
            row = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (info.fingerprint,)
            ).fetchone()
            if row:
                return dict(row), False
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain_pem.decode(), key_pem.decode(),
                    "candidate", now_iso(),
                ),
            )
            vid = cur.lastrowid
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row), True

    # ------------------------------------------------------------ 启用

    def activate(self, version_id: int, base_version_id: int) -> dict:
        """提交启用。比较-交换通过后在请求线程内同步执行，结果有界。"""
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["active_version_id"] != base_version_id:
                raise Conflict(
                    f"页面版号已过期（当前在用版本 #{st['active_version_id']}），"
                    "请刷新后重试"
                )
            inflight = c.execute(
                "SELECT seq FROM ops WHERE state='activating'"
            ).fetchone()
            if inflight:
                raise Conflict(f"另一启用操作 (#{inflight['seq']}) 正在进行，请稍后")
            v = c.execute("SELECT * FROM versions WHERE id=?", (version_id,)).fetchone()
            if not v:
                raise NotFound(f"版本 #{version_id} 不存在")
            if v["id"] == st["active_version_id"]:
                raise BadRequest(f"版本 #{version_id} 当前已在用")
            if v["status"] not in ("candidate", "failed", "superseded"):
                raise BadRequest(f"版本 #{version_id} 状态为 {v['status']}，不可启用")
            # 新操作取代所有仍待核实的旧操作
            c.execute(
                "UPDATE ops SET state='superseded',"
                " detail=COALESCE(detail,'') || ' 被更新的操作取代', updated_at=?"
                " WHERE state='pending_verify'",
                (now_iso(),),
            )
            seq = st["current_op_seq"] + 1
            ts = now_iso()
            c.execute(
                "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (seq, version_id, base_version_id, "activating", None, ts, ts),
            )
            c.execute("UPDATE state SET current_op_seq=?", (seq,))
        try:
            self._execute(seq)
        except Exception as exc:  # 任何未预期异常都不得让操作悬空
            log.exception("activate op #%s failed unexpectedly", seq)
            self._mark_pending(seq, f"内部错误（{exc!r}），待核实")
        return self.get_op(seq)

    def _execute(self, seq: int) -> None:
        op = self.get_op(seq)
        target = self._version(op["version_id"])
        base = self._version(op["base_version_id"])
        # 1. 落盘新证书文件（原子替换）
        self._write_live(target)
        if self.cfg.activate_delay_after_write:  # 测试钩子：制造崩溃窗口
            time.sleep(self.cfg.activate_delay_after_write)
        # 2. 请求 Nginx 平滑重载并等回执
        token = f"{seq}-{uuid.uuid4().hex[:8]}"
        self.control.request_reload(token)
        receipt = self.control.wait_receipt(token, self.cfg.receipt_timeout)
        # 3. 以新建 TLS 连接的实际握手结果为准
        served = None
        deadline = time.monotonic() + self.cfg.verify_timeout
        while time.monotonic() < deadline:
            try:
                served = self.control.probe()
            except ProbeError:
                served = None
            if served == target["fingerprint"]:
                break
            if receipt is not None and receipt.startswith("fail"):
                break
            time.sleep(self.cfg.probe_interval)
        # 4. 判定
        if served == target["fingerprint"]:
            self._finalize_success(seq, note="新 TLS 连接已返回新证书")
            return
        if receipt is not None and receipt.startswith("fail"):
            self._rollback_files(base)
            self._finalize_fail(seq, f"Nginx 重载失败（{receipt}），已沿用旧证书")
            return
        if receipt == "ok" and served is not None:
            self._rollback_files(base)
            self._finalize_fail(seq, "重载后新连接仍返回旧证书，已回退并保持旧证书在用")
            return
        # 回执不明或无法探测 -> 待核实
        reason = "重载回执超时" if receipt is None else "无法建立新连接核实"
        self._mark_pending(seq, f"{reason}，待核实")

    # ------------------------------------------------------------ 终态落库

    def _invalidate_probe(self) -> None:
        self._probe_cache = (0.0, None)

    def _finalize_success(self, seq: int, note: str = "") -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute("UPDATE versions SET status='superseded' WHERE status='active'")
            c.execute(
                "UPDATE versions SET status='active' WHERE id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE state SET active_version_id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE ops SET state='succeeded', detail=?, updated_at=? WHERE seq=?",
                (note or "启用成功", now_iso(), seq),
            )
        self._invalidate_probe()

    def _finalize_fail(self, seq: int, reason: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='failed', detail=?, updated_at=? WHERE seq=?",
                (reason, now_iso(), seq),
            )
            c.execute(
                "UPDATE versions SET status='failed' WHERE id=? AND status!='active'",
                (op["version_id"],),
            )
        self._invalidate_probe()

    def _mark_pending(self, seq: int, detail: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] != "activating":
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='pending_verify', detail=?, updated_at=?"
                " WHERE seq=?",
                (detail, now_iso(), seq),
            )

    # ------------------------------------------------------------ 后台核实

    def _reconcile_loop(self) -> None:
        while not self._stop.wait(2.0):
            try:
                self.reconcile_once()
            except Exception:
                log.exception("reconcile tick failed")

    def reconcile_once(self) -> None:
        with self.db.txn() as c:
            activating = c.execute(
                "SELECT COUNT(*) n FROM ops WHERE state='activating'"
            ).fetchone()["n"]
            if activating:
                return  # 前台请求线程 owns 启用中的操作
            op = c.execute(
                "SELECT * FROM ops WHERE state='pending_verify'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        if op:
            if st["current_op_seq"] != op["seq"]:
                with self.db.txn() as c:
                    c.execute(
                        "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                        " WHERE seq=?",
                        ("已有更新的操作，本操作结果作废", now_iso(), op["seq"]),
                    )
                return
            target = self._version(op["version_id"])
            try:
                served = self.control.probe()
            except ProbeError:
                return  # 无法确认，保持待核实
            if served == target["fingerprint"]:
                self._finalize_success(op["seq"], note="后台核实：新证书已生效")
                return
            created = dt.datetime.fromisoformat(op["created_at"])
            age = (dt.datetime.now(UTC) - created).total_seconds()
            if age > self.cfg.pending_ttl:
                active = self._version(st["active_version_id"])
                self._rollback_files(active)
                self._finalize_fail(
                    op["seq"], "超过待核实时限仍未生效，已回退到可确认的在用版本"
                )
            return
        # 无在途操作：保持"文件/实测/在用"三者一致（限流）
        if time.monotonic() - self._last_restore < self.cfg.restore_interval:
            return
        try:
            served = self.control.probe()
        except ProbeError:
            return
        active = self._version(st["active_version_id"])
        if active and served != active["fingerprint"]:
            self._last_restore = time.monotonic()
            self._ensure_live_matches_active(served)

    # ------------------------------------------------------------ 恢复辅助

    def _recover_to_confirmable(self, served: str) -> None:
        """按 Nginx 实际服务的指纹，把在用版本恢复到可确认的版本。"""
        with self.db.txn() as c:
            known = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (served,)
            ).fetchone()
            if known and known["status"] != "active":
                c.execute(
                    "UPDATE versions SET status='superseded' WHERE status='active'"
                )
                c.execute(
                    "UPDATE versions SET status='active' WHERE id=?", (known["id"],)
                )
                c.execute("UPDATE state SET active_version_id=?", (known["id"],))
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if active:
            self._write_live(dict(active))
            self.control.request_reload(f"recover-{uuid.uuid4().hex[:8]}")
            self._invalidate_probe()

    def _ensure_live_matches_active(self, served: str | None) -> None:
        with self.db.txn() as c:
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if not active:
            return
        live_fp = self.live_fingerprint()
        if live_fp != active["fingerprint"]:
            log.warning("live 文件与在用版本不一致，恢复为版本 #%s", active["id"])
            self._write_live(dict(active))
            self.control.request_reload(f"restore-{uuid.uuid4().hex[:8]}")
        elif served is not None and served != active["fingerprint"]:
            log.warning("Nginx 服务指纹与在用版本不一致，重新触发重载")
            self.control.request_reload(f"restore-{uuid.uuid4().hex[:8]}")

    def _rollback_files(self, version: dict) -> None:
        self._write_live(version)
        token = f"rollback-{uuid.uuid4().hex[:8]}"
        self.control.request_reload(token)
        self.control.wait_receipt(token, 3.0)  # 尽力而为

    # ------------------------------------------------------------ 查询

    def get_op(self, seq: int) -> dict:
        with self.db.txn() as c:
            row = self._op(c, seq)
            if not row:
                raise NotFound(f"操作 #{seq} 不存在")
            return dict(row)

    def status(self, probe: bool = True) -> dict:
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            versions = [
                dict(r)
                for r in c.execute(
                    "SELECT id, fingerprint, domain, subject, san, not_before,"
                    " not_after, status, created_at FROM versions ORDER BY id"
                ).fetchall()
            ]
            ops = [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM ops ORDER BY seq DESC LIMIT 10"
                ).fetchall()
            ]
        active = next(
            (v for v in versions if v["id"] == st["active_version_id"]), None
        )
        served = self.probe_cached() if probe else None
        if served is None:
            consistency = "unknown"
        elif active and served == active["fingerprint"]:
            consistency = "match"
        else:
            consistency = "mismatch"
        return {
            "domain": self.cfg.site_domain,
            "served_fingerprint": served,
            "consistency": consistency,
            "active_version_id": st["active_version_id"],
            "current_op_seq": st["current_op_seq"],
            "active": active,
            "versions": versions,
            "ops": ops,
            "latest_op": ops[0] if ops else None,
        }

    def probe_cached(self, ttl: float = 2.0) -> str | None:
        ts, val = self._probe_cache
        if time.monotonic() - ts < ttl:
            return val
        try:
            val = self.control.probe()
        except ProbeError:
            val = None
        self._probe_cache = (time.monotonic(), val)
        return val

    def live_fingerprint(self) -> str | None:
        try:
            with open(os.path.join(self.cfg.live_dir, "fullchain.pem"), "rb") as f:
                return certutil.fingerprint_pem_chain(f.read())
        except (OSError, certutil.CertError):
            return None

    # ------------------------------------------------------------ 内部

    def _version(self, vid: int) -> dict | None:
        if vid is None:
            return None
        with self.db.txn() as c:
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def _op(c, seq: int):
        return c.execute("SELECT * FROM ops WHERE seq=?", (seq,)).fetchone()

    @staticmethod
    def _latest_inflight(c):
        return c.execute(
            "SELECT * FROM ops WHERE state IN ('activating','pending_verify')"
            " ORDER BY seq DESC LIMIT 1"
        ).fetchone()

    def _write_live(self, version: dict) -> None:
        """原子写入 live 证书文件（先写临时文件再 rename）。"""
        for name, content in (
            ("fullchain.pem", version["cert_pem"]),
            ("privkey.pem", version["key_pem"]),
        ):
            tmp = os.path.join(self.cfg.live_dir, f".{name}.tmp")
            dst = os.path.join(self.cfg.live_dir, name)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dst)

    def _probe_with_grace(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.control.probe()
            except ProbeError:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(0.5)
