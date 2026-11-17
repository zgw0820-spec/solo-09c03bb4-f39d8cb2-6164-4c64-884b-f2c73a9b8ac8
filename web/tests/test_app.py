"""单元/集成测试：证书校验、并发控制、回滚、待核实与重启恢复。

FakeControl 模拟 nginx 行为：收到重载回执为 ok 时，
把"当前 live 目录里的证书"当作 nginx 对外服务的证书。
"""
from __future__ import annotations

import datetime as dt
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import certutil
from app.certutil import CertError
from app.service import BadRequest, CertService, Config, Conflict, ProbeError

DOMAIN = "demo.internal"


class FakeControl:
    """行为接近真实 nginx：reload 后服务 live 目录中的证书。"""

    def __init__(self, service: CertService):
        self.service = service
        self.receipt_mode = "ok"   # ok | fail | timeout
        self.served: str | None = None
        self.reload_count = 0
        self.probe_error = False

    def _live_fp(self):
        return self.service.live_fingerprint()

    def probe(self) -> str:
        if self.probe_error:
            raise ProbeError("fake probe error")
        if self.served is None:
            raise ProbeError("nothing served yet")
        return self.served

    def request_reload(self, token: str) -> None:
        self.reload_count += 1
        if self.receipt_mode == "ok":
            self.served = self._live_fp()

    def wait_receipt(self, token: str, timeout: float):
        if self.receipt_mode == "timeout":
            return None
        if self.receipt_mode == "fail":
            return "fail test: simulated reload failure"
        return "ok"


@pytest.fixture()
def cfg(tmp_path):
    return Config(
        site_domain=DOMAIN,
        data_dir=str(tmp_path / "data"),
        live_dir=str(tmp_path / "live"),
        reload_dir=str(tmp_path / "reload"),
        receipt_timeout=0.2,
        verify_timeout=1.5,
        pending_ttl=0.5,
        probe_interval=0.05,
        startup_probe_timeout=0.5,
        restore_interval=0.1,
    )


@pytest.fixture()
def service(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    yield svc
    svc.shutdown()


def make_cert(service, days_valid=365, not_before_days_ago=0, domain=DOMAIN):
    with open(f"{service.cfg.data_dir}/ca/ca.pem", "rb") as f:
        ca_cert = f.read()
    with open(f"{service.cfg.data_dir}/ca/ca-key.pem", "rb") as f:
        ca_key = f.read()
    return certutil.generate_server_cert(
        domain, ca_cert, ca_key,
        days_valid=days_valid, not_before_days_ago=not_before_days_ago,
    )


def upload_new(service, **kw):
    chain, key = make_cert(service, **kw)
    return service.upload(chain, key)[0]


# ---------------------------------------------------------------- 证书校验


def test_validate_ok(service):
    chain, key = make_cert(service)
    info = certutil.validate_upload(chain, key, DOMAIN)
    assert len(info.fingerprint) == 64


def test_validate_key_mismatch(service):
    chain, _ = make_cert(service)
    _, other_key = make_cert(service)
    with pytest.raises(CertError, match="不匹配"):
        certutil.validate_upload(chain, other_key, DOMAIN)


def test_validate_wrong_domain(service):
    chain, key = make_cert(service, domain="other.internal")
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_expired(service):
    chain, key = make_cert(service, days_valid=-1, not_before_days_ago=10)
    with pytest.raises(CertError, match="已过期"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_not_yet_valid(service):
    chain, key = make_cert(service, days_valid=365, not_before_days_ago=-5)
    with pytest.raises(CertError, match="尚未生效"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_broken_chain(service):
    chain, key = make_cert(service)
    leaf = chain.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    other_ca, _ = certutil.generate_ca("Other CA")
    with pytest.raises(CertError, match="证书链"):
        certutil.validate_upload(leaf + other_ca, key, DOMAIN)


def test_validate_encrypted_key(service):
    chain, _ = make_cert(service)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    with pytest.raises(CertError, match="加密"):
        certutil.validate_upload(chain, enc_key, DOMAIN)


def test_validate_self_signed_ok(service):
    ca, key = certutil.generate_ca("self-signed.demo.internal")
    # 自签名 CA 的 CN 不含站点域名，应被域名检查拒绝
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(ca, key, DOMAIN)


def test_wildcard_match():
    assert certutil.dns_name_matches("*.example.com", "a.example.com")
    assert not certutil.dns_name_matches("*.example.com", "a.b.example.com")
    assert not certutil.dns_name_matches("*.example.com", "example.com")
    assert certutil.dns_name_matches("example.com", "EXAMPLE.com")


# ---------------------------------------------------------------- 上传


def test_upload_and_duplicate(service):
    chain, key = make_cert(service)
    v1, created1 = service.upload(chain, key)
    v2, created2 = service.upload(chain, key)
    assert created1 and not created2
    assert v1["id"] == v2["id"]
    assert v1["status"] == "candidate"


# ---------------------------------------------------------------- 启用流程


def test_activate_happy_path(service):
    v2 = upload_new(service)
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "succeeded"
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.control.served == v2["fingerprint"]
    assert service.live_fingerprint() == v2["fingerprint"]
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[1] == "superseded"
    assert versions[v2["id"]] == "active"


def test_activate_stale_base_rejected(service):
    v2 = upload_new(service)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=999)
    st = service.status(probe=False)
    assert st["active_version_id"] == 1


def test_activate_already_active(service):
    with pytest.raises(BadRequest):
        service.activate(1, base_version_id=1)


def test_concurrent_activate_only_one_wins(service):
    v2 = upload_new(service)
    results, errors = [], []

    def worker():
        try:
            results.append(service.activate(v2["id"], base_version_id=1))
        except Conflict as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"应有且仅有一个提交成功: {results} {errors}"
    assert results[0]["state"] == "succeeded"
    assert len(errors) == 7
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert len(st["ops"]) == 1  # 只登记了一个操作


def test_duplicate_submit_after_success_rejected(service):
    v2 = upload_new(service)
    service.activate(v2["id"], base_version_id=1)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=1)  # 重复提交同一表单


def test_reload_failure_rolls_back(service):
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp  # nginx 当前服务旧证书
    service.control.receipt_mode = "fail"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "failed"
    assert "重载失败" in op["detail"]
    st = service.status(probe=False)
    assert st["active_version_id"] == 1
    # 文件已回滚，nginx 仍服务旧证书
    assert service.live_fingerprint() == old_fp
    assert service.control.served == old_fp
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[v2["id"]] == "failed"


def test_receipt_timeout_goes_pending_then_confirms(service):
    v2 = upload_new(service)
    service.control.receipt_mode = "timeout"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    assert service.status(probe=False)["active_version_id"] == 1  # 尚未切换
    # nginx 后来真的完成了重载
    service.control.served = service.live_fingerprint()
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.get_op(op["seq"])["state"] == "succeeded"


def test_pending_expires_and_rolls_back(service):
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.receipt_mode = "timeout"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # nginx 一直服务旧证书；超过宽限期后回退
    service.control.served = old_fp
    import time

    time.sleep(0.6)  # pending_ttl = 0.5
    service.reconcile_once()
    op = service.get_op(op["seq"])
    assert op["state"] == "failed"
    assert "回退" in op["detail"]
    assert service.live_fingerprint() == old_fp
    assert service.status(probe=False)["active_version_id"] == 1


def test_old_pending_op_cannot_overwrite_newer(service):
    """旧操作待核实期间有新提交成功后，旧操作不得再改动任何状态/文件。"""
    v2 = upload_new(service)
    v3 = upload_new(service)
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"
    # 新提交（基于同一在用版号 1）成功
    service.control.receipt_mode = "ok"
    op_b = service.activate(v3["id"], base_version_id=1)
    assert op_b["state"] == "succeeded"
    assert service.status(probe=False)["active_version_id"] == v3["id"]
    # 旧操作 A 在创建 B 时已被取代；即使 nginx 稍后开始服务 v2 的证书也不得翻盘
    assert service.get_op(op_a["seq"])["state"] == "superseded"
    service.control.served = v2["fingerprint"]
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v3["id"]
    assert service.live_fingerprint() == v3["fingerprint"]


# ---------------------------------------------------------------- 重启恢复


def restart(service_factory_cfg):
    svc = CertService(service_factory_cfg)
    svc.control = FakeControl(svc)
    return svc


def test_restart_confirms_successful_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    svc.control.receipt_mode = "timeout"
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # 模拟进程崩溃：nginx 实际已切到新证书
    served = svc.live_fingerprint()
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = served
    svc2.startup(background=False)
    st = svc2.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert svc2.get_op(op["seq"])["state"] == "succeeded"
    svc2.shutdown()


def test_restart_rolls_back_unconfirmed_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    svc.control.receipt_mode = "timeout"
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # 进程崩溃时 nginx 仍服务旧证书
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    st = svc2.status(probe=False)
    assert st["active_version_id"] == 1
    assert svc2.get_op(op["seq"])["state"] == "failed"
    assert svc2.live_fingerprint() == old_fp  # 文件已恢复到可确认版本
    svc2.shutdown()


def test_restart_with_activating_op_recovered(cfg):
    """进程在操作处于 activating 时崩溃（未留下任何终态）。"""
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 手工制造一个悬空的 activating 操作（等价于崩溃瞬间）
    with svc.db.txn() as c:
        st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        seq = st["current_op_seq"] + 1
        ts = certutil.dt.datetime.now(certutil.dt.timezone.utc).isoformat()
        c.execute(
            "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (seq, v2["id"], 1, "activating", None, ts, ts),
        )
        c.execute("UPDATE state SET current_op_seq=?", (seq,))
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    assert svc2.get_op(seq)["state"] == "failed"
    assert svc2.status(probe=False)["active_version_id"] == 1
    svc2.shutdown()


def test_restart_restores_tampered_live_files(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    active_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 带外篡改 live 文件
    chain, key = make_cert(svc)
    with open(f"{cfg.live_dir}/fullchain.pem", "wb") as f:
        f.write(chain)
    assert svc.live_fingerprint() != active_fp
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = active_fp
    svc2.startup(background=False)
    assert svc2.live_fingerprint() == active_fp
    assert svc2.control.reload_count >= 1  # 触发了恢复重载
    svc2.shutdown()


def test_reconciler_restores_out_of_band_change(service):
    """无在途操作时，nginx 实测指纹与在用版本不一致会被自动修复。"""
    active_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = "0" * 64  # 带外变更
    import time

    time.sleep(0.15)  # restore_interval = 0.1
    service.reconcile_once()
    assert service.control.reload_count >= 1
