"""证书解析、校验与演示证书生成。

校验规则（上传时执行）：
1. PEM 证书链可解析，叶子证书为链中第一张；
2. 私钥可解析且与叶子证书公钥匹配；
3. 叶子证书在有效期内（未生效/已过期均拒绝）；
4. 叶子证书 SAN（无 SAN 时回退 CN）覆盖站点域名（支持单层通配符）；
5. 证书链逐级签发关系完整（ issuer/subject 衔接且签名有效）。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


class CertError(Exception):
    """证书校验失败，消息面向操作员。"""


_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def fingerprint_pem_chain(pem: bytes | str) -> str:
    data = pem.encode() if isinstance(pem, str) else pem
    leaf = parse_pem_chain(data)[0]
    return fingerprint_der(leaf.public_bytes(serialization.Encoding.DER))


def parse_pem_chain(data: bytes) -> list[x509.Certificate]:
    blocks = _PEM_RE.findall(data)
    if not blocks:
        raise CertError("未在证书文件中找到 PEM 格式的证书")
    certs: list[x509.Certificate] = []
    for block in blocks:
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except ValueError as exc:
            raise CertError(f"证书 PEM 解析失败: {exc}") from exc
    return certs


def parse_private_key(data: bytes):
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError as exc:
        raise CertError("私钥已加密，请提供未加密的 PEM 私钥") from exc
    except ValueError as exc:
        raise CertError(f"私钥 PEM 解析失败: {exc}") from exc
    if not isinstance(
        key,
        (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey),
    ):
        raise CertError("不支持的私钥类型（仅支持 RSA / ECDSA / Ed25519）")
    return key


def _pub_der(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def dns_name_matches(pattern: str, domain: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    if not pattern:
        return False
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        # 单层通配：*.example.com 匹配 a.example.com，不匹配 a.b.example.com
        return domain.endswith(pattern[1:]) and domain.count(".") == pattern.count(".")
    return False


def _leaf_names(leaf: x509.Certificate) -> list[str]:
    try:
        san = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        names = list(san.get_values_for_type(x509.DNSName))
        if names:
            return names
    except x509.ExtensionNotFound:
        pass
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return [cn[0].value] if cn else []


def _verify_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    if child.issuer != issuer.subject:
        return False
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                rsa_padding(),
                child.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    return True


def rsa_padding():
    from cryptography.hazmat.primitives.asymmetric import padding

    return padding.PKCS1v15()


@dataclass
class CertInfo:
    fingerprint: str
    subject: str
    san: list[str] = field(default_factory=list)
    not_before: dt.datetime = None
    not_after: dt.datetime = None


def validate_upload(
    chain_pem: bytes, key_pem: bytes, domain: str, now: dt.datetime | None = None
) -> CertInfo:
    """校验上传的证书链与私钥，返回叶子证书信息。失败抛 CertError。"""
    now = now or dt.datetime.now(dt.timezone.utc)
    certs = parse_pem_chain(chain_pem)
    key = parse_private_key(key_pem)
    leaf = certs[0]

    if _pub_der(leaf.public_key()) != _pub_der(key.public_key()):
        raise CertError("证书与私钥不匹配")

    nb = leaf.not_valid_before_utc
    na = leaf.not_valid_after_utc
    if now < nb:
        raise CertError(f"证书尚未生效（生效时间 {nb.isoformat()}）")
    if now > na:
        raise CertError(f"证书已过期（过期时间 {na.isoformat()}）")

    names = _leaf_names(leaf)
    if not any(dns_name_matches(n, domain) for n in names):
        raise CertError(
            f"证书域名不包含站点域名 {domain}（证书域名: {', '.join(names) or '无'}）"
        )

    for i in range(len(certs) - 1):
        if not _verify_issued_by(certs[i], certs[i + 1]):
            raise CertError(
                f"证书链不完整或顺序错误：第 {i + 1} 张证书不由第 {i + 2} 张签发"
            )

    return CertInfo(
        fingerprint=fingerprint_der(leaf.public_bytes(serialization.Encoding.DER)),
        subject=leaf.subject.rfc4514_string(),
        san=names,
        not_before=nb,
        not_after=na,
    )


# ---------------------------------------------------------------- 演示证书生成


def generate_ca(common_name: str = "Demo Internal CA", days: int = 3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    return _cert_pem(cert), _key_pem(key)


def generate_server_cert(
    domain: str,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    days_valid: int = 365,
    not_before_days_ago: int = 0,
) -> tuple[bytes, bytes]:
    """用演示 CA 签发服务器证书，返回 (链 PEM[服务器+CA], 私钥 PEM)。"""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=not_before_days_ago))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    return _cert_pem(cert) + ca_cert_pem, _key_pem(key)


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
