# -*- coding: utf-8 -*-
"""密钥材料解析（D12 分发契约）。

- RSA 公钥 = X.509 SPKI DER，Base64 编码（PEM 仅作可选包装）
- RSA 私钥 = PKCS#8 DER，Base64 编码（PEM 可选包装）
- SM2 公钥 = 未压缩点 04‖X‖Y（65 字节），Base64 编码；必须在 sm2p256v1 曲线上（I5）
- SM2 私钥 = d 标量（32 字节大端），1 ≤ d < n
"""
import base64
import binascii
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

from .errors import KeyMaterialError

# sm2p256v1 曲线参数（GB/T 32918.5）
_SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


@dataclass(frozen=True)
class Sm2PublicKey:
    """SM2 公钥点（X‖Y 128 hex，无 04 前缀；uncompressed 含 04）。"""

    xy_hex: str
    uncompressed: bytes


def _material_to_der(material: str) -> bytes:
    """密钥材料 → DER 字节：接受 PEM 包装或单行 Base64（标准/URL 字母表，允许 padding）。"""
    text = material.strip()
    if "-----BEGIN" in text:
        body = "".join(line for line in text.splitlines() if "-----" not in line)
    else:
        body = "".join(text.split())
    if not body:
        raise KeyMaterialError("密钥内容为空")
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        raise KeyMaterialError("密钥材料无法解码为 Base64") from None


def load_rsa_public_key(material: str, expected_bits: Optional[int] = None) -> rsa.RSAPublicKey:
    """解析 RSA 公钥（SPKI DER，D12 材料串）；expected_bits 给定时校验长度与套件一致。"""
    der = _material_to_der(material)
    try:
        key = load_der_public_key(der)
    except (InvalidKey, ValueError, TypeError) as exc:
        raise KeyMaterialError(f"RSA 公钥解析失败（应为 SPKI DER Base64/PEM）: {exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyMaterialError("非 RSA 公钥材料")
    if expected_bits is not None and key.key_size != expected_bits:
        raise KeyMaterialError(
            "RSA 公钥长度 %d 与套件要求 %d 不符" % (key.key_size, expected_bits)
        )
    return key


def load_rsa_private_key(material: str, expected_bits: Optional[int] = None) -> rsa.RSAPrivateKey:
    """解析 RSA 私钥（PKCS#8 DER 无口令，D12 材料串）；expected_bits 给定时校验长度与套件一致。"""
    der = _material_to_der(material)
    try:
        key = load_der_private_key(der, password=None)
    except (InvalidKey, ValueError, TypeError) as exc:
        raise KeyMaterialError(f"RSA 私钥解析失败（应为 PKCS#8 DER Base64/PEM）: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError("非 RSA 私钥材料")
    if expected_bits is not None and key.key_size != expected_bits:
        raise KeyMaterialError(
            "RSA 私钥长度 %d 与套件要求 %d 不符" % (key.key_size, expected_bits)
        )
    return key


def load_sm2_public_key(material: str) -> Sm2PublicKey:
    """解析 SM2 公钥：未压缩点 04‖X‖Y 共 65 字节，且必须落在 sm2p256v1 曲线上（I5）。"""
    der = _material_to_der(material)
    if len(der) != 65 or der[0] != 0x04:
        raise KeyMaterialError(
            "SM2 公钥必须为未压缩点 04‖X‖Y（65 字节），实际 %d 字节" % len(der)
        )
    x = int.from_bytes(der[1:33], "big")
    y = int.from_bytes(der[33:65], "big")
    # I5：点必须在 sm2p256v1 曲线上（y² ≡ x³ + ax + b mod p）
    if (y * y - (x * x * x + _SM2_A * x + _SM2_B)) % _SM2_P != 0:
        raise KeyMaterialError("SM2 公钥点不在 sm2p256v1 曲线上")
    return Sm2PublicKey(xy_hex=der[1:].hex(), uncompressed=der)


def load_sm2_private_key(material: str) -> bytes:
    """解析 SM2 私钥：32 字节大端标量 d，取值范围 [1, n)（D12/I5）。"""
    der = _material_to_der(material)
    if len(der) != 32:
        raise KeyMaterialError("SM2 私钥必须为 32 字节大端标量 d，实际 %d 字节" % len(der))
    d = int.from_bytes(der, "big")
    if not 1 <= d < _SM2_N:
        raise KeyMaterialError("SM2 私钥标量 d 超出 [1, n) 范围")
    return der
