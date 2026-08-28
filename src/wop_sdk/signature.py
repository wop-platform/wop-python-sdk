# -*- coding: utf-8 -*-
"""结构化签名（F3/F7/D9）：SHA256withRSA（PKCS#1 v1.5）与 SM3withSM2（裸 r‖s 64B）。

定长编码前置校验：长度不符按解析类拒绝，先于任何密码学运算（§3.3①）。
"""
import os
from typing import Callable, Union, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import ProtocolFormatError, SignatureVerifyError
from .sm2crypto import _N, Sm2Ops, sm2_sign_with_sm3, sm2_verify_with_sm3
from .suites import Suite

Csprng = Callable[[int], bytes]
Signer = Union[rsa.RSAPrivateKey, Sm2Ops]
Verifier = Union[rsa.RSAPublicKey, Sm2Ops]


def sign(suite: Suite, signer: Signer, data: bytes, csprng: Csprng = os.urandom) -> bytes:
    """加签：RSA → PKCS#1 v1.5 + SHA-256；SM2 → SM3withSM2 裸 r‖s（k 走 csprng，I4）。"""
    if suite.family == "RSA":
        key = cast(rsa.RSAPrivateKey, signer)
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    for _ in range(256):
        k = int.from_bytes(csprng(32), "big")
        if 1 <= k < _N:
            return sm2_sign_with_sm3(signer, data, "%064x" % k)
    raise SignatureVerifyError("签名验证失败")  # pragma: no cover —— 2^-2048 概率


def verify(suite: Suite, verifier: Verifier, data: bytes, signature: bytes) -> None:
    """验签；失败抛 SignatureVerifyError（I7：对外模糊，不区分原因细节）。

    长度前置校验（解析类，先于密码学运算）：
    RSA3072 → 384B；RSA4096 → 512B；SM2 → 恒 64B（63B/65B/DER 一律拒绝）。
    """
    if suite.family == "RSA":
        if len(signature) != suite.key_bits // 8:
            raise ProtocolFormatError(
                "RSA 签名长度 %d 与套件 %d 位要求的 %d 字节不符"
                % (len(signature), suite.key_bits, suite.key_bits // 8)
            )
        try:
            pub = cast(rsa.RSAPublicKey, verifier)
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise SignatureVerifyError() from None
        return
    if len(signature) != 64:
        raise ProtocolFormatError(
            "SM2 签名必须为裸 r||s 64 字节（禁 DER），实际 %d 字节" % len(signature)
        )
    if not sm2_verify_with_sm3(verifier, signature.hex(), data):
        raise SignatureVerifyError()
