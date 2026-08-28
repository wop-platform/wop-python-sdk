# -*- coding: utf-8 -*-
"""请求体摘要（D2/F4）：`x-wop-content-digest: <alg> <小写hex>`。

- 恰好一个半角空格，多余空白拒绝而非容忍；
- hex 统一小写、固定 64 字符；
- 标签与套件族强耦合（I5）：sha-256 仅 RSA 族、sm3 仅 SM 族；
- 摘要对象 = wire 原始报文字节；无 body（GET）则 header 缺席。
"""
import hashlib
import re
from typing import Optional

from gmssl import sm3 as _sm3

from .errors import DigestMismatchError, ProtocolFormatError, UnsupportedSuiteError
from .suites import Suite

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def compute_digest(suite: Suite, data: bytes) -> bytes:
    """按套件族计算摘要（SHA-256 / SM3）。"""
    if suite.family == "RSA":
        return hashlib.sha256(data).digest()
    return bytes.fromhex(_sm3.sm3_hash(list(data)))


def build_digest_header(suite: Suite, body: bytes) -> str:
    """组装 `<alg> <小写hex>`（恰一空格）。"""
    return "%s %s" % (suite.digest_tag, compute_digest(suite, body).hex())


def check_digest_header(suite: Suite, value: Optional[str]) -> str:
    """格式层校验，通过返回 hex 值。

    拒绝：非两段/恰一空格不满足、未知标签、跨族标签（I5）、非小写 hex、长度 ≠ 64。
    """
    if value is None:
        raise ProtocolFormatError("digest 头缺席")
    parts = value.split(" ")
    if len(parts) != 2:
        raise ProtocolFormatError(
            "digest 头格式错误：必须为 '<alg> <hex>' 恰一空格，实际 %r" % value
        )
    tag, hex_value = parts
    expected_tag = suite.digest_tag
    if tag != expected_tag:
        # I5：标签与套件族强耦合（sha-256 仅 RSA 族、sm3 仅 SM 族）
        if tag in ("sha-256", "sm3"):
            raise UnsupportedSuiteError(
                "digest 标签 %s 与套件族 %s 不符（跨族拒绝）" % (tag, suite.family)
            )
        raise ProtocolFormatError("digest 标签未知：%r" % tag)
    if not _HEX64.match(hex_value):
        raise ProtocolFormatError("digest 值必须为 64 字符小写 hex，实际 %r" % hex_value)
    return hex_value


def verify_digest_header(suite: Suite, value: Optional[str], body: bytes) -> None:
    """格式 + 值双层校验（F6 第 2 步 digest 复核）。不匹配抛完整性类错误（明确）。"""
    expected = check_digest_header(suite, value)
    actual = compute_digest(suite, body).hex()
    if expected != actual:
        raise DigestMismatchError("内容摘要不匹配")
