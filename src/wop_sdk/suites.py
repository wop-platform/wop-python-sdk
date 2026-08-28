# -*- coding: utf-8 -*-
"""securityReq 套件解析（F1，crypto-strategy-spec §2）。

格式：WOP-<密钥算法标识>-<摘要算法标识>，三段式；
映射关系集中注册于代码（单一注册表，D13），无运行时配置入口。
"""
from dataclasses import dataclass
from typing import Optional

from .errors import SuiteParseError, UnsupportedSuiteError

# 密钥算法 → (族, RSA 位长)。SM2 族 key_bits=0。
_KEY_ALGORITHMS = {
    "RSA3072": ("RSA", 3072),
    "RSA4096": ("RSA", 4096),
    "SM2": ("SM", 0),
}
# 摘要算法 → (族, header 标签)；族与密钥算法族同名（I5 比对基准）
_DIGEST_ALGORITHMS = {
    "SHA256": ("RSA", "sha-256"),
    "SM3": ("SM", "sm3"),
}

# 族 → 报文对称算法 / DEK 包装算法 / 签名算法名
_FAMILY_MESSAGE_ALG = {"RSA": "AES-256-GCM", "SM": "SM4-GCM"}
_FAMILY_KEY_WRAP = {3072: "RSA-3072-OAEP", 4096: "RSA-4096-OAEP"}
_FAMILY_SIGN = {"RSA": "SHA256withRSA", "SM": "SM3withSM2"}


@dataclass(frozen=True)
class Suite:
    """一次请求的算法上下文（不可变；spec §4.4 AlgorithmSuite 的 SDK 侧映像）。"""

    security_req: str
    family: str  # "RSA" | "SM"
    key_bits: int  # 3072 | 4096 | 0（SM2）
    digest_alg: str  # "SHA256" | "SM3"
    digest_tag: str  # "sha-256" | "sm3"
    sign_alg: str
    message_alg: str  # "AES-256-GCM" | "SM4-GCM"
    key_wrap_alg: str


def parse_suite(security_req: Optional[str]) -> Suite:
    """解析 securityReq；失败按 §2.4 分类（解析类/支持类）拒绝。"""
    if security_req is None or not security_req.strip():
        raise SuiteParseError("securityReq 为空")
    parts = security_req.split("-")
    if len(parts) != 3 or parts[0] != "WOP":
        raise SuiteParseError(
            "securityReq 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式，实际 %r" % security_req
        )
    _, key_alg, digest_alg = parts
    if key_alg not in _KEY_ALGORITHMS:
        raise UnsupportedSuiteError("不支持的密钥算法：%s" % key_alg)
    if digest_alg not in _DIGEST_ALGORITHMS:
        raise UnsupportedSuiteError("不支持的摘要算法：%s" % digest_alg)
    family, key_bits = _KEY_ALGORITHMS[key_alg]
    digest_family, digest_tag = _DIGEST_ALGORITHMS[digest_alg]
    # I5：国际/国密跨族组合禁止（§2.3）
    if family != digest_family:
        raise UnsupportedSuiteError(
            "跨族算法组合被拒绝：%s（密钥族 %s 与摘要族 %s 不一致）"
            % (security_req, family, digest_family)
        )
    if family == "RSA":
        key_wrap_alg = _FAMILY_KEY_WRAP[key_bits]
    else:
        key_wrap_alg = "SM2"
    return Suite(
        security_req=security_req,
        family=family,
        key_bits=key_bits,
        digest_alg=digest_alg,
        digest_tag=digest_tag,
        sign_alg=_FAMILY_SIGN[family],
        message_alg=_FAMILY_MESSAGE_ALG[family],
        key_wrap_alg=key_wrap_alg,
    )
