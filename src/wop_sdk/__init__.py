# -*- coding: utf-8 -*-
"""WOP 商户侧官方 Python SDK。

协议核心（签名/摘要/数字信封/验签解密，纯函数、零网络 IO）+ 可插拔 HTTP 适配层。
"""
from .client import RequestDraft, VerifyResult, WopClient, WopConfig
from .errors import (
    DecryptError,
    DekConsistencyError,
    DigestMismatchError,
    KeyMaterialError,
    ProtocolFormatError,
    SignatureVerifyError,
    SuiteParseError,
    UnsupportedSuiteError,
    WopSdkError,
)
from .suites import Suite, parse_suite

__version__ = "0.1.1"

__all__ = [
    "WopClient",
    "WopConfig",
    "RequestDraft",
    "VerifyResult",
    "Suite",
    "parse_suite",
    "WopSdkError",
    "SuiteParseError",
    "UnsupportedSuiteError",
    "ProtocolFormatError",
    "KeyMaterialError",
    "DigestMismatchError",
    "SignatureVerifyError",
    "DecryptError",
    "DekConsistencyError",
    "__version__",
]
