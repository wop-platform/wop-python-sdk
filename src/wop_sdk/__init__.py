# -*- coding: utf-8 -*-
"""WOP 商户侧官方 Python SDK。

协议核心（签名/摘要/数字信封/验签解密，纯函数、零网络 IO）+ 可插拔 HTTP 适配层。
"""
from importlib.metadata import PackageNotFoundError, version as _dist_version

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

# 版本单一源：pyproject [project].version（经分发元数据读取），
# 未安装场景（纯源码树 import）兜底 0.0.0
try:
    __version__ = _dist_version("wop-python-sdk")
except PackageNotFoundError:  # pragma: no cover —— 无分发元数据时的兜底分支
    __version__ = "0.0.0"

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
