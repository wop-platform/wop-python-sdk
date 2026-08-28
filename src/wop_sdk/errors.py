# -*- coding: utf-8 -*-
"""WOP SDK 错误分类（crypto-strategy-spec §10.2）。

明确/模糊分界原则（I7）：鉴权前可判定的公开协议知识 → 明确（帮助商户集成自查）；
依赖密钥参与的判定 → 模糊（防 oracle）。验签/解密失败的对外消息不区分原因细节。
"""


class WopSdkError(Exception):
    """SDK 错误基类。"""


class SuiteParseError(WopSdkError):
    """解析类：securityReq 三段式/前缀/格式错误。对外语义明确。"""


class UnsupportedSuiteError(WopSdkError):
    """支持类：算法不在列表、跨族、密钥长度非法（I5）。对外语义明确。"""


class ProtocolFormatError(WopSdkError):
    """解析类：线上头结构（x-wop-sign / x-wop-encrypt / digest header）格式错误。明确。"""


class KeyMaterialError(WopSdkError):
    """配置类：密钥材料缺失/格式不符/不在指定曲线（D12、I5）。配置期可判定，明确。"""


class DigestMismatchError(WopSdkError):
    """完整性类：摘要不匹配。公开协议知识，明确。"""


class SignatureVerifyError(WopSdkError):
    """验签类：签名验证失败。对外模糊——不区分原因细节（I7）。"""

    def __init__(self, message: str = "签名验证失败"):
        super().__init__(message)


class DecryptError(WopSdkError):
    """解密类：DEK 解包失败、GCM tag 失败、SM2 密文校验失败。对外模糊（I7）。"""

    def __init__(self, message: str = "解密失败"):
        super().__init__(message)


class DekConsistencyError(WopSdkError):
    """一致性类：DEK alg 与套件族不符。公开映射知识，明确（D8/I3）。"""
