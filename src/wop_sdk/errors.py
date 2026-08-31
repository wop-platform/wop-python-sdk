# -*- coding: utf-8 -*-
"""WOP SDK 错误分类（crypto-strategy-spec §10.2）。

明确/模糊分界原则（I7）：鉴权前可判定的公开协议知识 → 明确（帮助商户集成自查）；
依赖密钥参与的判定 → 模糊（防 oracle）。验签/解密失败的对外消息不区分原因细节。

出向可观测错误统一形状 WopError{category, message}（sdk-spec §2.2）：
category 为闭集（小写 ASCII，跨语言恒定），各子类覆写 ``category`` 类属性。
"""
# §2.2 category 闭集（跨语言恒定；禁止新增取值，新增错误类只能映射到既有值）
ERROR_CATEGORIES: frozenset[str] = frozenset(
    {
        "configuration",  # 配置错误：appKey / 密钥材料缺失或非法、securityReq 非法或跨族（F1）
        "parse",          # 协议解析错误：header / 信封 / 线上编码格式（D1/D3）
        "unsupported",    # 能力不支持：合法套件但本 SDK 未实现
        "integrity",      # 完整性校验：digest 不匹配
        "consistency",    # 一致性校验：dek alg 与套件族不符（I3）
        "signature",      # 验签失败（I7：对外模糊）
        "decrypt",        # 解密失败（I7：对外模糊）
    }
)


class WopSdkError(Exception):
    """SDK 错误基类（§2.2 统一形状 WopError{category, message}）。

    子类必须覆写 ``category`` 为闭集值（ERROR_CATEGORIES）；基类空串表示
    「未归类」，SDK 不直接抛基类（构造/入参类错误抛 ConfigurationError）。
    """

    category: str = ""


class ConfigurationError(WopSdkError):
    """配置类：appKey / 密钥材料缺失或非法、入参非法（level/body 类型，§2.2 configuration）。"""

    category = "configuration"


class SuiteParseError(WopSdkError):
    """解析类：securityReq 三段式/前缀/格式错误。对外语义明确。"""

    category = "parse"


class UnsupportedSuiteError(WopSdkError):
    """支持类：算法不在列表、跨族、密钥长度非法（I5）。对外语义明确。"""

    category = "unsupported"


class ProtocolFormatError(WopSdkError):
    """解析类：线上头结构（x-wop-sign / x-wop-encrypt / digest header）格式错误。明确。"""

    category = "parse"


class KeyMaterialError(WopSdkError):
    """配置类：密钥材料缺失/格式不符/不在指定曲线（D12、I5）。配置期可判定，明确。"""

    category = "configuration"


class DigestMismatchError(WopSdkError):
    """完整性类：摘要不匹配。公开协议知识，明确。"""

    category = "integrity"


class SignatureVerifyError(WopSdkError):
    """验签类：签名验证失败。对外模糊——不区分原因细节（I7）。"""

    category = "signature"

    def __init__(self, message: str = "签名验证失败"):
        super().__init__(message)


class DecryptError(WopSdkError):
    """解密类：DEK 解包失败、GCM tag 失败、SM2 密文校验失败。对外模糊（I7）。"""

    category = "decrypt"

    def __init__(self, message: str = "解密失败"):
        super().__init__(message)


class DekConsistencyError(WopSdkError):
    """一致性类：DEK alg 与套件族不符。公开映射知识，明确（D8/I3）。"""

    category = "consistency"
