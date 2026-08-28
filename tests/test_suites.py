# -*- coding: utf-8 -*-
"""套件解析测试：securityReq 三套件 + 跨族/非法拒绝（F1、spec §2）。"""
import pytest

from wop_sdk.errors import SuiteParseError, UnsupportedSuiteError
from wop_sdk.suites import Suite, parse_suite


class TestParsePositive:
    def test_rsa3072(self):
        s = parse_suite("WOP-RSA3072-SHA256")
        assert s.security_req == "WOP-RSA3072-SHA256"
        assert s.family == "RSA"
        assert s.key_bits == 3072
        assert s.digest_tag == "sha-256"
        assert s.message_alg == "AES-256-GCM"
        assert s.key_wrap_alg == "RSA-3072-OAEP"
        assert s.sign_alg == "SHA256withRSA"

    def test_rsa4096(self):
        s = parse_suite("WOP-RSA4096-SHA256")
        assert s.family == "RSA"
        assert s.key_bits == 4096
        assert s.message_alg == "AES-256-GCM"  # Q2：4096 报文算法仍为 AES-256-GCM
        assert s.key_wrap_alg == "RSA-4096-OAEP"

    def test_sm2(self):
        s = parse_suite("WOP-SM2-SM3")
        assert s.family == "SM"
        assert s.key_bits == 0  # SM2 无 RSA 语义长度
        assert s.digest_tag == "sm3"
        assert s.message_alg == "SM4-GCM"
        assert s.key_wrap_alg == "SM2"
        assert s.sign_alg == "SM3withSM2"

    @pytest.mark.parametrize("req", ["WOP-RSA3072-SHA256", "WOP-RSA4096-SHA256", "WOP-SM2-SM3"])
    def test_all_three_suites_supported(self, req):
        assert parse_suite(req).security_req == req


class TestParseNegative:
    """spec §2.4：空值/格式/前缀 → 解析类；算法不在列表/跨族 → 支持类（I5）。"""

    @pytest.mark.parametrize("bad", ["", "   ", None])
    def test_empty_or_blank_rejected(self, bad):
        with pytest.raises(SuiteParseError):
            parse_suite(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "RSA3072-SHA256",  # 缺前缀
            "WOP-RSA3072",  # 两段
            "WOP-RSA3072-SHA256-EXTRA",  # 四段
            "wop-rsa3072-sha256",  # 前缀非 WOP（大小写敏感）
            "WOP/RSA3072/SHA256",  # 非法分隔符
        ],
    )
    def test_format_rejected(self, bad):
        with pytest.raises(SuiteParseError):
            parse_suite(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "WOP-RSA2048-SHA256",  # 密钥算法不在列表
            "WOP-ECDSA-SHA256",
            "WOP-RSA3072-SHA512",  # 摘要算法不在列表
            "WOP-SM2-SM4",
        ],
    )
    def test_unknown_algorithm_rejected(self, bad):
        with pytest.raises(UnsupportedSuiteError):
            parse_suite(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "WOP-RSA3072-SM3",  # 国际密钥 + 国密摘要
            "WOP-RSA4096-SM3",
            "WOP-SM2-SHA256",  # 国密密钥 + 国际摘要
        ],
    )
    def test_cross_family_rejected(self, bad):  # spec:I5
        with pytest.raises(UnsupportedSuiteError):
            parse_suite(bad)


class TestSuiteObject:
    def test_immutable(self):
        s = parse_suite("WOP-SM2-SM3")
        with pytest.raises(AttributeError):
            s.family = "RSA"

    def test_unknown_family_has_no_rsa_key_bits(self):
        assert parse_suite("WOP-SM2-SM3").key_bits == 0
