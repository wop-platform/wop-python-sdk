# -*- coding: utf-8 -*-
"""摘要测试：D2 格式钉（恰一空格/小写 hex/跨族拒绝/长度）、向量字节级、formatRules 全套。"""
import pytest

from wop_sdk.digest import (
    build_digest_header,
    check_digest_header,
    compute_digest,
    verify_digest_header,
)
from wop_sdk.errors import DigestMismatchError, ProtocolFormatError, UnsupportedSuiteError
from wop_sdk.suites import parse_suite

RSA = parse_suite("WOP-RSA3072-SHA256")
SM = parse_suite("WOP-SM2-SM3")


class TestComputeDigest:
    def test_sha256_vector(self, vectors):  # spec:A1 digest-sha256
        v = next(x for x in vectors["digest"] if x["id"] == "digest-sha256")
        assert compute_digest(RSA, v["input"].encode("utf-8")).hex() == v["expectedHex"]

    def test_sm3_vector(self, vectors):  # spec:A1 digest-sm3
        v = next(x for x in vectors["digest"] if x["id"] == "digest-sm3")
        assert compute_digest(SM, v["input"].encode("utf-8")).hex() == v["expectedHex"]


class TestBuildHeader:
    def test_sha256_header(self, vectors):  # spec:D2
        v = next(x for x in vectors["digest"] if x["id"] == "digest-sha256")
        assert build_digest_header(RSA, v["input"].encode("utf-8")) == v["expectedHeader"]

    def test_sm3_header(self, vectors):  # spec:D2
        v = next(x for x in vectors["digest"] if x["id"] == "digest-sm3")
        assert build_digest_header(SM, v["input"].encode("utf-8")) == v["expectedHeader"]

    def test_exactly_one_space_lowercase(self):
        header = build_digest_header(RSA, b"abc")
        assert header.startswith("sha-256 ")
        assert header.count(" ") == 1


class TestFormatRules:
    """formatRules 全套（spec:A2/F8）：accept = 格式层接受；reject = 拒绝。"""

    @pytest.mark.parametrize("rule_id", ["header-rsa-ok", "header-sm2-ok"])
    def test_accept_format(self, vectors, rule_id):
        rule = next(r for r in vectors["formatRules"] if r["id"] == rule_id)
        check_digest_header(parse_suite(rule["suite"]), rule["value"])

    @pytest.mark.parametrize(
        "rule_id",
        [
            "header-crossfamily",  # spec:I5 跨族
            "header-double-space",  # spec:D2 恰一空格
            "header-uppercase-hex",  # spec:F5 小写
            "header-wrong-hex-len",  # 必须 64 hex
            "b64url-with-padding",
            "b64url-illegal-char",
        ],
    )
    def test_reject(self, vectors, rule_id):
        rule = next(r for r in vectors["formatRules"] if r["id"] == rule_id)
        suite = parse_suite(rule.get("suite", "WOP-RSA3072-SHA256"))
        with pytest.raises((ProtocolFormatError, UnsupportedSuiteError, ValueError)):
            check_digest_header(suite, rule["value"])

    def test_crossfamily_is_support_error(self):
        # 跨族标签（I5）单独归为支持类语义（明确拒绝）
        with pytest.raises(UnsupportedSuiteError):
            check_digest_header(RSA, "sm3 " + "0" * 64)

    def test_double_space_is_format_error(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-256  " + "0" * 64)

    def test_uppercase_hex_is_format_error(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-256 " + "A" * 64)

    def test_wrong_len_is_format_error(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-256 " + "0" * 63)

    def test_unknown_tag_rejected(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-512 " + "0" * 128)

    def test_no_space_rejected(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-256" + "0" * 64)

    def test_tab_separator_rejected(self):
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA, "sha-256\t" + "0" * 64)


class TestVerifyValue:
    def test_match_ok(self):
        header = build_digest_header(RSA, b"real-body")
        verify_digest_header(RSA, header, b"real-body")

    def test_sm3_match_ok(self):
        header = build_digest_header(SM, b"sm-body")
        verify_digest_header(SM, header, b"sm-body")

    def test_mismatch_raises_integrity(self):  # spec:10.2 完整性类
        header = build_digest_header(RSA, b"real-body")
        with pytest.raises(DigestMismatchError):
            verify_digest_header(RSA, header, b"tampered-body")
