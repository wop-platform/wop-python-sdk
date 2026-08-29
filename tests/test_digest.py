# -*- coding: utf-8 -*-
"""摘要测试：D2 格式钉（恰一空格/小写 hex/跨族拒绝/长度）、向量字节级、formatRules 全套。"""
import pytest

import conftest
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
    """formatRules 三件套消费（spec:A2/F8）：循环全量 + 未知 id 哨兵 + 条数哨兵。

    本类消费 header-* 子集（check_digest_header 格式层：accept = 格式层接受；
    reject = 拒绝）；b64url-* 子集由 test_encoding.py 消费（b64url_decode）。
    """

    def test_sentinels(self, vectors):  # spec:A2 条数哨兵 + 未知 id 哨兵
        rules = vectors["formatRules"]
        assert len(rules) == conftest.FORMAT_RULES_COUNT  # 真源向量增删即炸
        ids = {r["id"] for r in rules}
        assert ids == conftest.ALL_FORMAT_RULE_IDS  # 新增 id 未显式接入即炸

    def test_header_rules_full_loop(self, vectors):  # spec:A2 全量循环
        seen = set()
        for rule in vectors["formatRules"]:  # 循环真源全量，禁止按 id 点名消费
            if rule["id"] not in conftest.HEADER_RULE_IDS:
                continue
            seen.add(rule["id"])
            suite = parse_suite(rule.get("suite", "WOP-RSA3072-SHA256"))
            if rule["expect"] == "accept":
                check_digest_header(suite, rule["value"])  # 正向断言：格式层通过
            else:
                with pytest.raises((ProtocolFormatError, UnsupportedSuiteError)):
                    check_digest_header(suite, rule["value"])
        assert seen == conftest.HEADER_RULE_IDS  # 子集完备：header-* 一条不漏

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
