# -*- coding: utf-8 -*-
"""编码层测试：base64url 严格无填充（F7/F6）、小写 hex（F5）、Java URLEncoder 语义（F2）。"""
import pytest

import conftest
from wop_sdk.encoding import b64url_decode, b64url_encode, hex_lower, java_urlencode, trimall


class TestB64urlStrict:
    """spec F7/D10：base64url 无填充，严格模式拒收 '=' 与字母表外字符。"""

    def test_roundtrip_arbitrary_bytes(self):
        for n in range(1, 70):
            data = bytes(range(n))
            assert b64url_decode(b64url_encode(data)) == data

    def test_encode_has_no_padding(self):
        # 2 字节 → 3 字符（无 '='）；3 字节 → 4 字符（整除不产生 '='）
        assert b64url_encode(b"\x01\x02") == "AQI"

    def test_encode_uses_url_alphabet(self):
        # 0xFB 0xFF 0xBF → 标准字母表出 "+/+"/，URL 字母表必须是 "-_-_"
        assert b64url_encode(b"\xfb\xff\xbf") == "-_-_"

    def test_reject_standard_alphabet_slash(self):
        with pytest.raises(ValueError):
            b64url_decode("ab/c")

    def test_reject_illegal_len_mod4_eq1(self):
        with pytest.raises(ValueError):
            b64url_decode("abcde")  # len % 4 == 1 不可能是合法无填充 base64

    def test_reject_non_alphabet_chars(self):
        with pytest.raises(ValueError):
            b64url_decode("ab cd")
        with pytest.raises(ValueError):
            b64url_decode("ab!cd")

    def test_reject_empty(self):
        with pytest.raises(ValueError):
            b64url_decode("")


class TestHexLower:
    """spec F5/D10：hex 统一小写。"""

    def test_lowercase(self):
        assert hex_lower(bytes.fromhex("00FF10")) == "00ff10"


class TestJavaUrlEncode:
    """spec F2：header 值 Java-URLEncoder 语义（对照网关 CanonicalRequestBuilderTest）。"""

    def test_space_becomes_pct20(self):  # spec:F2 空格→%20 而非 '+'
        assert java_urlencode("a b") == "a%20b"

    def test_plus_and_colon(self):
        assert java_urlencode("2026-08-18T15:30:00+08:00") == "2026-08-18T15%3A30%3A00%2B08%3A00"

    def test_semicolon_and_equals(self):  # spec:F2 x-wop-encrypt 值场景
        assert java_urlencode("L2;dek=abc") == "L2%3Bdek%3Dabc"

    def test_safe_chars_kept(self):
        # Java URLEncoder 保留集：字母数字与 . - * _
        assert java_urlencode("aZ09._*-") == "aZ09._*-"

    def test_rfc3986_extras_encoded(self):
        # Java URLEncoder 对 ! ~ ' ( ) 编码（区别于 JS encodeURIComponent）
        assert java_urlencode("!'()~") == "%21%27%28%29%7E"

    def test_multibyte_utf8_uppercase_hex(self):
        assert java_urlencode("值") == "%E5%80%BC"
        assert java_urlencode("—") == "%E2%80%94"

    def test_empty_and_none(self):
        assert java_urlencode("") == ""
        assert java_urlencode(None) == ""


class TestTrimall:
    """spec F2：去首尾空白，连续空白折叠为单个空格（对照 CanonicalRequestBuilder.trimall）。"""

    def test_collapse(self):
        assert trimall("   a   b   c  ") == "a b c"

    def test_quotes_kept(self):
        assert trimall('  "a   b   c"  ') == '"a b c"'

    def test_none(self):
        assert trimall(None) == ""

    def test_tabs_newlines_collapse(self):
        assert trimall("a\t\n b") == "a b"


class TestFormatRulesB64url:
    """formatRules b64url 子集三件套消费（spec:A2/F7/D10）：
    循环全量 + 未知 id 哨兵 + 条数哨兵；语义锚 = Go base64.RawURLEncoding.Strict()
    （RFC 4648 §3.5 尾随位 canonical）。header-* 子集由 test_digest.py 消费。
    """

    # accept 向量的正向字节断言（真源 note 标注的解码结果）
    _ACCEPT_BYTES = {
        "b64url-trailing-bits-canonical-2": b"\x00",  # AA → 1 字节 0x00
        "b64url-trailing-bits-canonical-3": b"Ma",  # TWE → 2 字节 0x4D 0x61
    }

    def test_sentinels(self, vectors):  # spec:A2 条数哨兵 + 未知 id 哨兵
        rules = vectors["formatRules"]
        assert len(rules) == conftest.FORMAT_RULES_COUNT  # 真源向量增删即炸
        ids = {r["id"] for r in rules}
        assert ids == conftest.ALL_FORMAT_RULE_IDS  # 新增 id 未显式接入即炸

    def test_b64url_rules_full_loop(self, vectors):  # spec:A2 全量循环
        seen = set()
        for rule in vectors["formatRules"]:  # 循环真源全量，禁止按 id 点名消费
            if rule["id"] not in conftest.B64URL_RULE_IDS:
                continue
            seen.add(rule["id"])
            if rule["expect"] == "accept":
                assert b64url_decode(rule["value"]) == self._ACCEPT_BYTES[rule["id"]]
            else:
                with pytest.raises(ValueError):
                    b64url_decode(rule["value"])
        assert seen == conftest.B64URL_RULE_IDS  # 子集完备：b64url-* 一条不漏
