# -*- coding: utf-8 -*-
"""编码层测试：base64url 严格无填充（F7/F6）、小写 hex（F5）、Java URLEncoder 语义（F2）。"""
import pytest

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
    def test_reject_padding_char(self):  # spec:F7 formatRules:b64url-with-padding
        with pytest.raises(ValueError):
            b64url_decode("abc=")

    def test_reject_standard_alphabet_plus(self):  # spec:F7 formatRules:b64url-illegal-char
        with pytest.raises(ValueError):
            b64url_decode("ab+c")

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
