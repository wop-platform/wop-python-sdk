# -*- coding: utf-8 -*-
"""canonicalRequest 构造测试（F2）：断言逐条移植网关 CanonicalRequestBuilderTest（Java），
保证跨语言零漂移。"""
from wop_sdk.canonical import build_canonical, canonical_headers


class TestCanonicalHeaders:
    def test_lowercase_sort_and_encode(self):  # spec:F2 对照 Java canonicalHeaders_shouldLowercaseSortAndEncode
        headers = {
            "X-Wop-Timestamp": "1774340000000",
            "My-Header1": "   a   b   c  ",
            "X-Wop-Appkey": "app_10012481831",
        }
        assert canonical_headers(headers) == (
            "my-header1:a%20b%20c\nx-wop-appkey:app_10012481831\nx-wop-timestamp:1774340000000"
        )

    def test_empty_and_none(self):  # 对照 Java canonicalHeaders_emptyInput_shouldReturnEmpty
        assert canonical_headers({}) == ""
        assert canonical_headers(None) == ""

    def test_trailing_newline_absent(self):
        assert not canonical_headers({"a": "1"}).endswith("\n")

    def test_name_and_value_both_trimall_encoded(self):
        # header 值含 ; = 与空格（x-wop-encrypt 场景）
        assert canonical_headers({"x-wop-encrypt": "L2;dek=abc def"}) == "x-wop-encrypt:L2%3Bdek%3Dabc%20def"

    def test_name_whitespace_collapsed_before_lower(self):
        assert canonical_headers({"  X-Wop  -  Appkey ": "v"}) == "x-wop%20-%20appkey:v"


class TestBuildCanonical:
    def test_five_segments(self):  # spec:F2 对照 Java build_shouldProduceFiveSegments
        canonical = build_canonical(
            "v1/1800", "post", "/gateway/logistics.order.query", "", "x-wop-appkey:app_1"
        )
        assert canonical == "v1/1800\nPOST\n/gateway/logistics.order.query\n\nx-wop-appkey:app_1"
        assert len(canonical.split("\n")) == 5

    def test_post_empty_query_keeps_blank_line(self):  # 分隔空行不可省略
        assert "\n\n" in build_canonical("v1/1", "POST", "/p", "", "")

    def test_null_segments_become_empty(self):  # 对照 Java build_nullSegments_shouldBeEmptyStrings
        assert build_canonical(None, None, None, None, None) == "\n\n\n\n"

    def test_method_uppercased(self):
        assert build_canonical("a", "get", "/p", "", "").split("\n")[1] == "GET"
