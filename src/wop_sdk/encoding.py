# -*- coding: utf-8 -*-
"""线上编码工具：base64url 严格无填充（F7/D10）、小写 hex（F5）、Java URLEncoder 语义（F2）。

严格模式参照 crypto-strategy-spec §3.4：服务端拒收带 '=' 的输入；
canonicalRequest 的 header 值编码语义对照网关 CanonicalRequestBuilder（Java）。
"""
import base64
import re
from typing import Optional

_B64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]+$")

# Java URLEncoder 的保留集：字母数字与 . - * _（空格单独处理为 %20）
_SAFE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._*-"
)


def b64url_encode(data: bytes) -> str:
    """字节 → base64url 无填充字符串。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """base64url 无填充字符串 → 字节。

    严格模式（F7/D10）：
    - 拒绝空串；
    - 拒绝 '=' 填充字符；
    - 拒绝字母表外字符（含 '+' '/' 空白等）；
    - 拒绝长度 % 4 == 1（不可能的 base64 长度）。
    """
    if not text:
        raise ValueError("base64url 输入为空")
    if "=" in text:
        raise ValueError("base64url 严格模式：拒绝 '=' 填充")
    if not _B64URL_ALPHABET.match(text):
        raise ValueError("base64url 字母表外字符")
    if len(text) % 4 == 1:
        raise ValueError("base64url 长度非法（% 4 == 1）")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hex_lower(data: bytes) -> str:
    """字节 → 小写 hex（F5/D10）。"""
    return data.hex()


def java_urlencode(text: Optional[str]) -> str:
    """Java URLEncoder.encode(text, UTF-8) 语义（F2）。

    - 保留集：字母数字与 . - * _；
    - 空格 → %20（Java 输出 '+' 后替换，等价结果）；
    - 其余字符按 UTF-8 字节逐字节 %XX（大写十六进制）；
    - None / 空串 → ""。
    """
    if text is None or text == "":
        return ""
    out = []
    for ch in text:
        if ch in _SAFE_CHARS:
            out.append(ch)
        elif ch == " ":
            out.append("%20")
        else:
            out.append("".join("%%%02X" % b for b in ch.encode("utf-8")))
    return "".join(out)


def trimall(text: Optional[str]) -> str:
    """去首尾空白，连续空白折叠为单个空格（F2，对照 CanonicalRequestBuilder.trimall）。"""
    if text is None:
        return ""
    return re.sub(r"\s+", " ", text.strip())
