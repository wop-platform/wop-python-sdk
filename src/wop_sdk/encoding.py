# -*- coding: utf-8 -*-
"""线上编码工具：base64url 严格无填充（F7/D10）、小写 hex（F5）、Java URLEncoder 语义（F2）。

严格模式参照 crypto-strategy-spec §3.4：服务端拒收带 '=' 的输入；
canonicalRequest 的 header 值编码语义对照网关 CanonicalRequestBuilder（Java）。
"""
import base64
import re
from typing import Optional

_B64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]+$")

# b64url 字符 → 6bit 索引（RFC 4648 §4 字母表：A-Z=0-25, a-z=26-51, 0-9=52-61, '-'=62, '_'=63）
_B64URL_INDEX = {
    ch: i
    for i, ch in enumerate(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
}

# Java URLEncoder 的保留集：字母数字与 . - * _（空格单独处理为 %20）
_SAFE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._*-"
)


def b64url_encode(data: bytes) -> str:
    """字节 → base64url 无填充字符串。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """base64url 无填充字符串 → 字节。

    严格模式（F7/D10，语义锚 = Go base64.RawURLEncoding.Strict()，RFC 4648 §3.5）：
    - 拒绝空串；
    - 拒绝 '=' 填充字符；
    - 拒绝字母表外字符（含 '+' '/' 空白等）；
    - 拒绝长度 % 4 == 1（不可能的 base64 长度）；
    - 拒绝非 canonical 尾随位：len % 4 == 2 时尾字符低 4 位须为零，
      len % 4 == 3 时尾字符低 2 位须为零（宽容解码会静默丢位，须显式拒绝）。
    """
    if not text:
        raise ValueError("base64url 输入为空")
    if "=" in text:
        raise ValueError("base64url 严格模式：拒绝 '=' 填充")
    if not _B64URL_ALPHABET.match(text):
        raise ValueError("base64url 字母表外字符")
    rem = len(text) % 4
    if rem == 1:
        raise ValueError("base64url 长度非法（% 4 == 1）")
    # RFC 4648 §3.5：尾字符低位是"丢弃位"，非零即非 canonical 编码
    if rem == 2 and _B64URL_INDEX[text[-1]] & 0xF:
        raise ValueError("base64url 尾随位非 canonical（len % 4 == 2，尾字符低 4 位须为零）")
    if rem == 3 and _B64URL_INDEX[text[-1]] & 0x3:
        raise ValueError("base64url 尾随位非 canonical（len % 4 == 3，尾字符低 2 位须为零）")
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
