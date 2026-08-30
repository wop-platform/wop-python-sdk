# -*- coding: utf-8 -*-
"""WopClient：协议核心编排（spec §2 概念 API 的 Python 映射）。

- build_request：组装协议头 + 签名 + 可选 L2 信封 → RequestDraft（零网络 IO）；
- verify_response / verify_callback：F6 固定顺序（结构前置校验 → 验签 → digest 复核 →
  DEK 解包 → alg 族比对 → bulk 解密），失败统一 VerifyResult(ok=False, reason, error)，
  验签/解密类 reason 模糊（I7），格式/完整性/一致性类 reason 明确（10.2）。
"""
import json
import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from .canonical import build_canonical, canonical_headers
from .digest import build_digest_header, verify_digest_header
from .encoding import b64url_encode
from .envelope import open_l2, seal_l2
from .errors import (
    DecryptError,
    DekConsistencyError,
    DigestMismatchError,
    ProtocolFormatError,
    SignatureVerifyError,
    SuiteParseError,
    UnsupportedSuiteError,
    WopSdkError,
)
from .keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    load_sm2_private_key,
    load_sm2_public_key,
)
from .signature import sign, verify
from .sm2crypto import Sm2Ops, sm2_derive_public_hex
from .suites import Suite, parse_suite

Csprng = Callable[[int], bytes]

_LEVELS = ("L0", "L2")
_DEK_PREFIX = "L2;dek="


def _now_ms() -> int:
    """毫秒时间戳（F9）；独立函数便于测试冻结。"""
    return int(time.time() * 1000)


@dataclass(frozen=True)
class WopConfig:
    """商户接入配置（密钥为材料串：PEM 或 Base64 单行，D12）。"""

    app_key: str
    suite: str
    merchant_private_key: str
    platform_public_key: str
    gateway_base_url: Optional[str] = None


@dataclass
class RequestDraft:
    """出向请求草稿：headers + wireBody，商户可直接交给任意 HTTP 栈。"""

    method: str
    path: str
    headers: Dict[str, str]
    wire_body: Optional[bytes]
    level: str


@dataclass
class VerifyResult:
    """响应/回调校验结果；reason 对验签/解密类模糊（I7）。

    error 携带原始分类异常（WopSdkError 子类，仅失败时非 None），
    供消费方按 10.2 错误分类编程处理（对齐 Go VerifyResult.Code）。
    """

    ok: bool
    plaintext: Optional[bytes] = None
    reason: Optional[str] = None
    error: Optional[WopSdkError] = None


class WopClient:
    """协议核心客户端（纯函数式产出，无连接状态）。"""

    def __init__(self, config: WopConfig, csprng: Csprng = os.urandom):
        if not config.app_key or not config.app_key.strip():
            raise WopSdkError("appKey 不能为空")
        self._config = config
        self._suite = parse_suite(config.suite)
        if self._suite.family == "RSA":
            self._signer = load_rsa_private_key(
                config.merchant_private_key, self._suite.key_bits
            )
            self._wrap_pub = load_rsa_public_key(
                config.platform_public_key, self._suite.key_bits
            )
        else:
            d = load_sm2_private_key(config.merchant_private_key)
            merchant_pub_hex = sm2_derive_public_hex(d.hex())
            self._signer = Sm2Ops(private_key_hex=d.hex(), public_xy_hex=merchant_pub_hex)
            platform_pub = load_sm2_public_key(config.platform_public_key)
            self._wrap_pub = Sm2Ops(public_xy_hex=platform_pub.xy_hex)
        self._csprng = csprng

    @property
    def suite(self) -> Suite:
        return self._suite

    # ---------- 出向 ----------

    def build_request(
        self,
        method: str,
        path: str,
        body: Optional[object] = None,
        *,
        level: str = "L0",
        query_string: str = "",
        expired_seconds: int = 1800,
        extra_headers: Optional[Dict[str, str]] = None,
        timestamp_ms: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> RequestDraft:
        """构造请求（F9）：协议头组装 → L2 可选封装 → canonicalRequest → 签名。

        timestamp_ms / nonce 为确定性钩子（重放/联调用；镜像 Go WithTimestamp/
        WithNonce）。随机流消费顺序合同（wop-specs/interop/v1）：
        [16B nonce 池][CEK][12B IV][k…]——nonce 注入时跳过 nonce 池段。
        """
        if level not in _LEVELS:
            raise ValueError("level 必须为 L0 或 L2，实际 %r" % level)
        safe_method = method.strip().upper()
        # spec:interop-v1 随机流消费顺序：nonce 池最前，先于 seal_l2 的 CEK/IV
        if not nonce:
            nonce = self._csprng(16).hex()  # F9：CSPRNG nonce
        wire: Optional[bytes] = None
        encrypt_header: Optional[str] = None
        if level == "L2":
            wire, encrypt_header = seal_l2(
                self._suite, self._wrap_pub, self._normalize_body(body), self._csprng
            )
        elif body is not None:
            wire = self._normalize_body(body)

        headers: Dict[str, str] = {
            "x-wop-appkey": self._config.app_key,
            "x-wop-timestamp": str(_now_ms() if timestamp_ms is None else int(timestamp_ms)),
            "x-wop-nonce": nonce,
        }
        if wire is not None:
            # D2：有 body 必产 digest；I1：digest 必入 signedHeaders（下方签名集合即全部头）
            headers["x-wop-content-digest"] = build_digest_header(self._suite, wire)
        if encrypt_header is not None:
            headers["x-wop-encrypt"] = encrypt_header

        app_headers: Dict[str, str] = {}
        for name, value in (extra_headers or {}).items():
            low = name.strip().lower()
            if low.startswith("x-wop-"):
                headers[low] = str(value).strip()
            else:
                app_headers[low] = str(value).strip()

        auth = "v1/%d" % expired_seconds
        canonical = build_canonical(
            auth, safe_method, path, query_string or "", canonical_headers(headers)
        )
        sig = sign(self._suite, self._signer, canonical.encode("utf-8"), csprng=self._csprng)
        headers["x-wop-sign"] = (
            f'{self._suite.security_req} {auth}/{";".join(sorted(iter(headers)))}/{b64url_encode(sig)}'
        )
        out: Dict[str, str] = dict(headers)
        if wire is not None:
            out.setdefault("content-type", "application/json")
        out |= app_headers
        return RequestDraft(safe_method, path, out, wire, level)

    @staticmethod
    def _normalize_body(body: Optional[object]) -> bytes:
        if body is None:
            raise ValueError("L2 封装需要明文 body")
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode("utf-8")
        if isinstance(body, dict):
            return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        raise TypeError("body 仅接受 bytes/str/dict，实际 %r" % type(body).__name__)

    # ---------- 入向 ----------

    def verify_response(
        self,
        headers: Dict[str, str],
        body: bytes,
        path: str,
        method: str = "POST",
        query_string: str = "",
    ) -> VerifyResult:
        """校验平台响应（F6 顺序固定）。path/query_string = 触发本次请求的 URI。"""
        lower = {str(k).lower().strip(): str(v).strip() for k, v in (headers or {}).items()}
        try:
            return self._verify_flow(lower, body, path, method.upper(), query_string or "")
        except (SignatureVerifyError, DecryptError, ProtocolFormatError, DigestMismatchError,
                DekConsistencyError, UnsupportedSuiteError, SuiteParseError) as exc:
            return VerifyResult(ok=False, reason=str(exc), error=exc)

    def verify_callback(
        self, headers: Dict[str, str], body: bytes, callback_path: str
    ) -> VerifyResult:
        """校验平台回调（URI 取回调 path，方法恒 POST）。"""
        return self.verify_response(headers, body, callback_path, method="POST")

    def _verify_flow(
        self, lower: Dict[str, str], body: bytes, path: str, method: str, query_string: str
    ) -> VerifyResult:
        sign_header = lower.get("x-wop-sign")
        if not sign_header:
            raise ProtocolFormatError("x-wop-sign 头缺席")
        suite_part, sep, rest = sign_header.partition(" ")
        if not suite_part or not sep or not rest:
            raise ProtocolFormatError("x-wop-sign 应为 '<securityReq> <authString>/<signedHeaders>/<signature>'")
        segs = rest.split("/")
        if len(segs) != 4:
            raise ProtocolFormatError(
                "x-wop-sign 应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature> 四段"
            )
        version, _expired, signed_names, sig_b64u = segs
        if version != "v1":
            raise ProtocolFormatError("不支持的协议版本：%r" % version)
        req_suite = parse_suite(suite_part)  # 解析类/支持类错误明确
        if req_suite.security_req != self._suite.security_req:
            raise UnsupportedSuiteError(
                f"响应声明套件 {suite_part} 与商户配置 {self._suite.security_req} 不符"
            )
        # F6 ①前置结构校验（公开协议知识，明确拒绝，先于验签；spec:interop-v1 n09/n10/n15）：
        # D2 有 body 必传 digest；I1 digest 必入 signedHeaders；无 body 不得携带 digest。
        digest_header = lower.get("x-wop-content-digest")
        if body:
            if digest_header is None:
                raise DigestMismatchError("有响应体但缺少 x-wop-content-digest")
            if "x-wop-content-digest" not in signed_names.split(";"):
                raise ProtocolFormatError("x-wop-content-digest 未列入 signedHeaders（I1）")
        elif digest_header is not None:
            raise ProtocolFormatError("无响应体不应携带 x-wop-content-digest")
        sig = _strict_decode_signature(sig_b64u)
        auth = f"{version}/{_expired}"
        signed: Dict[str, str] = {}
        for name in signed_names.split(";"):
            if name not in lower:
                raise ProtocolFormatError(f"签名声明的头在响应中缺席：{name}")
            signed[name] = lower[name]
        canonical = build_canonical(auth, method, path, query_string, canonical_headers(signed))
        # F6 ②先验签（I2：先验签后解密）
        verify(req_suite, self._wrap_pub, canonical.encode("utf-8"), sig)
        # F6 ③digest 复核（D2：有 body 必传；对象 = wire 原始字节）
        if body:
            verify_digest_header(self._suite, lower.get("x-wop-content-digest"), body)
        enc = lower.get("x-wop-encrypt")
        if enc is None:
            return VerifyResult(ok=True, plaintext=body)  # L0
        # F6 ④⑤⑥ DEK 解包 → alg 族比对 → bulk 解密（envelope.open_l2 内序）
        if not enc.startswith(_DEK_PREFIX):
            raise ProtocolFormatError(f"x-wop-encrypt 头格式错误：应为 {_DEK_PREFIX}<base64url>")
        plaintext = open_l2(self._suite, self._signer, body, enc[len(_DEK_PREFIX):])
        return VerifyResult(ok=True, plaintext=plaintext)


def _strict_decode_signature(sig_b64u: str) -> bytes:
    """签名严格解码（F7：拒 '=' / 字母表外字符）；失败归解析类。"""
    from .encoding import b64url_decode

    try:
        return b64url_decode(sig_b64u)
    except ValueError as exc:
        raise ProtocolFormatError(f"签名编码非法：{exc}") from exc
