# -*- coding: utf-8 -*-
"""Gherkin 场景步骤（pytest-bdd）：docs/scenario-analysis.md S1-S10 的验收级回归。

D5 纪律（入向测试的平台侧构造，禁止复用被测出向路径）：
- RSA L0/L2：cryptography 原语独立组装（PKCS1v15 签名 / AESGCM / OAEP 双 SHA-256 空 label），
  canonical 五段、digest、b64url 均在本文件手写，不经 wop_sdk 出向代码；
- SM2 L2：信封以 wop_sdk.sm2crypto/sm4gcm 底层原语手工组装（不经 seal_l2 组合层；
  原语已被黄金向量字节级锚定），签名/摘要直接调 gmssl（不经 wop_sdk 包装）。
"""
import base64
import hashlib
import json
import os
import re

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)
from gmssl import sm3 as _sm3
from gmssl.sm2 import CryptSM2
from pytest_bdd import given, parsers, scenarios, then, when

import wop_sdk.client as client_mod
from wop_sdk.client import WopClient, WopConfig
from wop_sdk.errors import (
    ConfigurationError,
    DecryptError,
    DigestMismatchError,
    ProtocolFormatError,
    SignatureVerifyError,
    SuiteParseError,
    UnsupportedSuiteError,
)
from wop_sdk.sm2crypto import Sm2Ops, sm2_encrypt
from wop_sdk.sm4gcm import sm4_gcm_encrypt

scenarios("features/wop_merchant.feature")

RSA_REQ = "WOP-RSA3072-SHA256"
SM_REQ = "WOP-SM2-SM3"
PATH = "/gateway/order.create"
CALLBACK_PATH = "/callback/notify"
FROZEN_MS = 1774340000000

# 命名业务报文（场景矩阵 S2/S5/S6/S7）
ORDER = {"orderId": 1}
ORDER_RESULT = {"code": "OK", "orderId": 1}
SECRET = {"data": "secret-value-42"}
CALLBACK = {"event": "paid", "amount": 100}
SM_SECRET = {"sm": True, "payload": "国密信封"}


def _enc(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# ---------- 平台侧独立构造（D5：不 import wop_sdk 出向路径） ----------

def _quote(s: str) -> str:
    """Java URLEncoder 语义（F2）：字母数字与 .-*_ 保留，空格→%20，其余 %XX 大写。"""
    from urllib.parse import quote

    return quote(s, safe=".*-")


def _independent_canonical(headers, method, path) -> str:
    lines = [f"{_quote(k)}:{_quote(v)}" for k, v in sorted(headers.items())]
    return "\n".join(["v1/1800", method, path, "", "\n".join(lines)])


def _platform_sign_rsa(headers, method, path, vec, suite_req=RSA_REQ):
    priv = load_der_private_key(base64.b64decode(vec["rsa3072"]["privatePkcs8B64"]), None)
    canonical = _independent_canonical(headers, method, path).encode("utf-8")
    sig = priv.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    headers["x-wop-sign"] = (
        f'{suite_req} v1/1800/{";".join(sorted(headers))}/{_b64u(sig)}'
    )
    return headers


def _base_headers() -> dict:
    return {
        "x-wop-appkey": "app_10012481831",
        "x-wop-timestamp": str(FROZEN_MS),
        "x-wop-nonce": "cd" * 16,
    }


def _platform_l0(vec, path, payload, *, with_digest=True, digest_of=None):
    body = _enc(payload)
    h = _base_headers()
    if with_digest and body:
        target = body if digest_of is None else digest_of
        h["x-wop-content-digest"] = f"sha-256 {hashlib.sha256(target).hexdigest()}"
    _platform_sign_rsa(h, "POST", path, vec)
    return h, body


def _platform_l2_rsa(vec, path, plaintext, *, wrong_key=False):
    key, other, iv = b"\x11" * 32, b"\x22" * 32, b"\x33" * 12
    cipher_key = other if wrong_key else key
    ct_tag = AESGCM(cipher_key).encrypt(iv, plaintext, b"")  # cryptography 原语（非 SDK Cipher 路径）
    wire = json.dumps({"encrypted": _b64u(ct_tag)}, separators=(",", ":")).encode("utf-8")
    dek = f"AES-256-GCM${_b64u(key)}${_b64u(iv)}"
    pub = load_der_public_key(base64.b64decode(vec["rsa3072"]["publicSpkiB64"]))
    wrapped = pub.encrypt(
        dek.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    h = _base_headers()
    h["x-wop-content-digest"] = f"sha-256 {hashlib.sha256(wire).hexdigest()}"
    h["x-wop-encrypt"] = f"L2;dek={_b64u(wrapped)}"
    _platform_sign_rsa(h, "POST", path, vec)
    return h, wire


def _platform_l2_sm2(vec, path, plaintext):
    d = base64.b64decode(vec["sm2"]["privateDB64"])
    d_hex = d.hex()
    g = CryptSM2(d_hex, "00" * 128)
    merchant_pub_xy = g._kg(int.from_bytes(d, "big"), g.ecc_table["g"])  # gmssl 直推公钥
    # ZA 摘要依赖公钥：覆写为平台密钥对公钥（绕过 gmssl __init__ 的 lstrip 缺陷，同 Sm2Ops 注释）
    g.public_key = merchant_pub_xy
    key, iv = b"\x44" * 16, b"\x55" * 12
    ct_tag = sm4_gcm_encrypt(key, iv, plaintext)  # 底层原语（黄金向量锚定）
    wire = json.dumps({"encrypted": _b64u(ct_tag)}, separators=(",", ":")).encode("utf-8")
    dek = f"SM4-GCM${_b64u(key)}${_b64u(iv)}"
    wrapped = sm2_encrypt(Sm2Ops(public_xy_hex=merchant_pub_xy), lambda n: b"\x66" * n, dek.encode())
    h = _base_headers()
    h["x-wop-content-digest"] = f"sm3 {_sm3.sm3_hash(list(wire))}"
    h["x-wop-encrypt"] = f"L2;dek={_b64u(wrapped)}"
    canonical = _independent_canonical(h, "POST", path)
    # spec:D15 平台按平台固定 ZA userId 签名（入向身份；D14 的 appKey 仅限商户出向签名）——
    # 独立手拼 ENTL‖ID‖a‖b‖g‖pub（不经 wop_sdk.sm2crypto 包装，D5 纪律不变）
    uid = b"1234567812345678"
    entl = format(len(uid) * 8, "04x")
    z = entl + uid.hex() + g.ecc_table["a"] + g.ecc_table["b"] + g.ecc_table["g"] + g.public_key
    za = _sm3.sm3_hash(list(bytes.fromhex(z)))
    e_hex = _sm3.sm3_hash(list(bytes.fromhex(za + canonical.encode("utf-8").hex())))
    sig_hex = g.sign(bytes.fromhex(e_hex), "%064x" % int.from_bytes(b"\x77" * 32, "big"))
    h["x-wop-sign"] = (
        f'{SM_REQ} v1/1800/{";".join(sorted(h))}/{_b64u(bytes.fromhex(sig_hex))}'
    )
    return h, wire


# ---------- 公共 fixture ----------

class Ctx:
    pass


@pytest.fixture
def ctx():
    return Ctx()


@pytest.fixture(autouse=True)
def _freeze_time(monkeypatch):
    monkeypatch.setattr(client_mod, "_now_ms", lambda: FROZEN_MS)


def _rsa_client(vec_keys):
    return WopClient(
        WopConfig(
            app_key="app_10012481831",
            suite=RSA_REQ,
            merchant_private_key=vec_keys["rsa3072"]["privatePkcs8B64"],
            platform_public_key=vec_keys["rsa3072"]["publicSpkiB64"],
        ),
        csprng=lambda n: b"\x5a" * n,
    )


def _sm_client(vec_keys):
    return WopClient(
        WopConfig(
            app_key="app_sm_001",
            suite=SM_REQ,
            merchant_private_key=vec_keys["sm2"]["privateDB64"],
            platform_public_key=vec_keys["sm2"]["publicPointB64"],
        ),
        csprng=lambda n: b"\x77" * n,
    )


# ---------- Given ----------

@given("商户使用黄金向量 RSA3072 密钥完成套件配置")
def rsa_setup(ctx, vectors):
    ctx.vec = vectors["keys"]
    ctx.client = _rsa_client(ctx.vec)


@given("商户使用黄金向量 SM2 密钥完成套件配置")
def sm_setup(ctx, vectors):
    ctx.vec = vectors["keys"]
    ctx.client = _sm_client(ctx.vec)


@given("平台独立返回 L0 下单结果响应")
def platform_l0(ctx):
    ctx.headers, ctx.body = _platform_l0(ctx.vec, PATH, ORDER_RESULT)
    ctx.expected_plain = _enc(ORDER_RESULT)


@given("平台独立返回缺少 digest 的响应")
def platform_l0_no_digest(ctx):
    h, body = _platform_l0(ctx.vec, PATH, ORDER_RESULT, with_digest=False)
    ctx.headers, ctx.body = h, body


@given("平台独立返回空响应体但携带 digest 的响应")
def platform_l0_empty_body_with_digest(ctx):
    h, _ = _platform_l0(ctx.vec, PATH, ORDER_RESULT)
    h.pop("x-wop-sign")
    _platform_sign_rsa(h, "POST", PATH, ctx.vec)
    ctx.headers, ctx.body = h, b""


@given("平台独立返回缺少 x-wop-sign 的响应")
def platform_l0_no_sign(ctx):
    h, body = _platform_l0(ctx.vec, PATH, ORDER_RESULT)
    h.pop("x-wop-sign")
    ctx.headers, ctx.body = h, body


@given("平台独立返回 L2 机密响应")
def platform_l2(ctx):
    ctx.headers, ctx.body = _platform_l2_rsa(ctx.vec, PATH, _enc(SECRET))
    ctx.expected_plain = _enc(SECRET)


@given("平台独立发送支付回调")
def platform_callback(ctx):
    ctx.headers, ctx.body = _platform_l0(ctx.vec, CALLBACK_PATH, CALLBACK)
    ctx.expected_plain = _enc(CALLBACK)


@given("平台以底层原语返回国密 L2 响应")
def platform_sm2_l2(ctx):
    ctx.headers, ctx.body = _platform_l2_sm2(ctx.vec, PATH, _enc(SM_SECRET))
    ctx.expected_plain = _enc(SM_SECRET)


# ---------- When ----------

@when("商户发起 L0 下单请求")
def merchant_build_l0(ctx):
    ctx.draft = ctx.client.build_request("POST", PATH, ORDER)


@when("商户发起无 body 的 GET 查询请求")
def merchant_build_get(ctx):
    ctx.draft = ctx.client.build_request("GET", "/gateway/order.query")


@when("商户以真实随机源连续两次发起 L0 下单请求")
def merchant_build_l0_real_random(ctx):
    client = WopClient(
        WopConfig(
            app_key="app_10012481831",
            suite=RSA_REQ,
            merchant_private_key=ctx.vec["rsa3072"]["privatePkcs8B64"],
            platform_public_key=ctx.vec["rsa3072"]["publicSpkiB64"],
        )
    )  # 默认 csprng = os.urandom（F9）
    ctx.nonces = [
        client.build_request("POST", PATH, ORDER).headers["x-wop-nonce"]
        for _ in range(2)
    ]


@when("商户发起 L2 加密下单请求")
def merchant_build_l2(ctx):
    ctx.draft = ctx.client.build_request("POST", PATH, ORDER, level="L2")


@when("商户以相同时间戳与 nonce 重复构建 L2 请求")
def merchant_build_l2_twice(ctx):
    kw = dict(level="L2", timestamp_ms=FROZEN_MS, nonce="ab" * 16)
    ctx.drafts = [ctx.client.build_request("POST", PATH, ORDER, **kw) for _ in range(2)]


@when(parsers.parse("商户使用非法套件 {suite} 初始化客户端"))
def merchant_bad_suite(ctx, suite, vectors):
    vec = vectors["keys"]
    try:
        WopClient(
            WopConfig(
                app_key="app_x",
                suite=suite,
                merchant_private_key=vec["rsa3072"]["privatePkcs8B64"],
                platform_public_key=vec["rsa3072"]["publicSpkiB64"],
            )
        )
    except Exception as exc:  # noqa: BLE001 —— 步骤层捕获供 Then 断言分类
        ctx.error = exc


@when("商户以非法等级 L3 发起请求")
def merchant_bad_level(ctx):
    try:
        ctx.client.build_request("POST", PATH, ORDER, level="L3")
    except ConfigurationError as exc:
        ctx.error = exc


@when("商户校验平台响应")
def merchant_verify(ctx):
    ctx.result = ctx.client.verify_response(ctx.headers, ctx.body, PATH)


@when("商户校验平台回调")
def merchant_verify_callback(ctx):
    ctx.result = ctx.client.verify_callback(ctx.headers, ctx.body, CALLBACK_PATH)


@when("平台篡改响应签名")
def platform_tamper_sig(ctx):
    parts = ctx.headers["x-wop-sign"].split("/")
    sig = parts[3]
    parts[3] = ("B" if sig[0] != "B" else "A") + sig[1:]
    ctx.headers["x-wop-sign"] = "/".join(parts)


@when("平台以错误摘要重新签名响应")
def platform_tamper_digest(ctx):
    h, body = _platform_l0(ctx.vec, PATH, ORDER_RESULT, digest_of=b"other-bytes")
    ctx.headers, ctx.body = h, body


@when("平台在签名编码后追加填充符号")
def platform_tamper_padding(ctx):
    parts = ctx.headers["x-wop-sign"].split("/")
    parts[3] += "="  # F7：严格模式拒 '='
    ctx.headers["x-wop-sign"] = "/".join(parts)


@when("平台以 RSA4096 套件声明响应")
def platform_tamper_suite(ctx):
    h, body = _platform_l0(ctx.vec, PATH, ORDER_RESULT, )
    h.pop("x-wop-sign")
    _platform_sign_rsa(h, "POST", PATH, ctx.vec, suite_req="WOP-RSA4096-SHA256")
    ctx.headers, ctx.body = h, body
@when("平台以错误密钥重组 L2 密文")
def platform_tamper_l2(ctx):
    h, body = _platform_l2_rsa(ctx.vec, PATH, ctx.expected_plain, wrong_key=True)
    ctx.headers, ctx.body = h, body


# ---------- Then ----------

def _sign_names(draft):
    return draft.headers["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")


@then("协议头携带 appKey 与冻结时间戳与 32 位十六进制 nonce")
def then_protocol_headers(ctx):
    h = ctx.draft.headers
    assert h["x-wop-appkey"] == "app_10012481831"
    assert h["x-wop-timestamp"] == str(FROZEN_MS)
    assert re.fullmatch(r"[0-9a-f]{32}", h["x-wop-nonce"])


@then("digest 头为 sha-256 加 64 位小写 hex")
def then_digest_format(ctx):
    tag, hexval = ctx.draft.headers["x-wop-content-digest"].split(" ")
    assert tag == "sha-256"
    assert re.fullmatch(r"[0-9a-f]{64}", hexval)


@then("digest 头列入签名头")
def then_digest_signed(ctx):
    assert "x-wop-content-digest" in _sign_names(ctx.draft)


@then("签名头以 WOP-RSA3072-SHA256 v1/1800 开头")
def then_sign_prefix(ctx):
    assert ctx.draft.headers["x-wop-sign"].startswith(f"{RSA_REQ} v1/1800/")


@then("签名段为 512 字符 base64url")
def then_sig_len(ctx):
    seg = ctx.draft.headers["x-wop-sign"].split("/")[3]
    assert len(seg) == 512 and "=" not in seg


@then("协议头不含 digest 头")
def then_no_digest(ctx):
    assert "x-wop-content-digest" not in ctx.draft.headers


@then("签名头不含 digest 段")
def then_no_digest_signed(ctx):
    assert "x-wop-content-digest" not in _sign_names(ctx.draft)


@then("wire body 为空")
def then_wire_none(ctx):
    assert ctx.draft.wire_body is None


@then("两次构建的 nonce 不同")
def then_nonce_random(ctx):
    a, b = ctx.nonces
    assert a != b and re.fullmatch(r"[0-9a-f]{32}", a)


@then("协议头携带 x-wop-encrypt 头且以 L2 前缀开头")
def then_encrypt_header(ctx):
    assert ctx.draft.headers["x-wop-encrypt"].startswith("L2;dek=")


@then("wire body 为含 encrypted 字段的 JSON 信封")
def then_envelope_body(ctx):
    obj = json.loads(ctx.draft.wire_body)
    assert set(obj) == {"encrypted"} and obj["encrypted"]
    assert ctx.draft.headers["content-type"] == "application/json"


@then("两次草稿逐字节一致")
def then_deterministic(ctx):
    a, b = ctx.drafts
    assert a.headers == b.headers
    assert a.wire_body == b.wire_body


@then("抛出 SuiteParseError")
def then_suite_parse_error(ctx):
    assert isinstance(ctx.error, SuiteParseError)


@then("抛出 UnsupportedSuiteError")
def then_unsupported_suite_error(ctx):
    assert isinstance(ctx.error, UnsupportedSuiteError)


@then("错误信息包含跨族字样")
def then_cross_family_message(ctx):
    assert "跨族" in str(ctx.error)


@then("抛出 ConfigurationError")
def then_configuration_error(ctx):  # spec:2.2
    assert isinstance(ctx.error, ConfigurationError)


@then("校验通过且明文为下单结果报文")
def then_verify_l0_ok(ctx):
    assert ctx.result.ok and ctx.result.plaintext == ctx.expected_plain


@then("校验失败且原因为模糊的签名验证失败")
def then_blur_sig(ctx):
    assert not ctx.result.ok
    assert ctx.result.reason == "签名验证失败"  # I7：恒定文案，不泄原因细节


@then("错误类型为 SignatureVerifyError")
def then_err_sig(ctx):
    assert isinstance(ctx.result.error, SignatureVerifyError)


@then("校验失败且错误类型为 DigestMismatchError")
def then_err_digest(ctx):
    assert not ctx.result.ok
    assert isinstance(ctx.result.error, DigestMismatchError)


@then("校验失败且错误类型为 ProtocolFormatError")
def then_err_format(ctx):
    assert not ctx.result.ok
    assert isinstance(ctx.result.error, ProtocolFormatError)


@then("校验失败且错误类型为 UnsupportedSuiteError")
def then_err_unsupported(ctx):
    assert not ctx.result.ok
    assert isinstance(ctx.result.error, UnsupportedSuiteError)


@then("校验失败且原因为模糊的解密失败")
def then_blur_decrypt(ctx):
    assert not ctx.result.ok
    assert ctx.result.reason == "解密失败"  # I7：GCM tag/解包失败一律模糊


@then("错误类型为 DecryptError")
def then_err_decrypt(ctx):
    assert isinstance(ctx.result.error, DecryptError)


@then("校验通过且解密明文为机密报文")
def then_l2_ok(ctx):
    assert ctx.result.ok and ctx.result.plaintext == ctx.expected_plain


@then("校验通过且明文为支付通知报文")
def then_callback_ok(ctx):
    assert ctx.result.ok and ctx.result.plaintext == ctx.expected_plain


@then("校验通过且解密明文为国密机密报文")
def then_sm2_l2_ok(ctx):
    assert ctx.result.ok and ctx.result.plaintext == ctx.expected_plain
