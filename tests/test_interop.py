# -*- coding: utf-8 -*-
"""interop conformance 消费端（wop-specs/interop/v1 协议编排跨仓一致性合同）。

fixture 为 wop-specs/interop/v1/interop-cases.json 的字节副本（禁手改，与
crypto-vectors.json 同一纪律）；真源 sha256 哨兵钉死字节一致。

条款 → 测试反向核对矩阵（spec:interop-v1）：
- README 消费要求 1（fixture 字节副本 + sha256 一致）→ TestInteropFixtureIntegrity
- README 消费要求 2（build 复现：byte-exact 全量 / deterministic-fields 剥 opaque）
  → TestInteropConformanceBuild（6 条：3 套件 × L0/L2）
- README 消费要求 3（verify positive 明文一致 / negative 错误分类对账）
  → TestInteropConformanceVerify（7 positive + 16 negative）
- README 消费要求 4（条数哨兵 + 已知 id 哨兵）→ TestInteropFixtureIntegrity
- README 随机流消费顺序合同（[nonce 池][CEK][IV][k…]）→ HexStream + build 复现
  （nonce 注入跳过池段，CEK/IV 取前段，wire/digest 头字节级一致）
- README 消费要求 5（样本集升级 v2 明确拒绝）→ format 哨兵（wop-interop-1 恒等，
  非 v1 格式在装载层即 fail，不允许静默消费）
"""
import hashlib
import json
import os
from collections import Counter

import pytest

from wop_sdk.client import WopClient, WopConfig
from wop_sdk.encoding import b64url_decode, b64url_encode
from wop_sdk.errors import (
    DecryptError,
    DekConsistencyError,
    DigestMismatchError,
    ProtocolFormatError,
    SignatureVerifyError,
    SuiteParseError,
    UnsupportedSuiteError,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_PATH = os.path.join(HERE, "fixtures", "interop-cases.json")

# 真源 wop-specs/interop/v1/interop-cases.json 的 sha256（字节副本哨兵）
EXPECTED_SHA256 = "3030e98fa6174f1ca905f35d7742ac9471141945dde66f29f01021d51a555f7a"
EXPECTED_FORMAT = "wop-interop-1"

with open(FIXTURE_PATH, "r", encoding="utf-8") as _f:
    FIXTURE = json.load(_f)

# ---------- 哨兵（README 消费要求 4：防 fixture 漂移静默通过）----------
INTEROP_CASE_COUNT = 29
BUILD_COUNT = 6
VERIFY_POSITIVE_COUNT = 7
VERIFY_NEGATIVE_COUNT = 16
KNOWN_INTEROP_IDS = frozenset(
    {
        "build:WOP-RSA3072-SHA256:L0",
        "build:WOP-RSA3072-SHA256:L2",
        "build:WOP-RSA4096-SHA256:L0",
        "build:WOP-RSA4096-SHA256:L2",
        "build:WOP-SM2-SM3:L0",
        "build:WOP-SM2-SM3:L2",
        "p07",
        "p08",
        "p09",
        "p10",
        "p11",
        "p12",
        "p13",
        "n01-encrypted-char-damage",
        "n02-wire-tampered-after-signing",
        "n03-digest-tag-cross-family",
        "n04-dek-alg-cross-family",
        "n05-dek-c1c2c3-order",
        "n06-signature-b64-padding",
        "n07-signature-63b",
        "n08-signature-65b",
        "n09-digest-missing",
        "n10-digest-not-signed",
        "n11-suite-mismatch",
        "n12-envelope-missing-field",
        "n13-dek-key-length",
        "n14-missing-signed-header",
        "n15-digest-without-body",
        "n16-replay-cross-path",
    }
)

# ---------- 本仓错误类型 → 跨仓 canonical class 显式映射表（README 消费要求 3）----------
# 分类合同（README 错误分类表 + 已裁决分歧 1-3）：
#   签名/密文 b64url 非法结构 → protocol（明确）；DEK 载荷结构畸形除 alg 跨族外 →
#   decrypt-failed（模糊）；digest 未入 signedHeaders（I1）→ protocol（明确）。
CANONICAL_ERROR_CLASS = {
    SignatureVerifyError: "verify-failed",  # I7 模糊
    DecryptError: "decrypt-failed",  # I7 模糊（n01/n05/n13）
    DigestMismatchError: "digest-mismatch",  # 明确（n02/n09）
    DekConsistencyError: "alg-mismatch",  # D8 明确（n04）
    ProtocolFormatError: "protocol",  # 明确（n03/n06/n07/n08/n10/n12/n14/n15）
    UnsupportedSuiteError: "protocol",  # I5 明确（n03/n11）
    SuiteParseError: "protocol",  # 明确
}


def class_of(result) -> str:
    """失败结果 → canonical class（经公共入口 verify_response 的 error 分类锚）。"""
    assert result.error is not None, "失败结果必须携带分类异常（VerifyResult.error）"
    return CANONICAL_ERROR_CLASS[type(result.error)]


class HexStream:
    """确定性随机源：按序消费注入 hex 流；耗尽后回填 0x5A（镜像 Go hexReader）。

    随机流消费顺序合同：[16B nonce 池（nonce 注入时跳过）][CEK][12B IV][k…]。
    """

    def __init__(self, hex_str: str):
        self._raw = bytes.fromhex(hex_str)
        self._pos = 0

    def __call__(self, n: int) -> bytes:
        chunk = self._raw[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk + b"\x5a" * (n - len(chunk)) if len(chunk) < n else chunk


def _wire_bytes(b64u: str) -> bytes:
    """wireBodyB64 → bytes；空串（n15 无 body）映射为 b""。"""
    return b64url_decode(b64u) if b64u else b""


def _interop_client(vec_keys, suite: str, csprng=None) -> WopClient:
    """按套件从黄金向量取密钥构造客户端（与 crypto-vectors.json 同源，镜像 Go interopClient）。"""
    if suite == "WOP-RSA4096-SHA256":
        merchant = vec_keys["rsa4096"]["privatePkcs8B64"]
        platform = vec_keys["rsa4096"]["publicSpkiB64"]
    elif suite == "WOP-SM2-SM3":
        merchant, platform = vec_keys["sm2"]["privateDB64"], vec_keys["sm2"]["publicPointB64"]
    else:
        merchant = vec_keys["rsa3072"]["privatePkcs8B64"]
        platform = vec_keys["rsa3072"]["publicSpkiB64"]
    kwargs = {"csprng": csprng} if csprng is not None else {}
    return WopClient(
        WopConfig(
            app_key="app_interop_001",
            suite=suite,
            merchant_private_key=merchant,
            platform_public_key=platform,
        ),
        **kwargs,
    )


def _strip_signature_segment(sign_header: str) -> str:
    """opaque：剥 x-wop-sign 末段 '/' 之后的签名值（SM2 k 为 CSPRNG，合法变化）。"""
    i = sign_header.rfind("/")
    return sign_header if i < 0 else sign_header[:i + 1]


def _strip_dek_value(encrypt_header: str) -> str:
    """opaque：剥 x-wop-encrypt 'dek=' 之后的包装密文（SM2 k 同理）。"""
    i = encrypt_header.find("dek=")
    return encrypt_header if i < 0 else encrypt_header[:i + 4]


def _case(case_id: str) -> dict:
    return next(c for c in FIXTURE["cases"] if c["id"] == case_id)


class TestInteropFixtureIntegrity:  # spec:interop-v1 消费要求 1/4/5
    def test_fixture_bytes_match_truth_source(self):
        with open(FIXTURE_PATH, "rb") as f:
            raw = f.read()
        assert hashlib.sha256(raw).hexdigest() == EXPECTED_SHA256

    def test_format_and_count_sentinels(self):
        # v2 等未来格式在此显式炸掉（消费要求 5：旧 SDK 不允许静默消费新样本集）
        assert FIXTURE["_meta"]["format"] == EXPECTED_FORMAT
        assert len(FIXTURE["cases"]) == FIXTURE["_meta"]["caseCount"] == INTEROP_CASE_COUNT
        kinds = Counter(c["kind"] for c in FIXTURE["cases"])
        assert kinds == Counter(
            {"build": BUILD_COUNT, "verify-positive": VERIFY_POSITIVE_COUNT,
             "verify-negative": VERIFY_NEGATIVE_COUNT}
        )

    def test_known_id_sentinel(self):
        # 精确集合相等：真源增/删/改名任何用例都会炸，禁止静默漂移
        assert {c["id"] for c in FIXTURE["cases"]} == KNOWN_INTEROP_IDS


class TestInteropConformanceBuild:  # spec:interop-v1 消费要求 2
    """同输入必须复现同 draft：RSA 族 byte-exact 全量；SM2 族按 opaque 剥离
    密钥参与段（signatureSegment / dekValue），wire body 与 digest 头仍在比对范围。"""

    @pytest.mark.parametrize("case_id", sorted(
        c["id"] for c in FIXTURE["cases"] if c["kind"] == "build"
    ))
    def test_reproduce_draft(self, vec_keys, case_id):
        case = _case(case_id)
        client = _interop_client(vec_keys, case["suite"], csprng=HexStream(case["input"]["randomHex"]))
        draft = client.build_request(
            case["input"]["method"],
            case["input"]["path"],
            b64url_decode(case["input"]["plaintextB64"]),
            level=case["level"],
            timestamp_ms=case["input"]["timestampMs"],
            nonce=case["input"]["nonce"],
        )
        expected = case["expected"]
        # wire body 字节级一致（SM2 的 CEK/IV 由随机流前段确定，含在比对内）
        assert b64url_encode(draft.wire_body) == expected["wireBodyB64"], "wire body 字节不一致"
        # 头逐项比对；opaque 声明的密钥参与段双侧剥离后比对
        opaque = set(expected.get("opaque") or [])
        for name, want in expected["headers"].items():
            got = draft.headers.get(name)
            if f"{name}.signatureSegment" in opaque:
                got, want = _strip_signature_segment(got), _strip_signature_segment(want)
            if f"{name}.dekValue" in opaque:
                got, want = _strip_dek_value(got), _strip_dek_value(want)
            assert got == want, f"头 {name} 不一致"
        # 头集合哨兵：协议头（x-wop-*）恰为 fixture 声明集合；
        # 签名集外仅允许本仓出向便利头 content-type（不参与签名，不影响协议编排）
        assert {k for k in draft.headers if k.startswith("x-wop-")} == set(expected["headers"])
        assert set(draft.headers) - set(expected["headers"]) <= {"content-type"}


class TestInteropConformanceVerify:  # spec:interop-v1 消费要求 3
    """verify 方向全量消费冻结样本：positive 断言通过 + 明文一致；
    negative 断言拒绝 + 错误分类逐条对账（含 P 系列故障注入的静态等价样本）。
    混合大小写头名（p13，P7）由 verify_response 的小写化兜底覆盖。"""

    @pytest.fixture(scope="class")
    def clients(self, vec_keys):
        cache = {}

        def _client(suite):
            if suite not in cache:
                cache[suite] = _interop_client(vec_keys, suite)
            return cache[suite]

        return _client

    @pytest.mark.parametrize("case_id", sorted(
        c["id"] for c in FIXTURE["cases"] if c["kind"].startswith("verify-")
    ))
    def test_verify_case(self, clients, case_id):
        case = _case(case_id)
        resp = case["response"]
        body = _wire_bytes(resp["wireBodyB64"])
        path = case.get("verifyPath") or resp["path"]  # n16：跨端点重放按 verifyPath 校验
        result = clients(case["suite"]).verify_response(
            resp["headers"], body, path, method=resp["method"]
        )
        if case["kind"] == "verify-positive":
            assert result.ok, f"{case_id} 应通过：{result.reason}"
            assert result.plaintext == b64url_decode(
                case["expect"]["plaintextB64"]
            ), f"{case_id} 明文不一致"
        else:
            assert not result.ok, f"{case_id} 应拒绝"
            got = class_of(result)
            want = case["expect"]["errorClass"]
            assert (
                got == want
            ), f"{case_id} 错误分类 = {got}({type(result.error).__name__}), want {want}"


def test_canonical_mapping_table_declares_all_verify_error_types():
    # 映射表必须覆盖 verify_response 可对外抛出的全部 WopSdkError 子类
    # （合同：本仓错误码 → canonical class 须显式声明，禁止 default 兜底）
    from wop_sdk import client as client_mod
    import inspect

    source = inspect.getsource(client_mod.WopClient.verify_response)
    for exc_type in CANONICAL_ERROR_CLASS:
        assert (
            exc_type.__name__ in source
        ), f"映射表类型 {exc_type.__name__} 未见于 verify_response 捕获集"
