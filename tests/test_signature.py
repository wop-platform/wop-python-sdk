# -*- coding: utf-8 -*-
"""签名测试：RSA PKCS1v15 / SM3withSM2 裸 r||s（F3/D9/F7）——黄金向量字节级 + 全负向量。"""
import pytest

from wop_sdk.encoding import b64url_decode, b64url_encode
from wop_sdk.errors import KeyMaterialError, ProtocolFormatError, SignatureVerifyError
from wop_sdk.keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    load_sm2_private_key,
    load_sm2_public_key,
)
from wop_sdk.signature import sign, verify
from wop_sdk.sm2crypto import Sm2Ops, sm2_sign_with_sm3, sm2_verify_with_sm3
from wop_sdk.suites import parse_suite

RSA3072 = parse_suite("WOP-RSA3072-SHA256")
RSA4096 = parse_suite("WOP-RSA4096-SHA256")
SM2 = parse_suite("WOP-SM2-SM3")

MSG = "WOP 跨语言测试向量 2026-08-28 — The quick brown fox jumps over the lazy dog."
MSG_B = MSG.encode("utf-8")


def _csprng_fixed(stream):
    it = iter(stream)
    return lambda n: next(it)


@pytest.fixture(scope="module")
def k3072(vec_keys):
    k = vec_keys["rsa3072"]
    return {
        "pub": load_rsa_public_key(k["publicSpkiB64"], 3072),
        "priv": load_rsa_private_key(k["privatePkcs8B64"], 3072),
    }


@pytest.fixture(scope="module")
def sm2m(vec_keys, vectors):
    k = vec_keys["sm2"]
    pub = load_sm2_public_key(k["publicPointB64"])
    d = load_sm2_private_key(k["privateDB64"])
    # spec:D14 黄金向量按 sm2UserId 生成（向量固定值仅作夹具，显式注入，禁回退 gmssl 默认）
    uid = vectors["inputs"]["sm2UserId"]
    return {"pub": pub, "d": d, "user_id": uid, "ops": Sm2Ops(d.hex(), pub.xy_hex, user_id=uid)}


class TestRsaSignVectors:
    def test_rsa3072_sign_byte_exact(self, vectors, k3072):  # spec:A1 rsa3072-sign
        v = next(x for x in vectors["signature"] if x["id"] == "rsa3072-sign")
        sig = sign(RSA3072, k3072["priv"], MSG_B)
        assert b64url_encode(sig) == v["expectedSigB64u"]
        assert len(sig) == v["sigLenBytes"]
        assert len(v["expectedSigB64u"]) == v["b64uLen"]

    def test_rsa4096_sign_byte_exact(self, vectors, vec_keys):  # spec:A1 rsa4096-sign
        v = next(x for x in vectors["signature"] if x["id"] == "rsa4096-sign")
        priv = load_rsa_private_key(vec_keys["rsa4096"]["privatePkcs8B64"], 4096)
        sig = sign(RSA4096, priv, MSG_B)
        assert b64url_encode(sig) == v["expectedSigB64u"]
        assert len(sig) == v["sigLenBytes"]

    def test_sign_deterministic_pkcs1v15(self, k3072):
        assert sign(RSA3072, k3072["priv"], MSG_B) == sign(RSA3072, k3072["priv"], MSG_B)


class TestRsaVerify:
    def test_verify_ok(self, vectors, k3072):
        v = next(x for x in vectors["signature"] if x["id"] == "rsa3072-sign")
        verify(RSA3072, k3072["pub"], MSG_B, b64url_decode(v["expectedSigB64u"]))

    def test_tampered_signature_rejected(self, vectors, k3072):  # spec:A2 tamper
        v = next(x for x in vectors["signature"] if x["id"] == "rsa3072-sign")
        sig = bytearray(b64url_decode(v["expectedSigB64u"]))
        sig[10] ^= 0xFF
        with pytest.raises(SignatureVerifyError):
            verify(RSA3072, k3072["pub"], MSG_B, bytes(sig))

    def test_wrong_message_rejected(self, vectors, k3072):
        v = next(x for x in vectors["signature"] if x["id"] == "rsa3072-sign")
        with pytest.raises(SignatureVerifyError):
            verify(RSA3072, k3072["pub"], b"other message", b64url_decode(v["expectedSigB64u"]))

    def test_wrong_length_rejected_before_crypto(self, k3072):  # 定长前置校验
        with pytest.raises(ProtocolFormatError):
            verify(RSA3072, k3072["pub"], MSG_B, b"\x00" * 100)

    def test_4096_length_distinct(self, vectors, vec_keys):
        pub = load_rsa_public_key(vec_keys["rsa4096"]["publicSpkiB64"], 4096)
        v = next(x for x in vectors["signature"] if x["id"] == "rsa3072-sign")
        with pytest.raises(ProtocolFormatError):
            verify(RSA4096, pub, MSG_B, b64url_decode(v["expectedSigB64u"]))


class TestSm2SignVector:
    def test_sm2_fixedk_byte_exact(self, vectors, sm2m):  # spec:A1 sm2-sign-fixedk（D9 裸 r||s）
        v = next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")
        k = b64url_decode(vectors["inputs"]["sm2FixedKB64u"]).hex()
        sig = sm2_sign_with_sm3(sm2m["ops"], MSG_B, k)
        assert sig.hex() == b64url_decode(v["expectedSigB64u"]).hex()
        assert len(sig) == 64  # r||s 各 32B，线上禁 DER

    def test_verify_ok(self, vectors, sm2m):
        v = next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")
        sm2_verify_with_sm3(sm2m["ops"], b64url_decode(v["expectedSigB64u"]).hex(), MSG_B)


class TestSm2VerifyNegative:
    def _expected_hex(self, vectors):
        v = next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")
        return b64url_decode(v["expectedSigB64u"]).hex()

    def test_tampered_r_rejected(self, vectors, sm2m):  # spec:A2 tamper
        hex_sig = self._expected_hex(vectors)
        bad = hex_sig[:-2] + ("00" if hex_sig[-2:] != "00" else "01")
        assert not sm2_verify_with_sm3(sm2m["ops"], bad, MSG_B)

    def test_wrong_message_rejected(self, vectors, sm2m):
        assert not sm2_verify_with_sm3(sm2m["ops"], self._expected_hex(vectors), b"other")

    def test_63b_rejected(self, vectors):  # spec:A2 任务书负向量 63B
        sig = b64url_decode(
            next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")["expectedSigB64u"]
        )
        with pytest.raises(ProtocolFormatError):
            verify(SM2, None, MSG_B, sig[:63])

    def test_65b_rejected(self, vectors):  # spec:A2 任务书负向量 65B
        sig = b64url_decode(
            next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")["expectedSigB64u"]
        )
        with pytest.raises(ProtocolFormatError):
            verify(SM2, None, MSG_B, sig + b"\x00")

    def test_der_rejected(self, vectors):  # spec:D9 线上禁 ASN.1/DER
        sig = b64url_decode(
            next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")["expectedSigB64u"]
        )
        r = sig[:32].lstrip(b"\x00") or b"\x00"
        s = sig[32:].lstrip(b"\x00") or b"\x00"
        der = bytes([0x30, 2 + 2 + len(r) + 2 + len(s), 0x02, len(r)]) + r + bytes([0x02, len(s)]) + s
        with pytest.raises(ProtocolFormatError):
            verify(SM2, None, MSG_B, der)

    def test_sign_via_client_api_uses_csprng_k(self, sm2m):
        # sign() 走 csprng 注入 k（I4：随机数生成点收敛）
        ops = Sm2Ops(sm2m["d"].hex(), sm2m["pub"].xy_hex, user_id=sm2m["user_id"])
        k = b"\x11" * 32
        sig = sign(SM2, ops, MSG_B, csprng=lambda n: k)
        assert len(sig) == 64
        sm2_verify_with_sm3(ops, sig.hex(), MSG_B)

    def test_sign_k_out_of_range_resampled(self, sm2m):
        # k ≥ n 或 k = 0 必须重采样（分支覆盖 + 正确性）
        ops = Sm2Ops(sm2m["d"].hex(), sm2m["pub"].xy_hex, user_id=sm2m["user_id"])
        n_bytes = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
        calls = [n_bytes, b"\x00" * 32, b"\x22" * 32]
        sig = sign(SM2, ops, MSG_B, csprng=_csprng_fixed(calls))
        assert len(sig) == 64
        sm2_verify_with_sm3(ops, sig.hex(), MSG_B)


class TestSm2KeyGuard:
    def test_ops_requires_valid_material(self):
        with pytest.raises(KeyMaterialError):
            Sm2Ops("zz", "zz")
