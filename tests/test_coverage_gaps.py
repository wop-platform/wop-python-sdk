# -*- coding: utf-8 -*-
"""覆盖率缺口闭合测试：错误分支、类型分支、SM2 防御路径（I5/I7）。"""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import wop_sdk.client as client_mod
from wop_sdk.client import WopClient, WopConfig
from wop_sdk.digest import check_digest_header
from wop_sdk.encoding import b64url_encode
from wop_sdk.envelope import message_decrypt, message_encrypt, open_l2, unwrap_dek, wrap_dek
from wop_sdk.errors import (
    ERROR_CATEGORIES,
    ConfigurationError,
    DecryptError,
    DekConsistencyError,
    DigestMismatchError,
    KeyMaterialError,
    ProtocolFormatError,
    SignatureVerifyError,
    SuiteParseError,
    UnsupportedSuiteError,
    WopSdkError,
)
from wop_sdk.keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    load_sm2_private_key,
    load_sm2_public_key,
)
from wop_sdk.signature import verify as sig_verify
from wop_sdk.sm2crypto import Sm2Ops, sm2_decrypt, sm2_sign_with_sm3
from wop_sdk.sm4gcm import sm4_gcm_decrypt
from wop_sdk.suites import parse_suite

RSA3072 = parse_suite("WOP-RSA3072-SHA256")
SM2 = parse_suite("WOP-SM2-SM3")


@pytest.fixture(scope="module")
def rsa_pair(vec_keys):
    k = vec_keys["rsa3072"]
    return (
        load_rsa_public_key(k["publicSpkiB64"], 3072),
        load_rsa_private_key(k["privatePkcs8B64"], 3072),
    )


@pytest.fixture(scope="module")
def sm2_pair(vec_keys, vectors):
    k = vec_keys["sm2"]
    pub = load_sm2_public_key(k["publicPointB64"])
    d = load_sm2_private_key(k["privateDB64"])
    # 验签路径需显式注入黄金向量 sm2UserId（D14：向量固定值仅作夹具，禁回退 gmssl 默认）
    uid = vectors["inputs"]["sm2UserId"]
    return (
        Sm2Ops(public_xy_hex=pub.xy_hex, user_id=uid),
        Sm2Ops(private_key_hex=d.hex(), public_xy_hex=pub.xy_hex, user_id=uid),
    )


@pytest.fixture(scope="module")
def gap_rsa_client(vec_keys):
    return WopClient(
        WopConfig("ak", "WOP-RSA3072-SHA256", vec_keys["rsa3072"]["privatePkcs8B64"], vec_keys["rsa3072"]["publicSpkiB64"]),
        csprng=lambda n: b"\x01" * n,
    )


class TestClientGaps:
    def test_now_ms_real(self):
        import time

        now = client_mod._now_ms()
        assert isinstance(now, int)
        assert abs(now - int(time.time() * 1000)) < 5000

    def test_suite_property(self, vec_keys):
        c = WopClient(
            WopConfig("ak", "WOP-SM2-SM3", vec_keys["sm2"]["privateDB64"], vec_keys["sm2"]["publicPointB64"]),
            csprng=lambda n: b"\x01" * n,
        )
        assert c.suite.security_req == "WOP-SM2-SM3"

    def test_normalize_body_str_and_type_error(self, gap_rsa_client):
        assert gap_rsa_client._normalize_body("文本") == "文本".encode("utf-8")
        with pytest.raises(ConfigurationError):
            gap_rsa_client._normalize_body(12345)


class TestDigestGap:
    def test_check_digest_header_none_rejected(self):  # digest 头缺席（D2）
        with pytest.raises(ProtocolFormatError):
            check_digest_header(RSA3072, None)


class TestEnvelopeGaps:
    def test_sm4_encrypt_key_len_rejected(self):
        with pytest.raises(DecryptError):
            message_encrypt(SM2, b"\x01" * 32, b"\x02" * 12, b"x")  # SM4 key 必须 16B

    def test_sm4_decrypt_iv_len_rejected(self):
        with pytest.raises(DecryptError):
            message_decrypt(SM2, b"\x01" * 16, b"\x02" * 11, b"\x00" * 32)

    def test_sm4_decrypt_short_cipher_rejected(self):
        with pytest.raises(ValueError):
            sm4_gcm_decrypt(b"\x01" * 16, b"\x02" * 12, b"\x00" * 10)

    def test_open_l2_valid_dek_bad_json_protocol(self, rsa_pair):  # spec:interop-v1 n12
        # 信封 JSON 形态 = 公开结构知识 → 解析类明确（interop 合同拉齐）
        payload = b"AES-256-GCM$" + b64url_encode(b"\x01" * 32).encode() + b"$" + b64url_encode(b"\x02" * 12).encode()
        wrapped = wrap_dek(RSA3072, rsa_pair[0], payload)
        with pytest.raises(ProtocolFormatError):
            open_l2(RSA3072, rsa_pair[1], b"not-json", b64url_encode(wrapped))

    def test_open_l2_valid_dek_encrypted_not_b64u(self, rsa_pair):  # spec:interop-v1 n12
        payload = b"AES-256-GCM$" + b64url_encode(b"\x01" * 32).encode() + b"$" + b64url_encode(b"\x02" * 12).encode()
        wrapped = wrap_dek(RSA3072, rsa_pair[0], payload)
        import json as _json

        wire = _json.dumps({"encrypted": "ab=cd"}).encode()
        with pytest.raises(ProtocolFormatError):
            open_l2(RSA3072, rsa_pair[1], wire, b64url_encode(wrapped))

    def test_unwrap_sm2_internal_error_blurred(self, sm2_pair):
        # 私钥材料损坏 → 内部异常统一模糊为 DecryptError（I7：不泄露细节）
        broken = Sm2Ops(public_xy_hex=sm2_pair[1].public_key)
        broken.private_key = "zz-not-hex"
        cipher = wrap_dek(SM2, sm2_pair[0], b"payload", csprng=lambda n: b"\x33" * 32)
        with pytest.raises(DecryptError):
            unwrap_dek(SM2, broken, cipher)


class TestKeysGaps:
    def test_empty_pem_body_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_rsa_public_key("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----", 3072)

    def test_ec_public_key_rejected_as_rsa(self):
        der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding", "PublicFormat"]).Encoding.DER,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding", "PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(KeyMaterialError):
            load_rsa_public_key(base64.b64encode(der).decode(), 3072)

    def test_rsa_public_bits_mismatch_rejected(self, vec_keys):
        with pytest.raises(KeyMaterialError):
            load_rsa_public_key(vec_keys["rsa4096"]["publicSpkiB64"], 3072)

    def test_rsa_private_garbage_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_rsa_private_key("!!!garbage!!!", 3072)

    def test_ec_private_key_rejected_as_rsa(self):
        from cryptography.hazmat.primitives import serialization

        der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(KeyMaterialError):
            load_rsa_private_key(base64.b64encode(der).decode(), 3072)

    def test_sm2_private_too_large_rejected(self):
        n_plus = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124")
        with pytest.raises(KeyMaterialError):
            load_sm2_private_key(base64.b64encode(n_plus).decode())


class TestSignatureGaps:
    def test_sm2_verify_fail_raises_blurred(self, vectors, sm2_pair):
        # signature.verify 的 SM2 失败路径（I7 模糊）
        v = next(x for x in vectors["signature"] if x["id"] == "sm2-sign-fixedk")
        from wop_sdk.encoding import b64url_decode

        sig = b64url_decode(v["expectedSigB64u"])
        verify_ops = sm2_pair[1]
        with pytest.raises(SignatureVerifyError):
            sig_verify(SM2, verify_ops, b"wrong-message", sig)


class TestSm2CryptoGaps:
    def test_ops_constructor_variants(self, vec_keys):
        pub = load_sm2_public_key(vec_keys["sm2"]["publicPointB64"])
        d = load_sm2_private_key(vec_keys["sm2"]["privateDB64"])
        Sm2Ops()  # 双 None（占位构造）
        ops_priv_only = Sm2Ops(private_key_hex=d.hex())
        assert ops_priv_only.private_key == d.hex()
        ops_pub_only = Sm2Ops(public_xy_hex=pub.xy_hex)
        assert ops_pub_only.public_key == pub.xy_hex
    def test_sign_without_user_id_rejected(self, vec_keys):
        # spec:D14 否定式条款：缺 userId 禁静默回退 gmssl 默认，签名路径抛 KeyMaterialError
        d = load_sm2_private_key(vec_keys["sm2"]["privateDB64"])
        ops = Sm2Ops(private_key_hex=d.hex())  # 无 user_id（_sm3_z 立即拒绝）
        with pytest.raises(KeyMaterialError):
            sm2_sign_with_sm3(ops, b"payload", "%064x" % 1)

    def test_encrypt_k_resampling(self, sm2_pair):
        # k 越界重采样（I4：CSPRNG 采样点收敛）
        n_bytes = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
        zero = b"\x00" * 32
        good = b"\x44" * 32
        stream = iter([n_bytes, zero, good])
        cipher = None
        from wop_sdk.sm2crypto import sm2_encrypt

        cipher = sm2_encrypt(sm2_pair[0], lambda n: next(stream), b"payload")
        assert sm2_decrypt(sm2_pair[1], cipher) == b"payload"

    def test_decrypt_short_cipher_rejected(self, sm2_pair):
        with pytest.raises(DecryptError):
            sm2_decrypt(sm2_pair[1], b"\x04\x01")

    def test_decrypt_c1_not_on_curve_rejected(self, sm2_pair):  # I5：曲线防御
        import os

        fake = b"\x04" + b"\x01" + os.urandom(31) + os.urandom(32) + b"\x00" * 33
        with pytest.raises(DecryptError):
            sm2_decrypt(sm2_pair[1], fake)

    def test_decrypt_bad_prefix_rejected(self, sm2_pair):
        with pytest.raises(DecryptError):
            sm2_decrypt(sm2_pair[1], b"\x03" + b"\x00" * 96)


class TestErrorCategories:  # spec:2.2 category 闭集与 I7 文案纪律
    def test_category_closed_set_exact(self):  # spec:2.2 否定式：多/少任一值即炸
        assert ERROR_CATEGORIES == frozenset(
            {"configuration", "parse", "unsupported", "integrity", "consistency", "signature", "decrypt"}
        )

    def test_every_error_class_maps_to_expected_category(self):  # spec:2.2 逐类枚举
        mapping = {
            ConfigurationError: "configuration",
            KeyMaterialError: "configuration",
            SuiteParseError: "parse",
            ProtocolFormatError: "parse",
            UnsupportedSuiteError: "unsupported",
            DigestMismatchError: "integrity",
            DekConsistencyError: "consistency",
            SignatureVerifyError: "signature",
            DecryptError: "decrypt",
        }
        for cls, expected in mapping.items():
            assert cls.category == expected, cls.__name__

    def test_base_class_unclassified_not_in_closed_set(self):  # spec:2.2 否定式
        # 基类「未归类」空串不入闭集；SDK 不直接抛基类
        assert WopSdkError.category == ""
        assert WopSdkError.category not in ERROR_CATEGORIES

    def test_i7_blur_messages_fixed(self):  # spec:2.2/I7 模糊文案恒定
        assert str(SignatureVerifyError()) == "签名验证失败"
        assert str(DecryptError()) == "解密失败"

    def test_empty_appkey_rejected_as_configuration(self, vec_keys):  # spec:2.1/2.2
        k = vec_keys["rsa3072"]
        with pytest.raises(ConfigurationError) as exc:
            WopClient(WopConfig("  ", "WOP-RSA3072-SHA256", k["privatePkcs8B64"], k["publicSpkiB64"]))
        assert exc.value.category == "configuration"
