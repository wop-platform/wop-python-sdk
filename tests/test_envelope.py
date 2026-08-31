# -*- coding: utf-8 -*-
"""L2 数字信封测试（F5/F4/D10/I3/I4/I7）：AES/SM4-GCM 向量字节级、OAEP 双 SHA-256、
SM2 C1C3C2、DEK 载荷、alg 族比对、负向量全套。"""
import json

import pytest

from wop_sdk.encoding import b64url_decode, b64url_encode
from wop_sdk.envelope import (
    build_dek_payload,
    message_decrypt,
    message_encrypt,
    open_l2,
    parse_dek_payload,
    seal_l2,
    unwrap_dek,
    wrap_dek,
)
from wop_sdk.errors import DecryptError, DekConsistencyError, ProtocolFormatError
from wop_sdk.keys import load_rsa_private_key, load_rsa_public_key, load_sm2_private_key, load_sm2_public_key
from wop_sdk.sm2crypto import Sm2Ops
from wop_sdk.suites import parse_suite

RSA3072 = parse_suite("WOP-RSA3072-SHA256")
SM2 = parse_suite("WOP-SM2-SM3")

PLAINTEXT = "WOP 跨语言测试向量 2026-08-28 — The quick brown fox jumps over the lazy dog."


def _vec(vectors, section, vid):
    return next(x for x in vectors[section] if x["id"] == vid)


@pytest.fixture(scope="module")
def rsa_pair(vec_keys):
    k = vec_keys["rsa3072"]
    return (
        load_rsa_public_key(k["publicSpkiB64"], 3072),
        load_rsa_private_key(k["privatePkcs8B64"], 3072),
    )


@pytest.fixture(scope="module")
def sm2_pair(vec_keys):
    k = vec_keys["sm2"]
    pub = load_sm2_public_key(k["publicPointB64"])
    d = load_sm2_private_key(k["privateDB64"])
    return (Sm2Ops(public_xy_hex=pub.xy_hex), Sm2Ops(private_key_hex=d.hex(), public_xy_hex=pub.xy_hex))


class TestMessageEncryptVectors:
    def test_aes256gcm_byte_exact(self, vectors):  # spec:A1 aesgcm-encrypt
        v = _vec(vectors, "messageEncrypt", "aesgcm-encrypt")
        ct = message_encrypt(
            RSA3072,
            b64url_decode(v["keyB64u"]),
            b64url_decode(v["ivB64u"]),
            b64url_decode(v["plaintextB64u"]),
        )
        assert b64url_encode(ct) == v["cipherTagB64u"]

    def test_sm4gcm_byte_exact(self, vectors):  # spec:A1 sm4gcm-encrypt（纯实现锚 D11）
        v = _vec(vectors, "messageEncrypt", "sm4gcm-encrypt")
        ct = message_encrypt(
            SM2,
            b64url_decode(v["keyB64u"]),
            b64url_decode(v["ivB64u"]),
            b64url_decode(v["plaintextB64u"]),
        )
        assert b64url_encode(ct) == v["cipherTagB64u"]

    def test_decrypt_vectors_roundtrip(self, vectors):
        for vid, suite in [("aesgcm-encrypt", RSA3072), ("sm4gcm-encrypt", SM2)]:
            v = _vec(vectors, "messageEncrypt", vid)
            plain = message_decrypt(
                suite,
                b64url_decode(v["keyB64u"]),
                b64url_decode(v["ivB64u"]),
                b64url_decode(v["cipherTagB64u"]),
            )
            assert plain == b64url_decode(v["plaintextB64u"])

    def test_empty_plaintext_roundtrip_both_families(self):
        for suite, klen in [(RSA3072, 32), (SM2, 16)]:
            key, iv = bytes(range(klen)), bytes(range(12))
            ct = message_encrypt(suite, key, iv, b"")
            assert message_decrypt(suite, key, iv, ct) == b""

    def test_tampered_tag_rejected_blurred(self):
        ct = bytearray(message_encrypt(RSA3072, b"\x01" * 32, b"\x02" * 12, b"hello"))
        ct[-1] ^= 0x01
        with pytest.raises(DecryptError) as exc:
            message_decrypt(RSA3072, b"\x01" * 32, b"\x02" * 12, bytes(ct))
        assert str(exc.value) == "解密失败"  # spec:I7 不区分 tag 失败细节

    def test_tampered_tag_rejected_sm4_blurred(self):
        ct = bytearray(message_encrypt(SM2, b"\x01" * 16, b"\x02" * 12, b"hello"))
        ct[-1] ^= 0x01
        with pytest.raises(DecryptError) as exc:
            message_decrypt(SM2, b"\x01" * 16, b"\x02" * 12, bytes(ct))
        assert str(exc.value) == "解密失败"

    def test_wrong_key_same_blurred_message(self):
        ct = message_encrypt(RSA3072, b"\x01" * 32, b"\x02" * 12, b"hello")
        with pytest.raises(DecryptError) as exc:
            message_decrypt(RSA3072, b"\x03" * 32, b"\x02" * 12, ct)
        assert str(exc.value) == "解密失败"  # spec:I7 与 tag 失败同消息

    def test_iv_length_enforced(self):
        with pytest.raises(DecryptError):
            message_decrypt(RSA3072, b"\x01" * 32, b"\x02" * 11, b"\x00" * 32)

    def test_key_length_enforced(self):
        with pytest.raises(DecryptError):
            message_encrypt(RSA3072, b"\x01" * 16, b"\x02" * 12, b"x")


class TestKeyEncryptVectors:
    def test_oaep3072_unwrap(self, vectors, rsa_pair):  # spec:A1 oaep3072-unwrap
        v = _vec(vectors, "keyEncrypt", "oaep3072-unwrap")
        out = unwrap_dek(RSA3072, rsa_pair[1], b64url_decode(v["cipherB64u"]))
        assert out.decode() == v["expectedPlaintext"]

    def test_oaep4096_unwrap(self, vectors, vec_keys):  # spec:A1 oaep4096-unwrap
        v = _vec(vectors, "keyEncrypt", "oaep4096-unwrap")
        priv = load_rsa_private_key(vec_keys["rsa4096"]["privatePkcs8B64"], 4096)
        out = unwrap_dek(parse_suite("WOP-RSA4096-SHA256"), priv, b64url_decode(v["cipherB64u"]))
        assert out.decode() == v["expectedPlaintext"]

    def test_mgf1_sha1_trap_rejected(self, vectors, rsa_pair):  # spec:A2 oaep3072-mgf1sha1-trap（F2 钉子）
        v = _vec(vectors, "keyEncrypt", "oaep3072-mgf1sha1-trap")
        with pytest.raises(DecryptError) as exc:
            unwrap_dek(RSA3072, rsa_pair[1], b64url_decode(v["cipherB64u"]))
        assert str(exc.value) == "解密失败"

    def test_oaep_wrap_roundtrip(self, vectors, rsa_pair):  # spec:A1 oaep3072-wrap-roundtrip
        v = _vec(vectors, "keyEncrypt", "oaep3072-wrap-roundtrip")
        wrapped = wrap_dek(RSA3072, rsa_pair[0], v["plaintext"].encode())
        assert unwrap_dek(RSA3072, rsa_pair[1], wrapped) == v["plaintext"].encode()

    def test_oaep_wrap_deterministic_from_csprng(self, rsa_pair):  # spec:interop-v1 OAEP-from-stream
        # 同 csprng 流两次包装字节一致（seed 取自注入流，跨仓 build 复现的前提）
        w1 = wrap_dek(RSA3072, rsa_pair[0], b"payload", csprng=lambda n: b"\x07" * n)
        w2 = wrap_dek(RSA3072, rsa_pair[0], b"payload", csprng=lambda n: b"\x07" * n)
        assert w1 == w2
        assert unwrap_dek(RSA3072, rsa_pair[1], w1) == b"payload"

    def test_oaep_wrap_payload_too_long_rejected(self, rsa_pair):
        # RSA3072 OAEP 上限 = 384 - 2*32 - 2 = 318 字节
        with pytest.raises(ValueError):
            wrap_dek(RSA3072, rsa_pair[0], b"x" * 319)

    def test_sm2_encrypt_fixedk_decrypt(self, vectors, sm2_pair):  # spec:A1 sm2-encrypt-fixedk
        v = _vec(vectors, "keyEncrypt", "sm2-encrypt-fixedk")
        out = unwrap_dek(SM2, sm2_pair[1], b64url_decode(v["cipherB64u"]))
        assert out.decode() == v["plaintext"]

    def test_sm2_c1c2c3_mismatch_rejected(self, vectors, sm2_pair):  # spec:A2 C1C2C3 顺序钉死
        v = _vec(vectors, "keyEncrypt", "sm2-encrypt-c1c2c3-mismatch")
        with pytest.raises(DecryptError) as exc:
            unwrap_dek(SM2, sm2_pair[1], b64url_decode(v["cipherB64u"]))
        assert str(exc.value) == "解密失败"

    def test_sm2_wrap_roundtrip(self, sm2_pair):
        payload = b"SM4-GCM$" + b"k" * 22 + b"$" + b"i" * 16
        wrapped = wrap_dek(SM2, sm2_pair[0], payload, csprng=lambda n: b"\x33" * 32)
        assert unwrap_dek(SM2, sm2_pair[1], wrapped) == payload

    def test_sm2_tampered_cipher_rejected(self, sm2_pair):
        payload = b"secret-payload"
        wrapped = bytearray(
            wrap_dek(SM2, sm2_pair[0], payload, csprng=lambda n: b"\x33" * 32)
        )
        wrapped[-1] ^= 0xFF
        with pytest.raises(DecryptError):
            unwrap_dek(SM2, sm2_pair[1], bytes(wrapped))

    def test_rsa_garbage_cipher_rejected_blurred(self, rsa_pair):
        with pytest.raises(DecryptError) as exc:
            unwrap_dek(RSA3072, rsa_pair[1], b"\x99" * 384)
        assert str(exc.value) == "解密失败"


class TestDekPayload:
    def test_build_rsa_vector(self, vectors):  # spec:A1 dek-rsa
        v = _vec(vectors, "dekPayload", "dek-rsa")
        assert (
            build_dek_payload(RSA3072, b64url_decode(v["keyB64u"]), b64url_decode(v["ivB64u"]))
            == v["expected"]
        )

    def test_build_sm2_vector(self, vectors):  # spec:A1 dek-sm2
        v = _vec(vectors, "dekPayload", "dek-sm2")
        assert (
            build_dek_payload(SM2, b64url_decode(v["keyB64u"]), b64url_decode(v["ivB64u"]))
            == v["expected"]
        )

    def test_parse_ok(self, vectors):
        v = _vec(vectors, "dekPayload", "dek-rsa")
        key, iv = parse_dek_payload(RSA3072, v["expected"])
        assert key == b64url_decode(v["keyB64u"]) and iv == b64url_decode(v["ivB64u"])

    def test_parse_two_segments_rejected(self):
        with pytest.raises(ProtocolFormatError):
            parse_dek_payload(RSA3072, "AES-256-GCM$onlyone")

    def test_parse_four_segments_rejected(self):
        with pytest.raises(ProtocolFormatError):
            parse_dek_payload(RSA3072, "AES-256-GCM$a$b$c")

    def test_alg_cross_family_rejected_before_decrypt(self):  # spec:I3/I5/D8
        # RSA 套件收到 SM4-GCM DEK → 一致性类错误（bulk 解密前，明确）
        payload = "SM4-GCM$" + "A" * 22 + "$" + "B" * 8
        with pytest.raises(DekConsistencyError):
            parse_dek_payload(RSA3072, payload)

    def test_alg_cross_family_sm_side(self):
        payload = "AES-256-GCM$" + "A" * 22 + "$" + "B" * 8
        with pytest.raises(DekConsistencyError):
            parse_dek_payload(SM2, payload)

    def test_unknown_alg_rejected(self):
        payload = "AES-128-GCM$" + "A" * 22 + "$" + "B" * 8
        with pytest.raises(ProtocolFormatError):
            parse_dek_payload(RSA3072, payload)

    def test_bad_b64u_key_rejected(self):
        payload = "AES-256-GCM$ab=cd$" + "B" * 8
        with pytest.raises(ProtocolFormatError):
            parse_dek_payload(RSA3072, payload)

    def test_key_length_mismatch_rejected(self):
        payload = 'AES-256-GCM$' + b64url_encode(b"\x01" * 16) + '$' + b64url_encode(b"\x02" * 12)
        with pytest.raises(ProtocolFormatError):
            parse_dek_payload(RSA3072, payload)


class TestSealOpenL2:
    def test_rsa_roundtrip(self, rsa_pair):
        wire, header = seal_l2(RSA3072, rsa_pair[0], PLAINTEXT.encode(), csprng=lambda n: b"\xab" * n)
        assert header.startswith("L2;dek=")
        obj = json.loads(wire)
        assert set(obj) == {"encrypted"}
        dek_b64u = header[len("L2;dek="):]
        assert open_l2(RSA3072, rsa_pair[1], wire, dek_b64u) == PLAINTEXT.encode()

    def test_sm2_roundtrip(self, sm2_pair):
        wire, header = seal_l2(SM2, sm2_pair[0], PLAINTEXT.encode(), csprng=lambda n: b"\xcd" * n)
        dek_b64u = header[len("L2;dek="):]
        assert open_l2(SM2, sm2_pair[1], wire, dek_b64u) == PLAINTEXT.encode()

    def test_seal_uses_fresh_iv_per_call(self, rsa_pair):
        # I4：同一密钥下 IV 永不复用 → 两次 seal 的 DEK 必不同（csprng 正常时）
        import os

        w1, h1 = seal_l2(RSA3072, rsa_pair[0], b"m", csprng=os.urandom)
        w2, h2 = seal_l2(RSA3072, rsa_pair[0], b"m", csprng=os.urandom)
        assert h1 != h2 and w1 != w2

    def test_open_bad_wire_json_protocol(self, rsa_pair):  # spec:interop-v1 n12 / playbook P2
        # 信封 JSON 形态 = 公开结构知识 → 解析类明确（interop 合同拉齐，不再归模糊）
        payload = b"AES-256-GCM$" + b64url_encode(b"\x01" * 32).encode() + b"$" + b64url_encode(b"\x02" * 12).encode()
        wrapped = wrap_dek(RSA3072, rsa_pair[0], payload)
        with pytest.raises(ProtocolFormatError):
            open_l2(RSA3072, rsa_pair[1], b"not-json", b64url_encode(wrapped))

    def test_open_missing_encrypted_protocol(self, rsa_pair):  # spec:interop-v1 n12
        payload = b"AES-256-GCM$" + b64url_encode(b"\x01" * 32).encode() + b"$" + b64url_encode(b"\x02" * 12).encode()
        wrapped = wrap_dek(RSA3072, rsa_pair[0], payload)
        wire = json.dumps({"other": 1}).encode()
        with pytest.raises(ProtocolFormatError):
            open_l2(RSA3072, rsa_pair[1], wire, b64url_encode(wrapped))

    def test_open_dek_b64u_padding_rejected(self, rsa_pair):
        # dek 值 b64url = 公开结构（F7）→ 解析类明确（对齐 Go DecodeB64URL→CodeProtocol）
        wire, _ = seal_l2(RSA3072, rsa_pair[0], b"m", csprng=lambda n: b"\xab" * n)
        with pytest.raises(ProtocolFormatError):
            open_l2(RSA3072, rsa_pair[1], wire, "abc=")  # F7 严格无填充

    def test_open_dek_payload_invalid_utf8_blurred(self, rsa_pair):
        # I7：解包成功但 DEK 载荷非 UTF-8 → 与解包失败同归模糊，不得向商户层逃逸
        dek_b64u = b64url_encode(
            wrap_dek(RSA3072, rsa_pair[0], b"\xff\xfe\x80", csprng=lambda n: b"\xab" * n)
        )
        wire = json.dumps({"encrypted": b64url_encode(b"x" * 48)}).encode()
        with pytest.raises(DecryptError):
            open_l2(RSA3072, rsa_pair[1], wire, dek_b64u)

    def test_open_cross_family_dek_consistent_error(self, sm2_pair, vectors):
        # RSA 套件 DEK 被塞进 SM 载荷：解包成功、alg 比对在 bulk 解密前明确拒绝
        v = _vec(vectors, "dekPayload", "dek-sm2")
        with pytest.raises(DekConsistencyError):
            parse_dek_payload(RSA3072, v["expected"])
