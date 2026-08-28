# -*- coding: utf-8 -*-
"""密钥解析测试：RSA SPKI/PKCS8（D12）、SM2 65B/32B（D12）、I5 跨族/曲线校验。"""
import base64
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

from wop_sdk.errors import KeyMaterialError
from wop_sdk.keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    load_sm2_private_key,
    load_sm2_public_key,
)


def _wrap_pem(b64: str, label: str) -> str:
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, body, label)


@pytest.fixture(scope="module")
def rsa3072(vec_keys):
    return vec_keys["rsa3072"]


@pytest.fixture(scope="module")
def rsa2048_priv():
    # 负向量用：长度不匹配套件
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class TestRsaKeys:
    def test_public_spki_base64(self, rsa3072):
        key = load_rsa_public_key(rsa3072["publicSpkiB64"], expected_bits=3072)
        assert key.key_size == 3072

    def test_public_spki_pem(self, rsa3072):
        pem = _wrap_pem(rsa3072["publicSpkiB64"], "PUBLIC KEY")
        assert load_rsa_public_key(pem, expected_bits=3072).key_size == 3072

    def test_private_pkcs8_base64(self, rsa3072):
        key = load_rsa_private_key(rsa3072["privatePkcs8B64"], expected_bits=3072)
        assert key.key_size == 3072

    def test_private_pkcs8_pem(self, rsa3072):
        pem = _wrap_pem(rsa3072["privatePkcs8B64"], "PRIVATE KEY")
        assert load_rsa_private_key(pem, expected_bits=3072).key_size == 3072

    def test_bits_mismatch_rejected(self, rsa2048_priv):
        with pytest.raises(KeyMaterialError):
            load_rsa_private_key(rsa2048_priv, expected_bits=3072)

    def test_garbage_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_rsa_public_key("not-a-key!!", expected_bits=3072)

    def test_sm2_material_rejected_as_rsa(self, vec_keys):
        # I5：SM2 公钥材料喂 RSA 解析器必须拒
        with pytest.raises(KeyMaterialError):
            load_rsa_public_key(vec_keys["sm2"]["publicPointB64"], expected_bits=3072)


class TestSm2Keys:
    def test_public_point_65b(self, vec_keys):
        pub = load_sm2_public_key(vec_keys["sm2"]["publicPointB64"])
        assert pub.uncompressed[0] == 0x04
        assert len(pub.uncompressed) == 65
        assert pub.xy_hex == pub.uncompressed[1:].hex()

    def test_public_accepts_urlsafe_encoding(self, vec_keys):
        raw = base64.b64decode(vec_keys["sm2"]["publicPointB64"])
        url_material = base64.urlsafe_b64encode(raw).decode()
        assert load_sm2_public_key(url_material).xy_hex == load_sm2_public_key(
            vec_keys["sm2"]["publicPointB64"]
        ).xy_hex

    def test_public_not_on_curve_rejected(self):
        # I5：65B 且 04 开头，但点不在 sm2p256v1 曲线上
        x = b"\x01" + os.urandom(31)
        fake = b"\x04" + x + os.urandom(32)  # 随机点，在曲线上的概率 ≈ 2^-128
        material = base64.b64encode(fake).decode()
        with pytest.raises(KeyMaterialError):
            load_sm2_public_key(material)

    def test_public_rsa_bytes_rejected(self, rsa3072):
        # I5：RSA SPKI DER 字节喂 SM2 公钥（长度即不符）
        with pytest.raises(KeyMaterialError):
            load_sm2_public_key(rsa3072["publicSpkiB64"])

    def test_public_missing_04_prefix_rejected(self, vec_keys):
        raw = base64.b64decode(vec_keys["sm2"]["publicPointB64"])
        bad = raw[1:]  # 去掉 04 前缀 → 64B
        with pytest.raises(KeyMaterialError):
            load_sm2_public_key(base64.b64encode(bad).decode())

    def test_private_d_32b(self, vec_keys):
        d = load_sm2_private_key(vec_keys["sm2"]["privateDB64"])
        assert len(d) == 32
        assert int.from_bytes(d, "big") > 0

    def test_private_zero_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_sm2_private_key(base64.b64encode(b"\x00" * 32).decode())

    def test_private_wrong_length_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_sm2_private_key(base64.b64encode(b"\x01" * 31).decode())

    def test_private_garbage_rejected(self):
        with pytest.raises(KeyMaterialError):
            load_sm2_private_key("!!!notbase64")
