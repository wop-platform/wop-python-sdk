# -*- coding: utf-8 -*-
"""变异测试缺口补杀（docs/mutation-report.md 存活体的可杀子集）。

对应存活变异体与契约依据：
- client.py WopConfig `frozen=True` / keys.py Sm2PublicKey `frozen=True`：
  配置与密钥材料不可变是 API 契约（防运行中被意外篡改）→ 断言 FrozenInstanceError。
- keys.py `_SM2_N`：D12/I5 边界合同 1 ≤ d < n —— d == n 必须被拒、d == n-1 必须被接受。
  期望值独立硬编码（GB/T 32918.5 sm2p256v1 曲线阶），禁止从被测模块导入（防镜像期望）。
- sm4gcm.py encrypt/decrypt `aad=b""` 默认值：F5 线上字节合同（GHASH 恒以空 AAD 参与），
  默认调用与显式 aad=b"" 必须逐字节一致、可互解。

其余存活体为等价变异（不修，见 mutation-report.md）：
encoding.py:17（字母表字典追加永不查询的键）、sm2crypto.py:19（int(x,17) 对十六进制串解析同值）、
sm2crypto.py:24（CSPRNG 重试上界 256→257，概率等价 ≈2^-2048）、
httpx/requests_transport 注解字符串（惰性求值，运行时不可观测）。
"""
import base64
from dataclasses import FrozenInstanceError

import pytest
from typing import get_type_hints

from wop_sdk.client import WopConfig
from wop_sdk.errors import DecryptError, KeyMaterialError
from wop_sdk.keys import Sm2PublicKey, load_sm2_private_key
from wop_sdk.sm2crypto import Sm2Ops, sm2_encrypt
from wop_sdk.sm4gcm import sm4_gcm_decrypt, sm4_gcm_encrypt

_KEY16 = bytes(range(16))
_IV12 = bytes(range(12))


class TestFrozenContracts:
    def test_wop_config_immutable(self):  # spec:mutation-kill frozen 契约
        config = WopConfig(
            app_key="a",
            suite="WOP-RSA3072-SHA256",
            merchant_private_key="x",
            platform_public_key="y",
        )
        with pytest.raises(FrozenInstanceError):
            config.app_key = "b"

    def test_sm2_public_key_immutable(self):  # spec:mutation-kill frozen 契约
        pk = Sm2PublicKey(xy_hex="11" * 64, uncompressed=b"\x04" + b"\x11" * 64)
        with pytest.raises(FrozenInstanceError):
            pk.xy_hex = "22" * 64


class TestSm2ScalarBoundary:
    # sm2p256v1 曲线阶 n（GB/T 32918.5）——独立硬编码，禁止从被测模块导入
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

    def test_d_equals_n_rejected(self):  # spec:D12 1 ≤ d < n 上界
        material = base64.b64encode(self.N.to_bytes(32, "big")).decode()
        with pytest.raises(KeyMaterialError, match="超出"):
            load_sm2_private_key(material)

    def test_d_equals_n_minus_one_accepted(self):  # spec:D12 边界内侧合法
        material = base64.b64encode((self.N - 1).to_bytes(32, "big")).decode()
        assert load_sm2_private_key(material) == (self.N - 1).to_bytes(32, "big")


class TestSm4GcmEmptyAadDefault:
    def test_default_aad_equals_explicit_empty(self):  # spec:F5 GHASH 空 AAD 合同
        ct_default = sm4_gcm_encrypt(_KEY16, _IV12, b"payload-42")
        ct_explicit = sm4_gcm_encrypt(_KEY16, _IV12, b"payload-42", aad=b"")
        assert ct_default == ct_explicit

    def test_default_aad_decrypt_roundtrip(self):  # spec:F5 解密侧同合同
        ct = sm4_gcm_encrypt(_KEY16, _IV12, b"payload-42", aad=b"")
        assert sm4_gcm_decrypt(_KEY16, _IV12, ct) == b"payload-42"
        assert sm4_gcm_decrypt(_KEY16, _IV12, ct, aad=b"") == b"payload-42"


class TestSm2EncryptRetryCeiling:
    """_MAX_K_RETRY 重试上界是可注入观测的硬边界（PR #17 Sourcery 审查修正）。

    概率近似（真实 CSPRNG 连续越界 ≈2^-2048）≠ 等价：csprng 是注入点，
    「连续 256 次越界后仍越界」与「第 257 次有效」行为分叉——原实现必须
    DecryptError，重试上界 ±1 的变异体必须被此测试击杀。
    """

    @staticmethod
    def _csprng(invalid_count):
        state = {"n": 0}

        def gen(size):
            i = state["n"]
            state["n"] += 1
            if i < invalid_count:
                return b"\xff" * size  # k = 2^(8·size)−1 ≥ N，恒越界
            return b"\x00" * (size - 1) + b"\x01"  # k = 1，合法

        return gen

    @pytest.fixture()
    def enc_ops(self, vectors):
        xy = base64.b64decode(vectors["keys"]["sm2"]["publicPointB64"])[1:].hex()
        return Sm2Ops(public_xy_hex=xy)

    def test_ceiling_exhausted_raises(self, enc_ops):  # spec:mutation-kill I4 重试上界
        with pytest.raises(DecryptError):
            sm2_encrypt(enc_ops, self._csprng(256), b"payload")

    def test_retry_then_success(self, enc_ops):  # 重试语义：越界后有效采样必须恢复
        out = sm2_encrypt(enc_ops, self._csprng(3), b"payload")
        assert out[0] == 0x04 and len(out) == 65 + 32 + len(b"payload")


class TestAnnotationReflection:
    """注解字符串写入 __annotations__ 且可被 get_type_hints 解析。

    原先以「惰性求值不可观测」将 __enter__ 返回类型注解入册等价被证伪
    （PR #17 CodeRabbit 审查）：变异为 "HttpxTransport!" 后 get_type_hints
    即抛 NameError——公共 API 反射面是可观测契约。本测试击杀该对变异体。
    """

    def test_enter_return_annotations_resolve(self):  # spec:mutation-kill 注解反射
        from wop_sdk.transports.httpx_transport import HttpxTransport
        from wop_sdk.transports.requests_transport import RequestsTransport

        assert get_type_hints(HttpxTransport.__enter__)["return"] is HttpxTransport
        assert get_type_hints(RequestsTransport.__enter__)["return"] is RequestsTransport
