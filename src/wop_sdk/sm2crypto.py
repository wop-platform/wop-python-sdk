# -*- coding: utf-8 -*-
"""SM2 底层操作：签名（裸 r‖s，D9）、加密（C1C3C2，D9）、解密（含 gmssl 缺失的 C3 校验）。

与 gmssl 原生 API 的差异（均为刻意为之）：
1. 绕开 ``CryptSM2.__init__`` 的 ``public_key.lstrip("04")`` 缺陷——合法 X 以 '0'/'4' 字符
   开头时（概率 ≈ 1/8）会被误剥，本类覆写 public_key 为标准 X‖Y 128+128 hex；
2. gmssl ``decrypt`` 计算摘要 u 却从不比对 C3——本模块自研解密补上完整性校验，
   C1C2C3 旧国标顺序密文在此必然失败（顺序钉死负向量的拦截点）；
3. gmssl ``encrypt``/``random_hex`` 使用 ``random.choice``（非 CSPRNG）——本模块的 k
   一律由调用方注入（生产走 csprng，测试走固定向量，I4）。
"""
from typing import Optional, cast

from gmssl import sm3 as _sm3
from gmssl.sm2 import CryptSM2, default_ecc_table

from .errors import DecryptError, KeyMaterialError

_N = int(default_ecc_table["n"], 16)
_P = int(default_ecc_table["p"], 16)
_A = int(default_ecc_table["a"], 16)
_B = int(default_ecc_table["b"], 16)

_MAX_K_RETRY = 256


class Sm2Ops(CryptSM2):
    """SM2 曲线运算封装（无可变共享状态）。"""

    def __init__(self, private_key_hex: Optional[str] = None, public_xy_hex: Optional[str] = None):
        super().__init__(private_key_hex or "00" * 32, "00" * 128)
        # 覆写绕过 lstrip 缺陷；public_key 恒为 X‖Y（128+128 hex，无 04 前缀）
        if public_xy_hex is not None:
            if len(public_xy_hex) != 64 * 2:
                raise KeyMaterialError("SM2 公钥 hex 必须为 X||Y 共 128 字符（X‖Y 各 32 字节）")
            self.public_key = public_xy_hex
        if private_key_hex is not None:
            self.private_key = private_key_hex


def _point_on_curve(xy_hex: str) -> bool:
    x = int(xy_hex[:64], 16)
    y = int(xy_hex[64:], 16)
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def sm2_sign_with_sm3(ops: Sm2Ops, data: bytes, k_hex: str) -> bytes:
    """SM3withSM2 签名：e = SM3(ZA‖M)，ZA userId = '1234567812345678'；输出裸 r‖s 64B。"""
    e_hex = ops._sm3_z(data)
    sig_hex = cast(str, ops.sign(bytes.fromhex(e_hex), k_hex))
    return bytes.fromhex(sig_hex)


def sm2_verify_with_sm3(ops: Sm2Ops, sig_hex: str, data: bytes) -> bool:
    """SM3withSM2 验签（裸 r‖s hex）。"""
    return bool(ops.verify_with_sm3(sig_hex, data))


def sm2_encrypt(ops: Sm2Ops, csprng, plaintext: bytes) -> bytes:
    """SM2 加密，线上格式 C1C3C2 裸拼接（C1 = 未压缩点 04‖X‖Y 65B）。

    k 由 csprng 注入（I4：CSPRNG，随机数生成点收敛于调用方）。
    """
    for _ in range(_MAX_K_RETRY):
        k = int.from_bytes(csprng(32), "big")
        if 1 <= k < _N:
            break
    else:  # pragma: no cover —— CSPRNG 连续 256 次不可用采样概率 ≈ 2^-2048
        raise DecryptError("解密失败")
    c1_xy = cast(str, ops._kg(k, ops.ecc_table["g"]))
    x2y2 = cast(str, ops._kg(k, ops.public_key))
    x2, y2 = x2y2[:64], x2y2[64:]
    c2 = _xor_kdf(plaintext, x2y2)
    c3 = _sm3.sm3_hash(list(bytes.fromhex(x2 + plaintext.hex() + y2)))
    return bytes.fromhex("04" + c1_xy + c3) + c2


def sm2_decrypt(ops: Sm2Ops, cipher: bytes) -> bytes:
    """SM2 解密（C1C3C2），C3 摘要校验失败抛 DecryptError（I7 模糊，不区分细节）。"""
    if len(cipher) < 65 + 32 + 1 or cipher[0] != 0x04:
        raise DecryptError("解密失败")
    c1_xy_hex = cipher[1:65].hex()
    if not _point_on_curve(c1_xy_hex):
        raise DecryptError("解密失败")
    c3_hex = cipher[65:97].hex()
    c2 = cipher[97:]
    x2y2 = cast(str, ops._kg(int(ops.private_key, 16), c1_xy_hex))
    x2, y2 = x2y2[:64], x2y2[64:]
    plaintext = _xor_kdf(c2, x2y2)
    u = _sm3.sm3_hash(list(bytes.fromhex(x2 + plaintext.hex() + y2)))
    if u != c3_hex:
        raise DecryptError("解密失败")
    return plaintext


def _xor_kdf(data: bytes, xy_hex: str) -> bytes:
    """SM2 KDF（x2‖y2 作种子）与数据异或；密钥流全零视为失败（概率 2^-128）。"""
    t = _sm3.sm3_kdf(xy_hex, len(data))
    if int(t, 16) == 0:
        raise DecryptError("解密失败")
    form = "%%0%dx" % (len(data) * 2)
    return bytes.fromhex(form % (int(data.hex(), 16) ^ int(t, 16)))
