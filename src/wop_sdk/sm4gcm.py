# -*- coding: utf-8 -*-
"""SM4-GCM（NIST SP 800-38D GCM 构造 × GB/T 32907 SM4 分组函数）。

gmssl ≥3.2.2 仅提供 SM4 ECB/CBC，无 GCM；本模块以 gmssl ``one_round``（无 padding
的单块加密原语）为底层分组函数实现 GCM（CTR + GHASH），正确性由黄金向量
sm4gcm-encrypt 字节级锚定（D11：官方 SDK 即 SM 生态答案）。
"""
from gmssl.sm4 import SM4_ENCRYPT, CryptSM4

_R = 0xE1 << 120  # GF(2^128) 约减多项式 x^128+x^7+x^2+x+1

def _gf_mult(x: int, y: int) -> int:
    """GF(2^128) 乘法（MSB-first 位串，SP 800-38D Algorithm 1）。"""
    z, v = 0, x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


class _Sm4Block:
    """SM4 单块加密函数对象（密钥扩展一次，线程封闭使用）。"""

    def __init__(self, key: bytes):
        self._cipher = CryptSM4()
        self._cipher.set_key(key, SM4_ENCRYPT)

    def __call__(self, block: bytes) -> bytes:
        return bytes(self._cipher.one_round(self._cipher.sk, list(block)))


def _ghash(h: int, aad: bytes, cipher: bytes) -> int:
    pad_a = (16 - len(aad) % 16) % 16
    pad_c = (16 - len(cipher) % 16) % 16
    data = (
        aad
        + b"\x00" * pad_a
        + cipher
        + b"\x00" * pad_c
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(cipher) * 8).to_bytes(8, "big")
    )
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mult(y ^ int.from_bytes(data[i : i + 16], "big"), h)
    return y


def _gcm_core(block_fn, iv: bytes, data: bytes, aad: bytes, ghash_over_input: bool):
    """GCM 公共路径：返回 (输出块, tag)。

    GHASH 恒作用于密文：加密方向密文 = CTR 输出，解密方向密文 = 输入 data。
    """
    h = int.from_bytes(block_fn(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ctr = int.from_bytes(j0, "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)  # inc32：仅低 32 位
        keystream = block_fn(ctr.to_bytes(16, "big"))
        out += bytes(p ^ k for p, k in zip(data[off : off + 16], keystream))
    ghash_input = data if ghash_over_input else bytes(out)
    s = _ghash(h, aad, ghash_input)
    tag = bytes(a ^ b for a, b in zip(block_fn(j0), s.to_bytes(16, "big")))
    return bytes(out), tag


def sm4_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """SM4-GCM 加密，返回 ciphertext‖tag（F4：tag 128bit 尾拼）。"""
    out, tag = _gcm_core(_Sm4Block(key), iv, plaintext, aad, ghash_over_input=False)
    return out + tag


def sm4_gcm_decrypt(key: bytes, iv: bytes, cipher_tag: bytes, aad: bytes = b"") -> bytes:
    """SM4-GCM 解密（输入 ciphertext‖tag）；tag 不符抛 ValueError。"""
    if len(cipher_tag) < 16:
        raise ValueError("密文短于 tag 长度")
    cipher, tag = cipher_tag[:-16], cipher_tag[-16:]
    out, expect = _gcm_core(_Sm4Block(key), iv, cipher, aad, ghash_over_input=True)
    if bytes(a ^ b for a, b in zip(tag, expect)) != b"\x00" * 16:
        raise ValueError("GCM tag 校验失败")
    return out
