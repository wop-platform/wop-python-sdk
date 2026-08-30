# -*- coding: utf-8 -*-
"""L2 数字信封（F5/D10/I3/I4/I7）。

- 报文加密：AES-256-GCM（cryptography）/ SM4-GCM（自研 GCM × gmssl SM4）；
  线上密文 = ciphertext‖tag 尾拼，整体 base64url 无填充；
- DEK 包装：RSA-OAEP（显式双 SHA-256 + 空 label，F2 头号漂移源）/ SM2（C1C3C2 裸拼接）；
- DEK 载荷：alg$base64url(key)$base64url(iv)；alg 族比对在解包后、bulk 解密前（D8/I3）；
- 解密失败（GCM tag、KDF、C3、OAEP）对外一律"解密失败"（I7 模糊化）。
"""
import hashlib
import json
import os
from typing import Callable, Tuple, Union, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .encoding import b64url_decode, b64url_encode
from .errors import DecryptError, DekConsistencyError, ProtocolFormatError
from .sm2crypto import Sm2Ops, sm2_decrypt, sm2_encrypt
from .sm4gcm import sm4_gcm_decrypt, sm4_gcm_encrypt
from .suites import Suite

Csprng = Callable[[int], bytes]
KeyMaterial = Union[rsa.RSAPublicKey, rsa.RSAPrivateKey, Sm2Ops]

_AES_KEY_LEN = 32
_SM4_KEY_LEN = 16
_IV_LEN = 12
_TAG_LEN = 16


def message_encrypt(suite: Suite, key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """报文对称加密 → ciphertext‖tag（F4 尾拼格式）。"""
    if suite.family == "RSA":
        if len(key) != _AES_KEY_LEN or len(iv) != _IV_LEN:
            raise DecryptError("解密失败")
        enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        return enc.update(plaintext) + enc.finalize() + enc.tag
    if len(key) != _SM4_KEY_LEN or len(iv) != _IV_LEN:
        raise DecryptError("解密失败")
    return sm4_gcm_encrypt(key, iv, plaintext, aad)


def message_decrypt(suite: Suite, key: bytes, iv: bytes, cipher_tag: bytes, aad: bytes = b"") -> bytes:
    """报文对称解密（输入 ciphertext‖tag）；任何失败对外模糊（I7）。"""
    if suite.family == "RSA":
        if len(key) != _AES_KEY_LEN or len(iv) != _IV_LEN or len(cipher_tag) < _TAG_LEN:
            raise DecryptError("解密失败")
        cipher, tag = cipher_tag[:-_TAG_LEN], cipher_tag[-_TAG_LEN:]
        dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        try:
            return dec.update(cipher) + dec.finalize()
        except Exception:
            raise DecryptError() from None
    if len(key) != _SM4_KEY_LEN or len(iv) != _IV_LEN or len(cipher_tag) < _TAG_LEN:
        raise DecryptError("解密失败")
    try:
        return sm4_gcm_decrypt(key, iv, cipher_tag, aad)
    except ValueError:
        raise DecryptError() from None


# OAEP 显式参数化（F2/D10）：OAEP 摘要 SHA-256 + MGF1 摘要显式钉死 SHA-256 + 空 label。
# JCA 串 OAEPWithSHA-256AndMGF1Padding 的 MGF1 默认 SHA-1，禁止依赖默认值。
def _oaep_params() -> _rsa_padding.OAEP:
    return _rsa_padding.OAEP(
        mgf=_rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_dek(suite: Suite, wrap_pub: KeyMaterial, payload: bytes, csprng: Csprng = os.urandom) -> bytes:
    """DEK 非对称包装（出向，平台公钥）。SM2 的 k 与 RSA-OAEP 的 seed 均走 csprng
    （I4 + interop 合同：OAEP-from-stream 确定——确定性钩子须覆盖全部随机消费点）。"""
    if suite.family == "RSA":
        return _rsa_oaep_encrypt_from_stream(cast(rsa.RSAPublicKey, wrap_pub), payload, csprng)
    return sm2_encrypt(cast(Sm2Ops, wrap_pub), csprng, payload)


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    """MGF1（SHA-256，RFC 8017 B.2.1）。"""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def _rsa_oaep_encrypt_from_stream(
    pub: rsa.RSAPublicKey, message: bytes, csprng: Csprng
) -> bytes:
    """RSAES-OAEP-ENCRYPT（RFC 8017 7.1.1）：摘要/MGF1 均钉死 SHA-256、空 label（F2/D10），
    seed 显式取自 csprng——与 Go EncryptOAEP(hash, random, …) 的随机流消费位逐字节对齐
    （interop/v1：RSA L2 build 样本 byte-exact 的前提）。
    """
    h_len = 32  # SHA-256 摘要长
    nums = pub.public_numbers()
    k = (nums.n.bit_length() + 7) // 8
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("OAEP 载荷超长：%d > %d" % (len(message), k - 2 * h_len - 2))
    l_hash = hashlib.sha256(b"").digest()  # 空 label
    seed = csprng(h_len)
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    db_mask = _mgf1_sha256(seed, k - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1_sha256(masked_db, h_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b"\x00" + masked_seed + masked_db
    m = int.from_bytes(em, "big")
    return pow(m, nums.e, nums.n).to_bytes(k, "big")


def unwrap_dek(suite: Suite, wrap_priv: KeyMaterial, wrapped: bytes) -> bytes:
    """DEK 解包（入向）；失败对外模糊（I7）。"""
    if suite.family == "RSA":
        try:
            return cast(rsa.RSAPrivateKey, wrap_priv).decrypt(wrapped, _oaep_params())
        except Exception:
            raise DecryptError() from None
    try:
        return sm2_decrypt(cast(Sm2Ops, wrap_priv), wrapped)
    except DecryptError:
        raise
    except Exception:
        raise DecryptError() from None


def build_dek_payload(suite: Suite, key: bytes, iv: bytes) -> str:
    """DEK 载荷 alg$base64url(key)$base64url(iv)（§6.1）。"""
    return f"{suite.message_alg}${b64url_encode(key)}${b64url_encode(iv)}"


def parse_dek_payload(suite: Suite, payload: str) -> Tuple[bytes, bytes]:
    """解析 DEK 载荷（明文，已解包后调用）。

    时序（D8/I3）：alg 段在载荷明文内部 → 解包之后、bulk 解密之前完成族比对。
    alg 与套件族不符 → 一致性类（明确）；结构/编码错误 → 解析类（明确）。
    """
    parts = payload.split("$")
    if len(parts) != 3:
        raise ProtocolFormatError("DEK 载荷必须为 alg$key$iv 三段，实际 %d 段" % len(parts))
    alg, key_b64u, iv_b64u = parts
    if alg not in ("AES-256-GCM", "SM4-GCM"):
        raise ProtocolFormatError("DEK 载荷 alg 未知：%r" % alg)
    if alg != suite.message_alg:  # I3/I5：族比对先于 bulk 解密
        raise DekConsistencyError(
            f"DEK 算法 {alg} 与套件 {suite.security_req} 要求的 {suite.message_alg} 不符"
        )
    try:
        key = b64url_decode(key_b64u)
        iv = b64url_decode(iv_b64u)
    except ValueError as exc:
        raise ProtocolFormatError(f"DEK 载荷 key/iv 编码非法：{exc}") from exc
    expected_key_len = _AES_KEY_LEN if suite.family == "RSA" else _SM4_KEY_LEN
    if len(key) != expected_key_len or len(iv) != _IV_LEN:
        raise ProtocolFormatError(
            "DEK 载荷 key/iv 长度非法（key %d、iv %d）" % (len(key), len(iv))
        )
    return key, iv


def seal_l2(
    suite: Suite, platform_pub: KeyMaterial, plaintext: bytes, csprng: Csprng = os.urandom
) -> Tuple[bytes, str]:
    """L2 加密封装 → (wireBody, x-wop-encrypt 头)。

    DEK 与 IV 均由 csprng 生成（I4：同一密钥下 IV 永不复用，生成点唯一）。
    """
    key_len = _AES_KEY_LEN if suite.family == "RSA" else _SM4_KEY_LEN
    key = csprng(key_len)
    iv = csprng(_IV_LEN)
    cipher_tag = message_encrypt(suite, key, iv, plaintext)
    wire_body = json.dumps({"encrypted": b64url_encode(cipher_tag)}, separators=(",", ":")).encode()
    payload = build_dek_payload(suite, key, iv).encode("utf-8")
    wrapped = wrap_dek(suite, platform_pub, payload, csprng)
    return wire_body, f"L2;dek={b64url_encode(wrapped)}"


def open_l2(suite: Suite, wrap_priv: KeyMaterial, wire_body: bytes, dek_b64u: str) -> bytes:
    """L2 解密（F6 第 4–6 步）：DEK 解包（模糊）→ alg 族比对（明确）→ bulk 解密（模糊）。

    错误分类（playbook §0 / interop 合同）：
    - 信封 JSON 形态与各 base64url 段 = 公开结构知识 → 解析类明确（P2/n12）；
    - DEK 载荷为解包后明文，除 alg 跨族（D8 明确）外一律解密类模糊（I7，P3/n13）。
    """
    try:
        wrapped = b64url_decode(dek_b64u)
    except ValueError:
        raise ProtocolFormatError("x-wop-encrypt 的 dek 值非合法 base64url（F7）") from None
    try:
        payload = unwrap_dek(suite, wrap_priv, wrapped).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # 解包成功但载荷非 UTF-8 → 与解包失败同归模糊（I7），不得向商户层逃逸
        raise DecryptError() from None
    try:
        key, iv = parse_dek_payload(suite, payload)
    except DekConsistencyError:
        raise  # alg 跨族：解包后明文内的公开映射知识，明确（D8/I3）
    except ProtocolFormatError:
        # 载荷结构在解包后才可见，属密钥参与层；除 alg 跨族外一律归入解密类
        # 模糊（I7 保守默认，interop 合同 n13 / playbook P3）
        raise DecryptError() from None
    try:
        obj = json.loads(wire_body)
        encrypted = obj["encrypted"]
    except Exception:
        raise ProtocolFormatError("L2 请求体须为含 encrypted 字段的 JSON 信封") from None
    try:
        cipher_tag = b64url_decode(encrypted)
    except (ValueError, TypeError):
        raise ProtocolFormatError("L2 请求体 encrypted 字段非合法 base64url（F7）") from None
    return message_decrypt(suite, key, iv, cipher_tag)
