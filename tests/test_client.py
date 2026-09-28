# -*- coding: utf-8 -*-
"""WopClient 编排测试：buildRequest（I1/D2/F9/F2/F3）、verifyResponse F6 固定顺序、
回调验证、L0/L2 全链路 roundtrip、幂等。"""
import hashlib
import json

import pytest

import wop_sdk.client as client_mod
from wop_sdk.canonical import build_canonical, canonical_headers
from wop_sdk.client import RequestDraft, WopClient, WopConfig
from wop_sdk.digest import build_digest_header
from wop_sdk.encoding import b64url_encode
from wop_sdk.errors import ConfigurationError
from wop_sdk.envelope import seal_l2
from wop_sdk.signature import sign
from wop_sdk.sm2crypto import PLATFORM_INBOUND_USER_ID, Sm2Ops

RSA_REQ = "WOP-RSA3072-SHA256"
SM_REQ = "WOP-SM2-SM3"
PATH = "/gateway/order.create"


@pytest.fixture(scope="module")
def vec_keys(vectors):
    return vectors["keys"]


@pytest.fixture(scope="module")
def rsa_client(vec_keys):
    return WopClient(
        WopConfig(
            app_key="app_10012481831",
            suite=RSA_REQ,
            merchant_private_key=vec_keys["rsa3072"]["privatePkcs8B64"],
            platform_public_key=vec_keys["rsa3072"]["publicSpkiB64"],
        ),
        csprng=lambda n: b"\x5a" * n,
    )


@pytest.fixture(scope="module")
def sm_client(vec_keys):
    return WopClient(
        WopConfig(
            app_key="app_sm_001",
            suite=SM_REQ,
            merchant_private_key=vec_keys["sm2"]["privateDB64"],
            platform_public_key=vec_keys["sm2"]["publicPointB64"],
        ),
        csprng=lambda n: b"\x77" * n,
    )


@pytest.fixture(autouse=True)
def _freeze_time(monkeypatch):
    monkeypatch.setattr(client_mod, "_now_ms", lambda: 1774340000000)


def platform_l2_response(client, path, plaintext, encrypt_override=None):
    """组装模拟平台的 L2 响应（复用 client 密钥对；spec:D15 平台响应按平台固定
    ZA userId 签名，非商户 appKey——密钥对同源仅为测试便利，身份按方向区分）。

    encrypt_override：以有效签名携带被篡改的 x-wop-encrypt 头（白盒 F6 顺序测试）。
    """
    wire, enc_header = seal_l2(client._suite, client._wrap_pub, plaintext, csprng=client._csprng)
    if encrypt_override is not None:
        enc_header = encrypt_override
    headers = {
        "x-wop-appkey": client._config.app_key,
        "x-wop-timestamp": "1774340000000",
        "x-wop-nonce": "ab" * 16,
        "x-wop-content-digest": build_digest_header(client._suite, wire),
        "x-wop-encrypt": enc_header,
    }
    auth = "v1/1800"
    canonical = build_canonical(auth, "POST", path, "", canonical_headers(headers))
    # spec:D15 SM2 平台响应以平台固定 ZA userId 签名；RSA 无 ZA 概念仍用商户签名者
    if isinstance(client._signer, Sm2Ops):
        signer = Sm2Ops(
            private_key_hex=client._signer.private_key,
            public_xy_hex=client._signer.public_key,
            user_id=PLATFORM_INBOUND_USER_ID,
        )
    else:
        signer = client._signer
    sig = sign(client._suite, signer, canonical.encode("utf-8"), csprng=client._csprng)
    out = dict(headers)
    out["x-wop-sign"] = (
        f'{client._suite.security_req} {auth}/{";".join(sorted(headers))}/{b64url_encode(sig)}'
    )
    return out, wire


class TestBuildRequestL0:
    def test_header_set_and_digest_signed(self, rsa_client):  # spec:I1/D2/F9
        draft = rsa_client.build_request("POST", PATH, {"orderId": 1})
        assert isinstance(draft, RequestDraft)
        h = draft.headers
        assert h["x-wop-appkey"] == "app_10012481831"
        assert h["x-wop-timestamp"] == "1774340000000"
        assert len(h["x-wop-nonce"]) == 32  # 16B hex（F9）
        names = h["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")
        assert "x-wop-content-digest" in names  # I1：digest 必入 signedHeaders
        assert names == sorted(names)
        assert {"x-wop-appkey", "x-wop-nonce", "x-wop-timestamp"} <= set(names)
        tag, hexval = h["x-wop-content-digest"].split(" ")
        assert (tag, len(hexval)) == ("sha-256", 64)
        assert draft.wire_body == json.dumps({"orderId": 1}, separators=(",", ":")).encode()

    def test_get_without_body_digest_absent(self, rsa_client):  # spec:D2 无 body 缺席
        draft = rsa_client.build_request("GET", "/gateway/order.query")
        h = draft.headers
        assert "x-wop-content-digest" not in h
        assert draft.wire_body is None
        names = h["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")
        assert "x-wop-content-digest" not in names
        assert "x-wop-encrypt" not in h

    def test_sign_header_structure(self, rsa_client):  # spec:F3/F7
        draft = rsa_client.build_request("POST", PATH, b"x")
        suite_part, rest = draft.headers["x-wop-sign"].split(" ", 1)
        assert suite_part == RSA_REQ
        segs = rest.split("/")
        assert segs[0] == "v1" and segs[1] == "1800"
        assert len(segs) == 4
        assert len(segs[3]) == 512  # RSA3072 恒 512 字符

    def test_expired_seconds_custom(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"x", expired_seconds=60)
        assert draft.headers["x-wop-sign"].split(" ")[1].split("/")[:2] == ["v1", "60"]

    def test_deterministic_replay(self, rsa_client, monkeypatch):  # spec:§2 幂等
        # 附录 I/I3：缺省 requestId 属 CSPRNG 豁免项；注入固定生成器后全头可重放
        import wop_sdk.client as client_mod
        monkeypatch.setattr(client_mod, "request_id_generator", lambda: "fixedreq" + "0" * 26)
        d1 = rsa_client.build_request("POST", PATH, b"same")
        d2 = rsa_client.build_request("POST", PATH, b"same")
        assert d1.headers == d2.headers and d1.wire_body == d2.wire_body
        assert d1.headers["x-wop-request-id"] == "fixedreq" + "0" * 26

    def test_extra_headers_override(self, rsa_client):
        draft = rsa_client.build_request(
            "POST", PATH, b"x", extra_headers={"X-Custom": "v", "x-wop-nonce": "forced"}
        )
        assert draft.headers["x-custom"] == "v"
        assert draft.headers["x-wop-nonce"] == "forced"

    def test_content_type_added_with_body(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"x")
        assert draft.headers.get("content-type") == "application/json"

    def test_invalid_level_rejected(self, rsa_client):  # spec:2.2 configuration 类
        with pytest.raises(ConfigurationError):
            rsa_client.build_request("POST", PATH, b"x", level="L3")

    def test_l2_without_body_rejected(self, rsa_client):  # spec:2.2 configuration 类
        with pytest.raises(ConfigurationError):
            rsa_client.build_request("POST", PATH, level="L2")

    def test_query_string_signed_in_canonical(self, rsa_client):
        # query_string 进入 canonical 第 4 段（可通过重放 verify 自证）
        draft = rsa_client.build_request("GET", "/q", query_string="a=1&b=2")
        r = rsa_client.verify_response(draft.headers, b"", "/q", method="GET", query_string="a=1&b=2")
        assert r.ok, r.reason
        r2 = rsa_client.verify_response(draft.headers, b"", "/q", method="GET", query_string="b=2")
        assert not r2.ok  # qs 参与 canonical，错 qs 必拒


class TestBuildRequestL2:
    def test_l2_envelope_headers(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, {"secret": True}, level="L2")
        h = draft.headers
        assert h["x-wop-encrypt"].startswith("L2;dek=")
        names = h["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")
        assert "x-wop-encrypt" in names  # L2 必入签
        assert "x-wop-content-digest" in names
        obj = json.loads(draft.wire_body)
        assert "encrypted" in obj
        tag, hexval = h["x-wop-content-digest"].split(" ")
        assert hexval == hashlib.sha256(draft.wire_body).hexdigest()  # D2：digest 对密文载体

    def test_l2_sm_suite(self, sm_client):
        draft = sm_client.build_request("POST", PATH, "国密信封".encode(), level="L2")
        assert draft.headers["x-wop-encrypt"].startswith("L2;dek=")
        assert draft.headers["x-wop-content-digest"].startswith("sm3 ")
        assert len(draft.headers["x-wop-sign"].split("/")[3]) == 86  # SM2 恒 86 字符


class TestConfigValidation:
    def test_suite_parse_error_propagates(self, vec_keys):
        with pytest.raises(Exception):
            WopClient(
                WopConfig(
                    "ak",
                    "WOP-RSA3072-SM3",
                    vec_keys["rsa3072"]["privatePkcs8B64"],
                    vec_keys["rsa3072"]["publicSpkiB64"],
                )
            )

    def test_key_family_mismatch_rejected(self, vec_keys):  # spec:I5
        with pytest.raises(Exception):
            WopClient(
                WopConfig(
                    "ak", SM_REQ,
                    vec_keys["rsa3072"]["privatePkcs8B64"],
                    vec_keys["sm2"]["publicPointB64"],
                )
            )

    def test_bits_mismatch_rejected(self, vec_keys):
        with pytest.raises(Exception):
            WopClient(
                WopConfig(
                    "ak", RSA_REQ,
                    vec_keys["rsa4096"]["privatePkcs8B64"],
                    vec_keys["rsa3072"]["publicSpkiB64"],
                )
            )

    def test_empty_appkey_rejected(self, vec_keys):
        with pytest.raises(Exception):
            WopClient(
                WopConfig(
                    "", RSA_REQ,
                    vec_keys["rsa3072"]["privatePkcs8B64"],
                    vec_keys["rsa3072"]["publicSpkiB64"],
                )
            )


class TestVerifyResponseL0:
    def test_l0_roundtrip_rsa(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b'{"code":0}')
        result = rsa_client.verify_response(draft.headers, draft.wire_body, PATH)
        assert result.ok, result.reason
        assert result.plaintext == draft.wire_body

    def test_l0_sm_self_draft_rejected(self, sm_client):  # spec:D15 否定式
        # D15 拆分：入向验签身份=平台固定值 ≠ 出向签名身份=appKey（D14），
        # 自发出向 draft 冒充平台响应必须被拒（RSA 无 ZA 概念，自回环不受影响）
        draft = sm_client.build_request("POST", PATH, "中文响应".encode())
        result = sm_client.verify_response(draft.headers, draft.wire_body, PATH)
        assert not result.ok

    def test_l0_no_body_response_ok(self, rsa_client):
        draft = rsa_client.build_request("GET", "/q")
        result = rsa_client.verify_response(draft.headers, b"", "/q", method="GET")
        assert result.ok and result.plaintext == b""

    def test_header_case_insensitive(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"b")
        mixed = {k.upper(): v for k, v in draft.headers.items()}
        assert rsa_client.verify_response(mixed, draft.wire_body, PATH).ok

    def test_sign_header_missing_rejected(self, rsa_client):
        r = rsa_client.verify_response({}, b"body", PATH)
        assert not r.ok and r.reason

    def test_sign_header_bad_structure_rejected(self, rsa_client):
        r = rsa_client.verify_response({"x-wop-sign": "garbage"}, b"b", PATH)
        assert not r.ok

    def test_sign_header_no_space_rejected(self, rsa_client):
        r = rsa_client.verify_response({"x-wop-sign": "WOP-RSA3072-SHA256v1/1/a/b"}, b"b", PATH)
        assert not r.ok

    def test_sign_header_three_segments_rejected(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"b")
        h = dict(draft.headers)
        suite, rest = h["x-wop-sign"].split(" ", 1)
        h["x-wop-sign"] = f"{suite} " + "/".join(rest.split("/")[:3])
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_bad_version_rejected(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"b")
        h = dict(draft.headers)
        suite, rest = h["x-wop-sign"].split(" ", 1)
        segs = rest.split("/")
        segs[0] = "v2"
        h["x-wop-sign"] = f"{suite} " + "/".join(segs)
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_tampered_body_hits_digest_check(self, rsa_client):  # spec:F6/D2 顺序②
        """body 篡改：头（签名覆盖物）完好 → 验签过 → digest 复核拦截。"""
        draft = rsa_client.build_request("POST", PATH, b'{"code":0}')
        r = rsa_client.verify_response(draft.headers, b'{"code":1}', PATH)
        assert not r.ok
        assert r.reason == "内容摘要不匹配"  # 完整性类明确（10.2）

    def test_tampered_signed_header_fails_sign_first(self, rsa_client):  # spec:F6/I2 顺序①
        """digest 头参与签名（I1）：篡改签内头 → 必先撞签名（I7 模糊）。"""
        draft = rsa_client.build_request("POST", PATH, b'{"code":0}')
        h = dict(draft.headers)
        h["x-wop-content-digest"] = "sha-256 " + "0" * 64
        r = rsa_client.verify_response(h, draft.wire_body, PATH)
        assert not r.ok
        assert r.reason == "签名验证失败"

    def test_body_present_digest_absent_rejected(self, rsa_client):  # spec:D2 有 body 必传
        draft = rsa_client.build_request("POST", PATH, b'{"code":0}')
        h = dict(draft.headers)
        h.pop("x-wop-content-digest")
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_digest_b64_padding_signature_rejected(self, rsa_client):  # spec:F7 带 = 拒
        draft = rsa_client.build_request("POST", PATH, b"b")
        h = dict(draft.headers)
        suite, rest = h["x-wop-sign"].split(" ", 1)
        segs = rest.split("/")
        segs[3] += "="
        h["x-wop-sign"] = f"{suite} " + "/".join(segs)
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_signed_header_missing_in_headers_rejected(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"b")
        h = dict(draft.headers)
        h.pop("x-wop-nonce")
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_suite_in_sign_header_mismatch_rejected(self, rsa_client):
        draft = rsa_client.build_request("POST", PATH, b"b")
        h = dict(draft.headers)
        h["x-wop-sign"] = f"{SM_REQ} " + h["x-wop-sign"].split(" ", 1)[1]
        assert not rsa_client.verify_response(h, draft.wire_body, PATH).ok

    def test_verify_callback_same_flow(self, rsa_client):  # spec:F6 回调
        draft = rsa_client.build_request("POST", "/callback/notify", b'{"event":"paid"}')
        r = rsa_client.verify_callback(draft.headers, draft.wire_body, "/callback/notify")
        assert r.ok and r.plaintext == draft.wire_body


class TestVerifyResponseL2:
    def test_l2_roundtrip_rsa(self, rsa_client):
        plain = b'{"secret":"payload"}'
        headers, wire = platform_l2_response(rsa_client, PATH, plain)
        r = rsa_client.verify_response(headers, wire, PATH)
        assert r.ok, r.reason
        assert r.plaintext == plain

    def test_l2_roundtrip_sm(self, sm_client):
        plain = "国密信封响应".encode()
        headers, wire = platform_l2_response(sm_client, PATH, plain)
        r = sm_client.verify_response(headers, wire, PATH)
        assert r.ok, r.reason
        assert r.plaintext == plain

    def test_dek_blurred_before_consistency_check_order(self, rsa_client):  # spec:F6 顺序③
        """坏 dek + 有效签名（重签）→ 验签过、digest 过 → DEK 解包模糊拒绝。"""
        headers, wire = platform_l2_response(rsa_client, PATH, b"m", encrypt_override="L2;dek=" + "A" * 512)
        r = rsa_client.verify_response(headers, wire, PATH)
        assert not r.ok and r.reason == "解密失败"

    def test_l2_encrypt_header_malformed_rejected(self, rsa_client):
        headers, wire = platform_l2_response(rsa_client, PATH, b"m", encrypt_override="L2")
        r = rsa_client.verify_response(headers, wire, PATH)
        assert not r.ok and "x-wop-encrypt" in r.reason

    def test_digest_over_cipher_wire(self, rsa_client):  # spec:D2 L2 摘要对象=密文载体
        headers, wire = platform_l2_response(rsa_client, PATH, b"m")
        raw = bytearray(wire)
        raw[len(raw) // 2] ^= 0x01  # 翻密文载体中间字节
        r = rsa_client.verify_response(headers, bytes(raw), PATH)
        assert not r.ok and r.reason == "内容摘要不匹配"  # digest 复核先于解密

    def test_l2_sm_tampered_wire_blurred(self, sm_client):
        headers, wire = platform_l2_response(sm_client, PATH, b"msg")
        bad = bytearray(wire)
        bad[-3] ^= 0x01
        r = sm_client.verify_response(headers, bytes(bad), PATH)
        assert not r.ok and r.reason == "内容摘要不匹配"


class TestRequestIdPassthrough:  # spec:wop-sdk-spec 附录 I（x-wop-request-id）
    """附录 I 三条对齐重点：I1 恒不入签、I2 值校验（控制字符/UTF-8 字节长）、
    I3 缺省生成（UUID 去连字符小写 32 hex）与日志义务。"""

    def test_explicit_value_trimmed_upstream(self, rsa_client):
        draft = rsa_client.build_request("GET", "/q", request_id="  req-001  ")
        assert draft.headers["x-wop-request-id"] == "req-001"  # trim 后原值，除 trim 外禁止改写

    def test_never_signed_and_sign_bytes_unchanged(self, rsa_client):  # spec:附录 I/I1
        with_id = rsa_client.build_request("GET", "/q", request_id="req-001")
        without = rsa_client.build_request("GET", "/q")
        signed_names = with_id.headers["x-wop-sign"].split("/")[2].split(";")
        assert "x-wop-request-id" not in signed_names
        assert with_id.headers["x-wop-sign"] == without.headers["x-wop-sign"]

    def test_default_generated_uuid32_and_fresh_per_call(self, rsa_client):  # spec:附录 I/I3
        import re

        a = rsa_client.build_request("GET", "/q")
        b = rsa_client.build_request("GET", "/q")
        assert re.fullmatch(r"[0-9a-f]{32}", a.headers["x-wop-request-id"])
        assert re.fullmatch(r"[0-9a-f]{32}", b.headers["x-wop-request-id"])
        assert a.headers["x-wop-request-id"] != b.headers["x-wop-request-id"]
        # 空格 trim 后为空 → 视为未设置，走缺省生成（\t/\n 属控制字符，trim 前扫描即拒）
        blank = rsa_client.build_request("GET", "/q", request_id="   ")
        assert re.fullmatch(r"[0-9a-f]{32}", blank.headers["x-wop-request-id"])

    @pytest.mark.parametrize(
        "bad",
        ["a\nb", "a\rb", "a\x00b", "a\x7fb", "a\tb", "\nlead", "trail\r", " \t ", "\x00", "\x7f"],
    )
    def test_control_chars_rejected_pre_trim(self, rsa_client, bad):  # spec:附录 I/I2
        with pytest.raises(ConfigurationError, match="控制字符"):
            rsa_client.build_request("GET", "/q", request_id=bad)

    def test_length_measured_in_utf8_bytes(self, rsa_client):  # spec:附录 I/I2
        # 128 ASCII 字节 OK；129 拒；42 中文 = 126 字节 OK；43 = 129 字节拒
        ok = rsa_client.build_request("GET", "/q", request_id="x" * 128)
        assert ok.headers["x-wop-request-id"] == "x" * 128
        with pytest.raises(ConfigurationError, match="UTF-8 字节长度不能超过 128（实际 129）"):
            rsa_client.build_request("GET", "/q", request_id="x" * 129)
        ok_cjk = rsa_client.build_request("GET", "/q", request_id="标" * 42)
        assert ok_cjk.headers["x-wop-request-id"] == "标" * 42
        with pytest.raises(ConfigurationError, match="UTF-8 字节长度不能超过 128（实际 129）"):
            rsa_client.build_request("GET", "/q", request_id="标" * 43)

    def test_outbound_log_contains_final_value(self, rsa_client, caplog):  # spec:附录 I/I3 日志义务
        import logging

        with caplog.at_level(logging.INFO, logger="wop_sdk.outbound"):
            rsa_client.build_request("GET", "/q", request_id="logreq001")
        lines = [r.getMessage() for r in caplog.records]
        assert any("x-wop-request-id=logreq001" in m and "GET /q" in m for m in lines)

    def test_injected_generator_bypasses_csprng_stream(self, rsa_client, monkeypatch):  # spec:I3 注入锚
        monkeypatch.setattr(client_mod, "request_id_generator", lambda: "gen-anchor-001")
        draft = rsa_client.build_request("POST", PATH, b"msg", level="L2")
        assert draft.headers["x-wop-request-id"] == "gen-anchor-001"
