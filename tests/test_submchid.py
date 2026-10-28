# -*- coding: utf-8 -*-
"""ISV D-13：子商户身份头 x-wop-sub-mch-id 入签与 AC-20 零回归。"""
import pytest

import wop_sdk.client as client_mod
from wop_sdk.canonical import build_canonical, canonical_headers
from wop_sdk.client import WopClient, WopConfig
from wop_sdk.encoding import b64url_decode
from wop_sdk.errors import ConfigurationError
from wop_sdk.keys import load_rsa_public_key
from wop_sdk.signature import verify

RSA_REQ = "WOP-RSA3072-SHA256"
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


def _assert_signature_valid(client, draft, pub_b64):
    suite_part, rest = draft.headers["x-wop-sign"].split(" ", 1)
    version, expired, names, sig = rest.split("/")
    assert suite_part == RSA_REQ
    signed_map = {n: draft.headers[n] for n in names.split(";")}
    canonical = build_canonical(
        f"{version}/{expired}", draft.method, draft.path, "", canonical_headers(signed_map)
    )
    verify(
        client.suite,
        load_rsa_public_key(pub_b64),
        canonical.encode("utf-8"),
        b64url_decode(sig),
    )


class TestSubMchIdSigned:
    def test_signed_and_signature_valid(self, rsa_client, vec_keys):
        cases = [
            (b'{"k":1}', "L0", ["x-wop-appkey", "x-wop-content-digest", "x-wop-nonce",
                                "x-wop-sub-mch-id", "x-wop-timestamp"]),
            (None, "L0", ["x-wop-appkey", "x-wop-nonce", "x-wop-sub-mch-id",
                          "x-wop-timestamp"]),
            (b'{"amount":1}', "L2", ["x-wop-appkey", "x-wop-content-digest", "x-wop-encrypt",
                                     "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp"]),
        ]
        for body, level, want in cases:
            draft = rsa_client.build_request(
                "POST", PATH, body, level=level, timestamp_ms=1774340000000, nonce="n",
                request_id="req-001", sub_mch_id="PLF-SUB-001",
            )
            assert draft.headers["x-wop-sub-mch-id"] == "PLF-SUB-001"
            signed_names = draft.headers["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")
            assert signed_names == want
            assert "x-wop-request-id" not in signed_names
            _assert_signature_valid(rsa_client, draft, vec_keys["rsa3072"]["publicSpkiB64"])

    def test_trimmed_upstream(self, rsa_client):
        draft = rsa_client.build_request("GET", PATH, sub_mch_id="  PLF-SUB-001  ")
        assert draft.headers["x-wop-sub-mch-id"] == "PLF-SUB-001"

    def test_extra_headers_equivalent_and_signed(self, rsa_client):
        draft = rsa_client.build_request(
            "GET", PATH, extra_headers={"X-Wop-Sub-Mch-Id": " PLF-SUB-001 "}
        )
        assert draft.headers["x-wop-sub-mch-id"] == "PLF-SUB-001"
        signed_names = draft.headers["x-wop-sign"].split(" ", 1)[1].split("/")[2].split(";")
        assert "x-wop-sub-mch-id" in signed_names

    def test_both_sources_rejected(self, rsa_client):
        with pytest.raises(ConfigurationError, match="x-wop-sub-mch-id"):
            rsa_client.build_request(
                "GET", PATH, sub_mch_id="p1",
                extra_headers={"x-wop-sub-mch-id": "p2"},
            )


class TestSubMchIdZeroRegression:  # spec:AC-20
    def test_absent_or_blank_behaves_as_before(self, rsa_client, monkeypatch):
        monkeypatch.setattr(client_mod, "request_id_generator", lambda: "fixed" + "0" * 27)
        common = dict(timestamp_ms=1774340000000, nonce="n1")
        baseline = rsa_client.build_request("POST", PATH, b'{"k":1}', **common)
        for blank in (None, "", "   "):
            draft = rsa_client.build_request("POST", PATH, b'{"k":1}', sub_mch_id=blank, **common)
            assert "x-wop-sub-mch-id" not in draft.headers
            assert draft.headers == baseline.headers


class TestSubMchIdValidation:
    @pytest.mark.parametrize(
        "bad", ["a\nb", "a\rb", "a\x00b", "a\tb", "\tsub", "sub\t", "a\x7fb"]
    )
    def test_control_chars_rejected_pre_trim(self, rsa_client, bad):
        with pytest.raises(ConfigurationError, match="可打印 ASCII"):
            rsa_client.build_request("GET", PATH, sub_mch_id=bad)

    def test_non_ascii_rejected_without_echo(self, rsa_client):
        with pytest.raises(ConfigurationError, match="可打印 ASCII") as exc:
            rsa_client.build_request("GET", PATH, sub_mch_id="PLF中文")
        assert "中文" not in str(exc.value)

    @pytest.mark.parametrize("bad", ["PLF SUB", "PLF  SUB"])
    def test_internal_space_rejected(self, rsa_client, bad):
        with pytest.raises(ConfigurationError, match="内部空白"):
            rsa_client.build_request("GET", PATH, sub_mch_id=bad)

    def test_length_boundary(self, rsa_client):
        ok = rsa_client.build_request("GET", PATH, sub_mch_id="x" * 128)
        assert ok.headers["x-wop-sub-mch-id"] == "x" * 128
        with pytest.raises(ConfigurationError, match="实际 129"):
            rsa_client.build_request("GET", PATH, sub_mch_id="x" * 129)

    def test_printable_ascii_boundary(self, rsa_client):
        draft = rsa_client.build_request("GET", PATH, sub_mch_id="!~")
        assert draft.headers["x-wop-sub-mch-id"] == "!~"

    @pytest.mark.parametrize("bad", [12345, 12.5, b"PLF-SUB-001", ["x"]])
    def test_non_str_param_rejected_as_configuration(self, rsa_client, bad):
        # 参数路径原值进校验链：非 str 一律 configuration，不抛裸 TypeError
        with pytest.raises(ConfigurationError, match="须为字符串"):
            rsa_client.build_request("GET", PATH, sub_mch_id=bad)

    def test_extra_headers_non_str_rejected_as_configuration(self, rsa_client):
        # 修复前 str(123) 会强转后入签；现原值进同一校验链
        with pytest.raises(ConfigurationError, match="须为字符串"):
            rsa_client.build_request("GET", PATH, extra_headers={"x-wop-sub-mch-id": 123})

    def test_extra_headers_none_means_absent(self, rsa_client, monkeypatch):
        # 修复前 str(None)="None" 会静默入签错误身份；现视为未设置，头缺席
        monkeypatch.setattr(client_mod, "request_id_generator", lambda: "fixed" + "0" * 27)
        common = dict(timestamp_ms=1774340000000, nonce="n1")
        baseline = rsa_client.build_request("GET", PATH, **common)
        draft = rsa_client.build_request(
            "GET", PATH, extra_headers={"x-wop-sub-mch-id": None}, **common
        )
        assert "x-wop-sub-mch-id" not in draft.headers
        assert draft.headers == baseline.headers
