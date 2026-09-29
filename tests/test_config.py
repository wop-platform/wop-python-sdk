# -*- coding: utf-8 -*-
"""config-spec P0：配置加载、校验、default_client/execute、path §7.7、K16 打码。"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest import mock

import pytest

from wop_sdk.client import WopClient, WopConfig
from wop_sdk.config import HttpClientSettings, WopSdkConfig, clear_cache, load, load_default
from wop_sdk.config._parser import parse_config_json
from wop_sdk.config._validator import join_url, validate_api_path, validate_gateway_url
from wop_sdk.errors import ConfigurationError, WopGatewayResponseError
from wop_sdk.transports import HttpResponse

RSA_REQ = "WOP-RSA3072-SHA256"
PATH = "/gateway/order/create"


def _valid_config_dict(vec_keys) -> dict:
    return {
        "appKey": "app_10012481831",
        "suite": RSA_REQ,
        "merchantPrivateKey": vec_keys["rsa3072"]["privatePkcs8B64"],
        "platformPublicKey": vec_keys["rsa3072"]["publicSpkiB64"],
        "serverRoot": "https://gw.example.com/gateway",
        "backupServerRoots": ["https://gw-backup.example.com/gateway"],
        "expiredSeconds": 1800,
        "httpClient": {
            "connectTimeout": 10000,
            "readTimeout": 30000,
            "maxRetryCount": 3,
        },
    }


def _write_config(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def valid_config_json(vec_keys):
    return json.dumps(_valid_config_dict(vec_keys), ensure_ascii=False)


@pytest.fixture
def valid_sdk_config(vec_keys):
    return parse_config_json(json.dumps(_valid_config_dict(vec_keys)))


@pytest.fixture(autouse=True)
def _reset_config_state():
    clear_cache()
    WopClient.reset_default()
    yield
    clear_cache()
    WopClient.reset_default()


class TestConfigParsing:
    def test_valid_json_load(self, valid_config_json):
        cfg = parse_config_json(valid_config_json)
        assert cfg.app_key == "app_10012481831"
        assert cfg.server_root == "https://gw.example.com/gateway"
        assert cfg.backup_server_roots == ("https://gw-backup.example.com/gateway",)
        assert cfg.http_client.connect_timeout == 10000

    def test_duplicate_app_key_rejected(self, vec_keys):
        # 手写 JSON 以保留重复键（json.dumps 不会产生重复键）
        text = (
            '{"appKey":"a","appKey":"b","suite":"WOP-RSA3072-SHA256",'
            '"merchantPrivateKey":"x","platformPublicKey":"y","serverRoot":"https://gw.example.com/gateway"}'
        )
        with pytest.raises(ConfigurationError, match="配置字段 appKey 重复"):
            parse_config_json(text)

    def test_duplicate_server_root_rejected(self, vec_keys):
        text = (
            '{"appKey":"a","suite":"WOP-RSA3072-SHA256","merchantPrivateKey":"x",'
            '"platformPublicKey":"y","serverRoot":"https://gw.example.com/gateway",'
            '"serverRoot":"https://gw.example.com/gateway"}'
        )
        with pytest.raises(ConfigurationError, match="配置字段 serverRoot 重复"):
            parse_config_json(text)

    def test_nan_expired_seconds_rejected(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["expiredSeconds"] = float("nan")
        with pytest.raises(ConfigurationError, match="类型非法"):
            parse_config_json(json.dumps(raw))

    def test_missing_app_key(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw.pop("appKey")
        with pytest.raises(ConfigurationError, match="缺少必填项: appKey"):
            parse_config_json(json.dumps(raw))

    def test_http_not_https(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["serverRoot"] = "http://gw.example.com/gateway"
        with pytest.raises(ConfigurationError, match="须为 HTTPS 绝对 URL"):
            parse_config_json(json.dumps(raw))

    def test_server_root_query_rejected(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["serverRoot"] = "https://gw.example.com/gateway?x=1"
        with pytest.raises(ConfigurationError, match="不得含 query 或 fragment"):
            parse_config_json(json.dumps(raw))

    def test_backup_indexed_validation(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["backupServerRoots"] = ["http://bad.example.com/gateway"]
        with pytest.raises(ConfigurationError, match="backupServerRoots\\[0\\].*HTTPS"):
            parse_config_json(json.dumps(raw))

    def test_expired_seconds_non_positive(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["expiredSeconds"] = 0
        with pytest.raises(ConfigurationError, match="expiredSeconds 须为正整数"):
            parse_config_json(json.dumps(raw))

    def test_invalid_suite(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["suite"] = "WOP-UNKNOWN"
        with pytest.raises(Exception):
            parse_config_json(json.dumps(raw))

    def test_server_root_trailing_slash_trimmed(self, vec_keys):
        raw = _valid_config_dict(vec_keys)
        raw["serverRoot"] = "https://gw.example.com/gateway/"
        cfg = parse_config_json(json.dumps(raw))
        assert cfg.server_root == "https://gw.example.com/gateway"


class TestConfigLoader:
    def test_load_file_and_cache(self, tmp_path, vec_keys, valid_config_json):
        cfg_path = tmp_path / "wopSdkConfig.json"
        cfg_path.write_text(valid_config_json, encoding="utf-8")
        first = load(cfg_path)
        second = load(cfg_path)
        assert first is second

    def test_clear_cache_reload(self, tmp_path, vec_keys, valid_config_json):
        cfg_path = tmp_path / "wopSdkConfig.json"
        cfg_path.write_text(valid_config_json, encoding="utf-8")
        first = load(cfg_path)
        clear_cache()
        second = load(cfg_path)
        assert first is not second
        assert first.app_key == second.app_key

    def test_load_default_env_override(self, tmp_path, vec_keys, monkeypatch):
        cfg_path = tmp_path / "cfg.json"
        _write_config(cfg_path, _valid_config_dict(vec_keys))
        monkeypatch.setenv("WOP_SDK_CONFIG_FILE", str(cfg_path))
        cfg = load_default()
        assert cfg.app_key == "app_10012481831"

    def test_explicit_unreadable_fail_fast(self, tmp_path, monkeypatch):
        missing = tmp_path / "missing.json"
        monkeypatch.setenv("WOP_SDK_CONFIG_FILE", str(missing))
        with pytest.raises(ConfigurationError, match="显式配置文件不可读"):
            load_default()


class TestK16Redaction:
    def test_wop_sdk_config_repr_redacts_keys(self, valid_sdk_config):
        text = repr(valid_sdk_config)
        assert "merchant_private_key=****" in text
        assert "platform_public_key=****" in text
        assert valid_sdk_config.merchant_private_key not in text

    def test_wop_config_repr_redacts_keys(self, vec_keys):
        cfg = WopConfig(
            app_key="ak",
            suite=RSA_REQ,
            merchant_private_key=vec_keys["rsa3072"]["privatePkcs8B64"],
            platform_public_key=vec_keys["rsa3072"]["publicSpkiB64"],
        )
        text = repr(cfg)
        assert "merchant_private_key=****" in text
        assert vec_keys["rsa3072"]["privatePkcs8B64"] not in text


class TestPathValidation:
    def test_join_url_c5(self):
        url = join_url("https://gw.example.com/gateway", "/gateway/order/create")
        assert url == "https://gw.example.com/gateway/gateway/order/create"
        url2 = join_url("https://gw.example.com/gateway/", "/gateway/order/create")
        assert url2 == url

    @pytest.mark.parametrize(
        "bad_path",
        [
            "//attacker.example/path",
            "http://evil/path",
            "/x?a=1",
            "no-leading-slash",
        ],
    )
    def test_invalid_paths_rejected(self, bad_path):
        with pytest.raises(ConfigurationError):
            validate_api_path(bad_path)

    def test_validate_gateway_url_https_only(self):
        with pytest.raises(ConfigurationError, match="须为 HTTPS"):
            validate_gateway_url("http://gw.example.com/gateway", "serverRoot")


class TestDefaultClient:
    def test_from_config_builder(self, vec_keys):
        cfg = (
            WopSdkConfig.builder()
            .app_key("app_10012481831")
            .suite(RSA_REQ)
            .merchant_private_key(vec_keys["rsa3072"]["privatePkcs8B64"])
            .platform_public_key(vec_keys["rsa3072"]["publicSpkiB64"])
            .server_root("https://gw.example.com/gateway")
            .build()
        )
        client = WopClient.from_config(cfg)
        assert client._sdk_config is cfg

    def test_default_client_singleton(self, valid_sdk_config, monkeypatch):
        created = []

        def fake_load_default():
            created.append(1)
            return valid_sdk_config

        monkeypatch.setattr("wop_sdk.config.load_default", fake_load_default)
        a = WopClient.default_client()
        b = WopClient.default_client()
        assert a is b
        assert len(created) == 1

    def test_reset_default_reloads_after_clear_cache(self, tmp_path, vec_keys, monkeypatch):
        cfg1_path = tmp_path / "c1.json"
        cfg2_path = tmp_path / "c2.json"
        d1 = _valid_config_dict(vec_keys)
        d2 = dict(d1, appKey="app_second_key")
        _write_config(cfg1_path, d1)
        _write_config(cfg2_path, d2)

        monkeypatch.setenv("WOP_SDK_CONFIG_FILE", str(cfg1_path))
        first = WopClient.default_client()
        assert first._config.app_key == "app_10012481831"

        clear_cache()
        WopClient.reset_default()
        monkeypatch.setenv("WOP_SDK_CONFIG_FILE", str(cfg2_path))
        second = WopClient.default_client()
        assert second._config.app_key == "app_second_key"
        assert first is not second

    def test_concurrent_default_client_single_instance(self, valid_sdk_config, monkeypatch):
        monkeypatch.setattr("wop_sdk.config.load_default", lambda: valid_sdk_config)
        results = []

        def worker():
            results.append(WopClient.default_client())

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len({id(x) for x in results}) == 1


class TestExecute:
    def test_execute_l0_roundtrip(self, valid_sdk_config):
        client = WopClient.from_config(valid_sdk_config, csprng=lambda n: b"\x5a" * n)
        draft_holder = {}

        class RecordingTransport:
            def send(self, method, url, headers, body):
                draft_holder["url"] = url
                draft = client.build_request("POST", PATH, b'{"code":0}')
                return HttpResponse(200, draft.headers, draft.wire_body)

        client._transport = RecordingTransport()
        result = client.execute("POST", PATH, b'{"code":0}')
        assert result.ok
        assert draft_holder["url"] == "https://gw.example.com/gateway/gateway/order/create"

    def test_execute_non_2xx_raises_gateway_error(self, valid_sdk_config):
        client = WopClient.from_config(valid_sdk_config)

        class BadGatewayTransport:
            def send(self, method, url, headers, body):
                return HttpResponse(502, {}, b"bad gateway")

        client._transport = BadGatewayTransport()
        with pytest.raises(WopGatewayResponseError) as exc:
            client.execute("POST", PATH, b"x")
        assert exc.value.status_code == 502
        assert exc.value.body == b"bad gateway"
        assert "HTTP 502" in str(exc.value)

    def test_execute_rejects_invalid_path(self, valid_sdk_config):
        client = WopClient.from_config(valid_sdk_config)
        with pytest.raises(ConfigurationError, match="// 开头"):
            client.execute("POST", "//evil/path", b"x")

    def test_execute_requires_config_layer_client(self, vec_keys):
        client = WopClient(
            WopConfig(
                app_key="ak",
                suite=RSA_REQ,
                merchant_private_key=vec_keys["rsa3072"]["privatePkcs8B64"],
                platform_public_key=vec_keys["rsa3072"]["publicSpkiB64"],
            )
        )
        with pytest.raises(ConfigurationError, match="execute 需要"):
            client.execute("POST", PATH, b"x")


class TestPackagedFallbackAndPort:  # Sourcery CR（PR #39）回归
    def test_packaged_resource_discoverable_when_no_user_config(self, monkeypatch, tmp_path):
        """K6 兜底：环境变量/cwd/userHome 全未命中 → 打包模板可被发现并读取。"""
        from wop_sdk.config import load_default
        from wop_sdk.errors import ConfigurationError

        monkeypatch.delenv("WOP_SDK_CONFIG_FILE", raising=False)
        monkeypatch.delenv("WOP_SDK_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)  # cwd 无 config/
        home = tmp_path / "home"
        home.mkdir()
        # loader 内 Path.cwd()（已 chdir 至空目录）与 Path.home() 一并指向空 home
        class _FakePath(Path):
            def __new__(cls, *args):
                return Path(*args) if args else home

            @classmethod
            def home(cls):  # noqa: D102
                return home

        monkeypatch.setattr("wop_sdk.config._loader.Path", _FakePath)
        clear_cache()
        try:
            load_default()
            raise AssertionError("模板占位符密钥应在密钥校验阶段失败")
        except ConfigurationError as exc:
            # 兜底资源被读取：失败发生在密钥校验，而非「未找到可读配置文件」
            assert "未找到可读配置文件" not in str(exc)

    def test_invalid_port_normalized_to_configuration_error(self):
        """Sourcery CR：非法端口（:abc）须抛 ConfigurationError 而非原生 ValueError。"""
        from wop_sdk.config._validator import validate_gateway_url

        try:
            validate_gateway_url("https://gw.example.com:abc/gateway", "serverRoot")
            raise AssertionError("非法端口应拒绝")
        except ConfigurationError as exc:
            assert "serverRoot 不是合法 URL" in str(exc)
        import pytest as _pytest
        with _pytest.raises(ConfigurationError):
            validate_gateway_url("https://gw.example.com:99999/gateway", "serverRoot")
