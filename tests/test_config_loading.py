# -*- coding: utf-8 -*-
"""配置加载链覆盖闭合：parser/loader/validator/builder/transport 发现的负例与边界。

缺口来源：CI 覆盖门禁 91.10% < 98%（_parser 69% / _loader 75% / _validator 77% /
transport_discovery 59%），PR 新增加载链未带测试。本文件按 term-missing 行号逐段闭合。
"""
import json
from pathlib import Path

import pytest

import wop_sdk.transport_discovery as discovery_mod
from wop_sdk.config import _loader as loader_mod
from wop_sdk.config._loader import CONFIG_FILE_ENV, load, load_default
from wop_sdk.config._models import WopSdkConfigBuilder
from wop_sdk.config._parser import parse_config_json
from wop_sdk.config._validator import validate_api_path, validate_gateway_url
from wop_sdk.errors import ConfigurationError
from helpers import _valid_config_dict, _write_config


def _raw(vec_keys, **overrides):
    """绕过 parser 的 Raw 快照，直打 validator。"""
    d = _valid_config_dict(vec_keys)
    return {**d, **overrides}


# ---------------- parser：文本与 JSON 结构 ----------------

@pytest.mark.parametrize("text,expect", [
    (None, "空内容"),
    ("  \t\n ", "空文件"),
    ('{"appKey": ', "解析失败"),
    ("[1,2]", "根节点须为对象"),
    ('{"appKey": NaN, "x": 1}', "非法"),
])
def test_parse_config_json_bad_text(text, expect):
    with pytest.raises(ConfigurationError, match=expect):
        parse_config_json(text)


def test_parse_config_json_duplicate_key():
    with pytest.raises(ConfigurationError, match="重复"):
        parse_config_json('{"appKey": "a", "appKey": "b"}')


def test_parse_config_json_bom_stripped(vec_keys):
    text = "﻿" + json.dumps(_valid_config_dict(vec_keys))
    assert parse_config_json(text).app_key == "app_10012481831"


# ---------------- parser：字段类型分支 ----------------

def _mutate(vec_keys, **kv):
    d = _valid_config_dict(vec_keys)
    d.update(kv)
    return json.dumps(d)


@pytest.mark.parametrize("field,bad,expect", [
    ("httpClient", None, None),                      # null → 全默认，成功
    ("httpClient", "x", "httpClient 类型非法"),
    ("httpClient", {"connectTimeout": {"a": 1}}, "不支持更深嵌套"),
    ("backupServerRoots", None, None),               # null → []，成功
    ("backupServerRoots", "x", "须为字符串数组"),
    ("backupServerRoots", [1], "须为字符串"),
    ("expiredSeconds", None, None),                  # null → 默认，成功
    ("expiredSeconds", True, "expiredSeconds"),
    ("expiredSeconds", 1.5, "expiredSeconds"),
    ("expiredSeconds", float("nan"), "类型非法"),
])
def test_parse_config_field_branches(vec_keys, field, bad, expect):
    text = _mutate(vec_keys, **{field: bad})
    if expect is None:
        parse_config_json(text)
    else:
        with pytest.raises(ConfigurationError, match=expect):
            parse_config_json(text)


@pytest.mark.parametrize("field,sub,bad", [
    ("httpClient", "connectTimeout", "x"),
    ("httpClient", "connectTimeout", -1),
    ("httpClient", "readTimeout", 0),
    ("httpClient", "readTimeout", 2.5),
    ("httpClient", "maxRetryCount", -2),
    ("httpClient", "maxRetryCount", False),
    ("httpClient", "connectTimeout", 1.0),           # 整 float 合法 → 成功
    ("httpClient", "maxRetryCount", 0),              # 非负合法 → 成功
])
def test_parse_http_client_scalars(vec_keys, field, sub, bad):
    text = _mutate(vec_keys, **{field: {sub: bad}})
    # readTimeout=0 拒绝（须为正，与 dotnet 口径一致；仅 maxRetryCount 允许 0=禁用重试 §7.3）
    ok = bad == 1.0 or (sub == "maxRetryCount" and bad == 0 and not isinstance(bad, bool))
    if ok:
        parse_config_json(text)
    else:
        with pytest.raises(ConfigurationError, match=sub):
            parse_config_json(text)


# ---------------- validator：必填/越界/URL ----------------

@pytest.mark.parametrize("field", ["appKey", "suite", "merchantPrivateKey", "platformPublicKey", "serverRoot"])
def test_validator_missing_required(vec_keys, field):
    # 空白值穿透 parser 的类型检查，由 validator 必填校验拦截
    d = _valid_config_dict(vec_keys)
    d[field] = "  "
    with pytest.raises(ConfigurationError, match=field):
        parse_config_json(json.dumps(d, ensure_ascii=False))


def test_validator_builder_expired_and_http(vec_keys):
    cfg = parse_config_json(json.dumps(_valid_config_dict(vec_keys)))
    b = WopSdkConfigBuilder().app_key(cfg.app_key).suite(cfg.suite).merchant_private_key(
        cfg.merchant_private_key
    ).platform_public_key(cfg.platform_public_key).server_root(cfg.server_root)
    assert b.server_root("https://x.example.com").backup_server_roots(()).expired_seconds(
        1800
    ).http_client(cfg.http_client).transport(None) is b
    b.build()
    with pytest.raises(ConfigurationError, match="expiredSeconds"):
        WopSdkConfigBuilder().app_key(cfg.app_key).suite(cfg.suite).merchant_private_key(
            cfg.merchant_private_key
        ).platform_public_key(cfg.platform_public_key).server_root(
            cfg.server_root
        ).expired_seconds(-1).build()


@pytest.mark.parametrize("url,expect", [
    (None, "不是合法 URL"),
    ("   ", "不是合法 URL"),
    ("http://gw.example.com", "须为 HTTPS"),
    ("https://gw.example.com/?q=1", "不得含 query"),
    ("https://gw.example.com/#f", "不得含 query"),
    ("https://gw.example.com:abc/", "不是合法 URL"),
])
def test_validate_gateway_url_negative(url, expect):
    with pytest.raises(ConfigurationError, match=expect):
        validate_gateway_url(url, "serverRoot")


def test_validate_gateway_url_normalizes():
    assert validate_gateway_url("https://GW.Example.com:8443/gateway/", "x") == \
        "https://gw.example.com:8443/gateway"


@pytest.mark.parametrize("path", [None, "", "gateway/x", "//x", "/a?b", "/a#b", "https://x.com/p"])
def test_validate_api_path_negative(path):
    with pytest.raises(ConfigurationError):
        validate_api_path(path)


# ---------------- loader：位置与发现 ----------------

def test_load_explicit_path_and_pkg(vec_keys, tmp_path):
    p = tmp_path / "cfg.json"
    _write_config(p, _valid_config_dict(vec_keys))
    assert load(Path(p)).app_key == "app_10012481831"
    assert load(str(p)).app_key == "app_10012481831"
    # 打包默认配置是占位模板，读取成功但必填校验拦截——pkg: 前缀路径至此闭合
    with pytest.raises(ConfigurationError, match="密钥解析失败"):
        load("pkg:wopSdkConfig.json")


def test_load_pkg_missing_resource():
    with pytest.raises(ConfigurationError, match="打包资源不存在"):
        load("pkg:no-such.json")


def test_load_unreadable_path(tmp_path):
    with pytest.raises(ConfigurationError, match="不可读"):
        load(tmp_path / "missing.json")


def test_load_read_oserror(vec_keys, tmp_path, monkeypatch):
    p = tmp_path / "cfg.json"
    _write_config(p, _valid_config_dict(vec_keys))

    def boom(*a, **kw):
        raise OSError("disk")

    monkeypatch.setattr(Path, "read_text", boom)
    with pytest.raises(ConfigurationError, match="读取失败"):
        load(p)


def test_discover_env_explicit_missing(vec_keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(CONFIG_FILE_ENV, str(tmp_path / "nope.json"))
    with pytest.raises(ConfigurationError, match="显式配置文件不可读"):
        load_default()


def test_discover_env_explicit_hit(vec_keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "cfg.json"
    _write_config(p, _valid_config_dict(vec_keys))
    monkeypatch.setenv(CONFIG_FILE_ENV, str(p))
    assert load_default().app_key == "app_10012481831"


def test_discover_cwd_candidate(vec_keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path / "wopSdkConfig.json", _valid_config_dict(vec_keys))
    assert load_default().app_key == "app_10012481831"


def test_discover_all_missing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(CONFIG_FILE_ENV, raising=False)
    monkeypatch.setattr(loader_mod.resources, "files", lambda pkg: _BoomPkg())
    with pytest.raises(ConfigurationError, match="未找到可读配置文件"):
        load_default()


class _BoomPkg:
    def joinpath(self, name):
        raise FileNotFoundError(name)


# ---------------- transport 发现 ----------------

def test_transport_discovery_no_available(monkeypatch):
    monkeypatch.setattr(discovery_mod, "_available_transports", lambda: {})
    with pytest.raises(ConfigurationError, match="未找到可用 HTTP 传输"):
        discovery_mod.discover_transport()


def test_transport_discovery_env_no_match(monkeypatch):
    monkeypatch.setattr(discovery_mod, "_available_transports", lambda: {"urllib": object})
    monkeypatch.setattr(discovery_mod, "_TRANSPORT_ENV", "WOP_TRANSPORT")
    monkeypatch.setenv("WOP_TRANSPORT", "nope")
    with pytest.raises(ConfigurationError, match="无匹配传输"):
        discovery_mod.discover_transport()


def test_transport_discovery_multiple_without_env(monkeypatch):
    monkeypatch.setattr(discovery_mod, "_available_transports", lambda: {"httpx": object, "requests": object})
    monkeypatch.delenv("WOP_TRANSPORT", raising=False)
    with pytest.raises(ConfigurationError, match="多个 HTTP 传输"):
        discovery_mod.discover_transport()


def test_transport_discovery_single_non_urllib(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(discovery_mod, "_available_transports", lambda: {"httpx": lambda: sentinel})
    monkeypatch.delenv("WOP_TRANSPORT", raising=False)
    assert discovery_mod.discover_transport() is sentinel


def test_transport_discovery_env_match(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(discovery_mod, "_available_transports", lambda: {"httpx": lambda: sentinel})
    monkeypatch.setattr(discovery_mod, "_TRANSPORT_ENV", "WOP_TRANSPORT")
    monkeypatch.setenv("WOP_TRANSPORT", " HTTPX ")
    assert discovery_mod.discover_transport() is sentinel


# ---------------- 第三轮残口：行 116/150-152/190 与 SM2/builder 负 timeout ----------------

def test_parse_http_client_unknown_key_ignored(vec_keys):
    parse_config_json(_mutate(vec_keys, httpClient={"foo": 1}))


def test_parse_expired_seconds_integral_float(vec_keys):
    cfg = parse_config_json(_mutate(vec_keys, expiredSeconds=1800.0))
    assert cfg.expired_seconds == 1800


def test_parse_app_key_null_rejected(vec_keys):
    with pytest.raises(ConfigurationError, match="appKey"):
        parse_config_json(_mutate(vec_keys, appKey=None))


def test_validator_sm2_suite(vec_keys):
    d = _valid_config_dict(vec_keys)
    d["suite"] = "WOP-SM2-SM3"
    d["merchantPrivateKey"] = vec_keys["sm2"]["privateDB64"]
    d["platformPublicKey"] = vec_keys["sm2"]["publicPointB64"]
    cfg = parse_config_json(json.dumps(d, ensure_ascii=False))
    assert str(cfg.suite).endswith("WOP-SM2-SM3") or getattr(cfg.suite, "suite_id", cfg.suite) == "WOP-SM2-SM3"


def test_validator_builder_negative_http_timeout(vec_keys):
    from wop_sdk.config._models import HttpClientSettings

    cfg = parse_config_json(json.dumps(_valid_config_dict(vec_keys)))
    bad_http = HttpClientSettings(connect_timeout=-1, read_timeout=30, max_retry_count=0)
    with pytest.raises(ConfigurationError, match="httpClient"):
        (
            WopSdkConfigBuilder()
            .app_key(cfg.app_key)
            .suite(cfg.suite)
            .merchant_private_key(cfg.merchant_private_key)
            .platform_public_key(cfg.platform_public_key)
            .server_root(cfg.server_root)
            .http_client(bad_http)
            .build()
        )


def test_available_transports_reports_installed():
    found = discovery_mod._available_transports()
    assert "urllib" in found
    assert discovery_mod._available_transports.__name__ == "_available_transports"
