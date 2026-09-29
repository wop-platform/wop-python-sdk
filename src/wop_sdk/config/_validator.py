# -*- coding: utf-8 -*-
"""§3.4 语义校验与字段归一化。"""
from __future__ import annotations

from typing import Tuple
from urllib.parse import urlparse

from ..errors import ConfigurationError, KeyMaterialError
from ..keys import load_rsa_private_key, load_rsa_public_key, load_sm2_private_key, load_sm2_public_key
from ..suites import parse_suite
from ._models import HttpClientSettings, WopSdkConfig


def validate_and_normalize(raw: WopSdkConfig) -> WopSdkConfig:
    """加载/构建后 fail-fast 校验并返回归一化快照。"""
    if not raw.app_key or not raw.app_key.strip():
        raise ConfigurationError("配置文件缺少必填项: appKey")
    if not raw.suite or not raw.suite.strip():
        raise ConfigurationError("配置文件缺少必填项: suite")
    if not raw.merchant_private_key or not raw.merchant_private_key.strip():
        raise ConfigurationError("配置文件缺少必填项: merchantPrivateKey")
    if not raw.platform_public_key or not raw.platform_public_key.strip():
        raise ConfigurationError("配置文件缺少必填项: platformPublicKey")
    if not raw.server_root or not raw.server_root.strip():
        raise ConfigurationError("配置文件缺少必填项: serverRoot")
    if raw.expired_seconds <= 0:
        raise ConfigurationError("expiredSeconds 须为正整数")

    suite = parse_suite(raw.suite.strip())
    try:
        if suite.family == "RSA":
            load_rsa_private_key(raw.merchant_private_key.strip(), suite.key_bits)
            load_rsa_public_key(raw.platform_public_key.strip(), suite.key_bits)
        else:
            load_sm2_private_key(raw.merchant_private_key.strip())
            load_sm2_public_key(raw.platform_public_key.strip())
    except KeyMaterialError as exc:
        raise ConfigurationError(f"密钥解析失败: {exc}") from exc

    server_root = validate_gateway_url(raw.server_root, "serverRoot")
    backups: Tuple[str, ...] = tuple(
        validate_gateway_url(item, f"backupServerRoots[{index}]")
        for index, item in enumerate(raw.backup_server_roots)
    )

    http = raw.http_client or HttpClientSettings()
    if http.connect_timeout <= 0 or http.read_timeout <= 0 or http.max_retry_count < 0:
        raise ConfigurationError("配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负")

    return WopSdkConfig(
        app_key=raw.app_key.strip(),
        suite=raw.suite.strip(),
        merchant_private_key=raw.merchant_private_key.strip(),
        platform_public_key=raw.platform_public_key.strip(),
        server_root=server_root,
        backup_server_roots=backups,
        expired_seconds=int(raw.expired_seconds),
        http_client=http,
        transport=raw.transport,
    )


def validate_gateway_url(value: str, field_name: str) -> str:
    """K20：HTTPS 绝对 URL，拒绝 query/fragment，加载时 trim 尾部 /。"""
    if value is None or not str(value).strip():
        raise ConfigurationError(f"{field_name} 不是合法 URL: {value}")
    trimmed = str(value).strip()
    try:
        parsed = urlparse(trimmed)
    except ValueError as exc:
        raise ConfigurationError(f"{field_name} 不是合法 URL: {trimmed}") from exc
    if not parsed.scheme or parsed.scheme.lower() != "https":
        raise ConfigurationError(f"{field_name} 须为 HTTPS 绝对 URL: {trimmed}")
    if parsed.query or parsed.fragment:
        raise ConfigurationError(f"{field_name} 不得含 query 或 fragment: {trimmed}")
    if not parsed.netloc:
        raise ConfigurationError(f"{field_name} 不是合法 URL: {trimmed}")
    host = parsed.hostname or ""
    # 非法端口（如 :abc / 越界）时 parsed.port 抛原生 ValueError，须归一为 ConfigurationError（Sourcery CR）
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError(f"{field_name} 不是合法 URL: {trimmed}") from exc
    path = parsed.path or ""
    normalized = "https://" + host.lower()
    if port is not None:
        normalized += f":{port}"
    normalized += path
    if normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def validate_api_path(path: str) -> None:
    """§7.7 API path 语法校验。"""
    if path is None or path == "":
        raise ConfigurationError("请求路径为空")
    if not path.startswith("/"):
        raise ConfigurationError(f"path 须以 / 开头: {path}")
    if path.startswith("//"):
        raise ConfigurationError(f"path 不得 // 开头: {path}")
    if "?" in path or "#" in path:
        raise ConfigurationError(f"path 不得含 query 或 fragment: {path}")
    lower = path.lower()
    if lower.startswith("http:") or lower.startswith("https:"):
        raise ConfigurationError(f"path 不得为绝对 URL: {path}")


def join_url(server_root: str, path: str) -> str:
    """§7.7 字符串拼接 serverRoot + path（K23）。"""
    validate_api_path(path)
    root = server_root[:-1] if server_root.endswith("/") else server_root
    trimmed_path = path[1:] if path.startswith("/") else path
    return f"{root}/{trimmed_path}"
