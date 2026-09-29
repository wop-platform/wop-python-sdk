# -*- coding: utf-8 -*-
"""配置 JSON 解析（K8/K21：标准库 json + 重复键检测 + NaN/Infinity 拒绝）。"""
from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Mapping, MutableMapping, Tuple

from ..errors import ConfigurationError
from ._models import DEFAULT_EXPIRED_SECONDS, HttpClientSettings, WopSdkConfig
from ._validator import validate_and_normalize

_ALLOWED_TOP_LEVEL = frozenset(
    {
        "appKey",
        "suite",
        "merchantPrivateKey",
        "platformPublicKey",
        "serverRoot",
        "backupServerRoots",
        "expiredSeconds",
        "httpClient",
    }
)
_ALLOWED_HTTP_CLIENT = frozenset({"connectTimeout", "readTimeout", "maxRetryCount"})


def _reject_non_finite(value: str) -> float:
    """parse_constant 钩子：拒绝 NaN / Infinity（§3.4 数值域）。"""
    if value in {"NaN", "Infinity", "-Infinity"}:
        raise ConfigurationError(f"配置字段 类型非法: {value}")
    return float(value)


def _duplicate_key_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """object_pairs_hook：任意 JSON 对象遇重复键即 fail-fast（K21）。"""
    seen: set[str] = set()
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ConfigurationError(f"配置字段 {key} 重复: {key}")
        seen.add(key)
        result[key] = value
    return result


def _strip_bom(text: str) -> str:
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def parse_config_json(text: str) -> WopSdkConfig:
    """UTF-8 JSON 文本 → 校验后的 WopSdkConfig。"""
    if text is None:
        raise ConfigurationError("配置文件 JSON 解析失败: 空内容")
    trimmed = _strip_bom(text.strip())
    if not trimmed:
        raise ConfigurationError("配置文件 JSON 解析失败: 空文件")
    try:
        root = json.loads(
            trimmed,
            object_pairs_hook=_duplicate_key_hook,
            parse_constant=_reject_non_finite,
        )
    except ConfigurationError:
        raise
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"配置文件 JSON 解析失败: {exc.msg}") from exc
    if not isinstance(root, dict):
        raise ConfigurationError("配置文件 JSON 解析失败: 根节点须为对象")
    return _bind_root(root)


def _bind_root(root: Mapping[str, Any]) -> WopSdkConfig:
    unknown = set(root.keys()) - _ALLOWED_TOP_LEVEL
    if unknown:
        # 未知字段忽略：仅处理已知键
        pass

    app_key = _require_string(root.get("appKey"), "appKey", required=False)
    suite = _require_string(root.get("suite"), "suite", required=False)
    merchant_private_key = _require_string(
        root.get("merchantPrivateKey"), "merchantPrivateKey", required=False
    )
    platform_public_key = _require_string(
        root.get("platformPublicKey"), "platformPublicKey", required=False
    )
    server_root = _require_string(root.get("serverRoot"), "serverRoot", required=False)

    backup_server_roots = _read_string_array(root.get("backupServerRoots"))
    expired_seconds = _read_expired_seconds(root.get("expiredSeconds"))
    http_client = _read_http_client(root.get("httpClient"))

    raw = WopSdkConfig(
        app_key=app_key or "",
        suite=suite or "",
        merchant_private_key=merchant_private_key or "",
        platform_public_key=platform_public_key or "",
        server_root=server_root or "",
        backup_server_roots=tuple(backup_server_roots),
        expired_seconds=expired_seconds,
        http_client=http_client,
        transport=None,
    )
    return validate_and_normalize(raw)


def _read_http_client(value: Any) -> HttpClientSettings:
    if value is None:
        return HttpClientSettings()
    if not isinstance(value, dict):
        raise ConfigurationError("配置字段 httpClient 类型非法: 须为对象")
    for nested_key, nested_value in value.items():
        if nested_key not in _ALLOWED_HTTP_CLIENT:
            continue
        if isinstance(nested_value, dict):
            raise ConfigurationError("配置字段 httpClient 类型非法: 不支持更深嵌套")
    connect = _read_positive_int(value.get("connectTimeout"), "connectTimeout", 10_000)
    read = _read_positive_int(value.get("readTimeout"), "readTimeout", 30_000)
    max_retry = _read_non_negative_int(value.get("maxRetryCount"), "maxRetryCount", 3)
    return HttpClientSettings(
        connect_timeout=connect,
        read_timeout=read,
        max_retry_count=max_retry,
    )


def _read_string_array(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigurationError("配置字段 backupServerRoots 类型非法: 须为字符串数组")
    result: List[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigurationError(
                f"配置字段 backupServerRoots[{index}] 类型非法: 须为字符串"
            )
        result.append(item)
    return result


def _read_expired_seconds(value: Any) -> int:
    if value is None:
        return DEFAULT_EXPIRED_SECONDS
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"配置字段 expiredSeconds 类型非法: {value!r}")
    if isinstance(value, float):
        if not math.isfinite(value) or value != int(value):
            raise ConfigurationError(f"配置字段 expiredSeconds 类型非法: {value!r}")
        value = int(value)
    if value <= 0:
        raise ConfigurationError("expiredSeconds 须为正整数")
    return int(value)


def _read_positive_int(value: Any, field_name: str, default: int) -> int:
    if value is None:
        return default
    parsed = _parse_int_field(value, field_name)
    if parsed <= 0:
        raise ConfigurationError(f"配置字段 {field_name} 类型非法: {value!r}")
    return parsed


def _read_non_negative_int(value: Any, field_name: str, default: int) -> int:
    if value is None:
        return default
    parsed = _parse_int_field(value, field_name)
    if parsed < 0:
        raise ConfigurationError(f"配置字段 {field_name} 类型非法: {value!r}")
    return parsed


def _parse_int_field(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"配置字段 {field_name} 类型非法: {value!r}")
    if isinstance(value, float):
        if not math.isfinite(value) or value != int(value):
            raise ConfigurationError(f"配置字段 {field_name} 类型非法: {value!r}")
        return int(value)
    return int(value)


def _require_string(value: Any, field_name: str, *, required: bool) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigurationError(f"配置字段 {field_name} 类型非法: {value!r}")
    return value
