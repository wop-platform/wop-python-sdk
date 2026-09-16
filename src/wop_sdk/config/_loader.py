# -*- coding: utf-8 -*-
"""配置加载入口（§4，线程安全缓存）。"""
from __future__ import annotations

import os
import threading
from importlib import resources
from pathlib import Path
from typing import Callable, Dict, Optional, Union

from ..errors import ConfigurationError
from ._models import WopSdkConfig
from ._parser import parse_config_json

CONFIG_FILE_ENV = "WOP_SDK_CONFIG"
CONFIG_FILE_OVERRIDE_ENV = "WOP_SDK_CONFIG_FILE"
CLASSPATH_PREFIXES = ("pkg:", "classpath:")
PACKAGED_CONFIG = "config/wopSdkConfig.json"

_cache_lock = threading.Lock()
_cache: Dict[str, WopSdkConfig] = {}


def clear_cache() -> None:
    """清除加载缓存（测试 / 配置轮换编排，K13）。"""
    with _cache_lock:
        _cache.clear()


def load_default() -> WopSdkConfig:
    """按 §4.2 自动发现并加载；同一位置缓存解析结果。"""
    cache_key, reader = _discover()
    return _load_cached(cache_key, reader)


def load(location: Union[str, Path]) -> WopSdkConfig:
    """显式位置；``pkg:`` 前缀读打包资源，其余为文件系统路径（K14）。"""
    if isinstance(location, Path):
        return _load_path(location)
    text = str(location)
    for prefix in CLASSPATH_PREFIXES:
        if text.startswith(prefix):
            resource = text[len(prefix) :]
            cache_key = f"{prefix}{resource}"
            return _load_cached(cache_key, lambda r=resource: _read_packaged(r))
    return _load_path(Path(text))


def _load_path(path: Path) -> WopSdkConfig:
    normalized = path.expanduser().resolve()
    cache_key = f"file:{normalized}"
    return _load_cached(cache_key, lambda: _read_file(normalized))


def _load_cached(cache_key: str, reader: Callable[[], str]) -> WopSdkConfig:
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached is not None:
            return cached
        parsed = parse_config_json(reader())
        _cache[cache_key] = parsed
        return parsed


def _read_file(path: Path) -> str:
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ConfigurationError(f"配置文件不可读: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"配置文件读取失败: {path}") from exc


def _read_packaged(resource: str) -> str:
    package = "wop_sdk.config"
    resource_name = resource.split("/", 1)[-1] if "/" in resource else resource
    try:
        data = resources.files(package).joinpath(resource_name).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, TypeError) as exc:
        raise ConfigurationError(f"打包资源不存在: {resource}") from exc
    return data


def _discover() -> tuple[str, Callable[[], str]]:
    """§4.2 六来源发现顺序。"""
    explicit = os.environ.get(CONFIG_FILE_OVERRIDE_ENV, "").strip()
    if explicit:
        path = Path(explicit)
        return _file_discovery(path, explicit=True)

    env = os.environ.get(CONFIG_FILE_ENV, "").strip()
    if env:
        path = Path(env)
        return _file_discovery(path, explicit=True)

    cwd = Path.cwd()
    candidates = [
        cwd / "config" / "wopSdkConfig.json",
        cwd / "wopSdkConfig.json",
        Path.home() / ".wop" / "wopSdkConfig.json",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.R_OK):
            return _file_discovery(candidate, explicit=False)

    packaged = PACKAGED_CONFIG.rsplit("/", 1)[-1]
    try:
        resources.files("wop_sdk.config").joinpath(packaged).read_bytes()
    except (FileNotFoundError, OSError, TypeError):
        expanded = ", ".join(str(item) for item in candidates)
        raise ConfigurationError(
            "未找到可读配置文件，已尝试: "
            f"WOP_SDK_CONFIG_FILE, {CONFIG_FILE_ENV}, {expanded}, 打包资源 {PACKAGED_CONFIG}"
        )
    cache_key = f"pkg:{PACKAGED_CONFIG}"
    return cache_key, lambda: _read_packaged(PACKAGED_CONFIG)


def _file_discovery(path: Path, *, explicit: bool) -> tuple[str, Callable[[], str]]:
    normalized = path.expanduser().resolve()
    cache_key = f"file:{normalized}"

    def reader() -> str:
        if not normalized.is_file() or not os.access(normalized, os.R_OK):
            if explicit:
                raise ConfigurationError(f"显式配置文件不可读: {normalized}")
            raise ConfigurationError(f"配置文件不可读: {normalized}")
        return _read_file(normalized)

    return cache_key, reader
