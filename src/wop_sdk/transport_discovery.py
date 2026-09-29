# -*- coding: utf-8 -*-
"""传输发现（config-spec §7.2 / K18 P0：默认 urllib，歧义 fail-fast）。"""
from __future__ import annotations

import importlib.util
import os
from typing import Dict, List

from .errors import ConfigurationError
from .transports import Transport, UrllibTransport

_TRANSPORT_ENV = "WOP_TRANSPORT"


def discover_transport() -> Transport:
    """发现唯一可用传输；零个或多个且无显式指定时 fail-fast（K12）。"""
    available = _available_transports()
    if not available:
        raise ConfigurationError("未找到可用 HTTP 传输，请确认 wop-python-sdk 安装完整")
    explicit = os.environ.get(_TRANSPORT_ENV, "").strip().lower()
    if explicit:
        transport = available.get(explicit)
        if transport is None:
            names = ", ".join(sorted(available))
            raise ConfigurationError(
                f"WOP_TRANSPORT={explicit!r} 无匹配传输，可用: {names}"
            )
        return transport()
    if "urllib" in available:
        # P0 默认适配器：peer 依赖并存时仍优先 stdlib urllib（附录 D）
        return available["urllib"]()
    if len(available) == 1:
        return next(iter(available.values()))()
    names = ", ".join(sorted(available))
    raise ConfigurationError(
        f"检测到多个 HTTP 传输 ({names})，请设置环境变量 {_TRANSPORT_ENV} 显式指定"
    )


def _available_transports() -> Dict[str, type]:
    found: Dict[str, type] = {"urllib": UrllibTransport}
    if importlib.util.find_spec("httpx") is not None:
        from .transports.httpx_transport import HttpxTransport

        found["httpx"] = HttpxTransport
    if importlib.util.find_spec("requests") is not None:
        from .transports.requests_transport import RequestsTransport

        found["requests"] = RequestsTransport
    # P0：仅 urllib 时不视为「多个」——过滤后若显式 env 未设且仅 urllib，直接返回
    if set(found.keys()) == {"urllib"}:
        return found
    return found
