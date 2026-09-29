# -*- coding: utf-8 -*-
"""配置不可变快照（§3，字段与 JSON camelCase 语义对齐）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from ..transports import Transport

DEFAULT_EXPIRED_SECONDS = 1800


@dataclass(frozen=True)
class HttpClientSettings:
    """HTTP 客户端全局设置（§3.3 httpClient 对象）。"""

    connect_timeout: int = 10_000
    read_timeout: int = 30_000
    max_retry_count: int = 3

    def __repr__(self) -> str:
        return (
            f"HttpClientSettings(connect_timeout={self.connect_timeout}, "
            f"read_timeout={self.read_timeout}, max_retry_count={self.max_retry_count})"
        )


@dataclass(frozen=True)
class WopSdkConfig:
    """配置不可变快照；build() / JSON 加载路径均经 §3.4 校验。"""

    app_key: str
    suite: str
    merchant_private_key: str
    platform_public_key: str
    server_root: str
    backup_server_roots: Tuple[str, ...] = field(default_factory=tuple)
    expired_seconds: int = DEFAULT_EXPIRED_SECONDS
    http_client: HttpClientSettings = field(default_factory=HttpClientSettings)
    transport: Optional["Transport"] = None

    def __repr__(self) -> str:
        # K16：日志/repr 私钥打码
        return (
            f"WopSdkConfig(app_key={self.app_key!r}, suite={self.suite!r}, "
            f"merchant_private_key=****, platform_public_key=****, "
            f"server_root={self.server_root!r}, backup_server_roots={self.backup_server_roots!r}, "
            f"expired_seconds={self.expired_seconds}, http_client={self.http_client!r})"
        )

    @classmethod
    def builder(cls) -> "WopSdkConfigBuilder":
        """程序化构造入口（K11）。"""
        return WopSdkConfigBuilder()


class WopSdkConfigBuilder:
    """WopSdkConfig 构建器；build() 执行与 JSON 路径等价的 §3.4 校验。"""

    def __init__(self) -> None:
        self._app_key: Optional[str] = None
        self._suite: Optional[str] = None
        self._merchant_private_key: Optional[str] = None
        self._platform_public_key: Optional[str] = None
        self._server_root: Optional[str] = None
        self._backup_server_roots: Tuple[str, ...] = tuple()
        self._expired_seconds: int = DEFAULT_EXPIRED_SECONDS
        self._http_client: HttpClientSettings = HttpClientSettings()
        self._transport: Optional["Transport"] = None

    def app_key(self, value: str) -> "WopSdkConfigBuilder":
        self._app_key = value
        return self

    def suite(self, value: str) -> "WopSdkConfigBuilder":
        self._suite = value
        return self

    def merchant_private_key(self, value: str) -> "WopSdkConfigBuilder":
        self._merchant_private_key = value
        return self

    def platform_public_key(self, value: str) -> "WopSdkConfigBuilder":
        self._platform_public_key = value
        return self

    def server_root(self, value: str) -> "WopSdkConfigBuilder":
        self._server_root = value
        return self

    def backup_server_roots(self, value: Tuple[str, ...]) -> "WopSdkConfigBuilder":
        self._backup_server_roots = value
        return self

    def expired_seconds(self, value: int) -> "WopSdkConfigBuilder":
        self._expired_seconds = value
        return self

    def http_client(self, value: HttpClientSettings) -> "WopSdkConfigBuilder":
        self._http_client = value
        return self

    def transport(self, value: Optional["Transport"]) -> "WopSdkConfigBuilder":
        self._transport = value
        return self

    def build(self) -> WopSdkConfig:
        from ._validator import validate_and_normalize

        raw = WopSdkConfig(
            app_key=self._app_key or "",
            suite=self._suite or "",
            merchant_private_key=self._merchant_private_key or "",
            platform_public_key=self._platform_public_key or "",
            server_root=self._server_root or "",
            backup_server_roots=self._backup_server_roots,
            expired_seconds=self._expired_seconds,
            http_client=self._http_client,
            transport=self._transport,
        )
        return validate_and_normalize(raw)
