# -*- coding: utf-8 -*-
"""可插拔 HTTP 适配层（Q1 定稿）：协议核心零网络 IO，传输以独立模块交付。

- ``Transport``：协议接口，商户自带栈时可直接实现或消费 RequestDraft；
- ``send_draft``：RequestDraft → Transport（URL 拼接归此，适配器只面对完整请求）；
- stdlib urllib 适配器随主包；httpx / requests 适配器为 peer 依赖（extras）。
"""
from dataclasses import dataclass
from typing import Dict, Optional, Protocol, runtime_checkable

from ..client import RequestDraft

__all__ = ["HttpResponse", "Transport", "UrllibTransport", "send_draft"]


@dataclass
class HttpResponse:
    """传输层归一响应：headers 键统一小写。"""

    status: int
    headers: Dict[str, str]
    body: bytes


@runtime_checkable
class Transport(Protocol):
    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        ...  # pragma: no cover —— Protocol 声明


def send_draft(transport: Transport, base_url: str, draft: RequestDraft) -> HttpResponse:
    """把 RequestDraft 交给 Transport：URL = base_url + path。"""
    url = base_url.rstrip("/") + draft.path
    return transport.send(draft.method, url, draft.headers, draft.wire_body)


from .urllib_transport import UrllibTransport  # noqa: E402  （置于 __all__ 定义后避免循环）
