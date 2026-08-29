# -*- coding: utf-8 -*-
"""可插拔 HTTP 适配层（Q1 定稿）：协议核心零网络 IO，传输以独立模块交付。

- ``Transport``：协议接口，商户自带栈时可直接实现或消费 RequestDraft；
- ``send_draft``：RequestDraft → Transport（URL 拼接归此，适配器只面对完整请求）；
- ``MAX_RESPONSE_BYTES`` / ``read_capped``：响应体 11MB 上限，流式读取中生效；
- stdlib urllib 适配器随主包；httpx / requests 适配器为 peer 依赖（extras）。
"""
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Protocol, runtime_checkable

from ..client import RequestDraft
from ..errors import ProtocolFormatError

__all__ = ["HttpResponse", "MAX_RESPONSE_BYTES", "Transport", "UrllibTransport", "read_capped", "send_draft"]

# 响应体上限 11MB：与网关 maxContentLength 及各语言 SDK（dotnet/Go 11<<20）对齐；
# 必须在读取过程中生效（流式计数），而非整体缓冲后检查
MAX_RESPONSE_BYTES = 11 << 20
_READ_CHUNK = 1 << 16


def read_capped(chunks: Iterable[bytes]) -> bytes:
    """流式消费响应体分块并累计；累计越上限即刻抛 ProtocolFormatError。

    逐块检查（读取过程中生效）：任何一 chunk 使累计超过 MAX_RESPONSE_BYTES 即中断，
    不再把无限/超大响应整体缓冲进内存。
    """
    buf = bytearray()
    for chunk in chunks:
        buf += chunk
        if len(buf) > MAX_RESPONSE_BYTES:
            raise ProtocolFormatError(
                "响应体超过传输层上限 %d 字节" % MAX_RESPONSE_BYTES
            )
    return bytes(buf)


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
