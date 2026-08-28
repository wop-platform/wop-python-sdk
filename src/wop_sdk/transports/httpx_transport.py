# -*- coding: utf-8 -*-
"""httpx peer 适配器（extras：``pip install 'wop-sdk[httpx]'``）。"""
from typing import Dict, Optional

from . import HttpResponse


class HttpxTransport:
    """httpx.Client 适配器；惰性导入，未安装时给出安装指引。"""

    def __init__(self, client=None):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover —— 视环境而定
            raise ImportError(
                "httpx 未安装；peer 适配器请执行 pip install 'wop-sdk[httpx]'"
            ) from exc
        self._client = client if client is not None else httpx.Client()

    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        resp = self._client.request(method, url, headers=headers, content=body)
        return HttpResponse(
            resp.status_code,
            {k.lower(): v for k, v in resp.headers.items()},
            resp.content,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpxTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
