# -*- coding: utf-8 -*-
"""httpx peer 适配器（extras：``pip install 'wop-python-sdk[httpx]'``）。"""
from typing import Dict, Optional

from . import HttpResponse, _READ_CHUNK, read_capped


class HttpxTransport:
    """httpx.Client 适配器；惰性导入，未安装时给出安装指引。

    响应走 ``Client.stream`` + ``iter_bytes`` 流式读取，累计超
    MAX_RESPONSE_BYTES（11MB）时即刻中断，不整体缓冲。
    """

    def __init__(self, client=None):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover —— 视环境而定
            raise ImportError(
                "httpx 未安装；peer 适配器请执行 pip install 'wop-python-sdk[httpx]'"
            ) from exc
        self._client = client if client is not None else httpx.Client()

    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        with self._client.stream(
            method, url, headers=headers, content=body
        ) as resp:
            data = read_capped(resp.iter_bytes(_READ_CHUNK))
            return HttpResponse(
                resp.status_code,
                {k.lower(): v for k, v in resp.headers.items()},
                data,
            )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpxTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
