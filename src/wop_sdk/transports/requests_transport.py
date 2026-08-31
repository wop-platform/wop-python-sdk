# -*- coding: utf-8 -*-
"""requests peer 适配器（extras：``pip install 'wop-python-sdk[requests]'``）。"""
from typing import Dict, Optional

from . import HttpResponse, _READ_CHUNK, read_capped


class RequestsTransport:
    """requests 适配器；惰性导入，未安装时给出安装指引。

    请求带 ``stream=True``，响应经 ``iter_content`` 流式读取，累计超
    MAX_RESPONSE_BYTES（11MB）时即刻中断，不整体缓冲。
    """

    def __init__(self, session=None):
        try:
            import requests
        except ImportError as exc:  # pragma: no cover —— 视环境而定
            raise ImportError(
                "requests 未安装；peer 适配器请执行 pip install 'wop-python-sdk[requests]'"
            ) from exc
        self._session = session if session is not None else requests.Session()

    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        """requests 流式执行请求（stream=True）：iter_content 逐块经 read_capped 限量后归一。"""
        resp = self._session.request(
            method, url, headers=headers, data=body, stream=True
        )
        try:
            data = read_capped(resp.iter_content(_READ_CHUNK))
        finally:
            resp.close()
        return HttpResponse(
            resp.status_code,
            {k.lower(): v for k, v in resp.headers.items()},
            data,
        )

    def close(self) -> None:
        """关闭底层 requests.Session（释放连接池）。"""
        self._session.close()

    def __enter__(self) -> "RequestsTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
