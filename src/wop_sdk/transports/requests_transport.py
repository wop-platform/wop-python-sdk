# -*- coding: utf-8 -*-
"""requests peer 适配器（extras：``pip install 'wop-sdk[requests]'``）。"""
from typing import Dict, Optional

from . import HttpResponse


class RequestsTransport:
    """requests 适配器；惰性导入，未安装时给出安装指引。"""

    def __init__(self, session=None):
        try:
            import requests
        except ImportError as exc:  # pragma: no cover —— 视环境而定
            raise ImportError(
                "requests 未安装；peer 适配器请执行 pip install 'wop-sdk[requests]'"
            ) from exc
        self._session = session if session is not None else requests.Session()

    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        resp = self._session.request(method, url, headers=headers, data=body)
        return HttpResponse(
            resp.status_code,
            {k.lower(): v for k, v in resp.headers.items()},
            resp.content,
        )

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "RequestsTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
