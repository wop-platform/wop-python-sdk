# -*- coding: utf-8 -*-
"""stdlib urllib 适配器（零依赖，随主包交付）。"""
import urllib.error
import urllib.request
from typing import Dict, Optional

from . import HttpResponse


class UrllibTransport:
    """urllib.request 适配器；4xx/5xx 返回响应体而非抛异常（协议错误也在 body 里）。"""

    def send(
        self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> HttpResponse:
        req = urllib.request.Request(url, data=body, method=method)
        for name, value in headers.items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req) as resp:
                return HttpResponse(
                    resp.status,
                    {k.lower(): v for k, v in resp.headers.items()},
                    resp.read(),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()
            )
