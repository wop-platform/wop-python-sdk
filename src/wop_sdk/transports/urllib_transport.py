# -*- coding: utf-8 -*-
"""stdlib urllib 适配器（零依赖，随主包交付）。"""
import urllib.error
import urllib.request
from typing import Dict, Iterator, Optional

from . import HttpResponse, _READ_CHUNK, read_capped


def _urllib_chunks(resp) -> Iterator[bytes]:
    """resp.read(n) 循环取块，直至 EOF；配合 read_capped 流式限量。"""
    while True:
        if chunk := resp.read(_READ_CHUNK):
            yield chunk
        else:
            break


class UrllibTransport:
    """urllib.request 适配器；4xx/5xx 返回响应体而非抛异常（协议错误也在 body 里）。

    响应体按块流式读取并在累计超 MAX_RESPONSE_BYTES（11MB）时即刻中断。
    """

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
                    read_capped(_urllib_chunks(resp)),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                exc.code,
                {k.lower(): v for k, v in exc.headers.items()},
                read_capped(_urllib_chunks(exc)),
            )
