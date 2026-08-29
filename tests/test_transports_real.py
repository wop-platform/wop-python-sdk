# -*- coding: utf-8 -*-
"""真实库 transport 兼容性测试（区别于 test_transports.py 的 fake 模块注入）。

- httpx：真 ``httpx.Client.stream`` 全链路，仅以官方 ``MockTransport`` 打桩 socket 层；
- requests：真 ``Session.request(stream=True)`` → HTTPAdapter.mount 分发，仅覆写
  ``HTTPAdapter.send`` 返回真实 ``requests.models.Response``（raw 提供流式分块）。

被测 API 面 = 适配器实际调用的稳定接口：
httpx ``Client()/Client.stream(method, url, headers=, content=)/Response.iter_bytes(n)/close()``
（区间 0.24–0.28）；requests ``Session()/Session.request(method, url, headers=, data=,
stream=)/Response.iter_content(n)/close()``（区间 2.28–最新）。
CI 覆盖两端：test 矩阵跑最新，oldest-deps 跑下界（httpx 0.24.0 / requests 2.28.0）。
本地未安装时 importorskip 跳过（fake 模块测试仍兜底结构正确性）。
"""
import pytest

from wop_sdk.errors import ProtocolFormatError
from wop_sdk.transports import MAX_RESPONSE_BYTES
from wop_sdk.transports.httpx_transport import HttpxTransport
from wop_sdk.transports.requests_transport import RequestsTransport

httpx = pytest.importorskip("httpx", reason="真库测试需要 httpx（CI extras 已装）")


class TestRealHttpx:
    def test_full_client_path(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["url"] = str(request.url)
            captured["body"] = request.content
            captured["headers"] = dict(request.headers)
            return httpx.Response(201, headers={"X-Wop-Sign": "sig"}, content=b"resp")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with HttpxTransport(client=client) as t:
            resp = t.send("POST", "https://gw.example.com/p", {"x-wop-appkey": "ak"}, b"body")
        # 真实 Client.request → MockTransport → Response 解析全链路
        assert resp.headers["x-wop-sign"] == "sig"
        assert resp.headers["content-length"] == "4"  # 真实 Response 自动头（fake 模块测不到）
        assert captured["url"] == "https://gw.example.com/p"
        assert captured["body"] == b"body"
        assert captured["headers"]["x-wop-appkey"] == "ak"  # 真实 Headers 小写键

    def test_over_limit_rejected_while_streaming(self):
        # 真库 Client.stream + iter_bytes 全链路：11MB+1 的响应在流式读取中被拒
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with HttpxTransport(client=client) as t:
            with pytest.raises(ProtocolFormatError):
                t.send("GET", "https://gw/q", {}, None)

    def test_get_without_body(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(204)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with HttpxTransport(client=client) as t:
            resp = t.send("GET", "https://gw/q", {}, None)
        assert (resp.status, resp.body, captured["body"]) == (204, b"", b"")


requests_lib = pytest.importorskip("requests", reason="真库测试需要 requests（CI extras 已装）")


class _BytesRaw:
    """urllib3 风格 raw 流：具备 stream()/close() 即可被 requests.iter_content 消费。"""

    def __init__(self, data):
        self._data = data

    def stream(self, chunk_size, decode_content=False):
        for i in range(0, len(self._data), chunk_size):
            yield self._data[i:i + chunk_size]

    def close(self):
        pass


class _StubAdapter(requests_lib.adapters.HTTPAdapter):
    """覆写 send() 返回真实 Response 对象；Session.request 的 headers/data 合并、
    adapter mount 分发、close() 全部走 requests 真码。响应体经 raw 流式供给
    （适配器以 stream=True + iter_content 消费）。"""

    def __init__(self, captured, body=b"r"):
        super().__init__()
        self._captured = captured
        self._body = body

    def send(self, request, **kwargs):
        self._captured["method"] = request.method
        self._captured["url"] = request.url
        self._captured["body"] = request.body
        self._captured["headers"] = dict(request.headers)
        resp = requests_lib.models.Response()
        resp.status_code = 200
        resp.headers["X-Wop-Sign"] = "sig"
        resp.raw = _BytesRaw(self._body)
        resp.request = request
        return resp


class TestRealRequests:
    def test_full_session_path(self):
        captured = {}
        session = requests_lib.Session()
        session.mount("https://", _StubAdapter(captured))
        with RequestsTransport(session=session) as t:
            resp = t.send("POST", "https://gw.example.com/p", {"x-wop-appkey": "ak"}, b"body")
        assert (resp.status, resp.body) == (200, b"r")
        assert resp.headers == {"x-wop-sign": "sig"}
        assert captured["method"] == "POST"
        assert captured["url"] == "https://gw.example.com/p"
        assert captured["body"] == b"body"
        assert captured["headers"]["x-wop-appkey"] == "ak"  # CaseInsensitiveDict 真实传递

    def test_get_without_body(self):
        captured = {}
        session = requests_lib.Session()
        session.mount("https://", _StubAdapter(captured))
        with RequestsTransport(session=session) as t:
            resp = t.send("GET", "https://gw/q", {}, None)
        assert resp.status == 200
        assert captured["body"] is None

    def test_over_limit_rejected_while_streaming(self):
        # 真库 Session.request(stream=True) + iter_content 全链路：越界响应被拒
        session = requests_lib.Session()
        session.mount("https://", _StubAdapter({}, body=b"x" * (MAX_RESPONSE_BYTES + 1)))
        with RequestsTransport(session=session) as t:
            with pytest.raises(ProtocolFormatError):
                t.send("GET", "https://gw/q", {}, None)
