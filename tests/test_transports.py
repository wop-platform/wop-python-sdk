# -*- coding: utf-8 -*-
"""传输层测试：Transport 协议、urllib 适配器（monkeypatch urlopen）、
httpx/requests peer 适配器（fake 模块注入）、未装依赖时的清晰报错、
11MB 响应体上限（边界可过 / 越界即拒 / 流式中断）。"""
import io
import sys
import types
import urllib.error
from unittest import mock

import pytest

from wop_sdk.client import RequestDraft
from wop_sdk.errors import ProtocolFormatError
from wop_sdk.transports import (
    MAX_RESPONSE_BYTES,
    _READ_CHUNK,
    HttpResponse,
    UrllibTransport,
    send_draft,
)
from wop_sdk.transports.httpx_transport import HttpxTransport
from wop_sdk.transports.requests_transport import RequestsTransport


class TestSendDraft:
    def test_url_join_and_pass_through(self):
        draft = RequestDraft("POST", "/gateway/x", {"x-wop-appkey": "ak"}, b"{}", "L0")
        captured = {}

        class FakeTransport:
            def send(self, method, url, headers, body):
                captured.update(method=method, url=url, headers=headers, body=body)
                return HttpResponse(200, {}, b"ok")

        resp = send_draft(FakeTransport(), "https://gw.example.com/", draft)
        assert resp.status == 200 and resp.body == b"ok"
        assert captured["url"] == "https://gw.example.com/gateway/x"
        assert captured["method"] == "POST"
        assert captured["headers"] is draft.headers
        assert captured["body"] == b"{}"

    def test_no_body_sends_none(self):
        draft = RequestDraft("GET", "/q", {}, None, "L0")

        class FakeTransport:
            def send(self, method, url, headers, body):
                assert body is None
                return HttpResponse(204, {}, b"")

        send_draft(FakeTransport(), "https://gw", draft)


def _ok_response(status=200, body=b'{"ok":1}', headers=None):
    resp_obj = mock.MagicMock()
    resp_obj.status = status
    resp_obj.headers = headers if headers is not None else {}
    # 流式语义：read(n) 返回至多 n 字节，EOF 返回 b""
    remaining = memoryview(body)

    def _read(size):
        nonlocal remaining
        chunk = bytes(remaining[:size])
        remaining = remaining[size:]
        return chunk

    resp_obj.read.side_effect = _read
    resp_obj.__enter__.return_value = resp_obj
    resp_obj.__exit__.return_value = False
    return resp_obj


class TestUrllibTransport:
    def test_success(self):
        resp_obj = _ok_response(200, b'{"ok":1}', {"Content-Type": "application/json", "X-Wop-Sign": "sig"})
        with mock.patch("urllib.request.urlopen", return_value=resp_obj):
            resp = UrllibTransport().send("POST", "https://gw/p", {"a": "b"}, b"body")
        assert resp.status == 200
        assert resp.body == b'{"ok":1}'
        assert resp.headers == {"content-type": "application/json", "x-wop-sign": "sig"}

    def test_http_error_returns_body(self):
        err = urllib.error.HTTPError(
            "url", 404, "Not Found", hdrs={"X-E": "1"}, fp=io.BytesIO(b'{"err":1}')
        )
        with mock.patch("urllib.request.urlopen", side_effect=err):
            resp = UrllibTransport().send("GET", "https://gw/p", {}, None)
        assert resp.status == 404
        assert resp.body == b'{"err":1}'
        assert resp.headers == {"x-e": "1"}

    def test_request_headers_and_body_applied(self):
        resp_obj = _ok_response()
        with mock.patch("urllib.request.urlopen", return_value=resp_obj) as urlopen:
            UrllibTransport().send("POST", "https://gw/p", {"x-wop-appkey": "ak"}, b"b")
        req = urlopen.call_args[0][0]
        assert req.get_header("X-wop-appkey") == "ak"
        assert req.data == b"b"


class _UrllibLimit:
    """urllib 上限边界：sized（有限总量）/ endless（无限流）两种 read 侧写。"""

    @staticmethod
    def _sized_read(total):
        state = {"remaining": total}

        def read(size):
            take = min(size, state["remaining"])
            state["remaining"] -= take
            return b"x" * take if take else b""

        return read

    @staticmethod
    def _endless_read(counter):
        def read(size):
            counter["count"] += 1
            return b"x" * size

        return read


class TestUrllibTransportLimit:
    def test_at_limit_passes(self):
        # 恰 11MB：等于上限不算越界
        resp_obj = _ok_response(200, b"", {})
        resp_obj.read.side_effect = _UrllibLimit._sized_read(MAX_RESPONSE_BYTES)
        with mock.patch("urllib.request.urlopen", return_value=resp_obj):
            resp = UrllibTransport().send("GET", "https://gw/p", {}, None)
        assert len(resp.body) == MAX_RESPONSE_BYTES

    def test_over_limit_rejected_immediately(self):
        reads = {"count": 0}
        resp_obj = _ok_response(200, b"", {})
        resp_obj.read.side_effect = _UrllibLimit._endless_read(reads)
        with mock.patch("urllib.request.urlopen", return_value=resp_obj):
            with pytest.raises(ProtocolFormatError):
                UrllibTransport().send("GET", "https://gw/p", {}, None)
        # 无限流也能返回 → 读取中流式计数生效；恰在累计首次越界的 chunk 处中断
        assert (reads["count"] - 1) * _READ_CHUNK <= MAX_RESPONSE_BYTES
        assert reads["count"] * _READ_CHUNK > MAX_RESPONSE_BYTES


class _FakeHttpxStream:
    def __init__(self, status_code=201, headers=None, body=b"resp"):
        self.status_code = status_code
        self.headers = headers if headers is not None else {"X-Wop-Sign": "s"}
        self._body = body

    def iter_bytes(self, chunk_size=None):
        size = chunk_size or _READ_CHUNK
        mv = memoryview(self._body)
        for i in range(0, len(mv), size):
            yield bytes(mv[i:i + size])

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _FakeHttpx:
    def __init__(self):
        self.calls = []

    def close(self):
        pass

    def stream(self, method, url, headers=None, content=None):
        self.calls.append((method, url, headers, content))
        return _FakeHttpxStream()


class TestHttpxTransport:
    def test_send(self, monkeypatch):
        fake_mod = types.ModuleType("httpx")
        fake_client = _FakeHttpx()
        fake_mod.Client = lambda: fake_client
        monkeypatch.setitem(sys.modules, "httpx", fake_mod)
        with HttpxTransport() as t:
            resp = t.send("POST", "https://gw/p", {"h": "1"}, b"body")
        assert (resp.status, resp.body, resp.headers) == (201, b"resp", {"x-wop-sign": "s"})
        assert fake_client.calls[0][2] == {"h": "1"}

    def test_missing_dependency_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "httpx", None)  # import httpx → ImportError
        with pytest.raises(ImportError, match="httpx"):
            HttpxTransport()


class TestHttpxTransportLimit:
    def _transport_with(self, monkeypatch, chunks_factory):
        fake_mod = types.ModuleType("httpx")
        fake_client = _FakeHttpx()
        stream = _FakeHttpxStream(body=b"")

        def iter_bytes(chunk_size=None):
            yield from chunks_factory(chunk_size or _READ_CHUNK)

        stream.iter_bytes = iter_bytes
        fake_client.stream = lambda *a, **k: stream
        fake_mod.Client = lambda: fake_client
        monkeypatch.setitem(sys.modules, "httpx", fake_mod)
        return HttpxTransport()

    def test_at_limit_passes(self, monkeypatch):
        t = self._transport_with(monkeypatch, lambda size: [b"x" * MAX_RESPONSE_BYTES])
        resp = t.send("GET", "https://gw/p", {}, None)
        assert len(resp.body) == MAX_RESPONSE_BYTES

    def test_over_limit_rejected_immediately(self, monkeypatch):
        reads = {"count": 0}

        def endless_chunks(size):
            while True:
                reads["count"] += 1
                yield b"x" * size

        t = self._transport_with(monkeypatch, endless_chunks)
        with pytest.raises(ProtocolFormatError):
            t.send("GET", "https://gw/p", {}, None)
        assert (reads["count"] - 1) * _READ_CHUNK <= MAX_RESPONSE_BYTES
        assert reads["count"] * _READ_CHUNK > MAX_RESPONSE_BYTES


class _FakeRequestsResponse:
    def __init__(self, status_code=200, headers=None, body=b"r"):
        self.status_code = status_code
        self.headers = headers if headers is not None else {"X-Wop-Sign": "s"}
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=1):
        mv = memoryview(self._body)
        for i in range(0, len(mv), chunk_size):
            yield bytes(mv[i:i + chunk_size])

    def close(self):
        self.closed = True


class _FakeRequests:
    def __init__(self, response=None):
        self.calls = []
        self.stream_flags = []
        self._response = response if response is not None else _FakeRequestsResponse()

    def close(self):
        pass

    def request(self, method, url, headers=None, data=None, stream=False):
        self.calls.append((method, url, headers, data))
        self.stream_flags.append(stream)
        return self._response


class TestRequestsTransport:
    def test_send(self, monkeypatch):
        fake_mod = types.ModuleType("requests")
        fake = _FakeRequests()
        fake_mod.Session = lambda: fake
        fake_mod.request = fake.request
        monkeypatch.setitem(sys.modules, "requests", fake_mod)
        with RequestsTransport() as t:
            resp = t.send("GET", "https://gw/q", {"h": "1"}, None)
        assert (resp.status, resp.body) == (200, b"r")
        assert fake.calls[0][3] is None
        assert fake.stream_flags == [True]  # 流式拉取，不整体缓冲

    def test_missing_dependency_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "requests", None)
        with pytest.raises(ImportError, match="requests"):
            RequestsTransport()


class TestRequestsTransportLimit:
    def test_at_limit_passes(self, monkeypatch):
        fake_mod = types.ModuleType("requests")
        fake = _FakeRequests(response=_FakeRequestsResponse(body=b"x" * MAX_RESPONSE_BYTES))
        fake_mod.Session = lambda: fake
        monkeypatch.setitem(sys.modules, "requests", fake_mod)
        with RequestsTransport() as t:
            resp = t.send("GET", "https://gw/q", {}, None)
        assert len(resp.body) == MAX_RESPONSE_BYTES

    def test_over_limit_rejected_and_response_closed(self, monkeypatch):
        reads = {"count": 0}

        def endless_chunks(size):
            while True:
                reads["count"] += 1
                yield b"x" * size

        response = _FakeRequestsResponse()
        response.iter_content = lambda chunk_size=1: endless_chunks(chunk_size)
        fake_mod = types.ModuleType("requests")
        fake = _FakeRequests(response=response)
        fake_mod.Session = lambda: fake
        monkeypatch.setitem(sys.modules, "requests", fake_mod)
        t = RequestsTransport()
        with pytest.raises(ProtocolFormatError):
            t.send("GET", "https://gw/q", {}, None)
        assert response.closed  # 越界中断也释放连接
        assert (reads["count"] - 1) * _READ_CHUNK <= MAX_RESPONSE_BYTES
        assert reads["count"] * _READ_CHUNK > MAX_RESPONSE_BYTES
