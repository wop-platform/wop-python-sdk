# -*- coding: utf-8 -*-
"""传输层测试：Transport 协议、urllib 适配器（monkeypatch urlopen）、
httpx/requests peer 适配器（fake 模块注入）、未装依赖时的清晰报错。"""
import io
import sys
import types
import urllib.error
from unittest import mock

import pytest

from wop_sdk.client import RequestDraft
from wop_sdk.transports import HttpResponse, UrllibTransport, send_draft
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
    resp_obj.read.return_value = body
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


class _FakeHttpx:
    def __init__(self):
        self.calls = []

    def close(self):
        pass

    def request(self, method, url, headers=None, content=None):
        self.calls.append((method, url, headers, content))
        return types.SimpleNamespace(
            status_code=201, headers={"X-Wop-Sign": "s"}, content=b"resp"
        )


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


class _FakeRequests:
    def __init__(self):
        self.calls = []

    def close(self):
        pass

    def request(self, method, url, headers=None, data=None):
        self.calls.append((method, url, headers, data))
        return types.SimpleNamespace(
            status_code=200, headers={"X-Wop-Sign": "s"}, content=b"r"
        )


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

    def test_missing_dependency_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "requests", None)
        with pytest.raises(ImportError, match="requests"):
            RequestsTransport()
