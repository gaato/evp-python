from __future__ import annotations

import gzip
import json
import subprocess
import sys
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from pyevp import JsonFetcher, TxtResolver
from pyevp.adapters import _fetch
from pyevp.adapters.urllib import (
    DnssecError,
    DohError,
    FetchError,
    UrllibDohResolver,
    UrllibFetcher,
)

NAME = "_email-verification.gmail.com"


def _answer(data: str, type_: int = 16) -> dict[str, Any]:
    return {"name": NAME, "type": type_, "TTL": 3600, "data": data}


DOH: dict[str, Any] = {
    "google": {"Status": 0, "AD": False, "Answer": [_answer("iss=accounts.google.com")]},
    "cloudflare": {"Status": 0, "AD": False, "Answer": [_answer('"iss=accounts.google.com"')]},
    "cname": {
        "Status": 0,
        "AD": True,
        "Answer": [_answer("target.example.", 5), _answer("iss=a.example")],
    },
    "nodata": {"Status": 0, "AD": False},
    "nxdomain": {"Status": 3, "AD": False},
    "servfail": {"Status": 2},
}


class _Handler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, str]]]

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, rest: bytes) -> None:
        """Send a 200 status line, then ``rest`` verbatim, then close the connection."""
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + rest)
        self.close_connection = True

    def do_GET(self) -> None:
        self.requests.append((self.path, dict(self.headers)))
        path = urlsplit(self.path).path
        match path.split("/")[1:]:
            case ["json"]:
                self._send(200, b'{"issuer": "https://issuer.example"}')
            case ["redirect"]:
                self._send(302, Location="/json")
            case ["html"]:
                self._send(200, b"<html>")
            case ["gzip"]:
                self._send(200, gzip.compress(b"{}"), Content_Encoding="gzip")
            case ["huge"]:
                self._send(200, b"[" + b"0," * _fetch.MAX_DOCUMENT_BYTES + b"0]")
            case ["short"]:
                self._send_raw(b"Content-Length: 100\r\n\r\n{}")
            case ["chunked-short"]:
                self._send_raw(b"Transfer-Encoding: chunked\r\n\r\n64\r\n{}")
            case ["created"]:
                self._send(201, b"{}")
            case ["doh", "http500"]:
                self._send(500)
            case ["doh", kind]:
                self._send(200, json.dumps(DOH[kind]).encode())
            case _:
                self._send(404)


@pytest.fixture(scope="module")
def server() -> Iterator[tuple[str, list[tuple[str, dict[str, str]]]]]:
    requests: list[tuple[str, dict[str, str]]] = []
    handler = type("Handler", (_Handler,), {"requests": requests})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", requests
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def base(server: tuple[str, list[Any]]) -> str:
    server[1].clear()
    return server[0]


@pytest.fixture
def requests(server: tuple[str, list[Any]]) -> list[tuple[str, dict[str, str]]]:
    return server[1]


# Environment proxies would intercept requests to the local server.
@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)


def test_satisfies_protocols() -> None:
    assert isinstance(UrllibFetcher(), JsonFetcher)
    assert isinstance(UrllibDohResolver(), TxtResolver)


def test_fetch_json(base: str, requests: list[Any]) -> None:
    assert UrllibFetcher().fetch_json(f"{base}/json") == {"issuer": "https://issuer.example"}
    [(_, headers)] = requests
    assert headers["Accept"] == "application/json"
    assert headers["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "path",
    ["/redirect", "/html", "/gzip", "/huge", "/created", "/missing", "/short", "/chunked-short"],
)
def test_fetch_errors(base: str, path: str) -> None:
    with pytest.raises(FetchError):
        UrllibFetcher().fetch_json(base + path)


def test_does_not_follow_redirects(base: str, requests: list[Any]) -> None:
    with pytest.raises(FetchError, match="HTTP 302"):
        UrllibFetcher().fetch_json(f"{base}/redirect")
    assert [path for path, _ in requests] == ["/redirect"]


def test_caller_redirect_handler_is_replaced(base: str, requests: list[Any]) -> None:
    fetcher = UrllibFetcher(handlers=[urllib.request.HTTPRedirectHandler()])
    with pytest.raises(FetchError, match="HTTP 302"):
        fetcher.fetch_json(f"{base}/redirect")
    assert [path for path, _ in requests] == ["/redirect"]


def test_connection_errors() -> None:
    # Port 9 (discard) on localhost is closed on any sane test machine.
    with pytest.raises(FetchError, match="failed"):
        UrllibFetcher(timeout=1).fetch_json("http://127.0.0.1:9/")


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("google", ["iss=accounts.google.com"]),
        ("cloudflare", ["iss=accounts.google.com"]),
        ("cname", ["iss=a.example"]),
        ("nodata", []),
        ("nxdomain", []),
    ],
)
def test_resolve(base: str, kind: str, expected: list[str]) -> None:
    assert UrllibDohResolver(f"{base}/doh/{kind}").resolve_txt(NAME) == expected


@pytest.mark.parametrize("kind", ["servfail", "http500"])
def test_resolve_errors(base: str, kind: str) -> None:
    with pytest.raises(DohError):
        UrllibDohResolver(f"{base}/doh/{kind}").resolve_txt(NAME)


@pytest.mark.parametrize("path", ["/short", "/chunked-short"])
def test_resolve_rejects_truncated_bodies(base: str, path: str) -> None:
    with pytest.raises(DohError):
        UrllibDohResolver(base + path).resolve_txt(NAME)


def test_resolve_rejects_non_json(base: str) -> None:
    with pytest.raises(DohError, match="did not return JSON"):
        UrllibDohResolver(f"{base}/html").resolve_txt(NAME)


def test_resolve_request_shape(base: str, requests: list[Any]) -> None:
    UrllibDohResolver(f"{base}/doh/google").resolve_txt(NAME)
    [(path, headers)] = requests
    assert parse_qs(urlsplit(path).query) == {"name": [NAME], "type": ["TXT"], "do": ["1"]}
    assert headers["Accept"] == "application/dns-json"


def test_resolve_keeps_endpoint_query(base: str, requests: list[Any]) -> None:
    resolver = UrllibDohResolver(f"{base}/doh/google?account=test#ignored")
    assert resolver.resolve_txt(NAME) == ["iss=accounts.google.com"]
    [(path, _)] = requests
    assert parse_qs(urlsplit(path).query) == {
        "account": ["test"],
        "name": [NAME],
        "type": ["TXT"],
        "do": ["1"],
    }


def test_require_dnssec(base: str) -> None:
    resolver = UrllibDohResolver(f"{base}/doh/cname", require_dnssec=True)
    assert resolver.resolve_txt(NAME) == ["iss=a.example"]
    with pytest.raises(DnssecError):
        UrllibDohResolver(f"{base}/doh/google", require_dnssec=True).resolve_txt(NAME)


def test_imports_without_httpx() -> None:
    code = (
        "import sys\n"
        "sys.modules.update(httpx=None, httpx2=None, dns=None)\n"
        "import pyevp.adapters.urllib\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
