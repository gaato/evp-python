"""Offline self-checks for the public-provider interop harness."""

from __future__ import annotations

import asyncio
import http.client
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from dns.exception import DNSException

from interop import chrome_evp as interop


def json_response(document: object) -> interop.HttpResponse:
    return interop.HttpResponse(
        200, "application/json; charset=utf-8", json.dumps(document).encode()
    )


def test_preflight_uses_site_document_and_mail_issuer() -> None:
    requests = []

    def get(url: str) -> interop.HttpResponse:
        requests.append(url)
        if url == f"{interop.ISSUER}/healthz":
            return interop.HttpResponse(200, "text/plain", b"ok")
        assert url == interop.WEB_IDENTITY
        return json_response({"accounts_endpoint": f"{interop.ISSUER}/fedcm/accounts"})

    def resolve(name: str) -> list[str]:
        assert name == interop.TXT_NAME
        return ["unrelated=value", "iss=mail.pyevp.dev"]

    interop.preflight(get, resolve)
    assert requests == [f"{interop.ISSUER}/healthz", interop.WEB_IDENTITY]


def test_preflight_rejects_unhealthy_provider() -> None:
    def get(url: str) -> interop.HttpResponse:
        assert url == f"{interop.ISSUER}/healthz"
        return interop.HttpResponse(503, "text/plain", b"unavailable")

    with pytest.raises(interop.ProviderUnavailable, match="healthz: HTTP 503"):
        interop.preflight(
            get, lambda _: pytest.fail("DNS must not run after a failed health check")
        )


@pytest.mark.parametrize(
    "response",
    [
        interop.HttpResponse(503, "text/plain", b"unavailable"),
        interop.HttpResponse(200, "text/html", b"{}"),
        interop.HttpResponse(200, "application/json", b"not json"),
        json_response({"accounts_endpoint": "https://pyevp.dev/fedcm/accounts"}),
        json_response({"accounts_endpoint": "https://mail.pyevp.dev.evil.test/accounts"}),
        json_response({"accounts_endpoint": "http://mail.pyevp.dev/accounts"}),
        json_response({"accounts_endpoint": "https://mail.pyevp.dev:bad/accounts"}),
        json_response([]),
    ],
)
def test_preflight_rejects_bad_web_identity(response: interop.HttpResponse) -> None:
    def get(url: str) -> interop.HttpResponse:
        if url.endswith("/healthz"):
            return interop.HttpResponse(200, "text/plain", b"ok")
        return response

    with pytest.raises(interop.ProviderUnavailable):
        interop.preflight(get, lambda _: ["iss=mail.pyevp.dev"])


@pytest.mark.parametrize("records", [[], ["iss=pyevp.dev"], ["iss=mail.pyevp.dev"] * 2])
def test_preflight_rejects_bad_txt(records: list[str]) -> None:
    response = json_response({"accounts_endpoint": f"{interop.ISSUER}/fedcm/accounts"})
    with pytest.raises(interop.ProviderUnavailable):
        interop.preflight(lambda _: response, lambda _: records)


@pytest.mark.parametrize("error", [OSError("offline"), DNSException("timeout")])
def test_preflight_wraps_transport_errors(error: Exception) -> None:
    def resolve(_: str) -> list[str]:
        raise error

    response = json_response({"accounts_endpoint": f"{interop.ISSUER}/fedcm/accounts"})
    with pytest.raises(interop.ProviderUnavailable, match=str(error)):
        interop.preflight(lambda _: response, resolve)


@pytest.mark.parametrize("error", [OSError("offline"), http.client.IncompleteRead(b"")])
def test_preflight_wraps_http_errors(error: Exception) -> None:
    def get(_: str) -> interop.HttpResponse:
        raise error

    with pytest.raises(interop.ProviderUnavailable, match="preflight:"):
        interop.preflight(get, lambda _: ["iss=mail.pyevp.dev"])


def test_unavailable_exits_before_starting_processes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def unavailable() -> None:
        raise interop.ProviderUnavailable("healthz: HTTP 503")

    def no_process(*args: Any, **kwargs: Any) -> None:
        pytest.fail("preflight must run before launching the RP or Chrome")

    monkeypatch.setenv("INTEROP_OUT", str(tmp_path))
    monkeypatch.setattr(interop, "preflight", unavailable)
    monkeypatch.setattr(interop, "process", no_process)
    assert interop.main() == interop.PROVIDER_UNAVAILABLE_EXIT
    output = capsys.readouterr().out
    assert "PROVIDER UNAVAILABLE: healthz: HTTP 503" in output
    assert "INTEROP FAILED" not in output


@pytest.mark.parametrize("email", [interop.EMAIL, None])
def test_parse_me(email: str | None) -> None:
    assert interop.parse_me({"email": email, "issued": 3, "build_sha": "abc123"}) == (
        interop.SessionState(email, 3, "abc123")
    )


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"issued": 0, "build_sha": "abc123"},
        {"email": 1, "issued": 0, "build_sha": "abc123"},
        {"email": interop.EMAIL, "issued": True, "build_sha": "abc123"},
        {"email": interop.EMAIL, "issued": -1, "build_sha": "abc123"},
        {"email": interop.EMAIL, "issued": "1", "build_sha": "abc123"},
        {"email": interop.EMAIL, "issued": 0, "build_sha": None},
    ],
)
def test_parse_me_rejects_malformed_session(document: object) -> None:
    with pytest.raises(interop.ProviderUnavailable):
        interop.parse_me(document)


def test_poll_uses_updated_browser_cookies_without_navigation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeTab(interop.DevTools):
        def __init__(self) -> None:
            self.polls = 0

        async def send(self, method: str, **params: Any) -> dict[str, Any]:
            assert method == "Network.getCookies"
            assert params == {"urls": [f"{interop.ISSUER}/me"]}
            self.polls += 1
            return {"cookies": [{"name": "session", "value": str(self.polls)}]}

    cookies = []

    def get(url: str, *, cookie: str = "") -> interop.HttpResponse:
        assert url == f"{interop.ISSUER}/me"
        cookies.append(cookie)
        # First poll sees the baseline; second observes Chrome's updated session.
        issued = 1 if cookie == "session=3" else 0
        return json_response({"email": interop.EMAIL, "issued": issued, "build_sha": "abc123"})

    async def no_sleep(delay: float) -> None:
        pass

    async def inline_transport(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    monkeypatch.setattr(interop, "fetch_response", get)
    monkeypatch.setattr(interop.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(interop.asyncio, "to_thread", inline_transport)

    async def check() -> None:
        session = interop.ProviderSession(FakeTab())
        before = await session.read()
        await session.wait_for_token(before, timeout=1)

    asyncio.run(check())
    assert cookies == ["session=1", "session=2", "session=3"]
    output = capsys.readouterr().out
    assert "provider build_sha=abc123" in output
    assert "issuer issued a token (0 -> 1)" in output
