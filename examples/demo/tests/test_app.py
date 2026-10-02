"""The demo app, tested against fakes."""

from __future__ import annotations

import re
from collections.abc import Iterator

import app as demo
import pytest
from app import AllowedIssuers, app, get_verifier
from fastapi.testclient import TestClient

from pyevp import AsyncVerifier, InMemoryReplayGuard
from pyevp.testing import AsyncInMemoryDns, AsyncInMemoryHttp, FakeBrowser, FakeIssuer

ORIGIN = "http://testserver"


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer.gmail_like()


@pytest.fixture
def stranger() -> FakeIssuer:
    """An issuer the demo does not allow, for a domain an attacker controls."""
    return FakeIssuer(host="evil.example", email_domains=("evil.example",))


@pytest.fixture
def http(issuer: FakeIssuer, stranger: FakeIssuer) -> AsyncInMemoryHttp:
    return AsyncInMemoryHttp(issuer.http_documents() | stranger.http_documents())


@pytest.fixture
def client(
    issuer: FakeIssuer,
    stranger: FakeIssuer,
    http: AsyncInMemoryHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    monkeypatch.setattr(demo, "ORIGIN", ORIGIN)
    dns = AsyncInMemoryDns(issuer.dns_records() | stranger.dns_records())
    verifier = AsyncVerifier(
        audience=ORIGIN,
        resolver=AllowedIssuers(dns, [issuer.issuer]),
        fetcher=http,
        clock=issuer.clock,
        replay_guard=InMemoryReplayGuard(clock=issuer.clock),
    )
    app.dependency_overrides[get_verifier] = lambda: verifier
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def _nonce(client: TestClient) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/").text)
    assert match
    return match.group(1)


def _present(issuer: FakeIssuer, email: str, nonce: str) -> str:
    browser = FakeBrowser(clock=issuer.clock)
    return browser.present(issuer.issue(email, browser.public_jwk), audience=ORIGIN, nonce=nonce)


def test_verified(client: TestClient, issuer: FakeIssuer) -> None:
    evt = _present(issuer, "alice@gmail.example", _nonce(client))
    response = client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 200
    assert "Verified" in response.text
    assert "alice@gmail.example" in response.text
    assert issuer.issuer in response.text


def test_no_token(client: TestClient) -> None:
    _nonce(client)
    response = client.post("/verify", data={"email": "alice@gmail.example"})
    assert response.status_code == 200
    assert "No token received" in response.text


def test_failure_shows_code(client: TestClient, issuer: FakeIssuer) -> None:
    _nonce(client)
    evt = _present(issuer, "alice@gmail.example", "stolen")
    response = client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "nonce_mismatch" in response.text


def test_replay(client: TestClient, issuer: FakeIssuer) -> None:
    nonce = _nonce(client)
    captured = dict(client.cookies)
    form = {"email": "alice@gmail.example", "evt": _present(issuer, "alice@gmail.example", nonce)}
    assert client.post("/verify", data=form).status_code == 200
    client.cookies.clear()
    client.cookies.update(captured)
    response = client.post("/verify", data=form)
    assert response.status_code == 400
    assert "token_replayed" in response.text


def test_unlisted_issuer_is_never_fetched(
    client: TestClient, stranger: FakeIssuer, http: AsyncInMemoryHttp
) -> None:
    evt = _present(stranger, "mallory@evil.example", _nonce(client))
    response = client.post("/verify", data={"email": "mallory@evil.example", "evt": evt})
    assert response.status_code == 400
    assert "issuer_discovery_failed" in response.text
    assert not any("evil.example" in url for url in http.requests)


def test_output_is_escaped(client: TestClient) -> None:
    _nonce(client)
    evt = "<script>alert(1)</script>"
    response = client.post("/verify", data={"email": "a@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "<script>alert(1)" not in response.text


def test_healthz_and_headers(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.text == "ok"
    assert response.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" not in response.headers
