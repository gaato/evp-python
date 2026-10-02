"""The issuer example, driven by a fake browser and checked by a verifier."""

from __future__ import annotations

from collections.abc import Iterator

import httpx2
import pytest
from app import ISSUANCE_PATH, JWKS_PATH, create_app
from fastapi.testclient import TestClient

from evp import Verifier
from evp.issuer import Issuer, SigningKey
from evp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

PUBLIC_URL = "https://testserver"
RP = "https://rp.example"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def issuer(clock: FixedClock) -> Issuer:
    return Issuer(
        issuer="https://issuer.example",
        issuance_endpoint=PUBLIC_URL + ISSUANCE_PATH,
        jwks_uri=PUBLIC_URL + JWKS_PATH,
        signer=SigningKey.generate(kid="2026-10"),
        email_domains=["example.com"],
        clock=clock,
    )


@pytest.fixture
def client(issuer: Issuer) -> Iterator[TestClient]:
    app = create_app(issuer, {"alice@example.com": "hunter2"}, session_secret="test")
    with TestClient(app, base_url=PUBLIC_URL) as client:
        yield client


def _issue(client: TestClient, browser: FakeBrowser, email: str) -> httpx2.Response:
    request = browser.issuance_request(email, endpoint=PUBLIC_URL + ISSUANCE_PATH)
    return client.post(ISSUANCE_PATH, headers=request["headers"], content=request["body"])


def _login(
    client: TestClient, email: str = "alice@example.com", password: str = "hunter2"
) -> httpx2.Response:
    return client.post("/login", data={"email": email, "password": password})


def test_documents(client: TestClient, issuer: Issuer) -> None:
    assert client.get("/.well-known/email-verification").json() == issuer.metadata_document()
    assert client.get(JWKS_PATH).json() == issuer.jwks_document()


def test_logged_in_user_gets_a_verifiable_token(
    client: TestClient, issuer: Issuer, clock: FixedClock
) -> None:
    assert _login(client).status_code == 200
    browser = FakeBrowser(clock=clock)
    response = _issue(client, browser, "alice@example.com")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    evt = response.json()["issuance_token"]

    verifier = Verifier(
        audience=RP,
        resolver=InMemoryDns({k: [v] for k, v in issuer.dns_txt_records().items()}),
        fetcher=InMemoryHttp(
            {
                "https://issuer.example/.well-known/email-verification": issuer.metadata_document(),
                issuer.jwks_uri: issuer.jwks_document(),
            }
        ),
        clock=clock,
    )
    token = browser.present(evt, audience=RP, nonce="n")
    assert verifier.verify(token, nonce="n", email="alice@example.com").email == "alice@example.com"


def test_failures_look_the_same(client: TestClient, clock: FixedClock) -> None:
    browser = FakeBrowser(clock=clock)
    anonymous = _issue(client, browser, "alice@example.com")
    _login(client)
    other_user = _issue(client, browser, "bob@example.com")
    other_domain = _issue(client, browser, "alice@other.example")
    assert anonymous.status_code == other_user.status_code == other_domain.status_code == 401
    assert anonymous.content == other_user.content == other_domain.content


def test_login_status(client: TestClient, clock: FixedClock) -> None:
    login = _login(client)
    assert login.headers["set-login"] == "logged-in"
    logout = client.post("/logout")
    assert logout.headers["set-login"] == "logged-out"
    assert _issue(client, FakeBrowser(clock=clock), "alice@example.com").status_code == 401


def test_fedcm_documents(client: TestClient) -> None:
    assert client.get("/.well-known/web-identity").json() == {
        "accounts_endpoint": "https://issuer.example/fedcm/accounts",
        "login_url": "https://issuer.example/login",
    }
    fedcm = {"Sec-Fetch-Dest": "webidentity"}
    assert client.get("/fedcm/accounts", headers=fedcm).status_code == 401
    _login(client)
    assert client.get("/fedcm/accounts").status_code == 400
    assert client.get("/fedcm/accounts", headers=fedcm).json() == {
        "accounts": [
            {"id": "alice@example.com", "email": "alice@example.com", "name": "alice@example.com"}
        ]
    }


def test_bad_password(client: TestClient) -> None:
    assert _login(client, password="nope").status_code == 401
    assert _login(client, email="nobody@example.com", password="x").status_code == 401


def test_unsigned_request(client: TestClient) -> None:
    response = client.post(
        ISSUANCE_PATH,
        headers={"Content-Type": "application/json", "Sec-Fetch-Dest": "email-verification"},
        content=b'{"email": "alice@example.com"}',
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_signature"
    assert response.headers["signature-error"] == "error=invalid_signature"
