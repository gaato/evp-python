"""The Django issuer example, driven by a fake browser and checked by a verifier."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.core import checks
from django.test import Client
from urls import issuer

from pyevp import Verifier
from pyevp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

RP = "https://rp.example"
EMAIL = "alice@example.com"
PASSWORD = "correct horse battery staple"
PAGE = {"Sec-Fetch-Dest": "document"}

pytestmark = pytest.mark.django_db


@pytest.fixture
def client() -> Client:
    User.objects.create_user("alice", email=EMAIL, password=PASSWORD)
    return Client(secure=True, HTTP_HOST="issuer.example")


def _login(client: Client) -> Any:
    data = {"username": "alice", "password": PASSWORD}
    return client.post("/accounts/login/", data, headers=PAGE)


def _browser() -> FakeBrowser:
    # The issuer runs on the real clock.
    return FakeBrowser(clock=FixedClock(datetime.now(UTC)))


def _issue(client: Client, browser: FakeBrowser, email: str = EMAIL) -> Any:
    request = browser.issuance_request(email, endpoint=issuer.issuance_endpoint)
    headers = dict(request["headers"])
    content_type = headers.pop("Content-Type")
    return client.post(
        "/email-verification/issuance", request["body"], content_type=content_type, headers=headers
    )


def test_settings_pass_the_checks() -> None:
    assert checks.run_checks(tags=[checks.Tags.security]) == []


def test_documents(client: Client) -> None:
    assert client.get("/.well-known/email-verification").json() == issuer.metadata_document()
    assert client.get("/email-verification/jwks").json() == issuer.jwks_document()
    assert client.get("/.well-known/web-identity").json() == {
        "accounts_endpoint": "https://issuer.example/fedcm/accounts",
        "login_url": "https://issuer.example/accounts/login/",
    }


def test_logged_in_user_gets_a_verifiable_token(client: Client) -> None:
    login = _login(client)
    assert login.status_code == 302
    assert login["Set-Login"] == "logged-in"
    fedcm = client.get("/fedcm/accounts", headers={"Sec-Fetch-Dest": "webidentity"})
    assert fedcm.json()["accounts"][0]["email"] == EMAIL

    browser = _browser()
    response = _issue(client, browser)
    assert response.status_code == 200, response.content
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
    )
    token = browser.present(evt, audience=RP, nonce="n")
    assert verifier.verify(token, nonce="n", email=EMAIL).email == EMAIL


def test_logged_out_user_gets_nothing(client: Client) -> None:
    _login(client)
    logout = client.post("/accounts/logout/", headers=PAGE)
    assert logout["Set-Login"] == "logged-out"
    assert _issue(client, _browser()).status_code == 401
