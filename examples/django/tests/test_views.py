"""The plain Django example, tested against fakes: also shows how applications can test."""

from __future__ import annotations

import re

import pytest
import views
from django.test import Client

from pyevp.contrib.django import EVPReplayGuard
from pyevp.testing import FakeBrowser, FakeIssuer, make_verifier

ORIGIN = "http://testserver"
EMAIL = "alice@example.com"

pytestmark = pytest.mark.django_db


@pytest.fixture
def issuer(monkeypatch: pytest.MonkeyPatch) -> FakeIssuer:
    issuer = FakeIssuer()
    verifier = make_verifier(
        issuer, audience=ORIGIN, replay_guard=EVPReplayGuard(clock=issuer.clock)
    )
    monkeypatch.setattr(views, "get_verifier", lambda: verifier)
    return issuer


def _nonce(client: Client) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/").content.decode())
    assert match
    return match.group(1)


def _token(issuer: FakeIssuer, nonce: str) -> str:
    browser = FakeBrowser(clock=issuer.clock)
    return browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=ORIGIN, nonce=nonce)


def test_signup_with_token(client: Client, issuer: FakeIssuer) -> None:
    evt = _token(issuer, _nonce(client))
    response = client.post("/", {"email": EMAIL, "evt": evt})
    assert response.json() == {"email": EMAIL, "verified": True, "issuer": "https://issuer.example"}
    # The nonce is single-use.
    response = client.post("/", {"email": EMAIL, "evt": evt})
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "nonce_mismatch"}}


def test_signup_with_bad_token(client: Client, issuer: FakeIssuer) -> None:
    _nonce(client)
    response = client.post("/", {"email": EMAIL, "evt": _token(issuer, "stolen")})
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "nonce_mismatch"}}


def test_signup_without_token_keeps_the_nonce(client: Client, issuer: FakeIssuer) -> None:
    nonce = _nonce(client)
    response = client.post("/", {"email": EMAIL, "evt": ""})
    assert response.json() == {"email": EMAIL, "verified": False}
    # Nothing used the nonce, so a resubmission with a token still verifies.
    response = client.post("/", {"email": EMAIL, "evt": _token(issuer, nonce)})
    assert response.json()["verified"] is True


def test_page_has_evp_fields(client: Client) -> None:
    html = client.get("/").content.decode()
    assert re.search(r'<input type="email" name="email" autocomplete="email"', html)
    assert html.count('autocomplete="email-verification-token"') == 1


def test_invalid_form_is_shown_again(client: Client) -> None:
    response = client.post("/", {"email": "not an address"})
    assert response.status_code == 200
    assert 'autocomplete="email-verification-token"' in response.content.decode()
