from __future__ import annotations

import re

import evp_allauth
import pytest
from allauth.account.models import EmailAddress
from django.core import mail
from django.core.cache import cache
from django.test import Client

from pyevp.testing import FakeBrowser, FakeIssuer, make_verifier

ORIGIN = "http://testserver"
EMAIL = "alice@example.com"
PASSWORD = "correct horse battery staple"

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    # allauth rate-limits confirmation mails per address via the cache.
    cache.clear()


@pytest.fixture
def issuer(monkeypatch: pytest.MonkeyPatch) -> FakeIssuer:
    issuer = FakeIssuer()
    verifier = make_verifier(issuer, audience=ORIGIN)
    monkeypatch.setattr(evp_allauth, "get_verifier", lambda: verifier)
    return issuer


def _nonce(client: Client) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/accounts/signup/").content.decode())
    assert match
    return match.group(1)


def _signup(client: Client, evt: str) -> None:
    client.post(
        "/accounts/signup/",
        {"email": EMAIL, "password1": PASSWORD, "password2": PASSWORD, "evt": evt},
    )


def test_valid_token_marks_email_verified(client: Client, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonce = _nonce(client)
    _signup(
        client,
        browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=ORIGIN, nonce=nonce),
    )
    assert EmailAddress.objects.get(email=EMAIL).verified
    assert mail.outbox == []


def test_invalid_token_falls_back_to_confirmation_mail(client: Client, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    _nonce(client)
    _signup(
        client, browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=ORIGIN, nonce="x")
    )
    assert not EmailAddress.objects.get(email=EMAIL).verified
    assert len(mail.outbox) == 1


def test_no_token_falls_back_to_confirmation_mail(client: Client, issuer: FakeIssuer) -> None:
    _nonce(client)
    _signup(client, "")
    assert not EmailAddress.objects.get(email=EMAIL).verified
    assert len(mail.outbox) == 1


def test_signup_page_has_evp_fields(client: Client) -> None:
    html = client.get("/accounts/signup/").content.decode()
    assert 'autocomplete="email-verification-token"' in html
    assert html.count('name="evt"') == 1
    assert re.search(r'<input[^>]*name="email"[^>]*autocomplete="email"', html) or re.search(
        r'<input[^>]*autocomplete="email"[^>]*name="email"', html
    )
