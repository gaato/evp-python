from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

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
    assert re.search(r'<input[^>]*name="email"[^>]*autocomplete="email"', html) or re.search(
        r'<input[^>]*autocomplete="email"[^>]*name="email"', html
    )


def test_replay_record_outlives_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cache backends keep whole seconds; truncating 359.3 would drop the record early.
    now = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    timeouts: list[object] = []

    def add(key: str, value: object, timeout: object) -> bool:
        timeouts.append(timeout)
        return True

    monkeypatch.setattr(evp_allauth.timezone, "now", lambda: now)
    monkeypatch.setattr(evp_allauth.django_cache, "add", add)
    evp_allauth.DjangoCacheReplayGuard().mark_used("k", now + timedelta(seconds=359.3))
    assert timeouts == [360]
