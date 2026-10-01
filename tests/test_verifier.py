from __future__ import annotations

from datetime import timedelta

import pytest

from evp import (
    DiscoveryError,
    ErrorCode,
    EVPError,
    NullCache,
    Profile,
    TokenError,
    Verifier,
)
from evp.testing import (
    FakeBrowser,
    FakeIssuer,
    FixedClock,
    InMemoryDns,
    InMemoryHttp,
    make_async_verifier,
    make_verifier,
)

from .conftest import AUDIENCE, EMAIL


def _http(verifier: Verifier) -> InMemoryHttp:
    fetcher = verifier._fetcher
    assert isinstance(fetcher, InMemoryHttp)
    return fetcher


def test_sync_verify(verifier: Verifier, token: str, nonce: str) -> None:
    result = verifier.verify(token, nonce=nonce, email=EMAIL)
    assert result.email == EMAIL
    assert result.issuer == "https://issuer.example"
    assert result.claims["email_verified"] is True


@pytest.mark.anyio
async def test_async_verify(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE)
    result = await verifier.verify(token, nonce=nonce, email=EMAIL)
    assert result.email == EMAIL


@pytest.mark.anyio
async def test_async_error(issuer: FakeIssuer, token: str) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE)
    with pytest.raises(TokenError) as exc:
        await verifier.verify(token, nonce="nope")
    assert exc.value.code is ErrorCode.NONCE_MISMATCH


def test_metadata_and_jwks_are_cached(
    issuer: FakeIssuer, browser: FakeBrowser, verifier: Verifier, nonce: str
) -> None:
    for _ in range(3):
        token = browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )
        verifier.verify(token, nonce=nonce)
    assert _http(verifier).requests == [issuer.metadata_url, issuer.jwks_uri]


def test_null_cache_fetches_every_time(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, cache=NullCache())
    verifier.verify(token, nonce=nonce)
    verifier.verify(token, nonce=nonce)
    assert len(_http(verifier).requests) == 4


def test_key_rotation_refreshes_jwks_once_interval_passed(
    issuer: FakeIssuer, browser: FakeBrowser, verifier: Verifier, nonce: str, clock: FixedClock
) -> None:
    def fresh_token() -> str:
        return browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )

    verifier.verify(fresh_token(), nonce=nonce)
    issuer.rotate_key()

    # Within min_refresh_interval the cached (stale) key set is reused.
    with pytest.raises(EVPError) as exc:
        verifier.verify(fresh_token(), nonce=nonce)
    assert exc.value.code is ErrorCode.EVT_SIGNATURE_INVALID

    clock.advance(timedelta(minutes=2))
    assert verifier.verify(fresh_token(), nonce=nonce).email == EMAIL
    assert _http(verifier).requests.count(issuer.jwks_uri) == 2


def test_gmail_like_issuer(clock: FixedClock, nonce: str) -> None:
    gmail = FakeIssuer.gmail_like(clock=clock, iss_format="host")
    browser = FakeBrowser(alg="EdDSA", clock=clock)
    token = browser.present(
        gmail.issue("bob@gmail.example", browser.public_jwk), audience=AUDIENCE, nonce=nonce
    )
    assert make_verifier(gmail, audience=AUDIENCE).verify(token, nonce=nonce).issuer == (
        "https://accounts.google.example"
    )
    with pytest.raises(EVPError):
        make_verifier(gmail, audience=AUDIENCE, profile=Profile.draft_hardt_02()).verify(
            token, nonce=nonce
        )


def test_strict_profile_accepts_conforming_tokens(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, profile=Profile.draft_hardt_02())
    assert verifier.verify(token, nonce=nonce).email == EMAIL


def test_es256(clock: FixedClock, nonce: str) -> None:
    issuer = FakeIssuer(alg="ES256", clock=clock)
    browser = FakeBrowser(alg="ES256", clock=clock)
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    assert make_verifier(issuer, audience=AUDIENCE).verify(token, nonce=nonce).email == EMAIL


def test_multiple_issuers(clock: FixedClock, nonce: str) -> None:
    a = FakeIssuer("a.example", email_domains=("a.test",), clock=clock)
    b = FakeIssuer("b.example", email_domains=("b.test",), clock=clock)
    browser = FakeBrowser(clock=clock)
    verifier = make_verifier(a, b, audience=AUDIENCE)
    token = browser.present(b.issue("x@b.test", browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    assert verifier.verify(token, nonce=nonce).issuer == "https://b.example"
    # a.example cannot vouch for b.test addresses.
    token = browser.present(a.issue("x@b.test", browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    with pytest.raises(DiscoveryError) as exc:
        verifier.verify(token, nonce=nonce)
    assert exc.value.code is ErrorCode.ISSUER_MISMATCH


def test_transport_failure_is_issuer_unreachable(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    verifier = Verifier(
        audience=AUDIENCE,
        resolver=InMemoryDns(issuer.dns_records()),
        fetcher=InMemoryHttp({}),
        clock=clock,
    )
    with pytest.raises(DiscoveryError) as exc:
        verifier.verify(token, nonce=nonce)
    assert exc.value.code is ErrorCode.ISSUER_UNREACHABLE
    assert exc.value.__cause__ is not None


def test_audience_override(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    token = browser.present(
        issuer.issue(EMAIL, browser.public_jwk), audience="https://other.example", nonce=nonce
    )
    assert verifier.verify(token, nonce=nonce, audience="https://other.example").email == EMAIL


@pytest.mark.parametrize(
    "audience", ["rp.example", "https://rp.example/", "https://rp.example/login", "ftp://rp"]
)
def test_invalid_audience(issuer: FakeIssuer, audience: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        make_verifier(issuer, audience=audience)


def test_localhost_audience_allowed(issuer: FakeIssuer) -> None:
    assert make_verifier(issuer, audience="http://localhost:8000").audience == (
        "http://localhost:8000"
    )
