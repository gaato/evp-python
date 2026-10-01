"""Verification rules, exercised through the sans-I/O generator and the sync driver."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, TypeAlias

import pytest

from evp import DEFAULT_PROFILE, ErrorCode, EVPError, Profile, Verifier
from evp._jose import b64url_encode
from evp.core import FetchJson, ResolveTxt, verification_steps
from evp.testing import FakeBrowser, FakeIssuer, FixedClock, make_verifier
from evp.token import build_kb

from .conftest import AUDIENCE, EMAIL


def test_steps_request_dns_then_metadata_then_jwks(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    steps = verification_steps(
        token, audience=AUDIENCE, nonce=nonce, now=clock(), profile=DEFAULT_PROFILE
    )
    assert next(steps) == ResolveTxt("_email-verification.example.com")
    assert steps.send(["iss=issuer.example"]) == FetchJson(issuer.metadata_url, "metadata")
    assert steps.send(issuer.metadata) == FetchJson(issuer.jwks_uri, "jwks")
    with pytest.raises(StopIteration) as stop:
        steps.send(issuer.jwks)
    assert stop.value.value.email == EMAIL
    assert stop.value.value.issuer == "https://issuer.example"


def test_offline_failures_request_no_io(token: str, clock: FixedClock) -> None:
    steps = verification_steps(
        token, audience=AUDIENCE, nonce="wrong", now=clock(), profile=DEFAULT_PROFILE
    )
    with pytest.raises(EVPError) as exc:
        next(steps)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH


def test_key_rotation_requests_refresh(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    stale_jwks = issuer.jwks
    issuer.rotate_key()
    fresh = FakeBrowser(clock=clock)
    token = fresh.present(issuer.issue(EMAIL, fresh.public_jwk), audience=AUDIENCE, nonce=nonce)
    steps = verification_steps(
        token, audience=AUDIENCE, nonce=nonce, now=clock(), profile=DEFAULT_PROFILE
    )
    next(steps)
    steps.send(["iss=issuer.example"])
    steps.send(issuer.metadata)
    assert steps.send(stale_jwks) == FetchJson(issuer.jwks_uri, "jwks", refresh=True)
    with pytest.raises(StopIteration):
        steps.send(issuer.jwks)


# --- negative cases -------------------------------------------------------------

# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Build: TypeAlias = Callable[[FakeIssuer, FakeBrowser, str, FixedClock], str]


def _present(
    issuer: FakeIssuer,
    browser: FakeBrowser,
    nonce: str,
    *,
    email: str = EMAIL,
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    audience: str = AUDIENCE,
    issued_at: datetime | None = None,
    typ: str = "kb+jwt",
) -> str:
    evt = issuer.issue(email, browser.public_jwk, claims=claims, header=header)
    return browser.present(evt, audience=audience, nonce=nonce, issued_at=issued_at, typ=typ)


def _tamper_kb_signature(token: str) -> str:
    h, p, sig = token.rsplit(".", 2)
    mid = len(sig) // 2
    return f"{h}.{p}.{sig[:mid]}{'A' if sig[mid] != 'A' else 'B'}{sig[mid + 1 :]}"


def _resign_kb(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    evt = issuer.issue(EMAIL, browser.public_jwk)
    other = FakeBrowser(clock=clock)
    return build_kb(
        evt, private_key=other.key, alg="Ed25519", audience=AUDIENCE, nonce=nonce, issued_at=clock()
    )


def _bad_sd_hash(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    evt1 = issuer.issue(EMAIL, browser.public_jwk)
    evt2 = issuer.issue(EMAIL, browser.public_jwk, claims={"extra": 1})
    kb = browser.present(evt1, audience=AUDIENCE, nonce=nonce).split("~")[1]
    return f"{evt2}~{kb}"


def _forged_evt(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    impostor = FakeIssuer(kid=issuer.kid, clock=clock)
    return _present(impostor, browser, nonce)


def _hs256_evt(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    _, payload, sig = issuer.issue(EMAIL, browser.public_jwk).split(".")
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "evt+jwt"}).encode())
    return browser.present(f"{header}.{payload}.{sig}", audience=AUDIENCE, nonce=nonce)


CASES: dict[str, tuple[Build, ErrorCode]] = {
    "wrong audience": (
        lambda i, b, n, c: _present(i, b, n, audience="https://evil.example"),
        ErrorCode.AUDIENCE_MISMATCH,
    ),
    "wrong nonce": (lambda i, b, n, c: _present(i, b, "other"), ErrorCode.NONCE_MISMATCH),
    "stale kb": (
        lambda i, b, n, c: _present(i, b, n, issued_at=c() - timedelta(minutes=7)),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "future kb": (
        lambda i, b, n, c: _present(i, b, n, issued_at=c() + timedelta(minutes=2)),
        ErrorCode.TOKEN_NOT_YET_VALID,
    ),
    "stale evt": (
        lambda i, b, n, c: _present(i, b, n, claims={"iat": int(c().timestamp()) - 3600}),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "expired evt": (
        lambda i, b, n, c: _present(i, b, n, claims={"exp": int(c().timestamp()) - 120}),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "kb typ": (lambda i, b, n, c: _present(i, b, n, typ="jwt"), ErrorCode.BAD_TYPE),
    "evt typ": (
        lambda i, b, n, c: _present(i, b, n, header={"typ": "evp-sd-jwt"}),
        ErrorCode.BAD_TYPE,
    ),
    "kb tampered": (
        lambda i, b, n, c: _tamper_kb_signature(_present(i, b, n)),
        ErrorCode.KB_SIGNATURE_INVALID,
    ),
    "kb wrong key": (_resign_kb, ErrorCode.KB_SIGNATURE_INVALID),
    "sd_hash": (_bad_sd_hash, ErrorCode.SD_HASH_MISMATCH),
    "evt forged": (_forged_evt, ErrorCode.EVT_SIGNATURE_INVALID),
    "evt hs256": (_hs256_evt, ErrorCode.UNSUPPORTED_ALG),
    "unknown kid": (
        lambda i, b, n, c: _present(i, b, n, header={"kid": "nope"}),
        ErrorCode.KEY_NOT_FOUND,
    ),
    "iss not delegated": (
        lambda i, b, n, c: _present(i, b, n, claims={"iss": "https://evil.example"}),
        ErrorCode.ISSUER_MISMATCH,
    ),
    "no dns record": (
        lambda i, b, n, c: _present(i, b, n, email="alice@unknown.example"),
        ErrorCode.ISSUER_DISCOVERY_FAILED,
    ),
    "not verified": (
        lambda i, b, n, c: _present(i, b, n, claims={"email_verified": False}),
        ErrorCode.EMAIL_NOT_VERIFIED,
    ),
    "missing email": (
        lambda i, b, n, c: _present(i, b, n, claims={"email": None}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "missing cnf": (
        lambda i, b, n, c: _present(i, b, n, claims={"cnf": None}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "private cnf": (
        lambda i, b, n, c: _present(i, b, n, claims={"cnf": {"jwk": b.key.as_dict(private=True)}}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "cnf alg mismatch": (
        lambda i, b, n, c: _present(
            i, b, n, claims={"cnf": {"jwk": {**b.public_jwk, "alg": "ES256"}}}
        ),
        ErrorCode.UNSUPPORTED_ALG,
    ),
    "bool iat": (
        lambda i, b, n, c: _present(i, b, n, claims={"iat": True}),
        ErrorCode.MALFORMED_TOKEN,
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_rejects(
    case: str,
    issuer: FakeIssuer,
    browser: FakeBrowser,
    nonce: str,
    clock: FixedClock,
    verifier: Verifier,
) -> None:
    build, code = CASES[case]
    with pytest.raises(EVPError) as exc:
        verifier.verify(build(issuer, browser, nonce, clock), nonce=nonce)
    assert exc.value.code is code


def test_every_error_code_is_exercised() -> None:
    covered = {code for _, code in CASES.values()} | {
        ErrorCode.EMAIL_MISMATCH,  # test_email_mismatch
        ErrorCode.METADATA_INVALID,  # test_discovery
        ErrorCode.ISSUER_UNREACHABLE,  # test_verifier
        ErrorCode.TOKEN_REPLAYED,  # test_replay
    }
    assert covered == set(ErrorCode)


def test_email_mismatch(verifier: Verifier, token: str, nonce: str) -> None:
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email="mallory@example.com")
    assert exc.value.code is ErrorCode.EMAIL_MISMATCH


@pytest.mark.parametrize(
    ("submitted", "profile", "ok"),
    [
        ("ALICE@example.com", Profile.compat_2026_10(), True),
        (" alice@example.com ", Profile.draft_hardt_02(), True),
        ("ALICE@example.com", Profile.draft_hardt_02(), False),
    ],
)
def test_email_comparison(
    issuer: FakeIssuer, token: str, nonce: str, submitted: str, profile: Profile, ok: bool
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, profile=profile)
    if ok:
        verifier.verify(token, nonce=nonce, email=submitted)
    else:
        with pytest.raises(EVPError):
            verifier.verify(token, nonce=nonce, email=submitted)


def test_is_private_email(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    token = _present(issuer, browser, nonce, claims={"is_private_email": True})
    assert verifier.verify(token, nonce=nonce).is_private_email
