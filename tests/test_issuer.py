from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import anyio
import pytest
from joserfc.jwk import ECKey, OKPKey

from evp import EVPError, InMemoryReplayGuard, Profile, Verifier, _httpsig, discovery
from evp._jose import decode_json_segment
from evp.diagnostics import discover
from evp.issuer import (
    IssuanceError,
    IssuanceErrorCode,
    IssuanceEvent,
    IssuanceProfile,
    IssuanceRequest,
    Issuer,
    SigningKey,
    is_valid_email,
)
from evp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

ISSUER = "https://issuer.example"
ENDPOINT = "https://accounts.issuer.example/email-verification/issuance"
JWKS_URI = "https://accounts.issuer.example/email-verification/jwks"
RP = "https://rp.example"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


def make_issuer(clock: FixedClock, **kwargs: Any) -> Issuer:
    options: dict[str, Any] = {
        "issuer": ISSUER,
        "issuance_endpoint": ENDPOINT,
        "jwks_uri": JWKS_URI,
        "signer": SigningKey.generate(kid="2026-10"),
        "email_domains": ["example.com"],
        "clock": clock,
    }
    options.update(kwargs)
    return Issuer(**options)


class Browser:
    def __init__(self, clock: FixedClock, alg: str = "Ed25519") -> None:
        self.clock = clock
        self.alg = alg
        if alg == "ES256":
            self.key: Any = ECKey.generate_key("P-256", private=True)
        else:
            self.key = OKPKey.generate_key("Ed25519", private=True)

    def request(
        self, email: str = "alice@example.com", *, body: dict[str, Any] | None = None, **kw: Any
    ) -> Any:
        raw = json.dumps(body if body is not None else {"email": email}).encode()
        options: dict[str, Any] = {
            "method": "POST",
            "endpoint": ENDPOINT,
            "body": raw,
            "private_key": self.key,
            "public_jwk": self.key.as_dict(private=False),
            "alg": self.alg,
            "created": self.clock(),
            "include_alg": False,
        }
        options.update(kw)
        headers = _httpsig.sign_request(**options)
        return {"method": "POST", "headers": headers, "body": raw}


def present(evt: str, browser: Browser, nonce: str = "n-1") -> str:
    fake = FakeBrowser(alg="Ed25519" if browser.alg == "Ed25519" else "ES256", clock=browser.clock)
    fake.key = browser.key
    return fake.present(evt, audience=RP, nonce=nonce)


def verifier_for(issuer: Issuer, clock: FixedClock, profile: Profile | None = None) -> Verifier:
    records = {name: [value] for name, value in issuer.dns_txt_records().items()}
    documents: dict[str, object] = {
        f"{ISSUER}/.well-known/email-verification": issuer.metadata_document(),
        JWKS_URI: issuer.jwks_document(),
    }
    kwargs: dict[str, Any] = {} if profile is None else {"profile": profile}
    return Verifier(
        audience=RP,
        resolver=InMemoryDns(records),
        fetcher=InMemoryHttp(documents),
        clock=clock,
        **kwargs,
    )


def error(issuer: Issuer, request: Any) -> IssuanceError:
    with pytest.raises(IssuanceError) as info:
        issuer.parse_request(**request)
    return info.value


# --- end to end ---


@pytest.mark.parametrize("profile", [Profile.compat_2026_10(), Profile.draft_hardt_02()])
@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_issued_tokens_verify(clock: FixedClock, profile: Profile, alg: str) -> None:
    issuer = make_issuer(clock, signer=SigningKey.generate(alg, kid="k1"))
    browser = Browser(clock, alg)
    request = issuer.parse_request(**browser.request())
    evt = issuer.issue(request)
    assert evt.endswith("~")
    result = verifier_for(issuer, clock, profile).verify(
        present(evt, browser), nonce="n-1", email="alice@example.com"
    )
    assert result.email == "alice@example.com"
    assert result.issuer == ISSUER


def test_evt_shape(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    evt = issuer.issue(issuer.parse_request(**browser.request("Alice@Example.com")))
    header, claims, _ = evt.removesuffix("~").split(".")
    assert decode_json_segment(header) == {"alg": "Ed25519", "kid": "2026-10", "typ": "evt+jwt"}
    assert decode_json_segment(claims) == {
        "iss": ISSUER,
        "iat": int(clock().timestamp()),
        "cnf": {"jwk": {**browser.key.as_dict(private=False), "alg": "Ed25519"}},
        "email": "Alice@Example.com",
        "email_verified": True,
    }


def test_polymorphic_eddsa_header(clock: FixedClock) -> None:
    profile = IssuanceProfile.chrome_153().replace(polymorphic_eddsa_header=True)
    issuer = make_issuer(clock, profile=profile)
    browser = Browser(clock)
    evt = issuer.issue(issuer.parse_request(**browser.request()))
    assert decode_json_segment(evt.split(".")[0])["alg"] == "EdDSA"
    verifier_for(issuer, clock).verify(present(evt, browser), nonce="n-1")


def test_success_response(clock: FixedClock) -> None:
    response = Issuer.success_response("a.b.c~")
    assert response.status == 200
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    assert json.loads(response.body) == {"issuance_token": "a.b.c~"}


# --- documents ---


def test_documents_pass_discovery_and_diagnostics(clock: FixedClock) -> None:
    retired = SigningKey.generate("ES256", kid="2026-04")
    issuer = make_issuer(clock, published_keys=[retired.public_jwk])
    metadata = discovery.validate_metadata(issuer.metadata_document(), ISSUER)
    assert metadata.issuance_endpoint == ENDPOINT
    keys = discovery.validate_jwks(issuer.jwks_document())
    assert [k["kid"] for k in keys] == ["2026-10", "2026-04"]
    assert all("d" not in k and k["key_ops"] == ["verify"] for k in keys)
    assert issuer.dns_txt_records() == {"_email-verification.example.com": "iss=issuer.example"}
    assert issuer.metadata_document()["private_email_supported"] is False

    records = {name: [value] for name, value in issuer.dns_txt_records().items()}
    documents: dict[str, object] = {
        f"{ISSUER}/.well-known/email-verification": issuer.metadata_document(),
        JWKS_URI: issuer.jwks_document(),
    }
    report = discover(
        "example.com",
        resolver=InMemoryDns(records),
        fetcher=InMemoryHttp(documents),
        profile=Profile.draft_hardt_02(),
    )
    assert report.ok, report


def test_rotation_old_tokens_still_verify(clock: FixedClock) -> None:
    old = SigningKey.generate(kid="old")
    browser = Browser(clock)
    before = make_issuer(clock, signer=old)
    evt = before.issue(before.parse_request(**browser.request()))
    after = make_issuer(
        clock, signer=SigningKey.generate(kid="new"), published_keys=[old.public_jwk]
    )
    verifier_for(after, clock).verify(present(evt, browser), nonce="n-1")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"issuer": "https://issuer.example/"}, "issuer"),
        ({"issuer": "issuer.example"}, "issuer"),
        ({"issuer": "https://issuer.example:8443"}, "issuer"),
        ({"issuance_endpoint": "http://accounts.issuer.example/x"}, "issuance_endpoint"),
        ({"jwks_uri": "https://accounts.issuer.example/jwks?x=1"}, "jwks_uri"),
        ({"email_domains": []}, "email_domains"),
        ({"signing_alg_values_supported": ["EdDSA"]}, "signing_alg_values_supported"),
        ({"signing_alg_values_supported": ["ES256"]}, "signing_alg_values_supported"),
        ({"published_keys": [{"kty": "OKP"}]}, "kid"),
    ],
)
def test_invalid_configuration(clock: FixedClock, kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        make_issuer(clock, **kwargs)


def test_duplicate_kid(clock: FixedClock) -> None:
    signer = SigningKey.generate(kid="same")
    other = SigningKey.generate(kid="same")
    with pytest.raises(ValueError, match="duplicate kid"):
        make_issuer(clock, signer=signer, published_keys=[other.public_jwk])


def test_signing_key_round_trips_through_jwk() -> None:
    key = SigningKey.generate("ES256", kid="k")
    loaded = SigningKey.from_jwk(key.private_jwk())
    assert loaded.public_jwk == key.public_jwk
    assert key.private_jwk()["d"] not in repr(loaded)


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
        {"kty": "OKP", "crv": "Ed448", "d": "AAAA", "x": "AAAA", "kid": "k"},
        {"kty": "OKP", "crv": "Ed25519", "d": "AAAA", "x": "AAAA", "kid": "k", "alg": "EdDSA"},
        {"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k"},
        {"kty": "OKP", "crv": "Ed25519", "d": "!!", "x": "AAAA", "kid": "k"},
    ],
)
def test_signing_key_rejects(jwk: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"kid|algorithm|private|invalid"):
        SigningKey.from_jwk(jwk)


# --- request validation ---


def test_wrong_method(clock: FixedClock) -> None:
    request = Browser(clock).request()
    assert error(make_issuer(clock), {**request, "method": "GET"}).code == "invalid_request"


@pytest.mark.parametrize(
    "content_type", [None, "application/x-www-form-urlencoded", "text/plain", "application/jsonx"]
)
def test_content_type(clock: FixedClock, content_type: str | None) -> None:
    request = Browser(clock).request()
    headers = {k: v for k, v in request["headers"].items() if k != "Content-Type"}
    if content_type is not None:
        headers["Content-Type"] = content_type
    exc = error(make_issuer(clock), {**request, "headers": headers})
    assert exc.code == IssuanceErrorCode.UNSUPPORTED_MEDIA_TYPE
    assert exc.to_response().status == 415


def test_content_type_parameters_are_ignored(clock: FixedClock) -> None:
    request = Browser(clock).request()
    request["headers"]["Content-Type"] = "Application/JSON; charset=utf-8"
    make_issuer(clock).parse_request(**request)


def test_legacy_request_token_is_refused(clock: FixedClock) -> None:
    exc = error(
        make_issuer(clock),
        {
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "Sec-Fetch-Dest": "email-verification",
            },
            "body": b"request_token=eyJ.eyJ.sig",
        },
    )
    assert exc.status == 415


@pytest.mark.parametrize("value", [None, "empty", "document"])
def test_sec_fetch_dest(clock: FixedClock, value: str | None) -> None:
    request = Browser(clock).request()
    del request["headers"]["Sec-Fetch-Dest"]
    if value is not None:
        request["headers"]["Sec-Fetch-Dest"] = value
    exc = error(make_issuer(clock), request)
    assert exc.code == "invalid_request"
    assert exc.to_response().status == 400


def test_bad_signature_sets_signature_error(clock: FixedClock) -> None:
    request = Browser(clock).request()
    request["body"] = json.dumps({"email": "mallory@example.com"}).encode()
    exc = error(make_issuer(clock), request)
    assert exc.code == "invalid_signature"
    response = exc.to_response()
    assert response.status == 400
    assert response.headers["Signature-Error"] == "error=invalid_signature"
    assert json.loads(response.body) == {
        "error": "invalid_signature",
        "error_description": "HTTP Message Signature verification failed",
    }


def test_stale_request(clock: FixedClock) -> None:
    request = Browser(clock).request()
    clock.advance(timedelta(seconds=301))
    assert error(make_issuer(clock), request).code == "invalid_signature"


def test_draft_profile_requires_hwk_alg(clock: FixedClock) -> None:
    issuer = make_issuer(clock, profile=IssuanceProfile.draft_hardt_02())
    exc = error(issuer, Browser(clock).request())
    assert exc.signature_error == "invalid_key"
    issuer.parse_request(**Browser(clock).request(include_alg=True))


def test_request_alg_limited_by_metadata(clock: FixedClock) -> None:
    issuer = make_issuer(clock, signing_alg_values_supported=["Ed25519"])
    exc = error(issuer, Browser(clock, "ES256").request())
    assert exc.signature_error == "unsupported_algorithm"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"email": 1},
        {"email": "not an email"},
        {"email": "alice@exämple.com"},
        {"email": "alice@example.com", "private_email": "yes"},
        {"email": "alice@example.com", "directed_email": 1},
        ["alice@example.com"],
    ],
)
def test_invalid_body(clock: FixedClock, body: Any) -> None:
    exc = error(make_issuer(clock), Browser(clock).request(body=body))
    assert exc.code == "invalid_request"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"email": "alice@example.com", "email": "bob@example.com"}',
        b'{"email": "\\ud800@example.com"}',
        b"\xff",
        b"[" * 100_000,
        b'{"email": "alice@example.com"' + b" " * 20_000 + b"}",
    ],
)
def test_malformed_json(clock: FixedClock, raw: bytes) -> None:
    browser = Browser(clock)
    headers = _httpsig.sign_request(
        method="POST",
        endpoint=ENDPOINT,
        body=raw,
        private_key=browser.key,
        public_jwk=browser.key.as_dict(private=False),
        alg="Ed25519",
        created=clock(),
    )
    exc = error(make_issuer(clock), {"method": "POST", "headers": headers, "body": raw})
    assert exc.code == "invalid_request"


@pytest.mark.parametrize(
    "body",
    [
        {"email": "alice@example.com", "private_email": True},
        {"email": "alice@example.com", "directed_email": "x@relay.example"},
    ],
)
def test_private_email_not_supported(clock: FixedClock, body: dict[str, Any]) -> None:
    exc = error(make_issuer(clock), Browser(clock).request(body=body))
    assert exc.code == "private_email_not_supported"
    assert exc.to_response().status == 400


def test_private_email_false_is_fine(clock: FixedClock) -> None:
    body = {"email": "alice@example.com", "private_email": False}
    make_issuer(clock).parse_request(**Browser(clock).request(body=body))


def test_foreign_domain_looks_like_an_unknown_account(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    foreign = error(issuer, Browser(clock).request("alice@other.example")).to_response()
    unknown = IssuanceError.authentication_required("no session").to_response()
    assert foreign == unknown
    assert unknown.status == 401


def test_domains_compare_case_insensitively(clock: FixedClock) -> None:
    issuer = make_issuer(clock, email_domains=["Example.COM"])
    assert issuer.parse_request(**Browser(clock).request("a@EXAMPLE.com")).email == "a@EXAMPLE.com"


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("a@b", True),
        ("a.b+c@sub.example.com", True),
        ("a@-b.example", False),
        ("a@b-.example", False),
        ("a@@b", False),
        ("a b@c", False),
        ("a@" + "b" * 64, False),
        ("ä@b", False),
        ("a@b\n", False),
    ],
)
def test_is_valid_email(value: str, valid: bool) -> None:
    assert is_valid_email(value) is valid


# --- replay and observability ---


def test_replay_guard(clock: FixedClock) -> None:
    issuer = make_issuer(clock, replay_guard=InMemoryReplayGuard(clock=clock))
    request = Browser(clock).request()
    issuer.parse_request(**request)
    assert error(issuer, request).code == "invalid_signature"


def test_async_replay_guard(clock: FixedClock) -> None:
    class AsyncGuard:
        def __init__(self) -> None:
            self.inner = InMemoryReplayGuard(clock=clock)

        async def mark_used(self, key: str, expires_at: Any) -> bool:
            return self.inner.mark_used(key, expires_at)

    issuer = make_issuer(clock, replay_guard=AsyncGuard())
    request = Browser(clock).request()
    with pytest.raises(TypeError):
        issuer.parse_request(**request)

    async def main() -> None:
        await issuer.aparse_request(**request)
        with pytest.raises(IssuanceError):
            await issuer.aparse_request(**request)

    anyio.run(main)


def test_observer(clock: FixedClock) -> None:
    events: list[IssuanceEvent] = []
    issuer = make_issuer(clock, observer=events.append)
    browser = Browser(clock)
    issuer.issue(issuer.parse_request(**browser.request()))
    request = browser.request()
    request["method"] = "GET"
    with pytest.raises(IssuanceError):
        issuer.parse_request(**request)
    assert events == [
        IssuanceEvent(True, "request", None, "example.com"),
        IssuanceEvent(True, "issue", None, "example.com"),
        IssuanceEvent(False, "request", IssuanceErrorCode.INVALID_REQUEST, None),
    ]


def test_observer_errors_are_swallowed(clock: FixedClock) -> None:
    def broken(event: IssuanceEvent) -> None:
        raise RuntimeError("boom")

    issuer = make_issuer(clock, observer=broken)
    issuer.parse_request(**Browser(clock).request())


def test_issued_token_does_not_verify_for_another_key(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    evt = issuer.issue(issuer.parse_request(**browser.request()))
    with pytest.raises(EVPError):
        verifier_for(issuer, clock).verify(present(evt, Browser(clock)), nonce="n-1")


def test_request_repr_hides_signature(clock: FixedClock) -> None:
    request = make_issuer(clock).parse_request(**Browser(clock).request())
    assert isinstance(request, IssuanceRequest)
    assert "signature" not in repr(request)
