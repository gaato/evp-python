from __future__ import annotations

import pytest

from pyevp import DEFAULT_PROFILE, DiscoveryError, ErrorCode, IssuerFormat
from pyevp.discovery import (
    canonical_issuer,
    email_domain,
    parse_txt_records,
    txt_name_for,
    validate_jwks,
    validate_metadata,
)


@pytest.mark.parametrize(
    ("email", "domain"),
    [
        ("a@example.com", "example.com"),
        ("a@Example.COM.", "example.com"),
        ('"a@b"@example.com', "example.com"),
        ("a@bücher.example", "xn--bcher-kva.example"),
        # IDNA2008: "ß" is a letter of its own, not "ss" as in IDNA2003.
        ("a@faß.example", "xn--fa-hia.example"),
        ("a@BÜCHER.example", "xn--bcher-kva.example"),
    ],
)
def test_email_domain(email: str, domain: str) -> None:
    assert email_domain(email) == domain


@pytest.mark.parametrize("email", ["", "a", "@example.com", "a@"])
def test_email_domain_invalid(email: str) -> None:
    with pytest.raises(ValueError, match="not an email"):
        email_domain(email)


@pytest.mark.parametrize("email", ["a@-bücher.example", "a@b\u200cü.example"])
def test_email_domain_invalid_idn(email: str) -> None:
    with pytest.raises(UnicodeError):
        email_domain(email)


def test_txt_name() -> None:
    assert txt_name_for("a@gmail.com", DEFAULT_PROFILE) == "_email-verification.gmail.com"


@pytest.mark.parametrize(
    ("value", "accepted", "expected"),
    [
        ("accounts.google.com", IssuerFormat.ANY, "https://accounts.google.com"),
        ("https://accounts.google.com", IssuerFormat.ANY, "https://accounts.google.com"),
        ("accounts.google.com", IssuerFormat.ORIGIN, None),
        ("https://accounts.google.com", IssuerFormat.HOST, None),
        ("https://accounts.google.com/", IssuerFormat.ANY, None),
        ("https://a.example:443", IssuerFormat.ANY, None),
        ("http://a.example", IssuerFormat.ANY, None),
        ("", IssuerFormat.ANY, None),
        ("https://", IssuerFormat.ANY, None),
    ],
)
def test_canonical_issuer(value: str, accepted: IssuerFormat, expected: str | None) -> None:
    assert canonical_issuer(value, accepted) == expected


def test_parse_txt_records() -> None:
    assert parse_txt_records(["v=spf1 -all", "iss=accounts.google.com"]) == (
        "https://accounts.google.com"
    )


@pytest.mark.parametrize(
    "records",
    [[], ["v=spf1"], ["iss=a.example", "iss=b.example"], ["iss="], ["iss=a.example/path"]],
)
def test_parse_txt_records_invalid(records: list[str]) -> None:
    with pytest.raises(DiscoveryError) as exc:
        parse_txt_records(records)
    assert exc.value.code is ErrorCode.ISSUER_DISCOVERY_FAILED


GOOD_METADATA = {
    "issuer": "https://accounts.google.com",
    "issuance_endpoint": "https://accounts.google.com/gsi/email-verification/issue",
    "jwks_uri": "https://verifiablecredentials-pa.googleapis.com/.well-known/vc-public-jwks",
    "signing_alg_values_supported": ["EdDSA"],
}


def test_validate_metadata() -> None:
    meta = validate_metadata(GOOD_METADATA, "https://accounts.google.com")
    assert meta.signing_alg_values_supported == ("EdDSA",)
    assert meta.jwks_uri.startswith("https://")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"issuer": "https://evil.example"}, ErrorCode.ISSUER_MISMATCH),
        ({"issuer": "accounts.google.com"}, ErrorCode.ISSUER_MISMATCH),
        ({"jwks_uri": "http://insecure.example/jwks"}, ErrorCode.METADATA_INVALID),
        ({"jwks_uri": None}, ErrorCode.METADATA_INVALID),
        ({"jwks_uri": "https://["}, ErrorCode.METADATA_INVALID),
        ({"issuance_endpoint": "https://[::1/issue"}, ErrorCode.METADATA_INVALID),
        ({"signing_alg_values_supported": "EdDSA"}, ErrorCode.METADATA_INVALID),
    ],
)
def test_validate_metadata_invalid(change: dict[str, object], code: ErrorCode) -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_metadata(GOOD_METADATA | change, "https://accounts.google.com")
    assert exc.value.code is code


def test_validate_metadata_not_object() -> None:
    with pytest.raises(DiscoveryError):
        validate_metadata([], "https://a.example")


def test_validate_jwks_drops_private_and_junk() -> None:
    public = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
    private = {**public, "d": "secret"}
    assert validate_jwks({"keys": [public, private, "junk", {}]}) == (public,)


@pytest.mark.parametrize(
    "bad",
    [
        {"alg": ["Ed25519"]},
        {"crv": ["Ed25519"]},
        {"kid": 1},
        {"use": None},
        {"key_ops": "verify"},
        {"key_ops": [1]},
        {"kty": ["OKP"]},
    ],
)
def test_validate_jwks_drops_badly_typed_members(bad: dict[str, object]) -> None:
    public = {"kty": "OKP", "crv": "Ed25519", "x": "abc", "alg": "Ed25519"}
    assert validate_jwks({"keys": [public, {**public, **bad}]}) == (public,)


@pytest.mark.parametrize("doc", [{}, {"keys": []}, {"keys": "x"}, [], {"keys": [{"d": "x"}]}])
def test_validate_jwks_invalid(doc: object) -> None:
    with pytest.raises(DiscoveryError):
        validate_jwks(doc)
