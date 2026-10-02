from __future__ import annotations

import pytest

from pyevp import ErrorCode, TokenError, _jose
from pyevp.testing import FakeBrowser, FakeIssuer
from pyevp.token import compute_sd_hash, parse_token


def test_parse_roundtrip(token: str) -> None:
    parsed = parse_token(token)
    assert parsed.evt.typ == "evt+jwt"
    assert parsed.kb.typ == "kb+jwt"
    assert parsed.disclosures == ()
    assert parsed.sd_hash_input == token.split("~", maxsplit=1)[0] + "~"
    assert parsed.kb.claims["sd_hash"] == compute_sd_hash(parsed.sd_hash_input)


def test_surrounding_whitespace_is_ignored(token: str) -> None:
    assert parse_token(f"  {token}\n").raw == token


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a.b.c",
        "a.b.c~",
        "~a.b.c",
        "not-a-jwt~a.b.c",
        "a.b~a.b.c",
        "x" * 20_000,
        "é.b.c~a.b.c",
    ],
)
def test_malformed(value: str) -> None:
    with pytest.raises(TokenError) as exc:
        parse_token(value)
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_excessive_nesting(token: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Python 3.11 raises RecursionError for ~1000 levels, which fit in a token. Newer versions
    # only fail far deeper than MAX_TOKEN_LENGTH allows, so simulate the failure.
    def loads(_: bytes) -> object:
        raise RecursionError

    monkeypatch.setattr(_jose.json, "loads", loads)
    with pytest.raises(TokenError) as exc:
        parse_token(token)
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_disclosures_rejected_by_default(token: str) -> None:
    evt, kb = token.split("~")
    with pytest.raises(TokenError):
        parse_token(f"{evt}~WyJzYWx0Il0~{kb}")


def test_disclosures_allowed(token: str) -> None:
    evt, kb = token.split("~")
    parsed = parse_token(f"{evt}~WyJzYWx0Il0~{kb}", allow_disclosures=True)
    assert parsed.disclosures == ("WyJzYWx0Il0",)
    assert parsed.sd_hash_input == f"{evt}~WyJzYWx0Il0~"


def test_presenting_an_issuance_token_with_its_tilde(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str
) -> None:
    evt = issuer.issue("alice@example.com", browser.public_jwk)
    with_tilde = browser.present(evt + "~", audience="https://rp.example", nonce=nonce)
    without = browser.present(evt, audience="https://rp.example", nonce=nonce)
    assert with_tilde == without
    assert parse_token(with_tilde).disclosures == ()
