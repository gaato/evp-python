"""Presentation token codec: ``<EVT>~[<disclosure>~...]<KB-JWT>``.

Parsing only splits and decodes; it performs no signature checks.  The build
helpers are used by :mod:`evp.testing` and are kept here so a future issuer
implementation can reuse them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from evp import _jose
from evp.errors import ErrorCode, TokenError
from evp.types import JSONObject

__all__ = [
    "CompactJWT",
    "ParsedToken",
    "build_kb",
    "compute_sd_hash",
    "parse_token",
    "sign_jwt",
]

# Generous upper bound to avoid spending effort on garbage input.
MAX_TOKEN_LENGTH = 16 * 1024


@dataclass(frozen=True, slots=True)
class CompactJWT:
    """A compact JWS whose header and payload were decoded but not verified."""

    compact: str
    header: JSONObject
    claims: JSONObject

    @classmethod
    def decode(cls, compact: str, *, what: str) -> CompactJWT:
        parts = compact.split(".")
        if len(parts) != 3 or not all(parts):
            raise TokenError(ErrorCode.MALFORMED_TOKEN, f"{what} is not a compact JWS")
        try:
            header = _jose.decode_json_segment(parts[0])
            claims = _jose.decode_json_segment(parts[1])
        except ValueError as exc:
            raise TokenError(ErrorCode.MALFORMED_TOKEN, f"{what}: {exc}") from exc
        return cls(compact=compact, header=header, claims=claims)

    @property
    def alg(self) -> str | None:
        value = self.header.get("alg")
        return value if isinstance(value, str) else None

    @property
    def typ(self) -> str | None:
        value = self.header.get("typ")
        return value if isinstance(value, str) else None


@dataclass(frozen=True, slots=True)
class ParsedToken:
    raw: str
    evt: CompactJWT
    disclosures: tuple[str, ...]
    kb: CompactJWT

    @property
    def sd_hash_input(self) -> str:
        """Everything before the KB-JWT, including the trailing ``~``."""
        return self.raw[: len(self.raw) - len(self.kb.compact)]


def parse_token(token: str, *, allow_disclosures: bool = False) -> ParsedToken:
    token = token.strip()
    if not token or len(token) > MAX_TOKEN_LENGTH or not token.isascii():
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "token is empty, too long or not ASCII")
    parts = token.split("~")
    if len(parts) < 2:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "token has no key-binding JWT")
    evt_part, *disclosures, kb_part = parts
    if disclosures and not allow_disclosures:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "token contains unexpected disclosures")
    if any(not d for d in disclosures):
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "token contains an empty disclosure")
    return ParsedToken(
        raw=token,
        evt=CompactJWT.decode(evt_part, what="EVT"),
        disclosures=tuple(disclosures),
        kb=CompactJWT.decode(kb_part, what="KB-JWT"),
    )


def compute_sd_hash(sd_hash_input: str) -> str:
    return _jose.b64url_encode(hashlib.sha256(sd_hash_input.encode("ascii")).digest())


def sign_jwt(header: JSONObject, claims: JSONObject, private_key: Any) -> str:
    """Sign ``claims`` as a compact JWS.  ``private_key`` is a joserfc key object."""
    return _jose.sign_compact(header, claims, private_key)


def build_kb(
    evt: str,
    *,
    private_key: Any,
    alg: str,
    audience: str,
    nonce: str,
    issued_at: datetime,
    typ: str = "kb+jwt",
    disclosures: tuple[str, ...] = (),
) -> str:
    """Append a key-binding JWT to an EVT, producing the presentation token."""
    prefix = "~".join((evt, *disclosures)) + "~"
    kb = sign_jwt(
        {"alg": alg, "typ": typ},
        {
            "aud": audience,
            "nonce": nonce,
            "iat": int(issued_at.timestamp()),
            "sd_hash": compute_sd_hash(prefix),
        },
        private_key,
    )
    return prefix + kb
