"""Thin wrappers over joserfc.  Nothing outside this module imports joserfc for verifying."""

from __future__ import annotations

import base64
import json
import warnings
from collections.abc import Mapping
from typing import Any

from joserfc import jwk, jws
from joserfc.errors import JoseError, SecurityWarning

from evp.types import JSONObject

# Never acceptable regardless of profile.
FORBIDDEN_ALGORITHMS = frozenset({"none", "HS256", "HS384", "HS512"})

_EC_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521", "ES256K": "secp256k1"}
_OKP_CURVES = {"Ed25519": {"Ed25519"}, "Ed448": {"Ed448"}, "EdDSA": {"Ed25519", "Ed448"}}
_EDDSA_FAMILY = frozenset({"EdDSA", "Ed25519", "Ed448"})


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_json_segment(segment: str) -> dict[str, Any]:
    """Decode a base64url JSON object.  Raises ``ValueError`` on any problem."""
    try:
        value = json.loads(b64url_decode(segment))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("segment is not base64url-encoded JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("segment is not a JSON object")
    return value


def algorithms_compatible(a: str, b: str) -> bool:
    """``EdDSA`` (RFC 8037) and ``Ed25519`` (RFC 9864) name the same thing for Ed25519 keys."""
    return a == b or (a in _EDDSA_FAMILY and b in _EDDSA_FAMILY)


def key_supports(alg: str, key: Mapping[str, Any]) -> bool:
    """Whether a public JWK can verify signatures made with ``alg``."""
    if alg in FORBIDDEN_ALGORITHMS:
        return False
    if key.get("use") not in (None, "sig"):
        return False
    key_alg = key.get("alg")
    if isinstance(key_alg, str) and not algorithms_compatible(alg, key_alg):
        return False
    kty, crv = key.get("kty"), key.get("crv")
    if alg in _OKP_CURVES:
        return kty == "OKP" and crv in _OKP_CURVES[alg]
    if alg in _EC_CURVES:
        return kty == "EC" and crv == _EC_CURVES[alg]
    if alg[:2] in ("RS", "PS"):
        return kty == "RSA"
    return False


def is_public_jwk(key: Mapping[str, Any]) -> bool:
    return isinstance(key.get("kty"), str) and not any(p in key for p in ("d", "p", "q", "k"))


def verify_compact(compact: str, key: JSONObject, alg: str) -> bool:
    """Verify a compact JWS signature with a single public JWK."""
    if not key_supports(alg, key):
        return False
    # joserfc enforces the JWK "alg" literally; alias handling is done above.
    material = {k: v for k, v in key.items() if k not in ("alg", "key_ops")}
    try:
        imported = jwk.import_key(material)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            jws.deserialize_compact(compact, imported, algorithms=[alg])
    except (JoseError, ValueError, TypeError):
        return False
    return True


def sign_compact(header: JSONObject, claims: JSONObject, private_key: Any) -> str:
    payload = json.dumps(dict(claims), separators=(",", ":")).encode()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        return jws.serialize_compact(dict(header), payload, private_key, algorithms=[header["alg"]])
