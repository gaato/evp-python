"""Issuer signing keys.

:class:`Signer` is the boundary for keys that never leave a KMS or HSM: implement
``sign`` with the service's raw-signature call.  :class:`SigningKey` is the
in-process implementation backed by a private JWK.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from joserfc.errors import JoseError
from joserfc.jwk import ECKey, OKPKey

from pyevp import _jose

__all__ = ["SIGNING_ALGORITHMS", "Signer", "SigningKey", "public_jwk"]

SIGNING_ALGORITHMS = frozenset({"Ed25519", "ES256"})
"""Fully specified algorithms an issuer may sign EVTs with."""

_CURVES = {"Ed25519": ("OKP", "Ed25519"), "ES256": ("EC", "P-256")}
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")


@runtime_checkable
class Signer(Protocol):
    alg: str
    """``Ed25519`` or ``ES256`` (fully specified, so never the polymorphic ``EdDSA``)."""
    kid: str

    @property
    def public_jwk(self) -> Mapping[str, Any]:
        """The verification key as published in the JWKS (with ``kid`` and ``alg``)."""
        ...

    def sign(self, signing_input: bytes) -> bytes:
        """Sign in JWS encoding (raw ``r || s`` for ES256)."""
        ...


def public_jwk(key: Mapping[str, Any], *, kid: str, alg: str) -> dict[str, Any]:
    """Normalise a public key for publication: no private members, ``kid``, ``alg``, use."""
    if alg not in SIGNING_ALGORITHMS:
        raise ValueError(f"unsupported signing algorithm {alg!r}; use one of Ed25519, ES256")
    if not kid:
        raise ValueError("issuer keys need a non-empty kid")
    jwk = {k: v for k, v in key.items() if k not in _PRIVATE_MEMBERS}
    jwk.update(kid=kid, alg=alg, use="sig", key_ops=["verify"])
    if (jwk.get("kty"), jwk.get("crv")) != _CURVES[alg]:
        raise ValueError(f"key type does not match {alg}")
    if _jose.import_public(jwk) is None:
        raise ValueError("invalid public key material")
    return jwk


class SigningKey:
    """A private key held in process memory."""

    def __init__(self, key: OKPKey | ECKey, *, kid: str, alg: str) -> None:
        self._key = key
        self.kid = kid
        self.alg = alg
        self._public = public_jwk(_derived_public(key), kid=kid, alg=alg)

    @classmethod
    def generate(cls, alg: str = "Ed25519", *, kid: str) -> SigningKey:
        if alg == "Ed25519":
            return cls(OKPKey.generate_key("Ed25519", private=True), kid=kid, alg=alg)
        if alg == "ES256":
            return cls(ECKey.generate_key("P-256", private=True), kid=kid, alg=alg)
        raise ValueError(f"unsupported signing algorithm {alg!r}; use one of Ed25519, ES256")

    @classmethod
    def from_jwk(cls, jwk: Mapping[str, Any]) -> SigningKey:
        """Load a private JWK; it must carry ``kid``, and ``alg`` unless the curve implies it."""
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("issuer keys need a non-empty kid")
        alg = jwk.get("alg") or {v: k for k, v in _CURVES.items()}.get(
            (jwk.get("kty"), jwk.get("crv"))
        )
        if alg not in SIGNING_ALGORITHMS:
            raise ValueError(f"unsupported signing algorithm {alg!r}; use one of Ed25519, ES256")
        if "d" not in jwk:
            raise ValueError("not a private key")
        material = {k: v for k, v in jwk.items() if k not in ("alg", "key_ops", "use", "kid")}
        cls_ = OKPKey if alg == "Ed25519" else ECKey
        try:
            key = cls_.import_key(material)
        except (JoseError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid private key: {exc}") from None
        # joserfc signs with ``d`` but reports the ``x`` it was given; a mismatch would
        # publish a key that verifies none of our signatures.
        derived = _derived_public(key)
        if any(material.get(m) != derived[m] for m in ("x", "y") if m in derived):
            raise ValueError("invalid private key: public key does not match the private key")
        return cls(key, kid=kid, alg=alg)

    @classmethod
    def from_pem(cls, pem: str | bytes, *, kid: str) -> SigningKey:
        """Load an Ed25519 or P-256 private key in PEM, as key stores and IdPs keep them."""
        for key_cls in (OKPKey, ECKey):
            try:
                key = key_cls.import_key(pem)
            except (JoseError, ValueError, TypeError):
                continue
            if not key.is_private:
                break
            jwk = key.as_dict(private=True)
            if (jwk["kty"], jwk["crv"]) not in _CURVES.values():
                raise ValueError(f"unsupported curve {jwk['crv']}; use Ed25519 or P-256")
            return cls.from_jwk({**jwk, "kid": kid})
        raise ValueError("not an Ed25519 or P-256 private key in PEM")

    def private_jwk(self) -> dict[str, Any]:
        """The private key as a JWK, for writing to a secret store."""
        return {**self._key.as_dict(private=True), "kid": self.kid, "alg": self.alg}

    @property
    def public_jwk(self) -> Mapping[str, Any]:
        return self._public

    def sign(self, signing_input: bytes) -> bytes:
        return _jose.sign_raw(signing_input, self._key, self.alg)

    def __repr__(self) -> str:
        return f"SigningKey(kid={self.kid!r}, alg={self.alg!r})"


def _derived_public(key: OKPKey | ECKey) -> dict[str, Any]:
    """The public JWK computed from the private key, ignoring any stored public members."""
    if isinstance(key, OKPKey):
        assert key.private_key is not None
        public: OKPKey | ECKey = OKPKey.import_key(key.private_key.public_key())
    else:
        assert key.private_key is not None
        public = ECKey.import_key(key.private_key.public_key())
    return dict(public.as_dict(private=False))
