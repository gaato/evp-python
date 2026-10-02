from __future__ import annotations

from typing import Any

import pytest

from pyevp._jose import algorithms_compatible, key_supports


@pytest.mark.parametrize(
    ("a", "b", "compatible"),
    [
        ("Ed25519", "Ed25519", True),
        ("EdDSA", "Ed25519", True),
        ("Ed25519", "EdDSA", True),
        ("EdDSA", "Ed448", True),
        ("Ed25519", "Ed448", False),
        ("Ed448", "Ed25519", False),
        ("ES256", "Ed25519", False),
        ("ES256", "ES384", False),
    ],
)
def test_algorithms_compatible(a: str, b: str, compatible: bool) -> None:
    assert algorithms_compatible(a, b) is compatible


ED25519 = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
ED448 = {"kty": "OKP", "crv": "Ed448", "x": "abc"}


@pytest.mark.parametrize(
    ("alg", "key", "supported"),
    [
        ("Ed25519", ED25519, True),
        ("EdDSA", ED25519, True),
        ("EdDSA", {**ED25519, "alg": "Ed25519"}, True),
        ("Ed25519", {**ED25519, "alg": "EdDSA"}, True),
        ("Ed25519", ED448, False),
        ("EdDSA", ED448, True),
        # A key whose alg contradicts its curve is not usable for either.
        ("EdDSA", {**ED25519, "alg": "Ed448"}, False),
        ("Ed25519", {**ED25519, "alg": "Ed448"}, False),
        ("Ed448", {**ED448, "alg": "Ed25519"}, False),
        ("ES256", {"kty": "EC", "crv": "P-256"}, True),
        ("ES256", {"kty": "EC", "crv": "P-384"}, False),
        ("Ed25519", {**ED25519, "alg": ["Ed25519"]}, False),
        ("Ed25519", {**ED25519, "crv": ["Ed25519"]}, False),
        ("Ed25519", {**ED25519, "key_ops": ["sign", "verify"]}, True),
        ("Ed25519", {**ED25519, "key_ops": ["encrypt"]}, False),
        ("Ed25519", {**ED25519, "key_ops": []}, False),
    ],
)
def test_key_supports(alg: str, key: dict[str, Any], supported: bool) -> None:
    assert key_supports(alg, key) is supported
