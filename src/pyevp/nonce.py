"""Nonce helpers.

The RP puts a fresh nonce on the form (``<input ... nonce="...">``), stores it
in the user's session, and passes it to ``verify``.  Storing and consuming the
nonce exactly once is the application's job; see the examples.
"""

from __future__ import annotations

import hmac
import secrets

__all__ = ["generate_nonce", "nonces_equal"]


def generate_nonce(nbytes: int = 32) -> str:
    """Return a URL-safe nonce with ``nbytes`` of entropy (at least 16)."""
    if nbytes < 16:
        raise ValueError("a nonce needs at least 128 bits of entropy")
    return secrets.token_urlsafe(nbytes)


def nonces_equal(a: str, b: str) -> bool:
    """Compare two nonces in constant time."""
    return hmac.compare_digest(a.encode(), b.encode())
