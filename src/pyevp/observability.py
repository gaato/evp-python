"""Hooks for logging and metrics.

Pass ``observer=`` to a verifier to receive one :class:`VerificationEvent` per
``verify`` call.  Observers must be fast and must not raise; exceptions are
logged and swallowed so that monitoring can never break authentication.

A Prometheus counter, for example::

    VERIFICATIONS = Counter("evp_verifications_total", "EVP verifications", ["result", "issuer"])

    def observe(event: VerificationEvent) -> None:
        VERIFICATIONS.labels(event.code or "ok", event.issuer or "").inc()
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import TypeAlias

from pyevp import discovery
from pyevp.errors import ErrorCode
from pyevp.token import parse_token

__all__ = ["LoggingObserver", "Observer", "VerificationEvent", "claimed_email_domain"]


@dataclass(frozen=True, slots=True)
class VerificationEvent:
    ok: bool
    code: ErrorCode | None
    """Set when verification failed with an :class:`~pyevp.EVPError`."""
    issuer: str | None
    """Canonical issuer; only known after a successful verification."""
    email_domain: str | None
    """Domain of the ``email`` claim, read from the token *before* verification."""
    profile: str
    duration: timedelta


# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Observer: TypeAlias = Callable[[VerificationEvent], None]
"""Receives one :class:`VerificationEvent` per verification; must not block or raise."""


# What ``email_domain`` returns for a name DNS could hold.  Anything else (spaces, line
# breaks, ...) comes from an unverified token and must not reach logs or metric labels.
_DNS_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")


def claimed_email_domain(token: str) -> str | None:
    """Best-effort domain of the (unverified) ``email`` claim, for grouping metrics.

    ``None`` unless the claim holds an address whose domain is a plausible DNS name.
    """
    try:
        email = parse_token(token, allow_disclosures=True).evt.claims.get("email")
        domain = discovery.email_domain(email) if isinstance(email, str) else None
    except Exception:
        return None
    return domain if domain is not None and _DNS_NAME.fullmatch(domain) else None


class LoggingObserver:
    """Log one line per verification to the ``pyevp`` logger (or ``logger``)."""

    def __init__(self, logger: logging.Logger | None = None, *, level: int = logging.INFO) -> None:
        self._logger = logger or logging.getLogger("pyevp")
        self._level = level

    def __call__(self, event: VerificationEvent) -> None:
        self._logger.log(
            self._level,
            "EVP verification %s code=%s issuer=%s domain=%s profile=%s duration_ms=%.1f",
            "succeeded" if event.ok else "failed",
            event.code,
            _escaped(event.issuer),
            _escaped(event.email_domain),
            _escaped(event.profile),
            event.duration.total_seconds() * 1000,
        )


def _escaped(value: str | None) -> str | None:
    """``value``, or its ``repr`` if it holds a line break or another unprintable character."""
    return value if value is None or value.isprintable() else repr(value)
