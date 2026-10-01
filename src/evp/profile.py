"""Verification profiles.

The protocol is still moving (algorithm names, ``iss`` format, ``kid`` rules, …)
and deployed issuers lag behind the drafts.  Every such knob lives here so that
following a spec change means adding a new preset rather than touching the
verification code.  Existing presets are never changed in incompatible ways.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any, Self

__all__ = [
    "DEFAULT_PROFILE",
    "EmailComparison",
    "IssuerFormat",
    "Profile",
]


class IssuerFormat(StrEnum):
    """Accepted spellings of an issuer identifier (token ``iss`` / DNS ``iss=``)."""

    HOST = "host"
    """Bare host, e.g. ``accounts.google.com`` (early drafts)."""
    ORIGIN = "origin"
    """HTTPS origin, e.g. ``https://accounts.google.com`` (draft-hardt -02)."""
    ANY = "any"


class EmailComparison(StrEnum):
    EXACT = "exact"
    """Byte-for-byte (IETF draft)."""
    CASE_INSENSITIVE = "case_insensitive"
    """Unicode case-folded (W3C Email Verification API)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Profile:
    name: str
    evt_types: frozenset[str]
    kb_types: frozenset[str]
    evt_algorithms: frozenset[str]
    kb_algorithms: frozenset[str]
    require_kid: bool
    """When false, an absent or empty ``kid`` tries every compatible issuer key."""
    require_cnf_alg: bool
    """Require ``cnf.jwk.alg`` and that it equals the KB-JWT ``alg``."""
    issuer_format: IssuerFormat
    email_comparison: EmailComparison
    max_token_age: timedelta
    clock_skew: timedelta
    require_exp: bool
    allow_disclosures: bool
    """Accept SD-JWT disclosures between the EVT and the KB-JWT (ignored otherwise)."""
    dns_label: str = "_email-verification"
    metadata_path: str = "/.well-known/email-verification"

    @classmethod
    def compat_2026_10(cls) -> Self:
        """Accept both the -02 draft and what Chrome + Gmail ship as of 2026-10.

        Gmail signs with ``EdDSA`` and publishes keys without ``kid``.
        """
        return cls(
            name="compat-2026-10",
            evt_types=frozenset({"evt+jwt"}),
            kb_types=frozenset({"kb+jwt"}),
            evt_algorithms=frozenset({"Ed25519", "EdDSA", "ES256"}),
            kb_algorithms=frozenset({"Ed25519", "EdDSA", "ES256"}),
            require_kid=False,
            require_cnf_alg=False,
            issuer_format=IssuerFormat.ANY,
            email_comparison=EmailComparison.CASE_INSENSITIVE,
            max_token_age=timedelta(minutes=5),
            clock_skew=timedelta(minutes=1),
            require_exp=False,
            allow_disclosures=False,
        )

    @classmethod
    def draft_hardt_02(cls) -> Self:
        """Strict reading of draft-hardt-email-verification editor's copy (-02)."""
        return cls(
            name="draft-hardt-02",
            evt_types=frozenset({"evt+jwt"}),
            kb_types=frozenset({"kb+jwt"}),
            evt_algorithms=frozenset({"Ed25519", "ES256"}),
            kb_algorithms=frozenset({"Ed25519", "ES256"}),
            require_kid=True,
            require_cnf_alg=True,
            issuer_format=IssuerFormat.ORIGIN,
            email_comparison=EmailComparison.EXACT,
            max_token_age=timedelta(minutes=5),
            clock_skew=timedelta(minutes=1),
            require_exp=False,
            allow_disclosures=False,
        )

    def replace(self, **changes: Any) -> Self:
        """Return a copy with some fields changed (``dataclasses.replace``)."""
        return dataclasses.replace(self, **changes)


DEFAULT_PROFILE = Profile.compat_2026_10()
