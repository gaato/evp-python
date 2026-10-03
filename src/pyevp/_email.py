"""Email address normalisation and comparison shared by verification and account lookup."""

from __future__ import annotations

from enum import StrEnum

import idna

__all__ = ["EmailComparison", "email_domain", "emails_match"]


class EmailComparison(StrEnum):
    """How a submitted address is compared with the asserted one."""

    EXACT = "exact"
    """Byte for byte (IETF draft)."""
    CASE_INSENSITIVE = "case_insensitive"
    """Local part Unicode case-folded, domain compared in IDNA2008 A-label form.

    Follows the W3C Email Verification API, without letting case folding merge two
    DNS names: ``a@faß.example`` does not match ``a@fass.example``.
    """


def _split(email: str) -> tuple[str, str]:
    local, sep, domain = email.rpartition("@")
    if not sep or not local or not domain:
        raise ValueError(f"not an email address: {email!r}")
    return local, domain


def email_domain(email: str) -> str:
    """Return the DNS (A-label) form of the domain part of ``email``.

    Internationalised domains are mapped with UTS #46 / IDNA2008, as browsers do.
    Python's ``"idna"`` codec implements IDNA2003, which maps some names onto other
    domains (``faß.example`` → ``fass.example``).  Raises :class:`UnicodeError` for
    invalid internationalised domains.
    """
    domain = _split(email)[1].rstrip(".")
    if domain.isascii():
        return domain.lower()
    return idna.encode(domain, uts46=True).decode("ascii")


def emails_match(asserted: str, submitted: str, comparison: EmailComparison) -> bool:
    """Whether two addresses name the same mailbox under ``comparison``.

    ``EXACT`` compares the strings byte for byte.  ``CASE_INSENSITIVE`` case-folds the
    local part and compares domains in their IDNA2008 A-label form, so that case
    folding never merges two DNS names (``faß.example`` is not ``fass.example``).
    Invalid addresses never match.
    """
    if comparison is EmailComparison.EXACT:
        return asserted == submitted
    try:
        (a_local, a_domain), (s_local, s_domain) = _split(asserted), _split(submitted)
        same_domain = email_domain(asserted) == email_domain(submitted)
    except (ValueError, UnicodeError):
        return False
    return (
        same_domain
        and a_domain.endswith(".") == s_domain.endswith(".")
        and a_local.casefold() == s_local.casefold()
    )
