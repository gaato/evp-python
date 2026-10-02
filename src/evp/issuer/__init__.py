"""Issuer side of the Email Verification Protocol (experimental).

Framework-neutral building blocks for running an issuer for your own email
domains: validate the browser's signed issuance request, mint EVTs, and produce
the metadata, JWKS and DNS records to publish.  See :class:`Issuer`.
"""

from evp.issuer.core import (
    IssuanceEvent,
    IssuanceObserver,
    IssuanceRequest,
    Issuer,
    is_valid_email,
)
from evp.issuer.errors import IssuanceError, IssuanceErrorCode, IssuanceResponse
from evp.issuer.fedcm import FEDCM_FETCH_DEST, accounts_document, web_identity_document
from evp.issuer.keys import SIGNING_ALGORITHMS, Signer, SigningKey, public_jwk
from evp.issuer.profile import DEFAULT_ISSUANCE_PROFILE, ISSUANCE_PROFILES, IssuanceProfile

__all__ = [
    "DEFAULT_ISSUANCE_PROFILE",
    "FEDCM_FETCH_DEST",
    "ISSUANCE_PROFILES",
    "SIGNING_ALGORITHMS",
    "IssuanceError",
    "IssuanceErrorCode",
    "IssuanceEvent",
    "IssuanceObserver",
    "IssuanceProfile",
    "IssuanceRequest",
    "IssuanceResponse",
    "Issuer",
    "Signer",
    "SigningKey",
    "accounts_document",
    "is_valid_email",
    "public_jwk",
    "web_identity_document",
]
