"""Live checks against deployed issuers.  Run with ``pytest -m network``.

These detect drift between the deployed ecosystem and the default profile;
they run weekly in CI (``.github/workflows/drift.yml``).
"""

from __future__ import annotations

import pytest

from evp import DEFAULT_PROFILE, Profile, _jose
from evp.adapters.dnspython import DnsPythonResolver
from evp.adapters.httpx import HttpxFetcher
from evp.discovery import (
    metadata_url,
    parse_txt_records,
    txt_name_for,
    validate_jwks,
    validate_metadata,
)

pytestmark = pytest.mark.network

KNOWN_ISSUERS = {"gmail.com": "https://accounts.google.com"}


@pytest.mark.parametrize(("domain", "expected_issuer"), KNOWN_ISSUERS.items())
@pytest.mark.parametrize("profile", [DEFAULT_PROFILE], ids=lambda p: p.name)
def test_issuer_discovery(domain: str, expected_issuer: str, profile: Profile) -> None:
    records = DnsPythonResolver().resolve_txt(txt_name_for(f"user@{domain}", profile))
    issuer = parse_txt_records(records)
    assert issuer == expected_issuer

    with HttpxFetcher() as fetcher:
        metadata = validate_metadata(fetcher.fetch_json(metadata_url(issuer, profile)), issuer)
        jwks = fetcher.fetch_json(metadata.jwks_uri)
    advertised = metadata.signing_alg_values_supported or ("Ed25519",)
    assert set(advertised) & profile.evt_algorithms, (
        f"{issuer} signs with {advertised}, none accepted by profile {profile.name}"
    )

    keys = validate_jwks(jwks)
    usable = [k for k in keys for alg in advertised if _jose.key_supports(alg, k)]
    assert usable, f"no key in {metadata.jwks_uri} usable with {advertised}"
    if profile.require_kid:
        assert all(k.get("kid") for k in usable)
