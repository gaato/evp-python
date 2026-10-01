"""Live checks against deployed issuers.  Run with ``pytest -m network``.

These detect drift between the deployed ecosystem and the default profile;
they run weekly in CI (``.github/workflows/drift.yml``).
"""

from __future__ import annotations

import pytest

from evp import DEFAULT_PROFILE, TxtResolver
from evp.adapters import doh
from evp.adapters.dnspython import DnsPythonResolver
from evp.adapters.httpx import HttpxFetcher
from evp.diagnostics import discover

pytestmark = pytest.mark.network

KNOWN_ISSUERS = {"gmail.com": "https://accounts.google.com"}

RESOLVERS = {
    "dns": DnsPythonResolver,
    "doh-google": lambda: doh.DohResolver(doh.GOOGLE),
    "doh-cloudflare": lambda: doh.DohResolver(doh.CLOUDFLARE),
}


@pytest.mark.parametrize(("domain", "expected_issuer"), KNOWN_ISSUERS.items())
@pytest.mark.parametrize("resolver", RESOLVERS.values(), ids=RESOLVERS.keys())
def test_known_issuers_work_with_default_profile(
    domain: str, expected_issuer: str, resolver: type[TxtResolver]
) -> None:
    txt = resolver()
    try:
        with HttpxFetcher() as fetcher:
            report = discover(domain, resolver=txt, fetcher=fetcher, profile=DEFAULT_PROFILE)
    finally:
        if isinstance(txt, doh.DohResolver):
            txt.close()
    assert report.issuer == expected_issuer
    assert report.ok, f"{domain} drifted from {DEFAULT_PROFILE.name}: {report.problems}"
