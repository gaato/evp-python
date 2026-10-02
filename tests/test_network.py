"""Live checks against deployed issuers.  Run with ``pytest -m network``.

These detect drift between the deployed ecosystem and the default profile;
they run weekly in CI (``.github/workflows/drift.yml``).
"""

from __future__ import annotations

import pytest

from pyevp import DEFAULT_PROFILE, TxtResolver
from pyevp.adapters import doh
from pyevp.adapters.dnspython import DnsPythonResolver
from pyevp.adapters.httpx import HttpxFetcher
from pyevp.adapters.urllib import UrllibDohResolver, UrllibFetcher
from pyevp.diagnostics import discover

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


@pytest.mark.parametrize(("domain", "expected_issuer"), KNOWN_ISSUERS.items())
@pytest.mark.parametrize("endpoint", [doh.GOOGLE, doh.CLOUDFLARE], ids=["google", "cloudflare"])
def test_known_issuers_work_with_stdlib_adapters(
    domain: str, expected_issuer: str, endpoint: str
) -> None:
    report = discover(
        domain,
        resolver=UrllibDohResolver(endpoint),
        fetcher=UrllibFetcher(),
        profile=DEFAULT_PROFILE,
    )
    assert report.issuer == expected_issuer
    assert report.ok, f"{domain} drifted from {DEFAULT_PROFILE.name}: {report.problems}"
