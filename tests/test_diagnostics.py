from __future__ import annotations

import pytest

from evp import DiscoveryError, ErrorCode, Profile
from evp.diagnostics import adiscover, discover
from evp.testing import AsyncInMemoryDns, AsyncInMemoryHttp, FakeIssuer, InMemoryDns, InMemoryHttp


def _ports(*issuers: FakeIssuer) -> tuple[InMemoryDns, InMemoryHttp]:
    records: dict[str, list[str]] = {}
    documents: dict[str, object] = {}
    for issuer in issuers:
        records |= issuer.dns_records()
        documents |= issuer.http_documents()
    return InMemoryDns(records), InMemoryHttp(documents)


def test_healthy_issuer(issuer: FakeIssuer) -> None:
    resolver, fetcher = _ports(issuer)
    report = discover("alice@example.com", resolver=resolver, fetcher=fetcher)
    assert report.ok
    assert report.issuer == "https://issuer.example"
    assert report.records == ("iss=issuer.example",)
    assert [k.kid for k in report.keys] == ["test-key-1"]


def test_accepts_domain_or_email(issuer: FakeIssuer) -> None:
    resolver, fetcher = _ports(issuer)
    assert discover("Example.COM", resolver=resolver, fetcher=fetcher).dns_name == (
        "_email-verification.example.com"
    )


def test_gmail_like_issuer_under_strict_profile() -> None:
    gmail = FakeIssuer.gmail_like()
    resolver, fetcher = _ports(gmail)
    compat = discover("gmail.example", resolver=resolver, fetcher=fetcher)
    strict = discover(
        "gmail.example", resolver=resolver, fetcher=fetcher, profile=Profile.draft_hardt_02()
    )
    assert compat.ok
    assert not strict.ok
    assert "EdDSA" in strict.problems[0]


def test_kid_required() -> None:
    issuer = FakeIssuer(kid=None)
    resolver, fetcher = _ports(issuer)
    report = discover(
        "example.com", resolver=resolver, fetcher=fetcher, profile=Profile.draft_hardt_02()
    )
    assert report.problems == ("profile draft-hardt-02 requires kid, but some keys have none",)


@pytest.mark.parametrize(
    ("break_it", "problem"),
    [
        (lambda dns, http, i: dns.records.clear(), "expected exactly one"),
        (lambda dns, http, i: http.documents.update({i.metadata_url: {}}), "metadata:"),
        (lambda dns, http, i: http.documents.update({i.jwks_uri: {"keys": []}}), "JWKS:"),
        (
            lambda dns, http, i: http.documents[i.metadata_url].update(
                signing_alg_values_supported=[]
            ),
            "issuer advertises an empty",
        ),
    ],
)
def test_problems(issuer: FakeIssuer, break_it, problem: str) -> None:
    resolver, fetcher = _ports(issuer)
    break_it(resolver, fetcher, issuer)
    report = discover("example.com", resolver=resolver, fetcher=fetcher)
    assert not report.ok
    assert report.problems[0].startswith(problem)


def test_absent_algorithm_list_defaults(issuer: FakeIssuer) -> None:
    resolver, fetcher = _ports(issuer)
    metadata = dict(issuer.metadata)
    del metadata["signing_alg_values_supported"]
    fetcher.documents[issuer.metadata_url] = metadata
    assert discover("example.com", resolver=resolver, fetcher=fetcher).ok


def test_transport_failure_raises(issuer: FakeIssuer) -> None:
    resolver, _ = _ports(issuer)
    with pytest.raises(DiscoveryError) as exc:
        discover("example.com", resolver=resolver, fetcher=InMemoryHttp({}))
    assert exc.value.code is ErrorCode.ISSUER_UNREACHABLE


@pytest.mark.anyio
async def test_async(issuer: FakeIssuer) -> None:
    report = await adiscover(
        "example.com",
        resolver=AsyncInMemoryDns(issuer.dns_records()),
        fetcher=AsyncInMemoryHttp(issuer.http_documents()),
    )
    assert report.ok
