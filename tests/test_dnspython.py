from __future__ import annotations

import dns.asyncresolver
import dns.flags
import dns.resolver
import pytest

from pyevp.adapters.dnspython import AsyncDnsPythonResolver, DnsPythonResolver


def _flags(resolver: dns.resolver.BaseResolver) -> dns.flags.Flag:
    assert resolver.flags is not None
    return dns.flags.Flag(resolver.flags)


@pytest.mark.parametrize(
    ("adapter", "factory"),
    [
        (DnsPythonResolver, dns.resolver.Resolver),
        (AsyncDnsPythonResolver, dns.asyncresolver.Resolver),
    ],
)
def test_require_dnssec_keeps_recursion_desired(adapter, factory) -> None:
    resolver = factory(configure=False)
    adapter(resolver, require_dnssec=True)
    assert _flags(resolver) & dns.flags.RD
    assert _flags(resolver) & dns.flags.AD
    assert resolver.edns == 0
    assert resolver.ednsflags & dns.flags.DO


def test_require_dnssec_keeps_explicit_flags() -> None:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.flags = dns.flags.CD
    DnsPythonResolver(resolver, require_dnssec=True)
    assert _flags(resolver) == dns.flags.CD | dns.flags.AD


def test_default_leaves_flags_alone() -> None:
    resolver = dns.resolver.Resolver(configure=False)
    DnsPythonResolver(resolver)
    assert resolver.flags is None
