"""TXT resolvers backed by dnspython (``pip install evp[dns]``)."""

from __future__ import annotations

import dns.asyncresolver
import dns.flags
import dns.resolver
from dns.resolver import Answer

__all__ = ["AsyncDnsPythonResolver", "DnsPythonResolver", "DnssecError"]

_EMPTY = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


class DnssecError(Exception):
    """The answer was not marked authenticated (AD) by the resolver."""


def _configure(resolver: dns.resolver.BaseResolver, require_dnssec: bool) -> None:
    if require_dnssec:
        resolver.use_edns(0, dns.flags.DO, 1232)
        resolver.flags = (resolver.flags or 0) | dns.flags.AD


def _records(answer: Answer, name: str, require_dnssec: bool) -> list[str]:
    if require_dnssec and not (answer.response.flags & dns.flags.AD):
        raise DnssecError(f"TXT answer for {name} is not DNSSEC-authenticated")
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


class DnsPythonResolver:
    """Synchronous resolver.

    With ``require_dnssec=True`` the answer must carry the AD flag, which is only
    meaningful when the configured upstream resolver validates DNSSEC and the
    path to it is trusted (e.g. a local validating resolver).
    """

    def __init__(
        self,
        resolver: dns.resolver.Resolver | None = None,
        *,
        require_dnssec: bool = False,
        lifetime: float = 5.0,
    ) -> None:
        self._resolver = resolver or dns.resolver.Resolver()
        self._resolver.lifetime = lifetime
        self._require_dnssec = require_dnssec
        _configure(self._resolver, require_dnssec)

    def resolve_txt(self, name: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, "TXT")
        except _EMPTY:
            return []
        return _records(answer, name, self._require_dnssec)


class AsyncDnsPythonResolver:
    def __init__(
        self,
        resolver: dns.asyncresolver.Resolver | None = None,
        *,
        require_dnssec: bool = False,
        lifetime: float = 5.0,
    ) -> None:
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._resolver.lifetime = lifetime
        self._require_dnssec = require_dnssec
        _configure(self._resolver, require_dnssec)

    async def resolve_txt(self, name: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, "TXT")
        except _EMPTY:
            return []
        return _records(answer, name, self._require_dnssec)
