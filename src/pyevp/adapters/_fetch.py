"""Pieces shared by the JSON fetchers; imports nothing outside the standard library."""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeAlias
from urllib.parse import urlsplit

__all__ = [
    "HEADERS",
    "MAX_DOCUMENT_BYTES",
    "AsyncResolveHost",
    "FetchError",
    "ResolveHost",
    "check_global_addresses",
    "decode",
    "host_of",
    "require_global",
    "system_resolve_host",
]

MAX_DOCUMENT_BYTES = 256 * 1024
# Bodies are read undecoded so the size cap applies to what is held in memory;
# a decompression bomb would otherwise be expanded before the cap is checked.
HEADERS = {"Accept": "application/json", "Accept-Encoding": "identity"}


class FetchError(Exception):
    pass


def decode(body: bytes, url: str) -> object:
    try:
        return json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise FetchError(f"GET {url} did not return JSON") from exc


# TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
ResolveHost: TypeAlias = Callable[[str], Iterable[str]]
"""Return the IP addresses ``host`` resolves to, as strings."""
AsyncResolveHost: TypeAlias = Callable[[str], Awaitable[Iterable[str]]]


def host_of(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise FetchError(f"GET {url}: no host")
    return host


def system_resolve_host(host: str) -> list[str]:
    return [str(info[4][0]) for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]


def require_global(url: str, resolve: ResolveHost) -> None:
    """Resolve the host of ``url`` and :func:`check_global_addresses`."""
    host = host_of(url)
    try:
        addresses = list(resolve(host))
    except OSError as exc:
        raise FetchError(f"GET {url}: cannot resolve {host}: {exc}") from exc
    check_global_addresses(url, host, addresses)


def check_global_addresses(url: str, host: str, addresses: Iterable[str]) -> None:
    """Refuse to fetch ``url`` unless every address of its host is globally routable.

    The host comes from DNS records and metadata that anyone can publish, so without
    this check a token could make the verifier fetch from the relying party's own
    network (SSRF).  The HTTP library resolves the name again when it connects; a
    DNS server that answers differently the second time is not caught here.
    """
    resolved = list(addresses)
    if not resolved:
        raise FetchError(f"GET {url}: {host} has no addresses")
    for address in resolved:
        try:
            ip = ipaddress.ip_address(address.partition("%")[0])
        except ValueError as exc:
            raise FetchError(f"GET {url}: {host} resolved to {address!r}") from exc
        if not ip.is_global:
            raise FetchError(f"GET {url}: {host} resolves to non-global address {ip}")
