"""JSON fetchers backed by httpx2 or httpx (``pip install pyevp[httpx2]`` / ``pyevp[httpx]``).

httpx2 is used for default clients when it is installed; a client from either
library can be passed in explicitly.
"""

from __future__ import annotations

import socket
from types import TracebackType
from typing import TYPE_CHECKING, Self

import anyio

from pyevp.adapters import _fetch
from pyevp.adapters._fetch import HEADERS as _HEADERS
from pyevp.adapters._fetch import (
    MAX_DOCUMENT_BYTES,
    AsyncResolveHost,
    FetchError,
    ResolveHost,
)
from pyevp.adapters._fetch import decode as _decode
from pyevp.adapters._http import http

if TYPE_CHECKING:
    from pyevp.adapters._http import AsyncClient, Client, Response

__all__ = ["AsyncHttpxFetcher", "FetchError", "HttpxFetcher"]


def _check(response: Response) -> None:
    if response.status_code != 200:
        raise FetchError(f"GET {response.request.url} returned HTTP {response.status_code}")
    if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
        raise FetchError(f"GET {response.request.url} returned a compressed response")


async def _anyio_resolve_host(host: str) -> list[str]:
    infos = await anyio.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


class HttpxFetcher:
    """Synchronous fetcher.

    Redirects are not followed, compressed responses are refused and bodies are size-capped.
    Before each request the host is resolved and refused unless every address is globally
    routable; pass ``require_global_addresses=False`` to reach an issuer on a private network
    (local development) or when an egress proxy enforces that policy and resolves names
    itself.  ``resolve_host`` replaces the system resolver used for that check.
    """

    def __init__(
        self,
        client: Client | None = None,
        *,
        timeout: float = 5.0,
        require_global_addresses: bool = True,
        resolve_host: ResolveHost = _fetch.system_resolve_host,
    ) -> None:
        self._owns_client = client is None
        self._client: Client = client or http.Client(timeout=timeout, follow_redirects=False)
        self._require_global = require_global_addresses
        self._resolve_host = resolve_host

    def fetch_json(self, url: str) -> object:
        if self._require_global:
            _fetch.require_global(url, self._resolve_host)
        with self._client.stream("GET", url, headers=_HEADERS, follow_redirects=False) as response:
            _check(response)
            body = bytearray()
            for chunk in response.iter_raw():
                body += chunk
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise FetchError(f"GET {url} response is too large")
        return _decode(bytes(body), url)

    def close(self) -> None:
        """Close the client this fetcher created; a client passed in stays open."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncHttpxFetcher:
    """Asynchronous counterpart of :class:`HttpxFetcher` (asyncio or trio)."""

    def __init__(
        self,
        client: AsyncClient | None = None,
        *,
        timeout: float = 5.0,
        require_global_addresses: bool = True,
        resolve_host: AsyncResolveHost = _anyio_resolve_host,
    ) -> None:
        self._owns_client = client is None
        self._client: AsyncClient = client or http.AsyncClient(
            timeout=timeout, follow_redirects=False
        )
        self._require_global = require_global_addresses
        self._resolve_host = resolve_host

    async def fetch_json(self, url: str) -> object:
        if self._require_global:
            host = _fetch.host_of(url)
            try:
                addresses = list(await self._resolve_host(host))
            except OSError as exc:
                raise FetchError(f"GET {url}: cannot resolve {host}: {exc}") from exc
            _fetch.check_global_addresses(url, host, addresses)
        async with self._client.stream(
            "GET", url, headers=_HEADERS, follow_redirects=False
        ) as response:
            _check(response)
            body = bytearray()
            async for chunk in response.aiter_raw():
                body += chunk
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise FetchError(f"GET {url} response is too large")
        return _decode(bytes(body), url)

    async def aclose(self) -> None:
        """Close the client this fetcher created; a client passed in stays open."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
