"""JSON fetchers backed by httpx2 or httpx (``pip install evp[httpx2]`` / ``evp[httpx]``).

httpx2 is used for default clients when it is installed; a client from either
library can be passed in explicitly.
"""

from __future__ import annotations

import json
from types import TracebackType
from typing import TYPE_CHECKING, Self

from evp.adapters._http import http

if TYPE_CHECKING:
    from evp.adapters._http import AsyncClient, Client, Response

__all__ = ["AsyncHttpxFetcher", "FetchError", "HttpxFetcher"]

MAX_DOCUMENT_BYTES = 256 * 1024
# Bodies are read undecoded so the size cap applies to what is held in memory;
# a decompression bomb would otherwise be expanded before the cap is checked.
_HEADERS = {"Accept": "application/json", "Accept-Encoding": "identity"}


class FetchError(Exception):
    pass


def _check(response: Response) -> None:
    if response.status_code != 200:
        raise FetchError(f"GET {response.request.url} returned HTTP {response.status_code}")
    if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
        raise FetchError(f"GET {response.request.url} returned a compressed response")


def _decode(body: bytes, url: str) -> object:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise FetchError(f"GET {url} did not return JSON") from exc


class HttpxFetcher:
    """Synchronous fetcher.

    Redirects are not followed, compressed responses are refused and bodies are size-capped.
    """

    def __init__(self, client: Client | None = None, *, timeout: float = 5.0) -> None:
        self._client: Client = client or http.Client(timeout=timeout, follow_redirects=False)

    def fetch_json(self, url: str) -> object:
        with self._client.stream("GET", url, headers=_HEADERS, follow_redirects=False) as response:
            _check(response)
            body = bytearray()
            for chunk in response.iter_raw():
                body += chunk
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise FetchError(f"GET {url} response is too large")
        return _decode(bytes(body), url)

    def close(self) -> None:
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
    def __init__(self, client: AsyncClient | None = None, *, timeout: float = 5.0) -> None:
        self._client: AsyncClient = client or http.AsyncClient(
            timeout=timeout, follow_redirects=False
        )

    async def fetch_json(self, url: str) -> object:
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
