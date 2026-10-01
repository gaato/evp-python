"""JSON fetchers backed by httpx (``pip install evp[httpx]``)."""

from __future__ import annotations

import json
from types import TracebackType
from typing import Self

import httpx

__all__ = ["AsyncHttpxFetcher", "FetchError", "HttpxFetcher"]

MAX_DOCUMENT_BYTES = 256 * 1024
_HEADERS = {"Accept": "application/json"}


class FetchError(Exception):
    pass


def _check(response: httpx.Response) -> None:
    if response.status_code != 200:
        raise FetchError(f"GET {response.request.url} returned HTTP {response.status_code}")


def _decode(body: bytes, url: str) -> object:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise FetchError(f"GET {url} did not return JSON") from exc


class HttpxFetcher:
    """Synchronous fetcher.  Redirects are not followed; bodies are size-capped."""

    def __init__(self, client: httpx.Client | None = None, *, timeout: float = 5.0) -> None:
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    def fetch_json(self, url: str) -> object:
        with self._client.stream("GET", url, headers=_HEADERS) as response:
            _check(response)
            body = bytearray()
            for chunk in response.iter_bytes():
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
    def __init__(self, client: httpx.AsyncClient | None = None, *, timeout: float = 5.0) -> None:
        self._client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def fetch_json(self, url: str) -> object:
        async with self._client.stream("GET", url, headers=_HEADERS) as response:
            _check(response)
            body = bytearray()
            async for chunk in response.aiter_bytes():
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
