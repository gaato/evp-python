from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from evp.adapters.httpx import AsyncHttpxFetcher, FetchError, HttpxFetcher

URL = "https://issuer.example/.well-known/email-verification"


def _handler(request: httpx.Request) -> httpx.Response:
    match request.url.path:
        case "/.well-known/email-verification":
            return httpx.Response(200, json={"issuer": "https://issuer.example"})
        case "/redirect":
            return httpx.Response(302, headers={"Location": "https://evil.example/"})
        case "/html":
            return httpx.Response(200, text="<html>")
        case "/huge":
            return httpx.Response(200, content=b"[" + b"0," * 200_000 + b"0]")
        case _:
            return httpx.Response(404)


@pytest.fixture
def fetcher() -> Iterator[HttpxFetcher]:
    with HttpxFetcher(httpx.Client(transport=httpx.MockTransport(_handler))) as fetcher:
        yield fetcher


def test_fetch_json(fetcher: HttpxFetcher) -> None:
    assert fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}


@pytest.mark.parametrize("path", ["/redirect", "/html", "/huge", "/missing"])
def test_fetch_errors(fetcher: HttpxFetcher, path: str) -> None:
    with pytest.raises(FetchError):
        fetcher.fetch_json(f"https://issuer.example{path}")


@pytest.mark.anyio
async def test_async_fetch_json() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    async with AsyncHttpxFetcher(client) as fetcher:
        assert await fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}
        with pytest.raises(FetchError):
            await fetcher.fetch_json("https://issuer.example/redirect")
