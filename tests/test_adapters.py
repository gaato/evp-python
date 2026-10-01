from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

from evp.adapters import _http
from evp.adapters.httpx import AsyncHttpxFetcher, FetchError, HttpxFetcher

URL = "https://issuer.example/.well-known/email-verification"

# The adapters accept a client from either library; test whichever are installed.
MODULES = [
    importlib.import_module(name)
    for name in ("httpx2", "httpx")
    if importlib.util.find_spec(name) is not None
]


def _handler(mod: ModuleType) -> Callable[[Any], Any]:
    def handle(request: Any) -> Any:
        match request.url.path:
            case "/.well-known/email-verification":
                return mod.Response(200, json={"issuer": "https://issuer.example"})
            case "/redirect":
                return mod.Response(302, headers={"Location": "https://evil.example/"})
            case "/html":
                return mod.Response(200, text="<html>")
            case "/huge":
                return mod.Response(200, content=b"[" + b"0," * 200_000 + b"0]")
            case _:
                return mod.Response(404)

    return handle


@pytest.fixture(params=MODULES, ids=lambda m: m.__name__)
def mod(request: pytest.FixtureRequest) -> ModuleType:
    return request.param


@pytest.fixture
def fetcher(mod: ModuleType) -> Iterator[HttpxFetcher]:
    with HttpxFetcher(mod.Client(transport=mod.MockTransport(_handler(mod)))) as fetcher:
        yield fetcher


def test_fetch_json(fetcher: HttpxFetcher) -> None:
    assert fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}


@pytest.mark.parametrize("path", ["/redirect", "/html", "/huge", "/missing"])
def test_fetch_errors(fetcher: HttpxFetcher, path: str) -> None:
    with pytest.raises(FetchError):
        fetcher.fetch_json(f"https://issuer.example{path}")


@pytest.mark.anyio
async def test_async_fetch_json(mod: ModuleType) -> None:
    client = mod.AsyncClient(transport=mod.MockTransport(_handler(mod)))
    async with AsyncHttpxFetcher(client) as fetcher:
        assert await fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}
        with pytest.raises(FetchError):
            await fetcher.fetch_json("https://issuer.example/redirect")


def test_prefers_httpx2() -> None:
    expected = "httpx2" if importlib.util.find_spec("httpx2") else "httpx"
    assert _http.http.__name__ == expected
    with HttpxFetcher() as fetcher:
        assert type(fetcher._client).__module__.split(".")[0] == expected
