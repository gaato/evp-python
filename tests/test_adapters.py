from __future__ import annotations

import gzip
import importlib
import importlib.util
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

import pyevp.adapters.httpx
from pyevp.adapters import _http
from pyevp.adapters.httpx import AsyncHttpxFetcher, FetchError, HttpxFetcher

URL = "https://issuer.example/.well-known/email-verification"
PUBLIC = ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]


def _public(host: str) -> list[str]:
    return PUBLIC


async def _apublic(host: str) -> list[str]:
    return PUBLIC


# The adapters accept a client from either library; test whichever are installed.
MODULES = [
    importlib.import_module(name)
    for name in ("httpx2", "httpx")
    if importlib.util.find_spec(name) is not None
]


def _transport(mod: ModuleType, handle: Callable[[Any], Any]) -> Any:
    """A MockTransport whose responses are unread streams, as on the network."""

    def streamed(request: Any) -> Any:
        r = handle(request)
        return mod.Response(r.status_code, headers=r.headers, stream=mod.ByteStream(r.content))

    return mod.MockTransport(streamed)


def _handler(mod: ModuleType) -> Callable[[Any], Any]:
    def handle(request: Any) -> Any:
        match request.url.path:
            case "/.well-known/email-verification":
                return mod.Response(200, json={"issuer": "https://issuer.example"})
            case "/redirect":
                return mod.Response(302, headers={"Location": "https://evil.example/"})
            case "/html":
                return mod.Response(200, text="<html>")
            case "/gzip":
                body = gzip.compress(b"[" + b"0," * 8_000_000 + b"0]")
                return mod.Response(200, content=body, headers={"Content-Encoding": "gzip"})
            case "/deep":
                return mod.Response(200, content=b"[" * 200_000 + b"]" * 200_000)
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
    with HttpxFetcher(
        mod.Client(transport=_transport(mod, _handler(mod))), resolve_host=_public
    ) as fetcher:
        yield fetcher


def test_fetch_json(fetcher: HttpxFetcher) -> None:
    assert fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}


@pytest.mark.parametrize("path", ["/redirect", "/html", "/gzip", "/huge", "/missing"])
def test_fetch_errors(fetcher: HttpxFetcher, path: str) -> None:
    with pytest.raises(FetchError):
        fetcher.fetch_json(f"https://issuer.example{path}")


@pytest.mark.anyio
async def test_async_fetch_json(mod: ModuleType) -> None:
    client = mod.AsyncClient(transport=_transport(mod, _handler(mod)))
    async with AsyncHttpxFetcher(client, resolve_host=_apublic) as fetcher:
        assert await fetcher.fetch_json(URL) == {"issuer": "https://issuer.example"}
        with pytest.raises(FetchError):
            await fetcher.fetch_json("https://issuer.example/redirect")


def test_deeply_nested_body(fetcher: HttpxFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pyevp.adapters.httpx, "MAX_DOCUMENT_BYTES", 1024 * 1024)
    with pytest.raises(FetchError, match="JSON"):
        fetcher.fetch_json("https://issuer.example/deep")


def test_requests_uncompressed_bodies(mod: ModuleType) -> None:
    seen: list[str | None] = []

    def handle(request: Any) -> Any:
        seen.append(request.headers.get("Accept-Encoding"))
        return mod.Response(200, json={})

    with HttpxFetcher(
        mod.Client(transport=_transport(mod, handle)), resolve_host=_public
    ) as fetcher:
        fetcher.fetch_json(URL)
    assert seen == ["identity"]


@pytest.mark.anyio
async def test_async_refuses_compressed_bodies(mod: ModuleType) -> None:
    client = mod.AsyncClient(transport=_transport(mod, _handler(mod)))
    async with AsyncHttpxFetcher(client, resolve_host=_apublic) as fetcher:
        with pytest.raises(FetchError, match="compressed"):
            await fetcher.fetch_json("https://issuer.example/gzip")


def _following(mod: ModuleType, seen: list[str], *, is_async: bool = False) -> Any:
    """A client configured to follow redirects, as an application might pass in."""

    def handle(request: Any) -> Any:
        seen.append(request.url.host)
        if request.url.host == "issuer.example":
            return mod.Response(302, headers={"Location": "https://elsewhere.example/"})
        return mod.Response(200, json={})

    cls = mod.AsyncClient if is_async else mod.Client
    return cls(transport=_transport(mod, handle), follow_redirects=True)


def test_injected_client_does_not_follow_redirects(mod: ModuleType) -> None:
    seen: list[str] = []
    with (
        HttpxFetcher(_following(mod, seen), resolve_host=_public) as fetcher,
        pytest.raises(FetchError),
    ):
        fetcher.fetch_json(URL)
    assert seen == ["issuer.example"]


@pytest.mark.anyio
async def test_async_injected_client_does_not_follow_redirects(mod: ModuleType) -> None:
    seen: list[str] = []
    async with AsyncHttpxFetcher(
        _following(mod, seen, is_async=True), resolve_host=_apublic
    ) as fetcher:
        with pytest.raises(FetchError):
            await fetcher.fetch_json(URL)
    assert seen == ["issuer.example"]


def test_prefers_httpx2() -> None:
    expected = "httpx2" if importlib.util.find_spec("httpx2") else "httpx"
    assert _http.http.__name__ == expected
    with HttpxFetcher() as fetcher:
        assert type(fetcher._client).__module__.split(".")[0] == expected


@pytest.mark.parametrize(
    "addresses",
    [
        [],
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::1"],
        ["fe80::1%eth0"],
        ["fd00::1"],
        ["::ffff:127.0.0.1"],
        ["93.184.215.14", "192.168.1.1"],
        ["not an address"],
    ],
)
def test_refuses_non_global_addresses(mod: ModuleType, addresses: list[str]) -> None:
    seen: list[Any] = []
    client = mod.Client(transport=_transport(mod, seen.append))
    with (
        HttpxFetcher(client, resolve_host=lambda host: addresses) as fetcher,
        pytest.raises(FetchError, match=r"issuer\.example"),
    ):
        fetcher.fetch_json(URL)
    assert not seen


@pytest.mark.anyio
async def test_async_refuses_non_global_addresses(mod: ModuleType) -> None:
    async def private(host: str) -> list[str]:
        return ["10.0.0.1"]

    client = mod.AsyncClient(transport=_transport(mod, _handler(mod)))
    async with AsyncHttpxFetcher(client, resolve_host=private) as fetcher:
        with pytest.raises(FetchError, match=r"non-global address 10\.0\.0\.1"):
            await fetcher.fetch_json(URL)


def test_resolution_failure_is_a_fetch_error(mod: ModuleType) -> None:
    def fail(host: str) -> list[str]:
        raise OSError("no such host")

    client = mod.Client(transport=_transport(mod, _handler(mod)))
    with (
        HttpxFetcher(client, resolve_host=fail) as fetcher,
        pytest.raises(FetchError, match=r"cannot resolve issuer\.example"),
    ):
        fetcher.fetch_json(URL)


def test_private_addresses_can_be_allowed(mod: ModuleType) -> None:
    client = mod.Client(transport=_transport(mod, _handler(mod)))
    with HttpxFetcher(
        client, require_global_addresses=False, resolve_host=lambda host: ["127.0.0.1"]
    ) as fetcher:
        assert fetcher.fetch_json(URL)


@pytest.mark.anyio
async def test_async_default_resolver_checks_literal_addresses(mod: ModuleType) -> None:
    client = mod.AsyncClient(transport=_transport(mod, _handler(mod)))
    async with AsyncHttpxFetcher(client) as fetcher:
        with pytest.raises(FetchError, match=r"non-global address 127\.0\.0\.1"):
            await fetcher.fetch_json("https://127.0.0.1/.well-known/email-verification")


def test_a_client_passed_in_stays_open(mod: ModuleType) -> None:
    client = mod.Client(transport=_transport(mod, _handler(mod)))
    with HttpxFetcher(client, resolve_host=_public):
        pass
    assert not client.is_closed
    owned = HttpxFetcher()
    owned.close()
    assert owned._client.is_closed


@pytest.mark.anyio
async def test_an_async_client_passed_in_stays_open(mod: ModuleType) -> None:
    client = mod.AsyncClient(transport=_transport(mod, _handler(mod)))
    async with AsyncHttpxFetcher(client, resolve_host=_apublic):
        pass
    assert not client.is_closed
    owned = AsyncHttpxFetcher()
    await owned.aclose()
    assert owned._client.is_closed
