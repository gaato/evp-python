"""TXT resolvers over DNS-over-HTTPS JSON APIs (``pip install evp[httpx2]`` or ``evp[httpx]``).

Useful where plain DNS is unavailable or untrusted (serverless platforms,
locked-down networks).  Only an HTTP client is needed; dnspython is not.

``require_dnssec`` checks the resolver's ``AD`` flag, which only means that the
DoH provider validated the answer: you are trusting that provider over TLS.
Unsigned zones (gmail.com, for example) never pass this check.

If you already use ``dnspython[doh]``, an RFC 8484 resolver is also possible::

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["https://cloudflare-dns.com/dns-query"]
    DnsPythonResolver(resolver)
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

from evp.adapters._http import http

if TYPE_CHECKING:
    from evp.adapters._http import AsyncClient, Client, Response

__all__ = [
    "CLOUDFLARE",
    "GOOGLE",
    "AsyncDohResolver",
    "DnssecError",
    "DohError",
    "DohResolver",
    "parse_txt_data",
]

GOOGLE = "https://dns.google/resolve"
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"

_TXT = 16
_NOERROR, _NXDOMAIN = 0, 3
_HEADERS = {"Accept": "application/dns-json"}


class DohError(Exception):
    """The DoH provider failed or answered with an error (e.g. SERVFAIL)."""


class DnssecError(DohError):
    """The answer was not marked authenticated (AD) by the DoH provider."""


def parse_txt_data(data: str) -> str:
    """Decode a JSON-API TXT ``data`` value into one string.

    Cloudflare returns presentation format: each character-string quoted, with
    ``\\"``, ``\\\\`` and ``\\DDD`` escapes, separated by spaces.  Google returns
    the strings already joined and unquoted.
    """
    if not data.startswith('"'):
        return data
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        if data[i].isspace():
            i += 1
            continue
        if data[i] != '"':
            raise DohError(f"malformed TXT data: {data!r}")
        i += 1
        while True:
            if i >= n:
                raise DohError(f"unterminated TXT string: {data!r}")
            c = data[i]
            if c == '"':
                i += 1
                break
            if c == "\\":
                if data[i + 1 : i + 4].isdigit() and len(data[i + 1 : i + 4]) == 3:
                    out.append(int(data[i + 1 : i + 4]) & 0xFF)
                    i += 4
                    continue
                if i + 1 >= n:
                    raise DohError(f"dangling escape in TXT data: {data!r}")
                c = data[i + 1]
                i += 1
            out += c.encode()
            i += 1
    return out.decode("utf-8", "replace")


def _records(document: object, name: str, require_dnssec: bool) -> list[str]:
    if not isinstance(document, dict):
        raise DohError(f"DoH answer for {name} is not a JSON object")
    status = document.get("Status")
    if status == _NXDOMAIN:
        return []
    if status != _NOERROR:
        raise DohError(f"DoH lookup of {name} failed with RCODE {status}")
    if require_dnssec and document.get("AD") is not True:
        raise DnssecError(f"TXT answer for {name} is not DNSSEC-authenticated")
    answers: Any = document.get("Answer") or []
    return [
        parse_txt_data(a["data"])
        for a in answers
        if isinstance(a, dict) and a.get("type") == _TXT and isinstance(a.get("data"), str)
    ]


def _check(response: Response, name: str) -> object:
    if response.status_code != 200:
        raise DohError(f"DoH lookup of {name} returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise DohError(f"DoH lookup of {name} did not return JSON") from exc


def _params(name: str) -> dict[str, str]:
    return {"name": name, "type": "TXT", "do": "1"}


class DohResolver:
    """Synchronous DoH TXT resolver (Google by default; pass ``endpoint=CLOUDFLARE`` etc.)."""

    def __init__(
        self,
        endpoint: str = GOOGLE,
        *,
        client: Client | None = None,
        require_dnssec: bool = False,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self._client: Client = client or http.Client(timeout=timeout, follow_redirects=False)
        self._require_dnssec = require_dnssec

    def resolve_txt(self, name: str) -> list[str]:
        response = self._client.get(self.endpoint, params=_params(name), headers=_HEADERS)
        return _records(_check(response, name), name, self._require_dnssec)

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


class AsyncDohResolver:
    def __init__(
        self,
        endpoint: str = GOOGLE,
        *,
        client: AsyncClient | None = None,
        require_dnssec: bool = False,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self._client: AsyncClient = client or http.AsyncClient(
            timeout=timeout, follow_redirects=False
        )
        self._require_dnssec = require_dnssec

    async def resolve_txt(self, name: str) -> list[str]:
        response = await self._client.get(self.endpoint, params=_params(name), headers=_HEADERS)
        return _records(_check(response, name), name, self._require_dnssec)

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
