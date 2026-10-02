"""DoH JSON API parsing shared by the resolvers; imports nothing outside the standard library."""

from __future__ import annotations

from typing import Any

__all__ = [
    "CLOUDFLARE",
    "GOOGLE",
    "HEADERS",
    "DnssecError",
    "DohError",
    "params",
    "parse_txt_data",
    "records",
]

GOOGLE = "https://dns.google/resolve"
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"

_TXT = 16
_NOERROR, _NXDOMAIN = 0, 3
HEADERS = {"Accept": "application/dns-json", "Accept-Encoding": "identity"}


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


def records(document: object, name: str, require_dnssec: bool) -> list[str]:
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


def params(name: str) -> dict[str, str]:
    return {"name": name, "type": "TXT", "do": "1"}
