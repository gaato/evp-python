"""Pieces shared by the JSON fetchers; imports nothing outside the standard library."""

from __future__ import annotations

import json

__all__ = ["HEADERS", "MAX_DOCUMENT_BYTES", "FetchError", "decode"]

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
