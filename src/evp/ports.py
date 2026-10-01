"""I/O boundaries.  Implement these to plug in your own DNS / HTTP / clock."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, TypeAlias, runtime_checkable

__all__ = [
    "AsyncJsonFetcher",
    "AsyncTxtResolver",
    "Clock",
    "JsonFetcher",
    "TxtResolver",
    "system_clock",
]

# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Clock: TypeAlias = Callable[[], datetime]
"""Returns the current time as an aware ``datetime``."""


def system_clock() -> datetime:
    return datetime.now(UTC)


@runtime_checkable
class TxtResolver(Protocol):
    def resolve_txt(self, name: str) -> list[str]:
        """Return each TXT record as one string (character-strings concatenated).

        Return an empty list for NXDOMAIN / NODATA; raise for other failures.
        """
        ...


@runtime_checkable
class AsyncTxtResolver(Protocol):
    async def resolve_txt(self, name: str) -> list[str]: ...


@runtime_checkable
class JsonFetcher(Protocol):
    def fetch_json(self, url: str) -> object:
        """GET ``url`` (no redirects to other origins) and return the decoded JSON.

        Raise on transport errors, non-200 responses or invalid JSON.
        """
        ...


@runtime_checkable
class AsyncJsonFetcher(Protocol):
    async def fetch_json(self, url: str) -> object: ...
