"""Caching of issuer metadata and key sets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from evp.ports import Clock, system_clock

__all__ = ["Cache", "CacheEntry", "InMemoryCache", "NullCache"]


@dataclass(frozen=True, slots=True)
class CacheEntry:
    value: object
    stored_at: datetime


class Cache(Protocol):
    """Key/value store for decoded JSON documents.

    Implementations may be backed by Django's cache, Redis, … ; they are called
    from both sync and async drivers so must not block for long.
    """

    def get(self, key: str) -> CacheEntry | None: ...

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None: ...


class NullCache:
    """A cache that stores nothing: every verification fetches metadata and keys."""

    def get(self, key: str) -> CacheEntry | None:
        return None

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        return None


class InMemoryCache:
    """Process-local TTL cache (not shared between workers)."""

    def __init__(self, *, clock: Clock = system_clock, max_entries: int = 256) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._data: dict[str, tuple[datetime, CacheEntry]] = {}

    def get(self, key: str) -> CacheEntry | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires_at, entry = item
        if self._clock() >= expires_at:
            del self._data[key]
            return None
        return entry

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        if len(self._data) >= self._max_entries and key not in self._data:
            self._data.pop(min(self._data, key=lambda k: self._data[k][0]))
        self._data[key] = (self._clock() + ttl, entry)
