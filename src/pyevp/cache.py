"""Caching of issuer metadata and key sets."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from pyevp.ports import Clock, system_clock

__all__ = ["AsyncCache", "Cache", "CacheEntry", "InMemoryCache", "NullCache"]


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


class AsyncCache(Protocol):
    """:class:`Cache` with coroutine methods, for stores that must not block the event loop.

    :class:`~pyevp.AsyncVerifier` accepts either kind.
    """

    async def get(self, key: str) -> CacheEntry | None: ...

    async def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None: ...


class NullCache:
    """A cache that stores nothing: every verification fetches metadata and keys."""

    def get(self, key: str) -> CacheEntry | None:
        return None

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        return None


class InMemoryCache:
    """Process-local TTL cache (not shared between workers).

    Safe to share between threads, e.g. one ``Verifier`` used by a threaded server.
    """

    def __init__(self, *, clock: Clock = system_clock, max_entries: int = 256) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._data: dict[str, tuple[datetime, CacheEntry]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> CacheEntry | None:
        now = self._clock()  # outside the lock: the clock is user code
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires_at, entry = item
            if now >= expires_at:
                del self._data[key]
                return None
            return entry

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        expires_at = self._clock() + ttl
        with self._lock:
            if len(self._data) >= self._max_entries and key not in self._data:
                del self._data[min(self._data, key=lambda k: self._data[k][0])]
            self._data[key] = (expires_at, entry)
