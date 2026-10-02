from __future__ import annotations

import threading
from datetime import datetime, timedelta

from pyevp import CacheEntry, InMemoryCache
from pyevp.testing import FixedClock

TTL = timedelta(minutes=10)


def _entry(clock: FixedClock, value: object = "v") -> CacheEntry:
    return CacheEntry(value=value, stored_at=clock())


def test_expiry(clock: FixedClock) -> None:
    cache = InMemoryCache(clock=clock)
    cache.set("k", _entry(clock), TTL)
    assert cache.get("k") is not None
    clock.advance(TTL)
    assert cache.get("k") is None
    assert cache.get("k") is None


def test_eviction_drops_the_soonest_to_expire(clock: FixedClock) -> None:
    cache = InMemoryCache(clock=clock, max_entries=2)
    cache.set("a", _entry(clock), TTL)
    cache.set("b", _entry(clock), TTL * 2)
    cache.set("c", _entry(clock), TTL)
    assert cache.get("a") is None
    assert cache.get("b") is not None
    assert cache.get("c") is not None


def test_concurrent_expiry_of_the_same_entry(clock: FixedClock) -> None:
    """Another reader dropping the expired entry first must not make this one fail."""
    cache: InMemoryCache
    nested = False

    def interleaving_clock() -> datetime:
        nonlocal nested
        if not nested:
            nested = True
            assert cache.get("k") is None  # the "other thread" gets in first
        return clock()

    cache = InMemoryCache(clock=interleaving_clock)
    cache._data["k"] = (clock() - TTL, _entry(clock))
    assert cache.get("k") is None


def test_threads(clock: FixedClock) -> None:
    cache = InMemoryCache(clock=clock, max_entries=8)
    errors: list[BaseException] = []

    def work(n: int) -> None:
        try:
            for i in range(2000):
                key = f"k{(n + i) % 16}"
                cache.set(key, _entry(clock, i), timedelta(seconds=i % 3))
                cache.get(key)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
