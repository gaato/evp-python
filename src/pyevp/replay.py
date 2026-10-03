"""Replay protection.

The single-use nonce is the primary defence against replay, but it only works
when the nonce lives server-side.  With client-side sessions (e.g. Starlette's
signed-cookie ``SessionMiddleware``) an attacker who captured a token can resend
it together with the old session cookie.  A replay guard closes that gap by
remembering every accepted token until it would expire anyway.

Implementations must make :meth:`ReplayGuard.mark_used` an atomic
"add if absent", shared by every worker that verifies tokens, for example:

- Redis: ``SET evp:<key> 1 NX PXAT <expires_at in ms>``, with
  ``maxmemory-policy noeviction``
- A database table with the key as primary key, as
  :class:`pyevp.contrib.django.EVPReplayGuard` does

The store must keep every record until ``expires_at``: caches that evict
entries under memory pressure (Memcached, Django's cache backends) do not.

``expires_at`` can already be past when verification took long; guards need not
handle that specially, because the verifier rejects the token afterwards.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Protocol, runtime_checkable

from pyevp.ports import Clock, system_clock

__all__ = ["AsyncReplayGuard", "InMemoryReplayGuard", "ReplayGuard"]


@runtime_checkable
class ReplayGuard(Protocol):
    def mark_used(self, key: str, expires_at: datetime) -> bool:
        """Remember ``key`` until ``expires_at``.

        Return ``True`` if the key was not already present, ``False`` otherwise.
        """
        ...


@runtime_checkable
class AsyncReplayGuard(Protocol):
    async def mark_used(self, key: str, expires_at: datetime) -> bool: ...


class InMemoryReplayGuard:
    """Process-local guard.

    Only correct when a single process verifies tokens; with several workers a
    token can be replayed against another worker.  Use a shared store there.
    """

    def __init__(self, *, clock: Clock = system_clock) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._seen: dict[str, datetime] = {}

    def mark_used(self, key: str, expires_at: datetime) -> bool:
        now = self._clock()
        with self._lock:
            self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
            if key in self._seen:
                return False
            self._seen[key] = expires_at
            return True
