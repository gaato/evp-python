"""Django integration (``pip install pyevp[django]``).

- :class:`DjangoCache` / :class:`AsyncDjangoCache` share issuer metadata and key
  sets between workers through Django's cache framework.
- :class:`DjangoReplayGuard` / :class:`AsyncDjangoReplayGuard` remember accepted
  tokens in a database table.  Add ``"pyevp.contrib.django"`` to
  ``INSTALLED_APPS`` and run ``migrate`` to create it.

::

    from pyevp import Verifier
    from pyevp.contrib.django import DjangoCache, DjangoReplayGuard

    verifier = Verifier.default(
        audience=settings.EVP_ORIGIN, cache=DjangoCache(), replay_guard=DjangoReplayGuard()
    )

Caches and databases are looked up on every call, so these can be created at
import time, before Django's settings are configured.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.cache import caches
from django.db import IntegrityError, transaction

from pyevp.cache import CacheEntry
from pyevp.ports import Clock, system_clock

__all__ = ["AsyncDjangoCache", "AsyncDjangoReplayGuard", "DjangoCache", "DjangoReplayGuard"]


def _digest(key: str) -> str:
    # Fixed length, so long URLs stay within Memcached's 250-byte key limit.
    return hashlib.sha256(key.encode()).hexdigest()


class _CacheBase:
    def __init__(self, alias: str = "default", *, prefix: str = "evp:") -> None:
        self.alias = alias
        self.prefix = prefix

    def _key(self, key: str) -> str:
        return self.prefix + _digest(key)


class DjangoCache(_CacheBase):
    """A :class:`~pyevp.Cache` backed by one of Django's ``CACHES``.

    Use a backend shared between workers (Redis, Memcached, database) for the
    cache to help; ``locmem`` is per process like :class:`~pyevp.InMemoryCache`.
    An evicted entry is simply fetched again.  With :class:`~pyevp.AsyncVerifier`,
    use :class:`AsyncDjangoCache`, which does not block the event loop.
    """

    def get(self, key: str) -> CacheEntry | None:
        entry = caches[self.alias].get(self._key(key))
        return entry if isinstance(entry, CacheEntry) else None

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        caches[self.alias].set(self._key(key), entry, timeout=ttl.total_seconds())


class AsyncDjangoCache(_CacheBase):
    """An :class:`~pyevp.AsyncCache` using Django's async cache API (``aget`` / ``aset``).

    Takes the same arguments as :class:`DjangoCache` and shares its entries.
    """

    async def get(self, key: str) -> CacheEntry | None:
        entry = await caches[self.alias].aget(self._key(key))
        return entry if isinstance(entry, CacheEntry) else None

    async def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        await caches[self.alias].aset(self._key(key), entry, timeout=ttl.total_seconds())


class _GuardBase:
    def __init__(self, using: str = "default", *, clock: Clock = system_clock) -> None:
        self.using = using
        self._clock = clock

    def _mark(self, key: str, expires_at: datetime) -> bool:
        from pyevp.contrib.django.models import UsedToken  # noqa: PLC0415

        connection = transaction.get_connection(self.using)
        # Outside an atomic block but with autocommit off, Django would treat the caller's
        # manual transaction as the outer block: nothing commits and a rollback forgets the
        # token.  (Inside an atomic block autocommit is off too; durable=True handles that.)
        if not connection.in_atomic_block and not connection.get_autocommit():
            raise RuntimeError(_MANUAL.format(using=self.using))
        rows = UsedToken.objects.using(self.using)
        try:
            # Durable: the record is committed here, not with (or rolled back with) the
            # caller's transaction.  Nested in one, Django raises instead.
            with transaction.atomic(using=self.using, durable=True):
                rows.filter(expires_at__lte=_db_time(self._clock())).delete()
                rows.create(key=_digest(key), expires_at=_db_time(expires_at))
        except IntegrityError:
            return False
        except RuntimeError as exc:
            if connection.in_atomic_block:
                raise RuntimeError(_NESTED.format(using=self.using)) from exc
            raise
        return True


_NESTED = (
    "DjangoReplayGuard must commit its record on its own, but database {using!r} is inside "
    "an atomic block (ATOMIC_REQUESTS or transaction.atomic()); a rollback there would "
    "forget the token.  Give the guard its own alias for the same database with "
    "ATOMIC_REQUESTS off, e.g. DjangoReplayGuard(using='evp'), or verify outside the "
    "transaction."
)


_MANUAL = (
    "DjangoReplayGuard must commit its record on its own, but autocommit is off on "
    "database {using!r} (AUTOCOMMIT=False or transaction.set_autocommit(False)); a "
    "rollback there would forget the token.  Give the guard its own alias for the same "
    "database with AUTOCOMMIT on, e.g. DjangoReplayGuard(using='evp')."
)


class DjangoReplayGuard(_GuardBase):
    """A :class:`~pyevp.ReplayGuard` storing accepted tokens in the database.

    Each token is a row keyed by its digest until the token expires; a second
    insert of the same key fails on the primary key, so concurrent workers
    cannot both accept a token.  Unlike a cache, the table never evicts rows
    early, and database errors propagate, so verification fails closed.
    Expired rows are deleted as new tokens are recorded.

    Each record is committed immediately in its own transaction, so a later
    rollback of the request cannot undo it.  Called inside a transaction on
    the same database (``ATOMIC_REQUESTS``, ``transaction.atomic()``, or with
    autocommit off) it raises ``RuntimeError`` instead; point ``using`` at a
    second alias for the same database with ``ATOMIC_REQUESTS`` off and
    autocommit on.  Django's ``TestCase`` transactions are exempt.

    Requires ``"pyevp.contrib.django"`` in ``INSTALLED_APPS`` and ``migrate``.
    """

    def mark_used(self, key: str, expires_at: datetime) -> bool:
        return self._mark(key, expires_at)


class AsyncDjangoReplayGuard(_GuardBase):
    """:class:`DjangoReplayGuard` for :class:`~pyevp.AsyncVerifier`.

    The database work runs in Django's thread for synchronous code.
    """

    async def mark_used(self, key: str, expires_at: datetime) -> bool:
        return await sync_to_async(self._mark, thread_sensitive=True)(key, expires_at)


def _db_time(value: datetime) -> datetime:
    # Without USE_TZ, Django stores naive datetimes (and SQLite / MySQL reject aware ones).
    return value if settings.USE_TZ else value.astimezone(UTC).replace(tzinfo=None)
