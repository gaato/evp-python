from __future__ import annotations

import contextlib
import warnings
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from django.core.cache import caches
from django.core.management import call_command
from django.db import connections, transaction
from django.test import override_settings

from pyevp import (
    AsyncCache,
    AsyncReplayGuard,
    Cache,
    CacheEntry,
    ErrorCode,
    ReplayGuard,
    TokenError,
)
from pyevp.contrib.django import (
    AsyncDjangoCache,
    AsyncDjangoReplayGuard,
    DjangoCache,
    DjangoReplayGuard,
)
from pyevp.testing import FakeIssuer, FixedClock, make_async_verifier, make_verifier

from . import _django
from .conftest import AUDIENCE, EMAIL

_django.configure()

# Models can only be imported once the app registry is ready.
from pyevp.contrib.django.models import UsedToken  # noqa: E402

LONG_URL = "https://issuer.example/" + "k" * 300


@pytest.fixture(scope="module", autouse=True)
def _database() -> Any:
    call_command("migrate", verbosity=0)
    call_command("createcachetable", verbosity=0)
    yield
    connections.close_all()


@pytest.fixture(autouse=True)
def _clean() -> None:
    for alias in ("default", "db"):
        caches[alias].clear()
    UsedToken.objects.all().delete()


def test_satisfies_protocols() -> None:
    cache: Cache = DjangoCache()
    async_cache: AsyncCache = AsyncDjangoCache()
    guard: ReplayGuard = DjangoReplayGuard()
    async_guard: AsyncReplayGuard = AsyncDjangoReplayGuard()
    assert isinstance(guard, ReplayGuard)
    assert isinstance(async_guard, AsyncReplayGuard)
    assert cache.get("missing") is None
    assert async_cache is not None


def test_migrations_match_models() -> None:
    call_command("makemigrations", "pyevp", check=True, dry_run=True, verbosity=0)


# --- cache ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["default", "db"])
def test_cache_round_trip(alias: str, clock: FixedClock) -> None:
    cache = DjangoCache(alias)
    entry = CacheEntry({"issuer": "https://issuer.example"}, clock())
    cache.set("https://issuer.example/meta", entry, timedelta(minutes=10))
    assert cache.get("https://issuer.example/meta") == entry
    assert cache.get("https://issuer.example/other") is None


def test_cache_keys_have_a_fixed_length(clock: FixedClock) -> None:
    # Memcached rejects keys over 250 bytes; Django warns about them on every backend,
    # which pytest turns into an error here.
    cache = DjangoCache()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cache.set(LONG_URL, CacheEntry(1, clock()), timedelta(minutes=10))
        assert cache.get(LONG_URL) == CacheEntry(1, clock())
    assert len(cache._key(LONG_URL)) == len("evp:") + 64


def test_cache_alias_and_prefix(clock: FixedClock) -> None:
    DjangoCache("db", prefix="x:").set("meta", CacheEntry(1, clock()), timedelta(minutes=10))
    assert DjangoCache("db", prefix="x:").get("meta") is not None
    assert DjangoCache("db").get("meta") is None
    assert DjangoCache("default", prefix="x:").get("meta") is None


def test_cache_ignores_foreign_values() -> None:
    cache = DjangoCache()
    caches["default"].set(cache._key("meta"), "not an entry")
    assert cache.get("meta") is None


def test_cache_passes_ttl(monkeypatch: pytest.MonkeyPatch, clock: FixedClock) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(caches["default"], "set", lambda *a, **kw: seen.append(kw["timeout"]))
    DjangoCache().set("meta", CacheEntry(1, clock()), timedelta(minutes=10))
    assert seen == [600]


@pytest.mark.anyio
async def test_async_cache_shares_entries(clock: FixedClock) -> None:
    entry = CacheEntry({"issuer": "https://issuer.example"}, clock())
    await AsyncDjangoCache("db").set(LONG_URL, entry, timedelta(minutes=10))
    assert await AsyncDjangoCache("db").get(LONG_URL) == entry
    assert await AsyncDjangoCache("db").get("missing") is None


# --- replay guard ----------------------------------------------------------------------


def test_replay_guard(clock: FixedClock) -> None:
    guard = DjangoReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert guard.mark_used("k", expires) is True
    assert guard.mark_used("k", expires) is False
    assert guard.mark_used("other", expires) is True
    assert UsedToken.objects.count() == 2


def test_records_are_not_evicted_by_volume(clock: FixedClock) -> None:
    # A cache would cull here (Django's default MAX_ENTRIES is 300) and forget "k".
    guard = DjangoReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert guard.mark_used("k", expires) is True
    for i in range(400):
        assert guard.mark_used(f"filler-{i}", expires) is True
    assert guard.mark_used("k", expires) is False


def test_expired_records_are_purged(clock: FixedClock) -> None:
    guard = DjangoReplayGuard(clock=clock)
    guard.mark_used("old", clock() + timedelta(minutes=5))
    clock.advance(timedelta(minutes=6))
    guard.mark_used("new", clock() + timedelta(minutes=5))
    assert UsedToken.objects.count() == 1


def test_arbitrary_keys_fit(clock: FixedClock) -> None:
    guard = DjangoReplayGuard(clock=clock)
    assert guard.mark_used("x" * 1000, clock() + timedelta(minutes=5)) is True
    assert guard.mark_used("x" * 1000, clock() + timedelta(minutes=5)) is False


def test_without_use_tz(clock: FixedClock) -> None:
    with override_settings(USE_TZ=False):
        guard = DjangoReplayGuard(clock=clock)
        expires = clock() + timedelta(minutes=5)
        assert guard.mark_used("k", expires) is True
        assert guard.mark_used("k", expires) is False
        [row] = UsedToken.objects.all()
        assert row.expires_at.tzinfo is None
        assert row.expires_at == expires.replace(tzinfo=None)


def test_database_errors_propagate(monkeypatch: pytest.MonkeyPatch, clock: FixedClock) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database down")

    monkeypatch.setattr(UsedToken.objects, "using", broken)
    with pytest.raises(RuntimeError):
        DjangoReplayGuard(clock=clock).mark_used("k", clock() + timedelta(minutes=5))


def test_refuses_to_run_inside_a_transaction(clock: FixedClock) -> None:
    # A savepoint would be rolled back with the caller's transaction, forgetting the token.
    guard = DjangoReplayGuard(clock=clock)
    with pytest.raises(RuntimeError, match="ATOMIC_REQUESTS"), transaction.atomic():
        guard.mark_used("k", clock() + timedelta(minutes=5))
    assert not UsedToken.objects.exists()


def test_outer_rollback_does_not_forget_tokens(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=DjangoReplayGuard("replay", clock=issuer.clock)
    )
    with transaction.atomic():
        assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
        transaction.set_rollback(True)
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


@contextlib.contextmanager
def _manual_transaction(using: str = "default") -> Iterator[None]:
    """Autocommit off, as with AUTOCOMMIT=False; rolled back on exit."""
    transaction.set_autocommit(False, using=using)
    try:
        yield
    finally:
        transaction.rollback(using=using)
        transaction.set_autocommit(True, using=using)


def test_refuses_to_run_with_autocommit_off(clock: FixedClock) -> None:
    guard = DjangoReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    with _manual_transaction():
        UsedToken.objects.create(key="earlier-write", expires_at=expires)
        with pytest.raises(RuntimeError, match="AUTOCOMMIT"):
            guard.mark_used("k", expires)
    assert not UsedToken.objects.exists()


def test_manual_rollback_does_not_reopen_tokens(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=DjangoReplayGuard(clock=issuer.clock)
    )
    with _manual_transaction():
        UsedToken.objects.create(key="earlier-write", expires_at=issuer.clock())
        with pytest.raises(RuntimeError):
            verifier.verify(token, nonce=nonce, email=EMAIL)
    # Nothing was half-recorded: the token is accepted once, then never again.
    assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_dedicated_alias_survives_manual_rollback(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=DjangoReplayGuard("replay", clock=issuer.clock)
    )
    with _manual_transaction():
        assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_works_inside_django_test_case_transactions(clock: FixedClock) -> None:
    # django.test.TestCase wraps each test in atomic blocks it marks like this.
    outer = transaction.atomic()
    outer._from_testcase = True
    guard = DjangoReplayGuard(clock=clock)
    with outer:
        assert guard.mark_used("k", clock() + timedelta(minutes=5)) is True
        assert guard.mark_used("k", clock() + timedelta(minutes=5)) is False


@pytest.mark.anyio
async def test_async_replay_guard(clock: FixedClock) -> None:
    guard = AsyncDjangoReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert await guard.mark_used("k", expires) is True
    assert await guard.mark_used("k", expires) is False


# --- end to end ------------------------------------------------------------------------


def test_verifier_end_to_end(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer,
        audience=AUDIENCE,
        cache=DjangoCache("db"),
        replay_guard=DjangoReplayGuard(clock=issuer.clock),
    )
    assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


@pytest.mark.anyio
async def test_async_verifier_with_database_cache(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    # A synchronous DatabaseCache call on the event loop raises SynchronousOnlyOperation.
    verifier = make_async_verifier(
        issuer,
        audience=AUDIENCE,
        cache=AsyncDjangoCache("db"),
        replay_guard=AsyncDjangoReplayGuard(clock=issuer.clock),
    )
    assert (await verifier.verify(token, nonce=nonce, email=EMAIL)).email == EMAIL
    with pytest.raises(TokenError) as exc:
        await verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED
