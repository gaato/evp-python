"""Drivers that run :func:`pyevp.core.verification_steps` against real ports."""

from __future__ import annotations

import inspect
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Self
from urllib.parse import urlsplit

from pyevp.cache import AsyncCache, Cache, CacheEntry, InMemoryCache
from pyevp.core import Effect, FetchJson, MarkUsed, ResolveTxt, Steps, verification_steps
from pyevp.errors import DiscoveryError, ErrorCode, EVPError, TokenError
from pyevp.observability import Observer, VerificationEvent, claimed_email_domain
from pyevp.ports import (
    AsyncJsonFetcher,
    AsyncTxtResolver,
    Clock,
    JsonFetcher,
    TxtResolver,
    system_clock,
)
from pyevp.profile import DEFAULT_PROFILE, Profile
from pyevp.replay import AsyncReplayGuard, ReplayGuard
from pyevp.types import VerifiedEmail

__all__ = ["AsyncVerifier", "Verifier"]

logger = logging.getLogger("pyevp")


def _validate_origin(origin: str) -> str:
    parts = urlsplit(origin)
    if (
        parts.scheme not in ("https", "http")
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
    ):
        raise ValueError(
            f"audience must be a serialized origin like 'https://rp.example': {origin!r}"
        )
    return origin


class _Base:
    def __init__(
        self,
        *,
        audience: str,
        profile: Profile,
        clock: Clock,
        cache_ttl: timedelta,
        min_refresh_interval: timedelta,
        replay_protection: bool,
        observer: Observer | None,
    ) -> None:
        self.audience = _validate_origin(audience)
        self._replay_protection = replay_protection
        self._observer = observer
        self.profile = profile
        self._clock = clock
        self._cache_ttl = cache_ttl
        self._min_refresh_interval = min_refresh_interval
        self._refresh_lock = threading.Lock()
        self._refresh_attempts: dict[str, datetime] = {}

    def _steps(self, token: str, nonce: str, email: str | None, audience: str | None) -> Steps:
        return verification_steps(
            token,
            audience=_validate_origin(audience) if audience is not None else self.audience,
            nonce=nonce,
            now=self._clock(),
            profile=self.profile,
            email=email,
            replay_protection=self._replay_protection,
        )

    def _notify(
        self, token: str, result: VerifiedEmail | None, error: Exception | None, started: float
    ) -> None:
        if self._observer is None:
            return
        try:
            self._observer(
                VerificationEvent(
                    ok=result is not None,
                    code=error.code if isinstance(error, EVPError) else None,
                    issuer=result.issuer if result is not None else None,
                    email_domain=claimed_email_domain(token),
                    profile=self.profile.name,
                    duration=timedelta(seconds=time.perf_counter() - started),
                )
            )
        except Exception:
            logger.exception("EVP observer raised; ignoring")

    def _reuse(self, effect: FetchJson, entry: CacheEntry | None) -> CacheEntry | None:
        """Decide whether the cached ``entry`` for ``effect.url`` answers the fetch."""
        if entry is None or not effect.refresh:
            return entry
        # A forced refresh is reserved before fetching, so failed fetches and concurrent
        # verifications count against min_refresh_interval too.  Within it, keep the cached
        # value.
        now = self._clock()
        with self._refresh_lock:
            last = max(entry.stored_at, self._refresh_attempts.get(effect.url, entry.stored_at))
            if now - last < self._min_refresh_interval:
                return entry
            self._refresh_attempts = {
                url: at
                for url, at in self._refresh_attempts.items()
                if now - at < self._min_refresh_interval
            }
            self._refresh_attempts[effect.url] = now
        return None

    def _check_marked(self, effect: MarkUsed, marked: bool) -> bool:
        # Freshness was judged when verification started.  If the token expired since,
        # the record just written may already be gone, and a replay would find nothing.
        if marked and self._clock() >= effect.expires_at:
            raise TokenError(ErrorCode.TOKEN_EXPIRED, "token expired during verification")
        return marked

    def _entry(self, value: object) -> CacheEntry:
        return CacheEntry(value, self._clock())


def _unreachable(effect: ResolveTxt | FetchJson, exc: Exception) -> DiscoveryError:
    target = effect.name if isinstance(effect, ResolveTxt) else effect.url
    err = DiscoveryError(ErrorCode.ISSUER_UNREACHABLE, f"lookup of {target} failed: {exc}")
    err.__cause__ = exc
    return err


class Verifier(_Base):
    """Synchronous verifier (Django, Flask, scripts).

    Thread-safe as long as the injected ports and cache are.
    """

    def __init__(
        self,
        *,
        audience: str,
        resolver: TxtResolver,
        fetcher: JsonFetcher,
        profile: Profile = DEFAULT_PROFILE,
        cache: Cache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard
        self._cache = cache if cache is not None else InMemoryCache(clock=clock)

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install pyevp[all]``).

        Any constructor argument, including ``resolver`` / ``fetcher``, can be overridden.
        """
        if "resolver" not in kwargs:
            from pyevp.adapters.dnspython import DnsPythonResolver  # noqa: PLC0415

            kwargs["resolver"] = DnsPythonResolver()
        if "fetcher" not in kwargs:
            from pyevp.adapters.httpx import HttpxFetcher  # noqa: PLC0415

            kwargs["fetcher"] = HttpxFetcher()
        return cls(audience=audience, **kwargs)

    def verify(
        self, token: str, *, nonce: str, email: str | None, audience: str | None = None
    ) -> VerifiedEmail:
        """Verify a presentation token.

        :param nonce: the nonce this server put on the form (from the session).
        :param email: the address the user submitted; checked against the token.  Pass
            ``None`` explicitly to skip the check and use the asserted address instead.
        :param audience: override the configured origin (multi-host deployments).
        :raises pyevp.EVPError: on any failure; see ``.code``.
        """
        started, result, error = time.perf_counter(), None, None
        try:
            result = self._run(self._steps(token, nonce, email, audience))
            return result
        except Exception as exc:
            error = exc
            raise
        finally:
            self._notify(token, result, error, started)

    def _run(self, steps: Steps) -> VerifiedEmail:
        try:
            effect = next(steps)
            while True:
                effect = steps.send(self._perform(effect))
        except StopIteration as stop:
            return stop.value
        finally:
            steps.close()

    def _perform(self, effect: Effect) -> object:
        if isinstance(effect, MarkUsed):
            # Failures of the application's own store propagate unchanged.
            assert self._replay_guard is not None
            return self._check_marked(
                effect, self._replay_guard.mark_used(effect.key, effect.expires_at)
            )
        try:
            match effect:
                case ResolveTxt(name=name):
                    return self._resolver.resolve_txt(name)
                case FetchJson(url=url):
                    if (entry := self._reuse(effect, self._cache.get(url))) is not None:
                        return entry.value
                    value = self._fetcher.fetch_json(url)
                    self._cache.set(url, self._entry(value), self._cache_ttl)
                    return value
        except EVPError:
            raise
        except Exception as exc:
            raise _unreachable(effect, exc) from exc


class AsyncVerifier(_Base):
    """Asynchronous verifier (FastAPI, Starlette, Django async views)."""

    def __init__(
        self,
        *,
        audience: str,
        resolver: AsyncTxtResolver,
        fetcher: AsyncJsonFetcher,
        profile: Profile = DEFAULT_PROFILE,
        cache: Cache | AsyncCache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard
        self._cache = cache if cache is not None else InMemoryCache(clock=clock)

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install pyevp[all]``).

        Any constructor argument, including ``resolver`` / ``fetcher``, can be overridden.
        """
        if "resolver" not in kwargs:
            from pyevp.adapters.dnspython import AsyncDnsPythonResolver  # noqa: PLC0415

            kwargs["resolver"] = AsyncDnsPythonResolver()
        if "fetcher" not in kwargs:
            from pyevp.adapters.httpx import AsyncHttpxFetcher  # noqa: PLC0415

            kwargs["fetcher"] = AsyncHttpxFetcher()
        return cls(audience=audience, **kwargs)

    async def verify(
        self, token: str, *, nonce: str, email: str | None, audience: str | None = None
    ) -> VerifiedEmail:
        """Async counterpart of :meth:`Verifier.verify`."""
        started, result, error = time.perf_counter(), None, None
        try:
            result = await self._run(self._steps(token, nonce, email, audience))
            return result
        except Exception as exc:
            error = exc
            raise
        finally:
            self._notify(token, result, error, started)

    async def _run(self, steps: Steps) -> VerifiedEmail:
        try:
            effect = next(steps)
            while True:
                effect = steps.send(await self._perform(effect))
        except StopIteration as stop:
            return stop.value
        finally:
            steps.close()

    async def _perform(self, effect: Effect) -> object:
        if isinstance(effect, MarkUsed):
            assert self._replay_guard is not None
            marked = self._replay_guard.mark_used(effect.key, effect.expires_at)
            return self._check_marked(
                effect, await marked if inspect.isawaitable(marked) else marked
            )
        try:
            match effect:
                case ResolveTxt(name=name):
                    return await self._resolver.resolve_txt(name)
                case FetchJson(url=url):
                    cached = self._cache.get(url)
                    if inspect.isawaitable(cached):
                        cached = await cached
                    if (entry := self._reuse(effect, cached)) is not None:
                        return entry.value
                    value = await self._fetcher.fetch_json(url)
                    stored = self._cache.set(url, self._entry(value), self._cache_ttl)
                    if inspect.isawaitable(stored):
                        await stored
                    return value
        except EVPError:
            raise
        except Exception as exc:
            raise _unreachable(effect, exc) from exc
