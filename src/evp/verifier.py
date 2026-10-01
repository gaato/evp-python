"""Drivers that run :func:`evp.core.verification_steps` against real ports."""

from __future__ import annotations

import inspect
import logging
import time
from datetime import timedelta
from typing import Any, Self
from urllib.parse import urlsplit

from evp.cache import Cache, CacheEntry, InMemoryCache
from evp.core import Effect, FetchJson, MarkUsed, ResolveTxt, Steps, verification_steps
from evp.errors import DiscoveryError, ErrorCode, EVPError
from evp.observability import Observer, VerificationEvent, claimed_email_domain
from evp.ports import (
    AsyncJsonFetcher,
    AsyncTxtResolver,
    Clock,
    JsonFetcher,
    TxtResolver,
    system_clock,
)
from evp.profile import DEFAULT_PROFILE, Profile
from evp.replay import AsyncReplayGuard, ReplayGuard
from evp.types import VerifiedEmail

__all__ = ["AsyncVerifier", "Verifier"]

logger = logging.getLogger("evp")


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
        cache: Cache | None,
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
        self._cache: Cache = cache if cache is not None else InMemoryCache(clock=clock)
        self._cache_ttl = cache_ttl
        self._min_refresh_interval = min_refresh_interval

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

    def _cached(self, effect: FetchJson) -> CacheEntry | None:
        entry = self._cache.get(effect.url)
        if entry is None:
            return None
        if effect.refresh and self._clock() - entry.stored_at >= self._min_refresh_interval:
            return None
        return entry

    def _store(self, effect: FetchJson, value: object) -> None:
        self._cache.set(effect.url, CacheEntry(value, self._clock()), self._cache_ttl)


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
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install evp[all]``).

        Any constructor argument, including ``resolver`` / ``fetcher``, can be overridden.
        """
        if "resolver" not in kwargs:
            from evp.adapters.dnspython import DnsPythonResolver  # noqa: PLC0415

            kwargs["resolver"] = DnsPythonResolver()
        if "fetcher" not in kwargs:
            from evp.adapters.httpx import HttpxFetcher  # noqa: PLC0415

            kwargs["fetcher"] = HttpxFetcher()
        return cls(audience=audience, **kwargs)

    def verify(
        self, token: str, *, nonce: str, email: str | None = None, audience: str | None = None
    ) -> VerifiedEmail:
        """Verify a presentation token.

        :param nonce: the nonce this server put on the form (from the session).
        :param email: the address the user submitted; checked against the token.
        :param audience: override the configured origin (multi-host deployments).
        :raises evp.EVPError: on any failure; see ``.code``.
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
            return self._replay_guard.mark_used(effect.key, effect.expires_at)
        try:
            match effect:
                case ResolveTxt(name=name):
                    return self._resolver.resolve_txt(name)
                case FetchJson():
                    if (entry := self._cached(effect)) is not None:
                        return entry.value
                    value = self._fetcher.fetch_json(effect.url)
                    self._store(effect, value)
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
        cache: Cache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install evp[all]``).

        Any constructor argument, including ``resolver`` / ``fetcher``, can be overridden.
        """
        if "resolver" not in kwargs:
            from evp.adapters.dnspython import AsyncDnsPythonResolver  # noqa: PLC0415

            kwargs["resolver"] = AsyncDnsPythonResolver()
        if "fetcher" not in kwargs:
            from evp.adapters.httpx import AsyncHttpxFetcher  # noqa: PLC0415

            kwargs["fetcher"] = AsyncHttpxFetcher()
        return cls(audience=audience, **kwargs)

    async def verify(
        self, token: str, *, nonce: str, email: str | None = None, audience: str | None = None
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
            return await marked if inspect.isawaitable(marked) else marked
        try:
            match effect:
                case ResolveTxt(name=name):
                    return await self._resolver.resolve_txt(name)
                case FetchJson():
                    if (entry := self._cached(effect)) is not None:
                        return entry.value
                    value = await self._fetcher.fetch_json(effect.url)
                    self._store(effect, value)
                    return value
        except EVPError:
            raise
        except Exception as exc:
            raise _unreachable(effect, exc) from exc
