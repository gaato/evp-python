"""Drivers that run :func:`evp.core.verification_steps` against real ports."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Self
from urllib.parse import urlsplit

from evp.cache import Cache, CacheEntry, InMemoryCache
from evp.core import Effect, FetchJson, ResolveTxt, Steps, verification_steps
from evp.errors import DiscoveryError, ErrorCode, EVPError
from evp.ports import (
    AsyncJsonFetcher,
    AsyncTxtResolver,
    Clock,
    JsonFetcher,
    TxtResolver,
    system_clock,
)
from evp.profile import DEFAULT_PROFILE, Profile
from evp.types import VerifiedEmail

__all__ = ["AsyncVerifier", "Verifier"]


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
    ) -> None:
        self.audience = _validate_origin(audience)
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
        )

    def _cached(self, effect: FetchJson) -> CacheEntry | None:
        entry = self._cache.get(effect.url)
        if entry is None:
            return None
        if effect.refresh and self._clock() - entry.stored_at >= self._min_refresh_interval:
            return None
        return entry

    def _store(self, effect: FetchJson, value: object) -> None:
        self._cache.set(effect.url, CacheEntry(value, self._clock()), self._cache_ttl)


def _unreachable(effect: Effect, exc: Exception) -> DiscoveryError:
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
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
        )
        self._resolver = resolver
        self._fetcher = fetcher

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install evp[all]``)."""
        from evp.adapters.dnspython import DnsPythonResolver  # noqa: PLC0415
        from evp.adapters.httpx import HttpxFetcher  # noqa: PLC0415

        return cls(
            audience=audience, resolver=DnsPythonResolver(), fetcher=HttpxFetcher(), **kwargs
        )

    def verify(
        self, token: str, *, nonce: str, email: str | None = None, audience: str | None = None
    ) -> VerifiedEmail:
        """Verify a presentation token.

        :param nonce: the nonce this server put on the form (from the session).
        :param email: the address the user submitted; checked against the token.
        :param audience: override the configured origin (multi-host deployments).
        :raises evp.EVPError: on any failure; see ``.code``.
        """
        steps = self._steps(token, nonce, email, audience)
        try:
            effect = next(steps)
            while True:
                effect = steps.send(self._perform(effect))
        except StopIteration as stop:
            return stop.value
        finally:
            steps.close()

    def _perform(self, effect: Effect) -> object:
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
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
        )
        self._resolver = resolver
        self._fetcher = fetcher

    @classmethod
    def default(cls, *, audience: str, **kwargs: Any) -> Self:
        """Build a verifier using dnspython and httpx (``pip install evp[all]``)."""
        from evp.adapters.dnspython import AsyncDnsPythonResolver  # noqa: PLC0415
        from evp.adapters.httpx import AsyncHttpxFetcher  # noqa: PLC0415

        return cls(
            audience=audience,
            resolver=AsyncDnsPythonResolver(),
            fetcher=AsyncHttpxFetcher(),
            **kwargs,
        )

    async def verify(
        self, token: str, *, nonce: str, email: str | None = None, audience: str | None = None
    ) -> VerifiedEmail:
        """Async counterpart of :meth:`Verifier.verify`."""
        steps = self._steps(token, nonce, email, audience)
        try:
            effect = next(steps)
            while True:
                effect = steps.send(await self._perform(effect))
        except StopIteration as stop:
            return stop.value
        finally:
            steps.close()

    async def _perform(self, effect: Effect) -> object:
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
