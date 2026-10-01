from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from evp import (
    AsyncReplayGuard,
    ErrorCode,
    EVPError,
    InMemoryReplayGuard,
    ReplayGuard,
    Verifier,
)
from evp.testing import FakeBrowser, FakeIssuer, FixedClock, make_async_verifier, make_verifier

from .conftest import AUDIENCE, EMAIL


class AsyncGuard:
    def __init__(self, clock: FixedClock) -> None:
        self.inner = InMemoryReplayGuard(clock=clock)

    async def mark_used(self, key: str, expires_at: datetime) -> bool:
        return self.inner.mark_used(key, expires_at)


class BrokenGuard:
    def mark_used(self, key: str, expires_at: datetime) -> bool:
        raise ConnectionError("store down")


def test_replay_rejected(issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=InMemoryReplayGuard(clock=clock)
    )
    assert verifier.verify(token, nonce=nonce).email == EMAIL
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_without_guard_replay_is_not_detected(verifier: Verifier, token: str, nonce: str) -> None:
    verifier.verify(token, nonce=nonce)
    verifier.verify(token, nonce=nonce)


def test_rejected_tokens_are_not_remembered(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    guard = InMemoryReplayGuard(clock=clock)
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=guard)
    with pytest.raises(EVPError):
        verifier.verify(token, nonce="wrong")
    assert verifier.verify(token, nonce=nonce).email == EMAIL


@pytest.mark.anyio
@pytest.mark.parametrize("guard_factory", [lambda c: InMemoryReplayGuard(clock=c), AsyncGuard])
async def test_async_replay(
    issuer: FakeIssuer,
    token: str,
    nonce: str,
    clock: FixedClock,
    guard_factory: Callable[[FixedClock], ReplayGuard | AsyncReplayGuard],
) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE, replay_guard=guard_factory(clock))
    await verifier.verify(token, nonce=nonce)
    with pytest.raises(EVPError) as exc:
        await verifier.verify(token, nonce=nonce)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_guard_failures_propagate_unchanged(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=BrokenGuard())
    with pytest.raises(ConnectionError):
        verifier.verify(token, nonce=nonce)


def test_expiry_matches_token_lifetime(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    seen: list[datetime] = []

    class Recorder:
        def mark_used(self, key: str, expires_at: datetime) -> bool:
            seen.append(expires_at)
            return True

    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=Recorder())
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    verifier.verify(token, nonce=nonce)
    profile = verifier.profile
    assert seen == [clock() + profile.max_token_age + profile.clock_skew]


def test_in_memory_guard_forgets_expired_keys(clock: FixedClock) -> None:
    guard = InMemoryReplayGuard(clock=clock)
    assert guard.mark_used("k", clock() + timedelta(minutes=1))
    assert not guard.mark_used("k", clock() + timedelta(minutes=1))
    clock.advance(timedelta(minutes=2))
    assert guard.mark_used("k", clock() + timedelta(minutes=1))
