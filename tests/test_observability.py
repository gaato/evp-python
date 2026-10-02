from __future__ import annotations

import logging
from datetime import timedelta

import pytest

from pyevp import ErrorCode, EVPError, LoggingObserver, VerificationEvent
from pyevp.observability import claimed_email_domain
from pyevp.testing import FakeIssuer, make_async_verifier, make_verifier

from .conftest import AUDIENCE


def test_success_event(issuer: FakeIssuer, token: str, nonce: str) -> None:
    events: list[VerificationEvent] = []
    make_verifier(issuer, audience=AUDIENCE, observer=events.append).verify(token, nonce=nonce)
    [event] = events
    assert event.ok
    assert event.code is None
    assert event.issuer == "https://issuer.example"
    assert event.email_domain == "example.com"
    assert event.profile == "compat-2026-10"
    assert event.duration >= timedelta(0)


def test_failure_event(issuer: FakeIssuer, token: str) -> None:
    events: list[VerificationEvent] = []
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=events.append)
    with pytest.raises(EVPError):
        verifier.verify(token, nonce="wrong")
    [event] = events
    assert not event.ok
    assert event.code is ErrorCode.NONCE_MISMATCH
    assert event.issuer is None
    assert event.email_domain == "example.com"


@pytest.mark.anyio
async def test_async_events(issuer: FakeIssuer, token: str, nonce: str) -> None:
    events: list[VerificationEvent] = []
    verifier = make_async_verifier(issuer, audience=AUDIENCE, observer=events.append)
    await verifier.verify(token, nonce=nonce)
    with pytest.raises(EVPError):
        await verifier.verify("garbage", nonce=nonce)
    assert [(e.ok, e.code, e.email_domain) for e in events] == [
        (True, None, "example.com"),
        (False, ErrorCode.MALFORMED_TOKEN, None),
    ]


def test_observer_errors_do_not_break_verification(
    issuer: FakeIssuer, token: str, nonce: str, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(event: VerificationEvent) -> None:
        raise RuntimeError("metrics backend down")

    verifier = make_verifier(issuer, audience=AUDIENCE, observer=broken)
    with caplog.at_level(logging.ERROR, logger="pyevp"):
        assert verifier.verify(token, nonce=nonce).email == "alice@example.com"
    assert "observer raised" in caplog.text


def test_logging_observer(
    issuer: FakeIssuer, token: str, nonce: str, caplog: pytest.LogCaptureFixture
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=LoggingObserver())
    with caplog.at_level(logging.INFO, logger="pyevp"):
        verifier.verify(token, nonce=nonce)
    assert "EVP verification succeeded" in caplog.text
    assert "issuer=https://issuer.example" in caplog.text


@pytest.mark.parametrize("value", ["", "a.b.c~d.e.f", "not a token"])
def test_claimed_email_domain_is_best_effort(value: str) -> None:
    assert claimed_email_domain(value) is None
