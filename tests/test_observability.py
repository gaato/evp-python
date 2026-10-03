from __future__ import annotations

import logging
from datetime import timedelta

import pytest

from pyevp import ErrorCode, EVPError, LoggingObserver, VerificationEvent
from pyevp.observability import claimed_email_domain
from pyevp.testing import FakeBrowser, FakeIssuer, make_async_verifier, make_verifier

from .conftest import AUDIENCE


def test_success_event(issuer: FakeIssuer, token: str, nonce: str) -> None:
    events: list[VerificationEvent] = []
    make_verifier(issuer, audience=AUDIENCE, observer=events.append).verify(
        token, nonce=nonce, email=None
    )
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
        verifier.verify(token, nonce="wrong", email=None)
    [event] = events
    assert not event.ok
    assert event.code is ErrorCode.NONCE_MISMATCH
    assert event.issuer is None
    assert event.email_domain == "example.com"


@pytest.mark.anyio
async def test_async_events(issuer: FakeIssuer, token: str, nonce: str) -> None:
    events: list[VerificationEvent] = []
    verifier = make_async_verifier(issuer, audience=AUDIENCE, observer=events.append)
    await verifier.verify(token, nonce=nonce, email=None)
    with pytest.raises(EVPError):
        await verifier.verify("garbage", nonce=nonce, email=None)
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
        assert verifier.verify(token, nonce=nonce, email=None).email == "alice@example.com"
    assert "observer raised" in caplog.text


def test_logging_observer(
    issuer: FakeIssuer, token: str, nonce: str, caplog: pytest.LogCaptureFixture
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=LoggingObserver())
    with caplog.at_level(logging.INFO, logger="pyevp"):
        verifier.verify(token, nonce=nonce, email=None)
    assert "EVP verification succeeded" in caplog.text
    assert "issuer=https://issuer.example" in caplog.text


@pytest.mark.parametrize("value", ["", "a.b.c~d.e.f", "not a token"])
def test_claimed_email_domain_is_best_effort(value: str) -> None:
    assert claimed_email_domain(value) is None


FORGED = "a@example.com\nFORGED_EVENT ok=true"


@pytest.mark.parametrize("email", [FORGED, "a@exa mple.com", "a@example.com\u2028x"])
def test_claimed_email_domain_is_a_dns_name(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, email: str
) -> None:
    token = browser.present(issuer.issue(email, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    assert claimed_email_domain(token) is None


def test_forged_domain_does_not_add_log_lines(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, caplog: pytest.LogCaptureFixture
) -> None:
    token = browser.present(
        issuer.issue(FORGED, browser.public_jwk), audience=AUDIENCE, nonce=nonce
    )
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=LoggingObserver())
    with caplog.at_level(logging.INFO, logger="pyevp"), pytest.raises(EVPError):
        verifier.verify(token, nonce=nonce, email=None)
    [record] = caplog.records
    assert "\n" not in record.getMessage()
    assert "domain=None" in record.getMessage()


def test_logging_observer_escapes_unprintable_fields(caplog: pytest.LogCaptureFixture) -> None:
    event = VerificationEvent(False, None, None, "x\nFORGED", "p\r", timedelta(0))
    with caplog.at_level(logging.INFO, logger="pyevp"):
        LoggingObserver()(event)
    [record] = caplog.records
    assert record.getMessage().count("\n") == 0
    assert "domain='x\\nFORGED'" in record.getMessage()
