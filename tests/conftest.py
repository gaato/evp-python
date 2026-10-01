from __future__ import annotations

import importlib.util

import pytest

from evp import Verifier, generate_nonce
from evp.testing import FakeBrowser, FakeIssuer, FixedClock, make_verifier

AUDIENCE = "https://rp.example"
EMAIL = "alice@example.com"

# Tests for optional adapters are skipped when the extras are not installed.
_REQUIRES = {
    "test_adapters.py": ("httpx",),
    "test_network.py": ("httpx", "dns"),
}
collect_ignore = [
    name
    for name, modules in _REQUIRES.items()
    if any(importlib.util.find_spec(m) is None for m in modules)
]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def issuer(clock: FixedClock) -> FakeIssuer:
    return FakeIssuer(clock=clock)


@pytest.fixture
def browser(clock: FixedClock) -> FakeBrowser:
    return FakeBrowser(clock=clock)


@pytest.fixture
def nonce() -> str:
    return generate_nonce()


@pytest.fixture
def verifier(issuer: FakeIssuer) -> Verifier:
    return make_verifier(issuer, audience=AUDIENCE)


@pytest.fixture
def token(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> str:
    return browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
