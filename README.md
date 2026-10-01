# evp

[![CI](https://github.com/gaato/evp-python/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gaato/evp-python/actions/workflows/ci.yml)
[![Spec drift](https://github.com/gaato/evp-python/actions/workflows/drift.yml/badge.svg)](https://github.com/gaato/evp-python/actions/workflows/drift.yml)
[![spec: draft-hardt-02](https://img.shields.io/badge/spec-draft--hardt--02-blue)](https://github.com/dickhardt/email-verification)
![status: alpha](https://img.shields.io/badge/status-alpha-orange)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/gaato/evp-python)

Relying-party verification for the **Email Verification Protocol** (EVP): the browser obtains a
token from the user's email provider proving they control an address, and your server verifies it,
with no confirmation email round-trip.

> **Status: alpha.** The protocol ([draft-hardt-email-verification], [WICG Email Verification API])
> and browser support (Chrome origin trial) are still changing. This library isolates every
> moving part in a versioned `Profile` so it can follow along.

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification

## Install

```sh
pip install "evp[all]"   # core + dnspython + httpx adapters
```

The core depends only on [joserfc]. DNS and HTTP are pluggable; `[all]` installs the default
adapters used by `Verifier.default()`.

[joserfc]: https://jose.authlib.org/

## How it works

1. Render a form with a fresh nonce stored in the user's session:

   ```html
   <input type="email" name="email" autocomplete="email">
   <input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
   ```

2. When the user picks an address, the browser fills `evt` with `<EVT>~<KB-JWT>`.
3. On submit, verify it:

   ```python
   from evp import Verifier, EVPError, generate_nonce

   verifier = Verifier.default(audience="https://example.com")  # your origin

   try:
       result = verifier.verify(form["evt"], nonce=session.pop("evp_nonce"), email=form["email"])
   except EVPError as exc:
       ...  # exc.code is a stable ErrorCode, e.g. "nonce_mismatch"; fall back to email confirmation
   else:
       result.email, result.issuer  # verified
   ```

   `AsyncVerifier` has the same API with `await verifier.verify(...)`.

Verification checks the key-binding JWT (audience, nonce, freshness, `sd_hash`, holder signature)
before doing any I/O. It then discovers the issuer from DNS (`_email-verification.<domain>`
TXT `iss=…`), fetches its metadata and JWKS (cached), and verifies the issuer's signature. Only
hosts derived from DNS are ever contacted, never hosts named in the token.

## Operations

### Replay protection

The nonce on the form is the first line of defence: store it server-side and consume it once.
If your sessions live client-side, as with Starlette's signed-cookie `SessionMiddleware`, an
attacker who captured a token can resend it together with the old cookie. A replay guard
remembers every accepted token until it would expire anyway:

```python
from evp import InMemoryReplayGuard

verifier = AsyncVerifier.default(audience="https://example.com", replay_guard=InMemoryReplayGuard())
```

`InMemoryReplayGuard` only works within one process. With several workers, implement
`mark_used(key, expires_at) -> bool` as an atomic "add if absent" on a shared store:

```python
class RedisReplayGuard:
    def __init__(self, redis):
        self.redis = redis

    def mark_used(self, key, expires_at):
        return bool(
            self.redis.set(f"evp:used:{key}", 1, nx=True, pxat=int(expires_at.timestamp() * 1000))
        )
```

Replays are rejected with `ErrorCode.TOKEN_REPLAYED`. The guard is only consulted after every
other check has passed, so rejected tokens never fill the store.

### Logging and metrics

Pass `observer=` to receive one `VerificationEvent` per `verify` call. It carries `ok`, `code`,
`issuer`, the claimed `email_domain`, `profile` and `duration`. `LoggingObserver()` logs one line
per verification to the `evp` logger. Anything else, such as a Prometheus counter, is a small
callable:

```python
def observe(event: VerificationEvent) -> None:
    VERIFICATIONS.labels(event.code or "ok", event.issuer or "").inc()


verifier = Verifier.default(audience="https://example.com", observer=observe)
```

Exceptions raised by an observer are logged and ignored, so monitoring can never break sign-in.

## Design

| Module | Role |
|---|---|
| `evp.core` | Sans-I/O verification: pure checks plus a generator that yields `ResolveTxt` / `FetchJson` effects |
| `evp.verifier` | `Verifier` / `AsyncVerifier`, thin drivers that run the core against injected ports |
| `evp.ports` | `TxtResolver`, `JsonFetcher` (sync and async) and `Clock` protocols |
| `evp.profile` | Spec knobs (algorithms, `typ`, `kid` rules, `iss` format, email comparison, freshness) |
| `evp.testing` | `FakeIssuer`, `FakeBrowser`, in-memory DNS/HTTP, `make_verifier()` |
| `evp.adapters` | dnspython / httpx implementations of the ports |

### Profiles

- `Profile.compat_2026_10()` is the default. It accepts what Chrome and Gmail ship today
  (`EdDSA`, keys without `kid`, host-form `iss`) as well as the -02 draft.
- `Profile.draft_hardt_02()` is a strict reading of the current draft.

Customise either with `profile.replace(max_token_age=timedelta(minutes=2))`. New presets are added
as the protocol evolves; existing ones are not changed incompatibly.

### Testing your application

```python
from evp.testing import FakeBrowser, FakeIssuer, make_verifier

issuer, browser = FakeIssuer(), FakeBrowser()
verifier = make_verifier(issuer, audience="https://example.com")
token = browser.present(
    issuer.issue("alice@example.com", browser.public_jwk),
    audience="https://example.com",
    nonce=nonce,
)
```

`FakeIssuer.gmail_like()` reproduces Gmail's current deviations from the draft.

## Compatibility policy

- Before 1.0, minor releases may contain breaking changes; they are listed in the
  [changelog](CHANGELOG.md). From 1.0 on, the project follows [Semantic Versioning].
- Profile presets are only ever added. An existing preset never changes behaviour; following
  the protocol means adding a new one.
- Switching `DEFAULT_PROFILE` to a newer preset is a breaking change (a major release after 1.0).
- `ErrorCode` values are stable. New codes may be added in minor releases, so handle unknown codes.
- Supported Pythons: 3.11 and newer. A version is dropped only after its upstream end of life.

Libraries that support older Pythons can still offer EVP as an optional extra by gating it with
an environment marker:

```toml
[project.optional-dependencies]
evp = ["evp>=1,<2; python_version >= '3.11'"]
```

[Semantic Versioning]: https://semver.org/

## Examples

Each example is a standalone project and a member of the uv workspace, with its own dependencies
and tests. Copy one out and replace `evp = { workspace = true }` with a normal dependency to start
your own.

- [`examples/fastapi/`](examples/fastapi/app.py) is a FastAPI app with session nonces. Its tests
  override the verifier dependency with fakes.
- [`examples/django_allauth/`](examples/django_allauth/evp_allauth.py) shows a django-allauth
  adapter. It marks the new `EmailAddress` verified when the token checks out, and falls back to
  normal email confirmation otherwise.

```sh
cd examples/fastapi && uv run uvicorn app:app --port 8000
cd examples/django_allauth && uv run manage.py migrate && uv run manage.py runserver
```

## Development

```sh
uv sync --all-packages --all-extras
uv run pytest              # library: unit + end-to-end with fakes
uv run pytest -m network   # live checks against deployed issuers (Gmail)
uv run --directory examples/fastapi pytest
uv run --directory examples/django_allauth pytest
uv run ruff check && uv run ruff format --check && uv run ty check
```

The library supports Python 3.11, so type aliases use `TypeAlias` instead of `type` statements
(marked `TODO(py3.12)`). When 3.11 support is dropped, raise `requires-python` and run
`uv run ruff check --select UP040 --fix --unsafe-fixes` to convert them back
(the fix is "unsafe" only because `type` aliases are evaluated lazily).

CI also runs the network checks weekly (`.github/workflows/drift.yml`) and opens a `spec-drift`
issue when the deployed ecosystem diverges from the default profile.

## License

[MIT](LICENSE)
