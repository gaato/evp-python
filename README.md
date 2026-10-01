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

CI also runs the network checks weekly (`.github/workflows/drift.yml`) and opens a `spec-drift`
issue when the deployed ecosystem diverges from the default profile.

## License

[MIT](LICENSE)
