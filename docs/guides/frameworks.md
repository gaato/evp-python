# Framework integration

The repository's `examples/` directory has a complete, tested project for each integration
below. Copy one out and replace `evp = { workspace = true }` with a normal dependency to start
your own.

## FastAPI

Create one {class}`~evp.AsyncVerifier` at startup and inject it as a dependency, so that tests can
override it. Starlette's `SessionMiddleware` keeps the session in a signed cookie, so the
example enables a replay guard.

```{literalinclude} ../../examples/fastapi/app.py
:language: python
:start-at: "@asynccontextmanager"
```

## fastapi-users

Register users through your own route. A valid token creates the user with
`is_verified=True`; otherwise the usual verification email applies. Build the `UserCreate` on
the server and pass `safe=False` only so that `is_verified` is kept.

```{literalinclude} ../../examples/fastapi_users/app.py
:language: python
:start-at: "@app.post(\"/register\""
:end-before: "@app.get(\"/me\""
```

## AuthX (passwordless login)

When the verified address *is* the login, replay protection is essential.

```{literalinclude} ../../examples/authx/app.py
:language: python
:start-at: "@app.post(\"/login\")"
```

## django-allauth

Override `DefaultAccountAdapter.is_email_verified`. A valid token makes the new `EmailAddress`
verified, so no confirmation mail is sent; anything else falls back to allauth's normal flow.

```{literalinclude} ../../examples/django_allauth/evp_allauth.py
:language: python
:start-at: "class DjangoCache:"
```

Add `{% evp_token_input %}` inside the signup form template, and set `ACCOUNT_ADAPTER`,
`ACCOUNT_FORMS["signup"]` and `EVP_ORIGIN` (see `examples/django_allauth/settings.py`).

## Other frameworks

Anything else works the same way: keep a nonce in the session, read the hidden `evt` field,
and call {meth}`evp.Verifier.verify`. Use {class}`~evp.Verifier` in synchronous code and
{class}`~evp.AsyncVerifier` under asyncio.
