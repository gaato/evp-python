# Quickstart

## Install

```sh
pip install "pyevp[all]"
```

`[all]` adds dnspython and httpx, which `Verifier.default()` uses for DNS and HTTPS. See
{doc}`guides/transport` for httpx2, DNS over HTTPS and other options.

## 1. Put a nonce on the form

Generate a fresh nonce per form, keep it in the user's session, and add two inputs: the email
field the user fills in, and a hidden field the browser fills with the token.

```python
from pyevp import generate_nonce

nonce = generate_nonce()
session["evp_nonce"] = nonce
```

```html
<input type="email" name="email" autocomplete="email">
<input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
```

The `nonce` must be a content attribute in the HTML. Frameworks that set it as a DOM property
are not picked up by the browser.

Chrome writes the token into the hidden field only when the form is submitted. Before that,
page scripts read an empty value, so check the token on the server, not in client-side
validation.

## 2. Verify on submit

Create the verifier once, with your origin as the audience:

```python
from pyevp import EVPError, Verifier

verifier = Verifier.default(audience="https://example.com")
```

Then, in the form handler:

```python
nonce = session.pop("evp_nonce", None)  # single use
token = form.get("evt")
if token and nonce:
    try:
        result = verifier.verify(token, nonce=nonce, email=form["email"])
    except EVPError as exc:
        log.info("EVP rejected: %s", exc.code)  # fall back to a confirmation email
    else:
        mark_verified(result.email)  # result.issuer, result.claims, ...
```

`AsyncVerifier` has the same API: `await verifier.verify(...)`.

## 3. Handle failures

Every failure raises a subclass of {class}`pyevp.EVPError` with a stable {class}`pyevp.ErrorCode`:

| Exception | Meaning | Typical codes |
|---|---|---|
| {class}`~pyevp.TokenError` | Malformed, stale, mis-bound or badly signed token | `nonce_mismatch`, `token_expired`, `token_replayed` |
| {class}`~pyevp.DiscoveryError` | The issuer could not be discovered or used | `issuer_mismatch`, `issuer_unreachable` |
| {class}`~pyevp.PolicyError` | Authentic, but not acceptable | `email_mismatch`, `email_not_verified` |

`issuer_unreachable` may be transient. Everything else means "do not trust this token". EVP is a
progressive enhancement: when there is no token, or it is rejected, fall back to your existing
verification flow.

```{important}
If your sessions are stored client-side, for example with Starlette's `SessionMiddleware`,
popping the nonce does not make it single-use. Enable {doc}`replay protection <guides/replay>`.
```
