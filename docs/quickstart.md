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

(handle-failures)=

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

Whatever the code, the safe default is the fallback. The codes tell you whether the user can
simply try again and whether something on your side needs attention:

| Code | Usually means | What to do |
|---|---|---|
| `nonce_mismatch` | The session expired or the form was submitted twice | Render a fresh form, or fall back |
| `token_expired` | The user took longer than `max_token_age` to submit | Render a fresh form, or fall back |
| `token_not_yet_valid` | Clock skew between the browser and your server | Fall back; if frequent, check your server clock |
| `email_mismatch` | The email field was edited after picking an address | Ask the user to pick the address again |
| `audience_mismatch` | `audience` differs from the page's origin | Fix your configuration (proxies, hostnames) |
| `issuer_unreachable` | DNS or HTTPS to the issuer failed; may be transient | Fall back; monitor the rate |
| `issuer_discovery_failed` | The email domain has no usable `_email-verification` record | Fall back |
| `metadata_invalid`, `key_not_found` | The issuer's metadata or keys are broken or rotating | Fall back; `pyevp discover <domain>` shows details |
| `unsupported_alg`, `bad_type` | The issuer signs in a way your profile does not accept | Fall back; compare with `pyevp discover` |
| `email_not_verified` | The issuer does not vouch for the address | Fall back |
| `token_replayed` | The token was already accepted once | Reject; this is a resubmission or an attack |
| `malformed_token` | The field did not contain an EVP token | Fall back; if frequent, check the form markup |
| `issuer_mismatch`, `evt_signature_invalid`, `kb_signature_invalid`, `sd_hash_mismatch` | Forged or tampered token | Fall back and log; do not trust the address |

Codes may be added in minor releases, so treat unknown codes as "fall back".

```{important}
If your sessions are stored client-side, for example with Starlette's `SessionMiddleware`,
popping the nonce does not make it single-use. Enable {doc}`replay protection <guides/replay>`.
```
