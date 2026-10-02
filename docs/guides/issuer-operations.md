# Running an issuer

```{warning}
**Experimental.** `evp.issuer` follows draft-hardt-email-verification-02 and the request format
Chrome sends from version 153 on. It has not yet been tested against Chrome end to end; until it
has, treat it as a preview and expect the `chrome-153` issuance profile to change.
```

`evp.issuer` provides building blocks for issuing EVTs for email domains you control. It does
not include an HTTP server or user accounts. You plug it into your web framework and your login
system. A complete FastAPI sketch lives in
[`examples/issuer_fastapi`](https://github.com/gaato/evp-python/tree/main/examples/issuer_fastapi).

## What an issuer does

1. Publishes `_email-verification.<domain> TXT "iss=<issuer host>"` for each email domain.
2. Serves a metadata document at `https://<issuer host>/.well-known/email-verification` and a
   JWKS at its `jwks_uri`.
3. Receives a `POST` from the browser at its `issuance_endpoint`. The request is signed with an
   HTTP Message Signature (RFC 9421) using a key the browser generated and sent in
   `Signature-Key: sig=hwk;…`, and it carries the issuer's own session cookies.
4. Checks that the logged-in user controls the requested address, then returns an EVT bound to
   the browser's key.

`evp.issuer` covers steps 1–4 except "the logged-in user controls the address", which is
yours.

## Set up

Generate a signing key and keep the private JWK in your secret store:

```sh
evp issuer keygen --kid 2026-10 --out signing-key.json
```

```python
from evp.issuer import Issuer, SigningKey

issuer = Issuer(
    issuer="https://issuer.example",
    issuance_endpoint="https://accounts.issuer.example/email-verification/issuance",
    jwks_uri="https://accounts.issuer.example/email-verification/jwks",
    signer=SigningKey.from_jwk(load_secret("evp-signing-key")),
    email_domains=["example.com"],
)
```

`issuance_endpoint` must be the exact public URL. The request signature covers its authority and
path. They are compared with this configured value, never with the `Host` header, so the issuer
works behind a reverse proxy and a signature made for another server is rejected.

Print what to publish, then check it as relying parties will see it:

```sh
evp issuer documents --issuer https://issuer.example \
    --issuance-endpoint https://accounts.issuer.example/email-verification/issuance \
    --jwks-uri https://accounts.issuer.example/email-verification/jwks \
    --key signing-key.json --domain example.com
evp discover example.com --profile draft-hardt-02
```

## Handle a request

```python
from evp.issuer import IssuanceError

try:
    request = issuer.parse_request(method=method, headers=raw_header_pairs, body=body)
    if current_user(cookies) is None or not current_user(cookies).owns(request.email):
        raise IssuanceError.authentication_required()
    response = issuer.success_response(issuer.issue(request))
except IssuanceError as exc:
    response = exc.to_response()
# response.status, response.headers, response.body
```

`parse_request` checks the method, `Content-Type`, `Sec-Fetch-Dest`, `Content-Digest`, the
signature and its freshness, the JSON body and the address. It also checks that the address is
in one of `email_domains`. It does **not** authenticate the user. Pass headers as `(name,
value)` pairs where your framework offers them, so that repeated header lines are kept apart.
With an async replay guard, use `aparse_request`.

`request.email` is exactly what the browser sent. The EVT asserts that string, and relying
parties compare it with what the user typed. If your accounts treat addresses
case-insensitively, compare them that way in `owns`, but do not rewrite `request.email`.

## Preventing account enumeration

The draft requires the same response whether the address does not exist, nobody is logged in,
or someone else is. Raise `IssuanceError.authentication_required()` in every one of these cases.
Its body is fixed, and `parse_request` uses it for addresses outside `email_domains` too. Keep
the work done on each path similar as well. For example, do not query a database only when the
address looks valid.

Error responses only ever carry a fixed description per code. The detailed reason is in the
exception message for your logs.

## Keys and rotation

- Every key has a `kid`, and every EVT names the key that signed it.
- To rotate, publish the next key before using it. Pass it in `published_keys=[...]` until
  relying parties' caches (minutes) have picked it up, and then make it the `signer`.
- Keep publishing the retired public key until no token it signed can still be presented.
  Relying parties accept EVTs for about five minutes, so a day is plenty.
- Keys that never leave a KMS or HSM implement {class}`evp.issuer.Signer`: `alg`, `kid`,
  `public_jwk`, and `sign(signing_input) -> bytes` in JWS encoding (raw `r || s` for ES256).

## Replay and rate limiting

A signed request is only accepted within 300 seconds of its `created` time. Within that window,
a captured request could be resent together with the cookies. Pass `replay_guard=` to refuse a
signature the second time it is seen. Use a shared store, as described in {doc}`replay`.

Rate-limit the issuance endpoint per IP address in front of the application. `observer=`
receives an {class}`evp.issuer.IssuanceEvent` for every validated request and issued token, for
metrics and audit logs.

## Cookies

The browser sends the issuer's first-party cookies with the issuance request. Mark the session
cookie `Secure` and scope it to the issuer's origin. Confirm the `SameSite` attribute your
target browser needs before going live. The example uses `SameSite=None`.

## Not supported yet

- `private_email` / `directed_email` requests are answered with `private_email_not_supported`,
  and the metadata says `private_email_supported: false`.
- The pre-153 Chrome format (`application/x-www-form-urlencoded` with a `request_token`) is
  refused with 415.
