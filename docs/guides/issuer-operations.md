# Running an issuer

```{warning}
**Experimental.** `pyevp.issuer` follows draft-hardt-email-verification-02 and the request format
Chrome sends from version 153 on. It was tested end to end with Chrome 154.0.8037.92 (the
`#email-verification-protocol` flag, or `--enable-features=EmailVerificationProtocol`), and a
nightly job runs the example issuer against current Chrome stable and beta
([`interop/`](https://github.com/gaato/pyevp/tree/main/interop)). Chrome and the draft are
still changing, so expect the `chrome-153` issuance profile to follow them.
```

`pyevp.issuer` provides building blocks for issuing EVTs for email domains you control. It does
not include an HTTP server or user accounts. You plug it into your web framework and your login
system. A complete FastAPI sketch lives in
[`examples/issuer_fastapi`](https://github.com/gaato/pyevp/tree/main/examples/issuer_fastapi).

## What an issuer does

1. Publishes `_email-verification.<domain> TXT "iss=<issuer host>"` for each email domain.
2. Serves a metadata document at `https://<issuer host>/.well-known/email-verification` and a
   JWKS at its `jwks_uri`.
3. Receives a `POST` from the browser at its `issuance_endpoint`. The request is signed with an
   HTTP Message Signature (RFC 9421) using a key the browser generated and sent in
   `Signature-Key: sig=hwk;…`, and it carries the issuer's own session cookies.
4. Checks that the logged-in user controls the requested address, then returns an EVT bound to
   the browser's key.

`pyevp.issuer` covers steps 1–4 except "the logged-in user controls the address", which is
yours. Chrome also requires the FedCM documents described in [What Chrome requires beyond the
draft](#what-chrome-requires-beyond-the-draft).

## Set up

Generate a signing key and keep the private JWK in your secret store:

```sh
pyevp issuer keygen --kid 2026-10 --out signing-key.json
```

```python
from pyevp.issuer import Issuer, SigningKey

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
pyevp issuer documents --issuer https://issuer.example \
    --issuance-endpoint https://accounts.issuer.example/email-verification/issuance \
    --jwks-uri https://accounts.issuer.example/email-verification/jwks \
    --key signing-key.json --domain example.com
pyevp discover example.com --profile draft-hardt-02
```

## Handle a request

```python
from pyevp.issuer import IssuanceError

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
- Keys that never leave a KMS or HSM implement {class}`pyevp.issuer.Signer`: `alg`, `kid`,
  `public_jwk`, and `sign(signing_input) -> bytes` in JWS encoding (raw `r || s` for ES256).

## Replay and rate limiting

A signed request is only accepted within 300 seconds of its `created` time. Within that window,
a captured request could be resent together with the cookies. Pass `replay_guard=` to refuse a
request the second time it is seen. The guard keys on the signed content rather than the
signature bytes, so re-encoding an ES256 signature does not get a request past it. Use a shared
store, as described in {doc}`replay`.

Rate-limit the issuance endpoint per IP address in front of the application. `observer=`
receives an {class}`pyevp.issuer.IssuanceEvent` for every accepted or rejected request
(including requests rejected as replays) and every issued token, for metrics and audit logs.

## What Chrome requires beyond the draft

Chrome 154 does more than the draft describes. Without the following, it fetches the metadata
and then stops without telling the page why.

- **FedCM account check.** Before issuing, Chrome fetches
  `https://<registrable domain of the issuer>/.well-known/web-identity`. For an issuer on
  `accounts.example.com`, that is `https://example.com/.well-known/web-identity`. Serve
  `pyevp.issuer.web_identity_document(accounts_endpoint=..., login_url=...)` there, with no
  `provider_urls` member. `accounts_endpoint` must be on the issuer's origin. Chrome requests it
  with the issuer's cookies and `Sec-Fetch-Dest: webidentity`. Answer with
  `pyevp.issuer.accounts_document([...])` listing the signed-in user's addresses; the typed address
  must be one of them.
- **Login status.** Chrome skips issuers it knows the user is signed out of. Send
  `Set-Login: logged-in` on a page response after login (or call
  `navigator.login.setStatus("logged-in")`), and `logged-out` on logout.
- **Cookies.** Both the accounts request and the issuance request are cross-site from the relying
  party, so the session cookie needs `SameSite=None; Secure`. Scope it to the issuer's origin.
- **EVT header.** Chrome accepts only `EdDSA`, `ES256` and `RS256` in the EVT header, not the
  `Ed25519` the draft requires. The default `chrome-153` profile therefore writes `EdDSA` for
  Ed25519 keys, as Gmail does. Relying parties using this library's default profile accept
  that, and the strict `draft-hardt-02` verifier profile does not. With an ES256 key, both are
  satisfied.

Chrome also shows the user a one-time prompt per address ("verify this email automatically?")
before the first issuance. It starts the check when focus moves from the email field to another
form field, and it rate-limits repeated failures per address.

## Not supported yet

- `private_email` / `directed_email` requests are answered with `private_email_not_supported`,
  and the metadata says `private_email_supported: false`.
- The pre-153 Chrome format (`application/x-www-form-urlencoded` with a `request_token`) is
  refused with 415.
