# Chrome interop test

`chrome_evp.py` runs the whole Email Verification Protocol flow in a real, headless Chrome:

1. Starts `examples/issuer_fastapi` as the issuer for `@pyevp.dev`, at `https://pyevp.dev`
   through the `pyevp-dev` Cloudflare Tunnel (see [pyevp.dev](#pyevpdev) below). Each run
   uses a fresh signing key and waits until pyevp.dev serves that key, so it knows the
   tunnel reaches this issuer.
2. Starts `examples/fastapi` as the relying party on `http://localhost:8001`.
3. Logs in to the issuer as `test@pyevp.dev`, types the address into the RP's form,
   submits it, and expects `{"verified": true, "issuer": "https://pyevp.dev"}`.

`.github/workflows/interop.yml` runs it every night on Chrome for Testing stable and beta.

## Running locally

```fish
cf tunnels run pyevp-dev &    # serve pyevp.dev from this machine
uv run --locked --all-packages --group interop python interop/chrome_evp.py
```

Set `CHROME` to use another binary, `INTEROP_HEADFUL=1` to watch the browser, and
`INTEROP_OUT` to keep logs and the final screenshot. Stop the tunnel afterwards: while it
runs, pyevp.dev requests may reach your machine instead of the nightly job.

## How Chrome is driven

- `--enable-features=EmailVerificationProtocol` turns EVP on (the
  `#email-verification-protocol` flag).
- Before the first issuance for an address, Chrome asks "verify this email automatically?"
  in a browser popup. DevTools cannot press it (it is not a FedCM dialog, and key events go
  to the page). The profile therefore starts with the answer Chrome saves after the user
  accepts: `autofill.email_verification_state` in `Default/Preferences`.
- Chrome starts the check when the email field loses focus and fills the hidden
  `email-verification-token` field only on submission. Scripts see it empty before, so the
  page cannot tell when the token is ready. The test watches the issuer's access log for
  Chrome's issuance request instead, then submits with a real (DevTools input) click and
  reads the RP's response. If the RP still got no token, it retries with a fresh form.
- Chrome sends the issuer's cookies with the FedCM accounts request and the issuance
  request, so the issuer login has to happen in the same profile first.

## pyevp.dev

`pyevp.dev` exists only for this test. It is set up by hand and rarely changes; if the setup
breaks, the nightly run fails. Keep this section in sync when you change anything.

| What | Value |
|---|---|
| DNS | `pyevp.dev CNAME c9e0272a-ee40-4f1a-8490-885d97acfa83.cfargotunnel.com` (proxied) |
| DNS | `_email-verification.pyevp.dev TXT "iss=pyevp.dev"` |
| Tunnel | `pyevp-dev` (`c9e0272a-ee40-4f1a-8490-885d97acfa83`), remotely managed |
| Ingress | `pyevp.dev` → `http://localhost:8000`, everything else 404 |

The issuer is the apex because Chrome fetches `/.well-known/web-identity` at the issuer's
registrable domain. The issuer app serves that file itself.

To recreate it:

```fish
cf tunnels create   # name pyevp-dev, config_src cloudflare; then use its id below
cf tunnels config update <tunnel-id> --body '{"config":{"ingress":[{"hostname":"pyevp.dev","service":"http://localhost:8000"},{"service":"http_status:404"}]}}'
cf dns records create -z pyevp.dev --body '{"type":"CNAME","name":"pyevp.dev","content":"<tunnel-id>.cfargotunnel.com","proxied":true}'
cf dns records create -z pyevp.dev --body '{"type":"TXT","name":"_email-verification.pyevp.dev","content":"\"iss=pyevp.dev\""}'
```

The nightly job runs in the `pyevp-dev` environment (deployable from `main` only) with one
secret, `PYEVP_TUNNEL_TOKEN`: the tunnel's connector token, from
`cf tunnels token get <tunnel-id>`. It can run the connector but not change the tunnel or
anything else in the account.
