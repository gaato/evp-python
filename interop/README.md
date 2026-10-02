# Chrome interop test

`chrome_evp.py` runs the Email Verification Protocol flow in a real, headless Chrome
against the permanent public demo provider:

1. Before launching Chrome, checks `https://mail.pyevp.dev/healthz`, the JSON
   `https://pyevp.dev/.well-known/web-identity` (its `accounts_endpoint` must be on
   `https://mail.pyevp.dev`), and `_email-verification.pyevp.dev` TXT discovery using
   pyevp's dnspython adapter and discovery parser. The discovered issuer must be
   `https://mail.pyevp.dev`.
2. Starts `examples/fastapi` as the relying party at `http://localhost:8001`, waits for
   it to be ready, and launches Chrome, using the library from this checkout (HEAD).
   The provider runs the deployed `:latest`
   image independently of the checkout; the test reports its `/me` `build_sha`.
3. Logs in as `demo@pyevp.dev` in a fresh Chrome profile by submitting the provider's
   `POST /login` form without fields.
4. Records the session's `/me` `issued` count before each flow, types the address into
   the RP's form, and polls `/me` until that count increases. It then submits and
   expects `{"verified": true, "issuer": "https://mail.pyevp.dev"}`. The RP also returns
   `email`, which must equal `demo@pyevp.dev`.

`.github/workflows/interop.yml` runs nightly on Chrome for Testing stable and beta.
The test also acts as a nightly monitor of the public demo. Preflight failures report
`PROVIDER UNAVAILABLE` and exit with **2**, rather than being labelled an interop
regression. HTTP or malformed-response failures from `/me` use the same classification.
Interop failures report `INTEROP FAILED` and exit with **1**; success exits with **0**.
The workflow's existing stable-failure issue reporting still applies to either failure,
so check the run log to distinguish provider availability from a library regression.

## Running locally

Install Chrome with EVP support and uv, then run from the repository root after the
public provider has been deployed:

```fish
uv sync --locked --all-packages --all-extras --group interop
uv run --no-sync python interop/chrome_evp.py
```

Set `CHROME` to use another binary, `INTEROP_HEADFUL=1` to watch the browser, and
`INTEROP_OUT` to keep process logs and the final RP screenshot:

```fish
env CHROME=/path/to/chrome INTEROP_HEADFUL=1 INTEROP_OUT=/tmp/pyevp-interop \
    uv run --no-sync python interop/chrome_evp.py
```

The test needs ports 8001 (RP) and 9333 (Chrome DevTools). Its browser profile is temporary
and removed afterwards. No local issuer, signing key, tunnel connector, or tunnel secret
is needed.

A small self-check uses fake HTTP, DNS, and CDP responses without starting Chrome or
contacting the provider:

```fish
uv run --no-sync python -m pytest interop/test_chrome_evp.py
```

## How Chrome is driven

- `--enable-features=EmailVerificationProtocol` turns EVP on (the
  `#email-verification-protocol` flag).
- Before the first issuance for an address, Chrome asks "verify this email automatically?"
  in a browser popup. DevTools cannot press it, so the profile starts with the answer
  Chrome saves after acceptance: `autofill.email_verification_state` in
  `Default/Preferences`.
- The `issuer_site` in that saved answer is the issuer origin, `https://mail.pyevp.dev`
  (`CHROME_ISSUER_SITE`), not the site `https://pyevp.dev`. Signing in through the
  provider's form is enough for Chrome's FedCM login status in this profile.
- Chrome fills the hidden `email-verification-token` field only on a real submission.
  While that token is pending, the test leaves the RP page in place. For each `/me`
  poll it retrieves the current cookies for `https://mail.pyevp.dev/me` via CDP
  `Network.getCookies` and sends them in an HTTP GET from Python. This includes the
  host-only HttpOnly session cookie and observes updates from issuance. The HTTP
  transport follows no redirects and does not write response cookies back to Chrome.
- After `issued` increases, the test waits one second for Chrome's local key binding,
  submits with a DevTools input click, and reads the RP response. If the RP got no token,
  it retries with a fresh form, up to three attempts. Each count poll is separated by
  half a second, with a 60-second issuance timeout and a 10-second HTTP timeout.
- `build_sha` is logged on the first `/me` read and whenever it changes during the run.

## pyevp.dev

The public demo hosts, routes, DNS, configuration, and deployment contract are described
in [examples/site/README.md](../examples/site/README.md). In particular, the site's
FedCM web-identity document is on `pyevp.dev`, while the issuer and session are on
`mail.pyevp.dev`. The only account, `demo@pyevp.dev`, is public and suitable only for demos.
