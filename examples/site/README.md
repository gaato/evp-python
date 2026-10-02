# pyevp.dev site and demo provider

One container serves two hosts:

| Host | What |
|---|---|
| `pyevp.dev` | The landing page and the FedCM `/.well-known/web-identity` for the whole site |
| `mail.pyevp.dev` | A demo email provider (EVP issuer) with one account, `demo@pyevp.dev` |

The relying-party demo at `demo.pyevp.dev` is a separate app (`examples/demo`).

Chrome reads exactly one `/.well-known/web-identity` per registrable domain, and it names a
single `accounts_endpoint`. So `pyevp.dev` can host only one issuer, and this is it: the nightly
interop test (`interop/`) runs against it too.

Anyone can sign in as `demo@pyevp.dev`. A token from this provider proves only that someone
pressed the button. Do not accept it anywhere but a demo.

## DNS

```
pyevp.dev                         -> this container (Cloudflare Tunnel)
mail.pyevp.dev                    -> this container (Cloudflare Tunnel)
_email-verification.pyevp.dev TXT "iss=mail.pyevp.dev"
pyevp.dev MX 0 .                  (null MX: the address receives no mail)
pyevp.dev TXT "v=spf1 -all"
_dmarc.pyevp.dev TXT "v=DMARC1; p=reject"
```

Rate limiting is done per client IP at Cloudflare, not in the app: behind the tunnel every
request comes from the same connector address.

## Configuration

| Variable | Default | |
|---|---|---|
| `EVP_SIGNING_JWK` | required | Private signing key as a JWK JSON string (`pyevp issuer keygen`) |
| `SESSION_SECRET` | required | Key for the provider's signed session cookie |
| `EVP_SITE_HOST` | `pyevp.dev` | Host of the landing page |
| `EVP_MAIL_HOST` | `mail.pyevp.dev` | Host of the provider; the issuer is `https://<this>` |
| `EVP_EMAIL_DOMAIN` | `pyevp.dev` | The demo address is `demo@<this>` |
| `EVP_DEMO_URL` | `https://demo.pyevp.dev` | Linked from both pages |
| `EVP_EXAMPLES_DIR` | Repository `examples/` | Root containing the three marked framework examples; the image sets this to `/app/examples` |
| `BUILD_SHA` | `unknown` | Reported by `/me`; the image sets it at build time |
| `EVP_DEV` | unset | `1` allows a missing key (an ephemeral one is generated) or session secret, and a missing stylesheet. Never set it in production |

The app refuses to start without `EVP_SIGNING_JWK` and `SESSION_SECRET` unless `EVP_DEV=1`:
a key generated on every start would change the JWKS on every auto-update restart.

The container listens on port 8080.

## Routes

`GET /healthz` answers `200 ok` on any host, so that the container health check (which calls
`127.0.0.1:8080`) works. Any other request for an unknown host gets 404.

### `pyevp.dev`

| Route | Response |
|---|---|
| `GET /` | The landing page |
| `GET /.well-known/web-identity` | `web_identity_document(accounts_endpoint="https://<mail host>/fedcm/accounts", login_url="https://<mail host>/login")`, `application/json` |

### `mail.pyevp.dev`

Paths follow `examples/issuer_fastapi`.

| Route | Response |
|---|---|
| `GET /` and `GET /login` | The provider page: what this is, and a single "Sign in as demo@pyevp.dev" (or "Sign out") button. `/login` is the FedCM `login_url` |
| `POST /login` | No form fields. Starts the session for `demo@pyevp.dev`, answers with the provider page, `Set-Login: logged-in`, and a `navigator.login.setStatus("logged-in")` call |
| `POST /logout` | Clears the session, answers with the provider page and `Set-Login: logged-out` (plus `setStatus`) |
| `GET /me` | `{"email": "demo@pyevp.dev" or null, "issued": <tokens issued in this session>, "build_sha": "..."}`, `Cache-Control: no-store` |
| `GET /.well-known/email-verification` | Issuer metadata |
| `GET /email-verification/jwks` | JWKS |
| `GET /fedcm/accounts` | FedCM accounts: requires `Sec-Fetch-Dest: webidentity`; the signed-in address or an empty list; `Cache-Control: no-store`; no CORS headers |
| `POST /email-verification/issuance` | Issuance, as in `examples/issuer_fastapi`. The email in the request must equal the session's address, compared case-insensitively |

`POST /login` and `POST /logout` reject requests whose `Sec-Fetch-Site` is present and not
`same-origin` with 403.

The session cookie is host-only on the mail host, `SameSite=None; Secure; HttpOnly`, and lasts
one hour. Chrome sends it with the FedCM accounts and issuance requests, which are cross-site
from the relying party.

Error responses carry no request details.

## Landing page

Templates are Jinja2 (`templates/`), rendered once at startup. The stylesheet is Tailwind CSS v4
with daisyUI 5 (default `light` and `dark` themes, following `prefers-color-scheme`), built
without Node by `scripts/build-css.sh` and inlined into each page. Code is highlighted with
Pygments on the server, with a light and a dark style.

The framework examples on the landing page are cut from the real examples, between marker
comments:

```python
# landing:start
...
# landing:end
```

| Tab | File |
|---|---|
| FastAPI | `examples/fastapi/app.py` |
| Flask | `examples/flask/app.py` |
| Django allauth | `examples/django_allauth/evp_allauth.py` |

Each file has exactly one marked region. The app refuses to start if one is missing, and a
test checks all of them, so the page cannot drift from code that CI runs.

Without JavaScript the examples are stacked sections with headings. A short inline script turns
them into WAI-ARIA tabs.

## Development

```sh
scripts/build-css.sh static/site.css   # downloads the pinned Tailwind and daisyUI once
EVP_DEV=1 uv run uvicorn app:app --port 8080
curl -H 'Host: pyevp.dev' localhost:8080/
uv run pytest
```
