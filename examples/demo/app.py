"""Public demo relying party (served at https://demo.pyevp.dev).

Run from this directory::

    uv run uvicorn app:app --port 8000

then open http://localhost:8000 in Chrome with the Email Verification Protocol
enabled and sign in with a Gmail address.

Configuration (environment):

``EVP_ORIGIN``
    The origin visitors use, e.g. ``https://demo.pyevp.dev``.  Default
    ``http://localhost:8000``.
``SESSION_SECRET``
    Key for the signed session cookie.  Required unless the origin is localhost.
``EVP_ALLOWED_ISSUERS``
    Space-separated issuer origins this demo accepts (default: Google and
    pyevp.dev).

The issuer allowlist matters for a public deployment: discovery fetches HTTPS URLs
chosen by whoever controls the email domain in the token, before any issuer
signature is checked.  Rejecting unknown issuers at the DNS step means the demo
only ever contacts issuers listed here.
"""

from __future__ import annotations

import html
import logging
import os
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from pyevp import (
    AsyncTxtResolver,
    AsyncVerifier,
    DiscoveryError,
    ErrorCode,
    EVPError,
    InMemoryReplayGuard,
    LoggingObserver,
    VerifiedEmail,
    generate_nonce,
)
from pyevp.adapters.dnspython import AsyncDnsPythonResolver
from pyevp.discovery import canonical_issuer
from pyevp.profile import IssuerFormat

ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000").rstrip("/")
DEFAULT_ISSUERS = "https://accounts.google.com https://pyevp.dev"
ALLOWED_ISSUERS = frozenset(os.environ.get("EVP_ALLOWED_ISSUERS", DEFAULT_ISSUERS).split())
SESSION_KEY = "evp_nonce"


def _session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET")
    if secret:
        return secret
    if ORIGIN.startswith(("http://localhost", "http://127.0.0.1")):
        return "dev-only"
    raise RuntimeError("SESSION_SECRET must be set when EVP_ORIGIN is not localhost")


class AllowedIssuers:
    """Resolver wrapper that refuses ``iss=`` records naming an issuer not in ``allowed``."""

    def __init__(self, inner: AsyncTxtResolver, allowed: Iterable[str]) -> None:
        self._inner = inner
        self._allowed = frozenset(allowed)

    async def resolve_txt(self, name: str) -> list[str]:
        records = await self._inner.resolve_txt(name)
        for record in records:
            if not record.startswith("iss="):
                continue
            issuer = canonical_issuer(record.removeprefix("iss=").strip(), IssuerFormat.ANY)
            if issuer not in self._allowed:
                raise DiscoveryError(
                    ErrorCode.ISSUER_DISCOVERY_FAILED,
                    f"this demo only accepts tokens from {', '.join(sorted(self._allowed))}",
                )
        return records


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(level=logging.INFO)
    # One process only: the replay guard lives in memory.
    app.state.verifier = AsyncVerifier.default(
        audience=ORIGIN,
        resolver=AllowedIssuers(AsyncDnsPythonResolver(), ALLOWED_ISSUERS),
        replay_guard=InMemoryReplayGuard(),
        observer=LoggingObserver(),
    )
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret(),
    https_only=ORIGIN.startswith("https://"),
    same_site="lax",
)


@app.middleware("http")
async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    # No Content-Security-Policy on purpose: with a header-delivered CSP, browsers
    # hide every element's nonce attribute, which may include the one EVP reads.
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


STYLE = """
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #fafafa; --muted: #5f6368;
  --card: #fff; --line: #dadce0; --ok: #137333; --bad: #c5221f; --accent: #1a73e8; }
@media (prefers-color-scheme: dark) { :root { --fg: #e8eaed; --bg: #202124;
  --muted: #9aa0a6; --card: #292a2d; --line: #3c4043; --ok: #81c995; --bad: #f28b82;
  --accent: #8ab4f8; } }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.55 system-ui, sans-serif; color: var(--fg);
  background: var(--bg); }
main { max-width: 40rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
.lead, .muted { color: var(--muted); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 1.25rem; margin: 1.5rem 0; }
label { display: block; font-weight: 600; margin-bottom: .4rem; }
input[type=email] { width: 100%; font: inherit; padding: .6rem .7rem;
  border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: inherit; }
button { margin-top: .9rem; font: inherit; font-weight: 600; padding: .55rem 1.2rem;
  border: 0; border-radius: 8px; background: var(--accent); color: var(--bg); cursor: pointer; }
button:disabled { opacity: .5; cursor: wait; }
.ok { color: var(--ok); } .bad { color: var(--bad); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 0; }
dt { color: var(--muted); } dd { margin: 0; overflow-wrap: anywhere; }
code { font-size: .9em; }
#warn { display: none; }
"""

SCRIPT = """
const email = document.getElementById("email");
const submit = document.getElementById("submit");
const hint = document.getElementById("hint");
if (!window.isSecureContext) document.getElementById("warn").style.display = "block";
// Chrome requests the token when the email field loses focus and fills it in only
// on submit, if it has arrived by then.  Give the request a few seconds.
let timer;
function show(left) {
  hint.textContent = left > 0 ? `Getting a token from your email provider… ${left}s` : "";
  submit.disabled = left > 0;
}
function wait() {
  clearInterval(timer);
  let left = 3;
  show(left);
  timer = setInterval(() => {
    left -= 1;
    show(left);
    if (left <= 0) clearInterval(timer);
  }, 1000);
}
email.addEventListener("change", wait);
"""


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{STYLE}</style>
</head>
<body><main>
<h1>pyevp demo</h1>
<p class="lead">Email verification without a confirmation email, using the
<a href="https://github.com/WICG/email-verification">Email Verification Protocol</a>
and <a href="https://github.com/gaato/pyevp">pyevp</a>.</p>
{body}
</main></body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> str:
    nonce = generate_nonce()
    request.session[SESSION_KEY] = nonce
    return _page(
        "pyevp demo",
        f"""
<div class="card" id="warn"><strong class="bad">This page is not a secure context.</strong>
Open it over HTTPS (or localhost); browsers only run EVP in secure contexts.</div>
<form class="card" method="post" action="/verify">
  <label for="email">Your Gmail address</label>
  <input type="email" id="email" name="email" autocomplete="email" required>
  <input type="hidden" name="evt" autocomplete="email-verification-token"
         nonce="{html.escape(nonce)}">
  <button id="submit">Verify</button>
  <p class="muted" id="hint" aria-live="polite"></p>
</form>
<div class="card">
<p><strong>What you need:</strong> Chrome 154 or later, desktop or Android, with EVP
turned on (<code>chrome://flags/#email-verification-protocol</code>), signed in to the
Google account for the address you enter.</p>
<p><strong>What happens:</strong> when you leave the field, Chrome asks Google for a
signed token proving you control the address. On submit, this server checks it
with pyevp: the issuer is found through DNS, the signature against the issuer's
published keys, and the token is bound to this page by a one-time nonce.</p>
<p class="muted">Nothing you enter is stored. Accepted issuers:
{html.escape(", ".join(sorted(ALLOWED_ISSUERS)))}.</p>
</div>
<script>{SCRIPT}</script>
""",
    )


def _verified(result: VerifiedEmail) -> str:
    rows = {
        "Email": result.email,
        "Issuer": result.issuer,
        "Issued at": result.issued_at.isoformat(),
        "Expires at": result.expires_at.isoformat() if result.expires_at else "-",
        "Private relay address": "yes" if result.is_private_email else "no",
    }
    items = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>" for k, v in rows.items())
    return f'<div class="card"><h2 class="ok">Verified</h2><dl>{items}</dl></div>'


NO_TOKEN = """<div class="card"><h2 class="bad">No token received</h2>
<p>The browser submitted the form without a verification token. A normal site would
now fall back to sending a confirmation email. Common reasons:</p>
<ul>
<li>EVP is not enabled in this browser, or the browser does not support it yet
(Chrome 153 and earlier do not).</li>
<li>The form was submitted before the token arrived. Leave the email field, wait a
few seconds, then submit.</li>
<li>Your email provider does not issue EVP tokens (Gmail does).</li>
<li>You are not signed in to that account in this browser.</li>
</ul></div>"""


@app.post("/verify", response_class=HTMLResponse)
async def verify(
    request: Request,
    verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
    email: Annotated[str, Form()],
    evt: Annotated[str, Form()] = "",
) -> HTMLResponse:
    # Single use: the nonce is consumed whether or not verification succeeds.
    nonce = request.session.pop(SESSION_KEY, None)
    again = '<p><a href="/">Try again</a></p>'
    if not evt:
        return HTMLResponse(_page("No token | pyevp demo", NO_TOKEN + again))
    if nonce is None:
        body = '<div class="card"><h2 class="bad">Session expired</h2></div>'
        return HTMLResponse(_page("Session expired | pyevp demo", body + again), 400)
    try:
        result = await verifier.verify(evt, nonce=nonce, email=email)
    except EVPError as exc:
        body = f"""<div class="card"><h2 class="bad">Verification failed</h2>
<dl><dt>Code</dt><dd><code>{html.escape(exc.code)}</code></dd>
<dt>Detail</dt><dd>{html.escape(exc.args[0])}</dd></dl></div>"""
        return HTMLResponse(_page("Failed | pyevp demo", body + again), 400)
    return HTMLResponse(_page("Verified | pyevp demo", _verified(result) + again))


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz() -> str:
    return "ok"
