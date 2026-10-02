"""Minimal FastAPI issuer for your own email domains (experimental).

This is a sketch of the moving parts, not a mail service: users are a dict and
log in with a password.  Configure it with environment variables::

    evp issuer keygen --kid 2026-10 --out signing-key.json
    export EVP_ISSUER=https://issuer.example
    export EVP_PUBLIC_URL=https://issuer.example     # where this app is reachable
    export EVP_EMAIL_DOMAINS=example.com
    export EVP_SIGNING_KEY=signing-key.json
    export SESSION_SECRET=...
    uv run uvicorn app:app --port 8000               # behind an HTTPS proxy

and publish ``_email-verification.example.com TXT "iss=issuer.example"``.
Check the result with ``evp discover example.com``.
"""

from __future__ import annotations

import hmac
import html
import json
import os
from typing import Annotated

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from evp.issuer import IssuanceError, IssuanceErrorCode, IssuanceResponse, Issuer, SigningKey

ISSUANCE_PATH = "/email-verification/issuance"
JWKS_PATH = "/email-verification/jwks"
MAX_BODY = 16 * 1024
SESSION_USER = "user"


def create_app(issuer: Issuer, users: dict[str, str], *, session_secret: str) -> FastAPI:
    """``users`` maps each email address to its (demo) password."""
    app = FastAPI()
    # The browser calls the issuance endpoint with the issuer's own cookies.  SameSite=None
    # and Secure keep the session cookie in that request; confirm the attributes against
    # the browser you target before going live.
    app.add_middleware(
        SessionMiddleware, secret_key=session_secret, same_site="none", https_only=True
    )

    @app.get("/.well-known/email-verification")
    async def metadata() -> JSONResponse:
        return JSONResponse(issuer.metadata_document())

    @app.get(JWKS_PATH)
    async def jwks() -> JSONResponse:
        return JSONResponse(issuer.jwks_document())

    @app.post(ISSUANCE_PATH)
    async def issuance(request: Request) -> Response:
        # Put per-IP rate limiting in front of this endpoint (proxy or middleware).
        body = await request.body()
        # Raw pairs keep repeated header lines apart.
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
        try:
            if len(body) > MAX_BODY:
                raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "body too large")
            parsed = await issuer.aparse_request(method=request.method, headers=headers, body=body)
            # One check for every way this can fail, so responses do not reveal accounts.
            if request.session.get(SESSION_USER) != parsed.email:
                raise IssuanceError.authentication_required()
            result = issuer.success_response(issuer.issue(parsed))
        except IssuanceError as exc:
            result = exc.to_response()
        return _response(result)

    @app.get("/login", response_class=HTMLResponse)
    async def login_form() -> str:
        return """<!doctype html>
<form method="post" action="/login">
  <input type="email" name="email" autocomplete="username" required>
  <input type="password" name="password" autocomplete="current-password" required>
  <button>Log in</button>
</form>"""

    @app.post("/login")
    async def login(
        request: Request, email: Annotated[str, Form()], password: Annotated[str, Form()]
    ) -> Response:
        expected = users.get(email, "")
        if not hmac.compare_digest(expected.encode(), password.encode()) or not expected:
            return HTMLResponse(f"<p>Wrong password for {html.escape(email)}</p>", status_code=401)
        request.session[SESSION_USER] = email
        # Login Status API: Chrome only asks issuers it knows the user is logged in to.
        return RedirectResponse("/login", status_code=303, headers={"Set-Login": "logged-in"})

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        request.session.clear()
        return RedirectResponse("/login", status_code=303, headers={"Set-Login": "logged-out"})

    return app


def _response(result: IssuanceResponse) -> Response:
    return Response(result.body, status_code=result.status, headers=result.headers)


def _from_environment() -> FastAPI:
    public_url = os.environ["EVP_PUBLIC_URL"].rstrip("/")
    with open(os.environ["EVP_SIGNING_KEY"]) as file:
        signer = SigningKey.from_jwk(json.load(file))
    issuer = Issuer(
        issuer=os.environ["EVP_ISSUER"],
        issuance_endpoint=public_url + ISSUANCE_PATH,
        jwks_uri=public_url + JWKS_PATH,
        signer=signer,
        email_domains=os.environ["EVP_EMAIL_DOMAINS"].split(","),
    )
    users = json.loads(os.environ.get("EVP_DEMO_USERS", "{}"))
    return create_app(issuer, users, session_secret=os.environ["SESSION_SECRET"])


app = _from_environment() if "EVP_ISSUER" in os.environ else FastAPI()
