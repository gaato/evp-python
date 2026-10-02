"""pyevp.dev and its mock email provider, served by one ASGI app."""

from __future__ import annotations

import json
import logging
import os
import secrets
import textwrap
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup
from pygments import highlight
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.python import PythonLexer
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Host, Route

from pyevp import Clock
from pyevp.issuer import (
    FEDCM_FETCH_DEST,
    IssuanceError,
    IssuanceErrorCode,
    Issuer,
    SigningKey,
    accounts_document,
    web_identity_document,
)
from pyevp.ports import system_clock

ISSUANCE_PATH = "/email-verification/issuance"
JWKS_PATH = "/email-verification/jwks"
ACCOUNTS_PATH = "/fedcm/accounts"
LOGIN_PATH = "/login"
MAX_BODY = 16 * 1024
SESSION_USER = "email"
HERE = Path(__file__).resolve().parent
EXAMPLES_DIR = HERE.parent
STYLESHEET = HERE / "static" / "site.css"
EXAMPLES = (
    ("fastapi", "FastAPI", "fastapi/app.py"),
    ("flask", "Flask", "flask/app.py"),
    ("django-allauth", "Django allauth", "django_allauth/evp_allauth.py"),
)
NO_STORE = {"Cache-Control": "no-store"}


def extract_example(path: Path) -> str:
    """Require one ordered marker pair, then remove markers and indentation."""
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "# landing:start"]
    ends = [i for i, line in enumerate(lines) if line.strip() == "# landing:end"]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError(f"{path} must contain exactly one ordered landing marker pair")
    return textwrap.dedent("\n".join(lines[starts[0] + 1 : ends[0]])) + "\n"


def _formatter(style: str, fallback: str) -> HtmlFormatter:
    try:
        selected = get_style_by_name(style)
    except ClassNotFound:
        selected = get_style_by_name(fallback)
    return HtmlFormatter(style=selected, cssclass="highlight")


def _render_pages(
    *,
    examples_dir: Path,
    stylesheet_path: Path,
    dev: bool,
    demo_url: str,
    site_host: str,
    email: str,
) -> dict[str, str]:
    try:
        stylesheet = stylesheet_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if not dev:
            raise RuntimeError("static/site.css is required unless EVP_DEV=1") from None
        logging.getLogger(__name__).warning("Missing static/site.css; using an empty stylesheet")
        stylesheet = ""
    light = _formatter("a11y-light", "default")
    dark = _formatter("a11y-dark", "native")
    pygments_css = (
        light.get_style_defs(".highlight")
        + "\n@media (prefers-color-scheme: dark) {\n"
        + dark.get_style_defs(".highlight")
        + "\n}"
    )
    templates = Environment(
        loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"])
    )
    context = {
        "stylesheet": Markup(stylesheet),
        "pygments_css": Markup(pygments_css),
        "demo_url": demo_url,
        "site_url": f"https://{site_host}",
        "email": email,
    }
    examples = [
        {
            "id": ident,
            "label": label,
            "code": Markup(highlight(extract_example(examples_dir / path), PythonLexer(), light)),
        }
        for ident, label, path in EXAMPLES
    ]
    pages = {"landing": templates.get_template("landing.html").render(examples=examples, **context)}
    mail = templates.get_template("mail.html")
    for name, signed_in, status in (
        ("signed-out", False, None),
        ("signed-in", True, None),
        ("logged-in", True, "logged-in"),
        ("logged-out", False, "logged-out"),
    ):
        pages[name] = mail.render(signed_in=signed_in, login_status=status, **context)
    return pages


async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _site_app(issuer: Issuer, pages: dict[str, str]) -> FastAPI:
    site = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @site.get("/")
    async def landing() -> HTMLResponse:
        return HTMLResponse(pages["landing"])

    @site.get("/.well-known/web-identity")
    async def web_identity() -> JSONResponse:
        return JSONResponse(
            web_identity_document(
                accounts_endpoint=issuer.issuer + ACCOUNTS_PATH,
                login_url=issuer.issuer + LOGIN_PATH,
            )
        )

    return site


async def _issuance(request: Request, issuer: Issuer) -> Response:
    body = await request.body()
    headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
    try:
        if len(body) > MAX_BODY:
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "body too large")
        parsed = await issuer.aparse_request(method=request.method, headers=headers, body=body)
        email = request.session.get(SESSION_USER)
        if email is None or email.casefold() != parsed.email.casefold():
            raise IssuanceError.authentication_required()
        result = issuer.success_response(issuer.issue(parsed))
        request.session["issued"] = request.session.get("issued", 0) + 1
    except IssuanceError as exc:
        result = exc.to_response()
    return Response(result.body, status_code=result.status, headers=result.headers)


def _mail_app(
    issuer: Issuer,
    pages: dict[str, str],
    *,
    email: str,
    session_secret: str,
    build_sha: str,
) -> FastAPI:
    mail = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mail.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="pyevp_mail_session",
        same_site="none",
        https_only=True,
        max_age=3600,
    )

    @mail.get("/")
    @mail.get(LOGIN_PATH)
    async def provider(request: Request) -> HTMLResponse:
        name = "signed-in" if request.session.get(SESSION_USER) else "signed-out"
        return HTMLResponse(pages[name], headers=NO_STORE)

    @mail.post(LOGIN_PATH)
    async def login(request: Request) -> Response:
        if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
            return JSONResponse({"error": "forbidden"}, status_code=403, headers=NO_STORE)
        request.session.clear()
        request.session.update({SESSION_USER: email, "issued": 0})
        return HTMLResponse(pages["logged-in"], headers={**NO_STORE, "Set-Login": "logged-in"})

    @mail.post("/logout")
    async def logout(request: Request) -> Response:
        if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
            return JSONResponse({"error": "forbidden"}, status_code=403, headers=NO_STORE)
        request.session.clear()
        return HTMLResponse(pages["logged-out"], headers={**NO_STORE, "Set-Login": "logged-out"})

    @mail.get("/me")
    async def me(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "email": request.session.get(SESSION_USER),
                "issued": request.session.get("issued", 0),
                "build_sha": build_sha,
            },
            headers=NO_STORE,
        )

    @mail.get("/.well-known/email-verification")
    async def metadata() -> JSONResponse:
        return JSONResponse(issuer.metadata_document())

    @mail.get(JWKS_PATH)
    async def jwks() -> JSONResponse:
        return JSONResponse(issuer.jwks_document())

    @mail.get(ACCOUNTS_PATH)
    async def accounts(request: Request) -> JSONResponse:
        if request.headers.get("sec-fetch-dest") != FEDCM_FETCH_DEST:
            return JSONResponse({"error": "not a FedCM request"}, status_code=400, headers=NO_STORE)
        user = request.session.get(SESSION_USER)
        if user is None:
            return JSONResponse({"accounts": []}, status_code=401, headers=NO_STORE)
        return JSONResponse(accounts_document([user]), headers=NO_STORE)

    @mail.post(ISSUANCE_PATH)
    async def issuance(request: Request) -> Response:
        return await _issuance(request, issuer)

    return mail


def create_app(
    *,
    signer: SigningKey | None = None,
    session_secret: str | None = None,
    site_host: str = "pyevp.dev",
    mail_host: str = "mail.pyevp.dev",
    email_domain: str = "pyevp.dev",
    demo_url: str = "https://demo.pyevp.dev",
    build_sha: str = "unknown",
    examples_dir: Path = EXAMPLES_DIR,
    stylesheet_path: Path = STYLESHEET,
    dev: bool = False,
    clock: Clock = system_clock,
) -> Starlette:
    """Explicit settings; only ``_from_environment`` reads environment variables."""
    if signer is None:
        if not dev:
            raise RuntimeError("EVP_SIGNING_JWK is required unless EVP_DEV=1")
        signer = SigningKey.generate(kid="dev")
    if not session_secret:
        if not dev:
            raise RuntimeError("SESSION_SECRET is required unless EVP_DEV=1")
        session_secret = secrets.token_urlsafe(32)
    base = f"https://{mail_host}"
    issuer = Issuer(
        issuer=base,
        issuance_endpoint=base + ISSUANCE_PATH,
        jwks_uri=base + JWKS_PATH,
        signer=signer,
        email_domains=[email_domain],
        clock=clock,
    )
    email = f"demo@{email_domain}"
    pages: dict[str, str] = {}

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        pages.update(
            _render_pages(
                examples_dir=examples_dir,
                stylesheet_path=stylesheet_path,
                dev=dev,
                demo_url=demo_url,
                site_host=site_host,
                email=email,
            )
        )
        yield

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
            Host(site_host, _site_app(issuer, pages)),
            Host(
                mail_host,
                _mail_app(
                    issuer, pages, email=email, session_secret=session_secret, build_sha=build_sha
                ),
            ),
        ],
        lifespan=lifespan,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=_security_headers)],
    )
    app.state.issuer = issuer
    return app


def _from_environment() -> Starlette:
    jwk = os.environ.get("EVP_SIGNING_JWK")
    return create_app(
        signer=SigningKey.from_jwk(json.loads(jwk)) if jwk else None,
        session_secret=os.environ.get("SESSION_SECRET"),
        site_host=os.environ.get("EVP_SITE_HOST", "pyevp.dev"),
        mail_host=os.environ.get("EVP_MAIL_HOST", "mail.pyevp.dev"),
        email_domain=os.environ.get("EVP_EMAIL_DOMAIN", "pyevp.dev"),
        demo_url=os.environ.get("EVP_DEMO_URL", "https://demo.pyevp.dev"),
        build_sha=os.environ.get("BUILD_SHA", "unknown"),
        examples_dir=Path(os.environ.get("EVP_EXAMPLES_DIR", EXAMPLES_DIR)),
        stylesheet_path=STYLESHEET,
        dev=os.environ.get("EVP_DEV") == "1",
    )


app = _from_environment()
