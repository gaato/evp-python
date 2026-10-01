"""Minimal FastAPI relying party.

Run from this directory::

    uv run uvicorn app:app --port 8000

then open http://localhost:8000 in a browser that supports the Email
Verification Protocol.  Tests swap the verifier for one wired to fakes via
``app.dependency_overrides`` (see ``tests/test_app.py``).
"""

from __future__ import annotations

import html
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.middleware.sessions import SessionMiddleware

from evp import AsyncVerifier, EVPError, InMemoryReplayGuard, generate_nonce

ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000")
SESSION_KEY = "evp_nonce"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # SessionMiddleware keeps the session in a signed cookie, so popping the nonce
    # does not stop an attacker from resending a captured token with the old
    # cookie.  The replay guard does.  Use a shared store (e.g. Redis) when
    # running more than one worker.
    app.state.verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", "dev-only"))


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


@app.get("/", response_class=HTMLResponse)
async def form(request: Request) -> str:
    nonce = generate_nonce()
    request.session[SESSION_KEY] = nonce
    return f"""<!doctype html>
<form method="post" action="/signup">
  <input type="email" name="email" autocomplete="email" required>
  <input type="hidden" name="evt" autocomplete="email-verification-token"
         nonce="{html.escape(nonce)}">
  <button>Sign up</button>
</form>"""


@app.post("/signup")
async def signup(
    request: Request,
    verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
    email: Annotated[str, Form()],
    evt: Annotated[str, Form()] = "",
) -> dict[str, object]:
    # Single use: the nonce is consumed whether or not verification succeeds.
    nonce = request.session.pop(SESSION_KEY, None)
    if not evt or nonce is None:
        # No token: fall back to sending a confirmation email, as before EVP.
        return {"email": email, "verified": False}
    try:
        result = await verifier.verify(evt, nonce=nonce, email=email)
    except EVPError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code}) from exc
    return {"email": result.email, "verified": True, "issuer": result.issuer}
