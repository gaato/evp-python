"""FastAPI JSON API for a single-page app, without server sessions.

The frontend runs on its own origin (``EVP_ORIGIN``) and calls this API with
credentials.  There is no session to hold the nonce, so ``GET /api/evp/nonce``
puts it in an HttpOnly cookie.  Password recovery skips the email when the
browser presents a token for the address (see the "Password recovery" guide).

Run from this directory::

    uv run uvicorn app:app --port 8000

Users live in memory and emails go to ``OUTBOX``, to keep the example short.
Tests swap the verifier via ``app.dependency_overrides`` (see ``tests/test_app.py``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pyevp import AsyncVerifier, EVPError, InMemoryReplayGuard, generate_nonce

logger = logging.getLogger(__name__)

# The origin of the frontend, where the form is.  It is the audience of the
# tokens, not this API's own origin.
ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:5173")
RESET_SECRET = os.environ.get("RESET_SECRET", "dev-only").encode()
NONCE_MAX_AGE = 600
RESET_MAX_AGE = 900
GENERIC_REPLY = "If that address is registered, we sent a password recovery link"


@dataclass
class User:
    email: str
    active: bool = True
    password_hash: bytes = b""


USERS: dict[str, User] = {}
OUTBOX: list[tuple[str, str]] = []  # (address, reset token)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # The nonce cookie is client-side state: a captured token could be sent again
    # with the old cookie.  The replay guard refuses the second use.  Use a shared
    # store (e.g. Redis) when running more than one worker.
    app.state.verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    yield


app = FastAPI(lifespan=lifespan)
# The frontend sends requests with credentials, so that the nonce cookie travels.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
api = APIRouter(prefix="/api")


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


Verifier = Annotated[AsyncVerifier, Depends(get_verifier)]


class Nonce(BaseModel):
    nonce: str


class RecoveryRequest(BaseModel):
    email: str
    evt: str = ""


class RecoveryReply(BaseModel):
    message: str
    reset_token: str | None = None


class ResetRequest(BaseModel):
    token: str
    new_password: str


# nonce:start
def nonce_cookie() -> tuple[str, bool]:
    """The cookie's name and whether it is Secure."""
    # Over HTTPS, the __Secure- prefix stops plain-HTTP hosts on the same site
    # from setting the cookie.
    secure = ORIGIN.startswith("https://")
    return ("__Secure-evp_nonce" if secure else "evp_nonce"), secure


@api.get("/evp/nonce")
async def evp_nonce(response: Response) -> Nonce:
    nonce = generate_nonce()
    name, secure = nonce_cookie()
    response.set_cookie(
        name,
        nonce,
        max_age=NONCE_MAX_AGE,
        path="/api",
        httponly=True,
        samesite="strict",
        secure=secure,
    )
    return Nonce(nonce=nonce)


async def verify_evt(
    request: Request, response: Response, verifier: AsyncVerifier, *, token: str, email: str
) -> bool:
    """Whether ``token`` proves that this browser controls ``email``."""
    if not token:
        # Keep the nonce: the browser has not used it yet.
        return False
    name, secure = nonce_cookie()
    nonce = request.cookies.get(name)
    response.delete_cookie(name, path="/api", httponly=True, samesite="strict", secure=secure)
    if nonce is None:
        return False
    try:
        await verifier.verify(token, nonce=nonce, email=email)
    except EVPError as exc:
        logger.info("EVP token rejected: %s", exc.code)
        return False
    return True
    # nonce:end


# recovery:start
@api.post("/password-recovery", response_model_exclude_none=True)
async def password_recovery(
    body: RecoveryRequest,
    request: Request,
    response: Response,
    verifier: Verifier,
    background: BackgroundTasks,
) -> RecoveryReply:
    # Verify before looking the user up, so that the reply, its cookies and its
    # timing do not depend on whether the address is registered.
    verified = await verify_evt(request, response, verifier, token=body.evt, email=body.email)
    user = USERS.get(body.email.lower())
    if user is None or not user.active:
        return RecoveryReply(message=GENERIC_REPLY)
    if verified:
        # The browser proved control of the address: hand over the token that
        # the recovery email would carry.
        return RecoveryReply(message="Address verified", reset_token=make_reset_token(user.email))
    # In the background, so that sending does not make this reply slower.
    background.add_task(send_recovery_email, user.email, make_reset_token(user.email))
    return RecoveryReply(message=GENERIC_REPLY)
    # recovery:end


@api.post("/reset-password")
async def reset_password(body: ResetRequest) -> dict[str, str]:
    email = check_reset_token(body.token)
    user = USERS.get(email) if email else None
    if user is None or not user.active:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.password_hash = hash_password(body.new_password)
    return {"message": "Password updated"}


app.include_router(api)


def send_recovery_email(address: str, token: str) -> None:
    OUTBOX.append((address, token))


def make_reset_token(email: str) -> str:
    claims = {"email": email, "exp": int(time.time()) + RESET_MAX_AGE}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    return f"{payload}.{_sign(payload)}"


def check_reset_token(token: str) -> str | None:
    payload, _, signature = token.rpartition(".")
    # As bytes: compare_digest refuses non-ASCII str, and the token is user input.
    if not hmac.compare_digest(signature.encode(), _sign(payload).encode()):
        return None
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims["email"] if claims["exp"] > time.time() else None


def _sign(payload: str) -> str:
    return hmac.new(RESET_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
