"""django-allauth integration: trust EVP tokens at signup.

EVP is a progressive enhancement here: when the browser supplies a valid token
the new ``EmailAddress`` is created as verified and no confirmation mail is
sent; otherwise allauth's normal email confirmation flow runs.

Wiring (see ``settings.py``): ``"pyevp.contrib.django"`` in ``INSTALLED_APPS``,
``ACCOUNT_ADAPTER``, ``ACCOUNT_FORMS["signup"]`` and ``EVP_ORIGIN``.  The signup
template adds the token input with ``{% load pyevp %}`` and ``{% evp_token_input %}``.
"""

from __future__ import annotations

import logging
from functools import cache

from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.forms import SignupForm
from django.conf import settings
from django.http import HttpRequest

from pyevp import EVPError, Verifier
from pyevp.contrib.django import EVPCache, EVPReplayGuard, verify_request

logger = logging.getLogger(__name__)


@cache
def get_verifier() -> Verifier:
    return Verifier.default(
        audience=settings.EVP_ORIGIN, cache=EVPCache(), replay_guard=EVPReplayGuard()
    )


class EVPSignupForm(SignupForm):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        # The browser only offers verified addresses for autocomplete="email" fields.
        self.fields["email"].widget.attrs["autocomplete"] = "email"


class EVPAccountAdapter(DefaultAccountAdapter):
    def is_email_verified(self, request: HttpRequest, email: str) -> bool:
        if super().is_email_verified(request, email):
            return True
        # The nonce is single-use, so remember the outcome for repeated calls.
        verified: dict[str, bool] = request.__dict__.setdefault("_evp_verified", {})
        if email not in verified:
            verified[email] = self._verify(request, email)
        return verified[email]

    def _verify(self, request: HttpRequest, email: str) -> bool:
        try:
            return verify_request(request, get_verifier(), email=email) is not None
        except EVPError as exc:
            logger.info("EVP token rejected: %s", exc.code)
            return False
