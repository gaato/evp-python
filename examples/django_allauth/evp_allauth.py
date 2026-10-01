"""django-allauth integration: trust EVP tokens at signup.

EVP is a progressive enhancement here: when the browser supplies a valid token
the new ``EmailAddress`` is created as verified and no confirmation mail is
sent; otherwise allauth's normal email confirmation flow runs.

Wiring (see ``settings.py``): ``ACCOUNT_ADAPTER``, ``ACCOUNT_FORMS["signup"]``,
``EVP_ORIGIN``, and this module as a template builtin so that the signup
template can use ``{% evp_token_input %}``.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from functools import cache

from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.forms import SignupForm
from django import forms, template
from django.conf import settings
from django.core.cache import cache as django_cache
from django.http import HttpRequest
from django.utils.html import format_html

from evp import CacheEntry, EVPError, Verifier, generate_nonce

logger = logging.getLogger(__name__)
SESSION_KEY = "evp_nonce"
register = template.Library()


class DjangoCache:
    """Share issuer metadata / JWKS between workers via Django's cache framework."""

    def get(self, key: str) -> CacheEntry | None:
        return django_cache.get(f"evp:{key}")

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        django_cache.set(f"evp:{key}", entry, timeout=ttl.total_seconds())


@cache
def get_verifier() -> Verifier:
    return Verifier.default(audience=settings.EVP_ORIGIN, cache=DjangoCache())


@register.simple_tag(takes_context=True)
def evp_token_input(context: template.Context) -> str:
    nonce = generate_nonce()
    context["request"].session[SESSION_KEY] = nonce
    return format_html(
        '<input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{}">',
        nonce,
    )


class EVPSignupForm(SignupForm):
    evt = forms.CharField(required=False, widget=forms.HiddenInput)

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
        token = request.POST.get("evt", "")
        # `session` is added by SessionMiddleware, which Django's types do not model.
        nonce = request.session.pop(SESSION_KEY, None)  # ty: ignore[unresolved-attribute]
        if not token or nonce is None:
            return False
        try:
            get_verifier().verify(token, nonce=nonce, email=email)
        except EVPError as exc:
            logger.info("EVP token rejected: %s", exc.code)
            return False
        return True
