"""Plain Django relying party: a signup form that trusts EVP tokens.

Run from this directory::

    uv run manage.py migrate
    uv run manage.py runserver 8000

then open http://localhost:8000 in a browser that supports the Email
Verification Protocol.  Tests replace ``get_verifier`` with a verifier wired
to fakes (see ``tests/test_views.py``).
"""

from __future__ import annotations

from functools import cache

from django import forms
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render

from pyevp import EVPError, Verifier
from pyevp.contrib.django import EVPCache, EVPReplayGuard, verify_request


@cache
def get_verifier() -> Verifier:
    return Verifier.default(
        audience=settings.EVP_ORIGIN, cache=EVPCache(), replay_guard=EVPReplayGuard()
    )


class SignupForm(forms.Form):
    # The browser only offers verified addresses for autocomplete="email" fields.
    email = forms.EmailField(widget=forms.EmailInput(attrs={"autocomplete": "email"}))


# landing:start
def signup(request: HttpRequest) -> HttpResponse:
    form = SignupForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"]
        try:
            result = verify_request(request, get_verifier(), email=email)
        except EVPError as exc:
            return JsonResponse({"error": {"code": exc.code}}, status=400)
        if result is None:
            # No token: fall back to sending a confirmation email, as before EVP.
            return JsonResponse({"email": email, "verified": False})
        return JsonResponse({"email": result.email, "verified": True, "issuer": result.issuer})
    # {% evp_token_input %} in the template puts a nonce in the session.
    return render(request, "signup.html", {"form": form})
    # landing:end
