from __future__ import annotations

import json

from django.conf import settings
from django.urls import include, path
from django.views.generic import TemplateView

from pyevp.contrib.django.issuer import IssuerSite
from pyevp.issuer import Issuer, SigningKey


def _signer() -> SigningKey:
    if settings.EVP_SIGNING_KEY is None:
        return SigningKey.generate(kid="dev")
    with open(settings.EVP_SIGNING_KEY) as file:
        return SigningKey.from_jwk(json.load(file))


issuer = Issuer(
    issuer=settings.EVP_ISSUER,
    issuance_endpoint=f"{settings.EVP_PUBLIC_URL}/{IssuerSite.issuance_path}",
    jwks_uri=f"{settings.EVP_PUBLIC_URL}/{IssuerSite.jwks_path}",
    signer=_signer(),
    email_domains=settings.EVP_EMAIL_DOMAINS,
)
evp = IssuerSite(issuer)

urlpatterns = [
    # The issuer's endpoints and, when the issuer's host is its own registrable
    # domain, Chrome's FedCM well-known.  Otherwise serve the latter there yourself.
    path("", include(evp.urls)),
    path("accounts/", include("django.contrib.auth.urls")),
    path("", TemplateView.as_view(template_name="home.html")),
]
