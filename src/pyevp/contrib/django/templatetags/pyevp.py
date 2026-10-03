"""Template tags for EVP forms, loaded with ``{% load pyevp %}``."""

from __future__ import annotations

from django import template
from django.core.exceptions import ImproperlyConfigured
from django.utils.html import format_html
from django.utils.safestring import SafeString

from pyevp.contrib.django import get_nonce

register = template.Library()


@register.simple_tag(takes_context=True)
def evp_token_input(context: template.Context, field: str = "evt") -> SafeString:
    """Render the hidden input that the browser fills with the token.

    Put it inside the form, next to ``<input type="email" autocomplete="email">``.
    All tags on a page share one nonce (see :func:`~pyevp.contrib.django.get_nonce`).
    """
    request = context.get("request")
    if request is None:
        raise ImproperlyConfigured(
            "{% evp_token_input %} needs the request in the template context: enable "
            "django.template.context_processors.request or render with a request."
        )
    return format_html(
        '<input type="hidden" name="{}" autocomplete="email-verification-token" nonce="{}">',
        field,
        get_nonce(request),
    )
