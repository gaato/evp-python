from __future__ import annotations

from django.apps import AppConfig
from django.core import checks


class PyevpConfig(AppConfig):
    name = "pyevp.contrib.django"
    label = "pyevp"
    verbose_name = "Email Verification Protocol"

    def ready(self) -> None:
        from pyevp.contrib.django.issuer import check_session_cookie  # noqa: PLC0415

        checks.register(check_session_cookie, checks.Tags.security)
