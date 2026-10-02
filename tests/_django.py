"""Django settings shared by the tests of ``pyevp.contrib.django``."""

from __future__ import annotations

import atexit
import shutil
import tempfile
from pathlib import Path

import django
from django.conf import settings

_tmp = Path(tempfile.mkdtemp(prefix="pyevp-django-"))
atexit.register(shutil.rmtree, _tmp, ignore_errors=True)


def configure() -> None:
    """Configure Django once; call it before importing models."""
    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
            "pyevp.contrib.django",
        ],
        DATABASES={
            # A file, not :memory:, so that sync_to_async's thread sees the same data.
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(_tmp / "db.sqlite3")},
            # The recipe for ATOMIC_REQUESTS: a second alias for the same database.
            "replay": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(_tmp / "db.sqlite3")},
        },
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
            "db": {
                "BACKEND": "django.core.cache.backends.db.DatabaseCache",
                "LOCATION": "evp_cache",
            },
        },
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "pyevp.contrib.django.issuer.LoginStatusMiddleware",
        ],
        ALLOWED_HOSTS=["testserver", "issuer.example"],
        SECRET_KEY="test",
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True,
        PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
        USE_TZ=True,
    )
    django.setup()
