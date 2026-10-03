"""Minimal settings for the example (development only)."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-not-secret")
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
ROOT_URLCONF = "urls"

# The origin the browser puts in the KB-JWT "aud" claim.
EVP_ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000")

INSTALLED_APPS = [
    "django.contrib.sessions",
    "pyevp.contrib.django",  # {% load pyevp %} and DjangoReplayGuard's table
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "OPTIONS": {
            # {% evp_token_input %} reads the request from the context.
            "context_processors": ["django.template.context_processors.request"],
        },
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
USE_TZ = True
