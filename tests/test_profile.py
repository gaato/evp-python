from __future__ import annotations

import dataclasses
from datetime import timedelta

import pytest

from evp import DEFAULT_PROFILE, EmailComparison, Profile


def test_default_is_compat() -> None:
    assert Profile.compat_2026_10() == DEFAULT_PROFILE


def test_replace_returns_new_profile() -> None:
    custom = DEFAULT_PROFILE.replace(max_token_age=timedelta(minutes=1))
    assert custom.max_token_age == timedelta(minutes=1)
    assert DEFAULT_PROFILE.max_token_age == timedelta(minutes=5)


def test_profiles_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_PROFILE.require_kid = True  # ty: ignore[invalid-assignment]


def test_strict_profile_forbids_eddsa() -> None:
    strict = Profile.draft_hardt_02()
    assert "EdDSA" not in strict.evt_algorithms
    assert strict.email_comparison is EmailComparison.EXACT
    assert strict.require_kid
