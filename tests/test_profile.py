from __future__ import annotations

import dataclasses
import typing
from datetime import timedelta

import pytest

from pyevp import DEFAULT_PROFILE, EmailComparison, Profile
from pyevp.issuer.profile import IssuanceProfile, IssuanceProfileChanges
from pyevp.profile import ProfileChanges


def test_default_is_compat() -> None:
    assert Profile.compat_2026_10() == DEFAULT_PROFILE


def test_replace_returns_new_profile() -> None:
    custom = DEFAULT_PROFILE.replace(max_token_age=timedelta(minutes=1))
    assert custom.max_token_age == timedelta(minutes=1)
    assert DEFAULT_PROFILE.max_token_age == timedelta(minutes=5)


@pytest.mark.parametrize(
    ("profile", "changes"),
    [(Profile, ProfileChanges), (IssuanceProfile, IssuanceProfileChanges)],
)
def test_replace_arguments_match_the_fields(profile: type, changes: type) -> None:
    hints = typing.get_type_hints
    assert list(hints(changes).items()) == list(hints(profile).items())


def test_replace_refuses_unknown_fields() -> None:
    with pytest.raises(TypeError):
        DEFAULT_PROFILE.replace(max_token_agee=timedelta(minutes=1))


def test_profiles_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_PROFILE.require_kid = True  # ty: ignore[invalid-assignment]


def test_strict_profile_forbids_eddsa() -> None:
    strict = Profile.draft_hardt_02()
    assert "EdDSA" not in strict.evt_algorithms
    assert strict.email_comparison is EmailComparison.EXACT
    assert strict.require_kid
