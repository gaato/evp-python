from __future__ import annotations

from typing import ClassVar

from django.db import models


class UsedToken(models.Model):
    """A token accepted by :class:`pyevp.contrib.django.EVPReplayGuard`."""

    key = models.CharField(max_length=64, primary_key=True)
    expires_at = models.DateTimeField(db_index=True)

    objects: ClassVar[models.Manager] = models.Manager()
