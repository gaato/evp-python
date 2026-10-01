from __future__ import annotations

import os
import tempfile

# Must be set before ``app`` is imported: the engine is created at import time.
os.environ.setdefault(
    "DATABASE_URL", f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/fastapi_users_test.db"
)
