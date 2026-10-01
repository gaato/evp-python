"""``evp`` command / ``python -m evp``.  Requires ``pip install "evp[cli]"``."""

from __future__ import annotations

import sys

MISSING_EXTRA = 3


def main() -> None:
    try:
        from evp.cli import app  # noqa: PLC0415
    except ImportError as exc:
        if exc.name not in {"typer", "click", "rich"}:
            raise
        print(
            'The evp command needs the "cli" extra:\n'
            '  pip install "evp[cli]"\n'
            "or run it without installing:\n"
            '  uvx --from "evp[cli]" evp --help',
            file=sys.stderr,
        )
        raise SystemExit(MISSING_EXTRA) from None
    app()


if __name__ == "__main__":
    main()
