"""``pyevp`` command / ``python -m pyevp``.  Requires ``pip install "pyevp[cli]"``."""

from __future__ import annotations

import sys

MISSING_EXTRA = 3


def main() -> None:
    try:
        from pyevp.cli import app  # noqa: PLC0415
    except ImportError as exc:
        if exc.name not in {"typer", "click", "rich"}:
            raise
        print(
            'The pyevp command needs the "cli" extra:\n'
            '  pip install "pyevp[cli]"\n'
            "or run it without installing:\n"
            '  uvx --from "pyevp[cli]" pyevp --help',
            file=sys.stderr,
        )
        raise SystemExit(MISSING_EXTRA) from None
    app()


if __name__ == "__main__":
    main()
