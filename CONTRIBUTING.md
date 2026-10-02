# Contributing

## Development

```sh
uv sync --all-packages --all-extras
uv run pytest              # library: unit + end-to-end with fakes
uv run pytest -m network   # live checks against deployed issuers (Gmail)
uv run ruff check && uv run ruff format --check && uv run ty check
```

Each example under `examples/` is a member of the uv workspace with its own tests:

```sh
uv run --directory examples/fastapi pytest
uv run --directory examples/flask pytest
uv run --directory examples/django_allauth pytest
```

To try one in a browser:

```sh
cd examples/fastapi && uv run uvicorn app:app --port 8000
cd examples/flask && uv run flask run --port 8000
cd examples/django_allauth && uv run manage.py migrate && uv run manage.py runserver
```

To start your own project from an example, copy it out and replace
`pyevp = { workspace = true }` with a normal dependency.

## Following the protocol

CI runs the network checks weekly (`.github/workflows/drift.yml`) and opens a `spec-drift` issue
when the deployed ecosystem diverges from the default profile. Behaviour changes go into a new
profile preset; existing presets are never changed incompatibly (see the
[compatibility policy](https://pyevp.readthedocs.io/en/latest/compatibility.html)).

## Python versions

The library supports Python 3.11, so type aliases use `TypeAlias` instead of `type` statements
(marked `TODO(py3.12)`). When 3.11 support is dropped, raise `requires-python` and run
`uv run ruff check --select UP040 --fix --unsafe-fixes` to convert them back
(the fix is "unsafe" only because `type` aliases are evaluated lazily).

## Releases

Bump `version` in `pyproject.toml`, move the `Unreleased` changelog entries under the new
version, and push a `vX.Y.Z` tag. `.github/workflows/release.yml` checks that the tag matches
the version and publishes to PyPI through trusted publishing.
