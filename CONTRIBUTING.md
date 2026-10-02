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
uv run --directory examples/issuer_django pytest
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
[compatibility policy](https://docs.pyevp.dev/en/latest/compatibility.html)).

## Translations

The docs have a Japanese translation, kept as gettext catalogs in `docs/locales/ja/LC_MESSAGES/`.
After changing the English docs or a docstring, refresh the catalogs and commit the updated `.po`
files:

```sh
uv run sphinx-build -b gettext docs docs/_build/gettext
uv run sphinx-intl update -p docs/_build/gettext -l ja -d docs/locales
```

Entries that are untranslated or marked fuzzy (because their English text changed) show in
English until someone translates or reviews them and removes the `fuzzy` flag.

`api.po` also holds the autodoc docstrings. Sphinx parses every translation for a page with that
page's parser, so even docstring entries are MyST there: write roles as ``{class}`Verifier` ``,
not ``:class:`Verifier` ``, and drop the `::` that introduces a literal block. The field labels
(Parameters, Raises, Return type) come from Sphinx's own catalog, not from `api.po`.

Link to sections with explicit labels (`(label-name)=` above the heading, then
`[text](#label-name)`), not with anchors derived from heading text. A heading that starts with a
number, like `3. Handle failures`, needs the dot escaped in its translation (`3\\. …` in the
`.po` file), or it is parsed as a list and the translation is dropped.

### Japanese style

Follow the [JTF style guide](https://www.jtf.jp/pdf/jtf_style_guide.pdf) except for spacing, and
keep to the existing translation:

- です・ます. Write 「〜できます」, not 「〜することができます」. Leave "you" untranslated.
- Keep the long vowel at the end of katakana words: ユーザー, ブラウザー, サーバー, アダプター.
- Put a half-width space between Japanese and Latin letters, digits or code (`DNS の TXT レコード`,
  `1 つ`, `2 回`), but never before a particle (`発行者を`, not `発行者 を`).
- Use full-width parentheses in running text. End a sentence that introduces a code block or list
  with 「。」 (「次のように設定します。」), not a colon.
- Give the English term in parentheses only the first time it appears on a page: 発行者（issuer）.

| English | Japanese |
|---|---|
| issuer | 発行者 |
| relying party (RP) | リライングパーティー（RP） |
| verify, verification | 検証する、検証 |
| raise (an exception) | 送出する |
| override (a method) | オーバーライドする |
| fall back | フォールバックする |
| replay protection, replay guard | リプレイ対策、リプレイガード |
| hidden field | hidden フィールド |
| body (of a request) | ボディ |
| discovery | ディスカバリー (noun only) |
| end-to-end | エンドツーエンド |
| fake | フェイク |
| presentation token | 提示用のトークン |
| key binding (KB-JWT) | 鍵バインディング |
| holder key | ホルダーの鍵 |
| canonical (issuer) | 正規化された |
| claim | クレーム |
| driver, port, effect | ドライバー、ポート、エフェクト |
| fetcher, resolver | フェッチャー、リゾルバー |
| fail closed | 安全側に失敗する |
| verifier, nonce, disclosure | (untranslated) |

### Building

To build the Japanese docs locally and check progress:

```fish
uv sync --all-extras --group docs
uv run sphinx-build -W --keep-going -D language=ja -b html docs docs/_build/ja
xdg-open docs/_build/ja/index.html
uv run sphinx-intl stat -d docs/locales -l ja
```

The Read the Docs project `pyevp-ja` builds the same repository with the language set to Japanese.
It serves <https://docs.pyevp.dev/ja/latest/> and is linked to `pyevp` as a translation.

## Python versions

The library supports Python 3.11, so type aliases use `TypeAlias` instead of `type` statements
(marked `TODO(py3.12)`). When 3.11 support is dropped, raise `requires-python` and run
`uv run ruff check --select UP040 --fix --unsafe-fixes` to convert them back
(the fix is "unsafe" only because `type` aliases are evaluated lazily).

## Releases

Bump `version` in `pyproject.toml` and push a `vX.Y.Z` tag. `.github/workflows/release.yml`
checks that the tag matches the version and publishes to PyPI through trusted publishing.

There is no changelog before the first release. Start `CHANGELOG.md` with it (and link it from
`pyproject.toml`, the docs and the compatibility policy), then record changes from there on.
