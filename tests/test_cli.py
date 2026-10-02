from __future__ import annotations

import builtins
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from rich.console import Console
from typer import Typer
from typer.testing import CliRunner

from pyevp import __main__ as entry
from pyevp.cli import make_app
from pyevp.testing import FakeBrowser, FakeIssuer, FixedClock, InMemoryDns, InMemoryHttp

ORIGIN = "https://rp.example"
runner = CliRunner()


@pytest.fixture
def issuer() -> FakeIssuer:
    # The CLI uses the real clock.
    return FakeIssuer(clock=FixedClock(datetime.now(UTC)))


@pytest.fixture
def seen_doh() -> list[str | None]:
    return []


@pytest.fixture
def app(issuer: FakeIssuer, seen_doh: list[str | None]) -> Typer:
    def resolver(doh: str | None) -> InMemoryDns:
        seen_doh.append(doh)
        return InMemoryDns(issuer.dns_records())

    return make_app(
        resolver_factory=resolver,
        fetcher_factory=lambda: InMemoryHttp(issuer.http_documents()),
        console=Console(width=200),
    )


def _token(issuer: FakeIssuer, nonce: str = "n0nce") -> str:
    browser = FakeBrowser(clock=issuer.clock)
    return browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )


def test_discover_json(app: Typer, seen_doh: list[str | None]) -> None:
    result = runner.invoke(app, ["discover", "alice@example.com", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["ok"] is True
    assert data["issuer"] == "https://issuer.example"
    assert seen_doh == [None]


def test_discover_pretty_and_doh(app: Typer, seen_doh: list[str | None]) -> None:
    result = runner.invoke(app, ["discover", "example.com", "--doh"])
    assert result.exit_code == 0, result.output
    assert "https://issuer.example" in result.output
    assert seen_doh == ["https://dns.google/resolve"]


def test_discover_problem_exit_code(app: Typer) -> None:
    result = runner.invoke(app, ["discover", "nowhere.example", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False


def test_unknown_profile(app: Typer) -> None:
    result = runner.invoke(app, ["discover", "example.com", "--profile", "nope"])
    assert result.exit_code == 2


def test_inspect(app: Typer, issuer: FakeIssuer) -> None:
    result = runner.invoke(app, ["inspect", "--json"], input=_token(issuer))
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["signatures_verified"] is False
    assert data["evt"]["claims"]["email"] == "alice@example.com"
    assert data["checks"]["sd_hash_matches"] is True
    assert data["checks"]["holder_key_thumbprint"]


def test_inspect_pretty(app: Typer, issuer: FakeIssuer) -> None:
    result = runner.invoke(app, ["inspect", _token(issuer)])
    assert result.exit_code == 0, result.output
    assert "NOT verified" in result.output


@pytest.mark.parametrize("iat", [1e100, float("nan"), 10**30])
@pytest.mark.parametrize("args", [[], ["--json"]])
def test_inspect_out_of_range_dates(
    app: Typer, issuer: FakeIssuer, iat: float, args: list[str]
) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    evt = issuer.issue("alice@example.com", browser.public_jwk, claims={"iat": iat})
    token = browser.present(evt, audience=ORIGIN, nonce="n0nce")
    result = runner.invoke(app, ["inspect", token, *args])
    assert result.exit_code == 0, result.output


def test_inspect_malformed(app: Typer) -> None:
    result = runner.invoke(app, ["inspect", "garbage", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["code"] == "malformed_token"


def test_verify(app: Typer, issuer: FakeIssuer) -> None:
    args = ["verify", _token(issuer), "--audience", ORIGIN, "--nonce", "n0nce", "--json"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["email"] == "alice@example.com"


def test_verify_failure(app: Typer, issuer: FakeIssuer) -> None:
    args = ["verify", _token(issuer), "--audience", ORIGIN, "--nonce", "other"]
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert "nonce_mismatch" in result.output


def test_verify_bad_audience(app: Typer, issuer: FakeIssuer) -> None:
    result = runner.invoke(app, ["verify", _token(issuer), "--audience", "x", "--nonce", "n"])
    assert result.exit_code == 2


def test_missing_extra_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "pyevp.cli":
            raise ModuleNotFoundError("No module named 'typer'", name="typer")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as exc:
        entry.main()
    assert exc.value.code == entry.MISSING_EXTRA
    assert 'uvx --from "pyevp[cli]"' in capsys.readouterr().err


def test_issuer_keygen_and_documents(app: Typer, tmp_path: Any) -> None:
    key_path = tmp_path / "key.json"
    result = runner.invoke(app, ["issuer", "keygen", "--kid", "2026-10", "--out", str(key_path)])
    assert result.exit_code == 0, result.output
    public = json.loads(result.output)
    assert public["kid"] == "2026-10"
    assert "d" not in public
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(key_path.read_text())["d"]

    again = runner.invoke(app, ["issuer", "keygen", "--kid", "x", "--out", str(key_path)])
    assert again.exit_code == 2

    retired_path = tmp_path / "retired.json"
    runner.invoke(
        app, ["issuer", "keygen", "--kid", "2026-04", "--alg", "ES256", "--out", str(retired_path)]
    )
    result = runner.invoke(
        app,
        [
            "issuer",
            "documents",
            "--issuer",
            "https://issuer.example",
            "--issuance-endpoint",
            "https://issuer.example/evp/issue",
            "--jwks-uri",
            "https://issuer.example/evp/jwks",
            "--key",
            str(key_path),
            "--domain",
            "example.com",
            "--domain",
            "example.org",
            "--publish",
            str(retired_path),
        ],
    )
    assert result.exit_code == 0, result.output
    documents = json.loads(result.output)
    assert documents["metadata"]["issuer"] == "https://issuer.example"
    assert [k["kid"] for k in documents["jwks"]["keys"]] == ["2026-10", "2026-04"]
    assert all("d" not in k for k in documents["jwks"]["keys"])
    assert documents["dns_txt"] == {
        "_email-verification.example.com": "iss=issuer.example",
        "_email-verification.example.org": "iss=issuer.example",
    }


def test_issuer_keygen_rejects_unknown_alg(app: Typer, tmp_path: Any) -> None:
    path = tmp_path / "key.json"
    result = runner.invoke(
        app, ["issuer", "keygen", "--kid", "k", "--alg", "EdDSA", "--out", str(path)]
    )
    assert result.exit_code == 2
    assert not path.exists()


def test_issuer_documents_bad_config(app: Typer, tmp_path: Any) -> None:
    path = tmp_path / "key.json"
    runner.invoke(app, ["issuer", "keygen", "--kid", "k", "--out", str(path)])
    result = runner.invoke(
        app,
        [
            "issuer",
            "documents",
            "--issuer",
            "https://issuer.example/",
            "--issuance-endpoint",
            "https://issuer.example/evp/issue",
            "--jwks-uri",
            "https://issuer.example/evp/jwks",
            "--key",
            str(path),
            "--domain",
            "example.com",
        ],
    )
    assert result.exit_code == 2
