"""Host routing and the mock provider, driven by a fake browser."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from starlette.applications import Starlette
from starlette.routing import Host, Route

from pyevp import Verifier
from pyevp.issuer import Issuer, SigningKey
from pyevp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

# Importing the deployment entry point must be explicit about development mode.
# The patch ends before any test; factories are tested independently of the environment.
with patch.dict(os.environ, {"EVP_DEV": "1", "EVP_SIGNING_JWK": "", "SESSION_SECRET": ""}):
    import app as site

SITE = "https://pyevp.dev"
MAIL = "https://mail.pyevp.dev"
RP = "https://demo.pyevp.dev"
EMAIL = "demo@pyevp.dev"
COOKIE = "pyevp_mail_session"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def signer() -> SigningKey:
    return SigningKey.generate(kid="test")


@pytest.fixture
def stylesheet(tmp_path: Path) -> Path:
    path = tmp_path / "site.css"
    path.write_text("/* test stylesheet */", encoding="utf-8")
    return path


@pytest.fixture
def application(signer: SigningKey, clock: FixedClock, stylesheet: Path) -> Starlette:
    return site.create_app(
        signer=signer,
        session_secret="test-session-secret",
        clock=clock,
        stylesheet_path=stylesheet,
        build_sha="test-sha",
    )


@pytest.fixture
def issuer(application: Starlette) -> Issuer:
    return application.state.issuer


@pytest.fixture
def client(application: Starlette) -> Iterator[TestClient]:
    with TestClient(application, base_url=MAIL) as client:
        yield client


def _issue(client: TestClient, browser: FakeBrowser, email: str = EMAIL) -> httpx2.Response:
    request = browser.issuance_request(email, endpoint=MAIL + site.ISSUANCE_PATH)
    return client.post(site.ISSUANCE_PATH, headers=request["headers"], content=request["body"])


class PageText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _page_text(page: str) -> str:
    parser = PageText()
    parser.feed(page)
    return "".join(parser.parts)


@pytest.mark.parametrize("host", ["pyevp.dev", "mail.pyevp.dev", "unknown.example", "127.0.0.1"])
def test_healthz_on_any_host(client: TestClient, host: str) -> None:
    response = client.get("/healthz", headers={"Host": host})
    assert response.status_code == 200
    assert response.text == "ok"


@pytest.mark.parametrize("path", ["/", "/login", "/me", "/.well-known/web-identity"])
def test_unknown_host(client: TestClient, path: str) -> None:
    assert client.get(path, headers={"Host": "unknown.example"}).status_code == 404


def test_routing_order_and_disabled_docs(application: Starlette, client: TestClient) -> None:
    routes = application.routes
    assert isinstance(routes[0], Route)
    assert routes[0].path == "/healthz"
    for route, host in zip(routes[1:], ["pyevp.dev", "mail.pyevp.dev"], strict=True):
        assert isinstance(route, Host)
        assert route.host == host
        assert isinstance(route.app, FastAPI)
        assert route.app.docs_url is None
        assert route.app.redoc_url is None
        assert route.app.openapi_url is None
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path, headers={"Host": host}).status_code == 404


def test_web_identity(client: TestClient) -> None:
    response = client.get(SITE + "/.well-known/web-identity")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "accounts_endpoint": MAIL + site.ACCOUNTS_PATH,
        "login_url": MAIL + site.LOGIN_PATH,
    }
    assert client.get("/.well-known/web-identity").status_code == 404


def test_metadata_and_jwks(client: TestClient, issuer: Issuer) -> None:
    response = client.get("/.well-known/email-verification")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == issuer.metadata_document()
    assert response.json()["issuer"] == MAIL
    assert response.json()["issuance_endpoint"] == MAIL + site.ISSUANCE_PATH
    response = client.get(site.JWKS_PATH)
    assert response.headers["content-type"] == "application/json"
    assert response.json() == issuer.jwks_document()
    assert "d" not in response.json()["keys"][0]


def test_accounts(client: TestClient) -> None:
    for headers in ({}, {"Sec-Fetch-Dest": "document"}):
        response = client.get(site.ACCOUNTS_PATH, headers=headers)
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"
    fedcm = {"Sec-Fetch-Dest": "webidentity", "Origin": RP}
    response = client.get(site.ACCOUNTS_PATH, headers=fedcm)
    assert response.status_code == 401
    assert response.json() == {"accounts": []}
    assert response.headers["cache-control"] == "no-store"
    client.post("/login")
    response = client.get(site.ACCOUNTS_PATH, headers=fedcm)
    assert response.status_code == 200
    assert response.json() == {"accounts": [{"id": EMAIL, "email": EMAIL, "name": EMAIL}]}
    assert response.headers["cache-control"] == "no-store"
    assert not any(name.startswith("access-control-") for name in response.headers)


@pytest.mark.parametrize("path", ["/", "/login"])
def test_provider_page(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert f"Sign in as {EMAIL}" in response.text
    assert "not a mailbox" in response.text
    assert "proves nothing" in response.text
    assert 'action="/login"' in response.text
    assert 'href="https://demo.pyevp.dev"' in response.text
    assert 'href="https://pyevp.dev"' in response.text
    assert "/* test stylesheet */" in response.text
    assert "<input" not in response.text
    client.post("/login")
    response = client.get(path)
    assert "Sign out" in response.text
    assert 'action="/logout"' in response.text
    assert "setStatus(" not in response.text


def test_login_logout_and_me(client: TestClient) -> None:
    response = client.get("/me")
    assert response.json() == {"email": None, "issued": 0, "build_sha": "test-sha"}
    assert response.headers["cache-control"] == "no-store"
    login = client.post("/login", headers={"Sec-Fetch-Site": "same-origin"})
    assert login.status_code == 200
    assert login.headers["cache-control"] == "no-store"
    assert login.headers["set-login"] == "logged-in"
    assert 'navigator.login.setStatus("logged-in")' in login.text
    assert COOKIE in client.cookies
    assert client.get("/me").json() == {"email": EMAIL, "issued": 0, "build_sha": "test-sha"}
    logout = client.post("/logout")
    assert logout.status_code == 200
    assert logout.headers["cache-control"] == "no-store"
    assert logout.headers["set-login"] == "logged-out"
    assert 'navigator.login.setStatus("logged-out")' in logout.text
    assert COOKIE not in client.cookies
    assert client.get("/me").json() == {"email": None, "issued": 0, "build_sha": "test-sha"}


@pytest.mark.parametrize("path", ["/login", "/logout"])
@pytest.mark.parametrize("fetch_site", ["cross-site", "same-site", "none", ""])
def test_csrf_rejected(client: TestClient, path: str, fetch_site: str) -> None:
    client.post("/login")
    before = client.get("/me").json()
    response = client.post(path, headers={"Sec-Fetch-Site": fetch_site})
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert "set-login" not in response.headers
    assert client.get("/me").json() == before


def test_csrf_cannot_create_a_session(client: TestClient) -> None:
    response = client.post("/login", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert COOKIE not in client.cookies


def test_cookie_attributes_and_host_isolation(client: TestClient) -> None:
    response = client.post("/login")
    cookie = SimpleCookie(response.headers["set-cookie"])[COOKIE]
    assert cookie["path"] == "/"
    assert cookie["max-age"] == "3600"
    assert cookie["samesite"].lower() == "none"
    assert cookie["secure"]
    assert cookie["httponly"]
    assert not cookie["domain"]
    landing = client.get(SITE + "/")
    assert "set-cookie" not in landing.headers
    assert COOKIE not in landing.request.headers.get("cookie", "")
    assert COOKIE in client.get("/me").request.headers["cookie"]
    response = client.post("/logout")
    cleared = SimpleCookie(response.headers["set-cookie"])[COOKIE]
    assert cleared.value == "null"
    assert cleared["expires"]
    assert cleared["secure"]
    assert cleared["httponly"]
    assert cleared["samesite"].lower() == "none"
    assert not cleared["domain"]


@pytest.mark.parametrize("email", [EMAIL, "DeMo@PyEvP.DeV"])
def test_full_issuance(
    client: TestClient,
    issuer: Issuer,
    clock: FixedClock,
    email: str,
) -> None:
    client.post("/login")
    browser = FakeBrowser(clock=clock)
    response = _issue(client, browser, email)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    verifier = Verifier(
        audience=RP,
        resolver=InMemoryDns({k: [v] for k, v in issuer.dns_txt_records().items()}),
        fetcher=InMemoryHttp(
            {
                MAIL + "/.well-known/email-verification": client.get(
                    "/.well-known/email-verification"
                ).json(),
                issuer.jwks_uri: client.get(site.JWKS_PATH).json(),
            }
        ),
        clock=clock,
    )
    token = browser.present(response.json()["issuance_token"], audience=RP, nonce="n")
    assert verifier.verify(token, nonce="n", email=email).email == email
    response = client.get("/me")
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"email": EMAIL, "issued": 1, "build_sha": "test-sha"}
    assert _issue(client, FakeBrowser(clock=clock)).status_code == 200
    assert client.get("/me").json()["issued"] == 2
    assert _issue(client, browser, "other@pyevp.dev").status_code == 401
    assert client.get("/me").json()["issued"] == 2
    client.post("/login")
    assert client.get("/me").json()["issued"] == 0
    client.post("/logout")
    assert client.get("/me").json()["issued"] == 0


def test_issuance_failures_look_the_same(client: TestClient, clock: FixedClock) -> None:
    browser = FakeBrowser(clock=clock)
    signed_out = _issue(client, browser)
    assert client.get("/me").json()["issued"] == 0
    client.post("/login")
    wrong_user = _issue(client, browser, "someone@pyevp.dev")
    wrong_domain = _issue(client, browser, "someone@other.example")
    assert signed_out.status_code == wrong_user.status_code == wrong_domain.status_code == 401
    assert signed_out.content == wrong_user.content == wrong_domain.content
    assert signed_out.json()["error"] == "authentication_required"
    assert signed_out.headers["cache-control"] == "no-store"
    assert client.get("/me").json()["issued"] == 0
    client.post("/logout")
    assert _issue(client, browser).status_code == 401


def test_unsigned_and_oversized_requests(client: TestClient) -> None:
    response = client.post(
        site.ISSUANCE_PATH,
        headers={"Content-Type": "application/json", "Sec-Fetch-Dest": "email-verification"},
        content=b'{"email":"private-request-detail@pyevp.dev"}',
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_signature"
    assert response.headers["signature-error"] == "error=invalid_signature"
    assert "private-request-detail" not in response.text
    response = client.post(site.ISSUANCE_PATH, content=b"private-request-detail" * site.MAX_BODY)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert response.headers["cache-control"] == "no-store"
    assert "private-request-detail" not in response.text


@pytest.mark.parametrize("missing", ["key", "secret"])
def test_factory_requires_production_credentials(
    signer: SigningKey,
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An ambient development environment cannot change the explicit factory settings.
    monkeypatch.setenv("EVP_DEV", "1")
    with pytest.raises(
        RuntimeError, match="EVP_SIGNING_JWK" if missing == "key" else "SESSION_SECRET"
    ):
        site.create_app(signer=None if missing == "key" else signer, session_secret=None)


def test_missing_stylesheet_refuses_startup(signer: SigningKey, tmp_path: Path) -> None:
    app = site.create_app(
        signer=signer, session_secret="test", stylesheet_path=tmp_path / "absent.css"
    )
    with pytest.raises(RuntimeError, match=r"static/site\.css"), TestClient(app):
        pass


def test_dev_ephemeral_keys_and_missing_css(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = site.create_app(dev=True, stylesheet_path=tmp_path / "absent.css")
    other = site.create_app(dev=True)
    assert app.state.issuer.signer.kid == "dev"
    assert app.state.issuer.jwks_document() != other.state.issuer.jwks_document()
    with TestClient(app, base_url=SITE) as client:
        assert client.get("/").status_code == 200
    assert "Missing static/site.css" in caplog.text


def test_environment_settings(monkeypatch: pytest.MonkeyPatch, stylesheet: Path) -> None:
    for variable in ("EVP_SIGNING_JWK", "SESSION_SECRET", "EVP_DEV"):
        monkeypatch.delenv(variable, raising=False)
    with pytest.raises(RuntimeError, match="EVP_SIGNING_JWK"):
        site._from_environment()
    key = OKPKey.generate_key("Ed25519", private=True).as_dict(private=True)
    key["kid"] = "environment-test"
    monkeypatch.setenv("EVP_SIGNING_JWK", json.dumps(key))
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        site._from_environment()
    monkeypatch.setenv("SESSION_SECRET", "environment-secret")
    monkeypatch.setenv("EVP_SITE_HOST", "site.example")
    monkeypatch.setenv("EVP_MAIL_HOST", "mail.example")
    monkeypatch.setenv("EVP_EMAIL_DOMAIN", "email.example")
    monkeypatch.setenv("EVP_DEMO_URL", "https://rp.example")
    monkeypatch.setenv("BUILD_SHA", "environment-sha")
    custom_examples = stylesheet.parent / "examples"
    for _, _, path in site.EXAMPLES:
        example = custom_examples / path
        example.parent.mkdir(parents=True, exist_ok=True)
        example.write_text("# landing:start\n# selected EVP_EXAMPLES_DIR\n# landing:end\n")
    monkeypatch.setenv("EVP_EXAMPLES_DIR", str(custom_examples))
    monkeypatch.setattr(site, "STYLESHEET", stylesheet)
    with TestClient(site._from_environment(), base_url="https://mail.example") as client:
        assert client.post("/login").headers["set-login"] == "logged-in"
        assert client.get("/me").json() == {
            "email": "demo@email.example",
            "issued": 0,
            "build_sha": "environment-sha",
        }
        identity = client.get("https://site.example/.well-known/web-identity").json()
        assert identity["accounts_endpoint"] == "https://mail.example/fedcm/accounts"
        landing = client.get("https://site.example/").text
        assert 'href="https://rp.example"' in landing
        assert "# selected EVP_EXAMPLES_DIR" in _page_text(landing)
        assert client.get(site.JWKS_PATH).json()["keys"][0]["kid"] == "environment-test"


def test_real_markers_and_landing(client: TestClient) -> None:
    response = client.get(SITE + "/")
    assert response.status_code == 200
    text = _page_text(response.text)
    assert 'pip install "pyevp[all]"' in text
    for url in (
        RP,
        "https://pyevp.readthedocs.io/",
        "https://pyevp.readthedocs.io/ja/latest/",
        "https://github.com/gaato/pyevp",
        "https://pypi.org/project/pyevp/",
        "https://github.com/gaato/pyevp/blob/main/LICENSE",
        "https://pyevp.readthedocs.io/en/latest/compatibility.html",
    ):
        assert f'href="{url}"' in response.text
    for ident, label, path in site.EXAMPLES:
        source = site.EXAMPLES_DIR / path
        lines = source.read_text().splitlines()
        assert sum(line.strip() == "# landing:start" for line in lines) == 1
        assert sum(line.strip() == "# landing:end" for line in lines) == 1
        code = site.extract_example(source)
        assert 10 <= len(code.splitlines()) <= 30
        assert "nonce" in code
        assert ".verify(" in code
        assert "except EVPError" in code
        assert code in text
        assert f'<section id="example-{ident}"' in response.text
        assert f">{label}</h3>" in response.text
    assert "# landing:start" not in response.text
    assert "/* test stylesheet */" in response.text
    assert "@media (prefers-color-scheme: dark)" in response.text
    assert 'role="tabpanel"' not in response.text  # No-JS sections stay visible.
    assert "ArrowRight" in response.text
    assert "ArrowLeft" in response.text


@pytest.mark.parametrize(
    "source",
    [
        "pass\n",
        "# landing:start\npass\n",
        "# landing:end\npass\n",
        "# landing:start\n# landing:start\npass\n# landing:end\n",
        "# landing:start\npass\n# landing:end\n# landing:end\n",
        "# landing:end\npass\n# landing:start\n",
    ],
)
def test_invalid_markers_raise(tmp_path: Path, source: str) -> None:
    path = tmp_path / "app.py"
    path.write_text(source)
    with pytest.raises(ValueError, match="exactly one ordered landing marker pair"):
        site.extract_example(path)


def test_marker_dedent(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("outside\n    # landing:start\n    if True:\n        pass\n    # landing:end\n")
    assert site.extract_example(path) == "if True:\n    pass\n"


def test_missing_example_refuses_startup(tmp_path: Path, stylesheet: Path) -> None:
    app = site.create_app(dev=True, examples_dir=tmp_path, stylesheet_path=stylesheet)
    with pytest.raises(FileNotFoundError), TestClient(app):
        pass


def test_landing_is_rendered_once(application: Starlette, stylesheet: Path) -> None:
    with TestClient(application, base_url=SITE) as client:
        before = client.get("/").text
        stylesheet.write_text("/* changed after startup */")
        assert client.get("/").text == before


def test_formatter_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def without_plugin(name: str) -> type:
        if name.startswith("a11y-"):
            raise ClassNotFound(name)
        return get_style_by_name(name)

    monkeypatch.setattr(site, "get_style_by_name", without_plugin)
    assert site._formatter("a11y-light", "default").style == get_style_by_name("default")
    assert site._formatter("a11y-dark", "native").style == get_style_by_name("native")


def test_security_headers(client: TestClient) -> None:
    for url in (SITE + "/", MAIL + "/", MAIL + "/healthz"):
        response = client.get(url)
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
