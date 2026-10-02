"""End-to-end EVP check with a real Chrome against https://pyevp.dev.

Starts the example issuer (``examples/issuer_fastapi``) behind the ``pyevp-dev``
Cloudflare Tunnel and the example relying party (``examples/fastapi``) on localhost,
then drives a headless Chrome over the DevTools protocol: log in to the issuer, type
the address into the RP's form, submit, and check that the RP verified the token.

Run from the repository root::

    uv run --locked --all-packages --group interop python interop/chrome_evp.py

Environment:

``CHROME``
    Chrome binary (default ``google-chrome``).
``PYEVP_TUNNEL_TOKEN``
    Connector token for the tunnel. When set, ``cloudflared`` is started here (CI);
    otherwise run ``cf tunnels run pyevp-dev`` yourself first.
``INTEROP_OUT``
    Directory for logs and screenshots (default: a temporary directory).
``INTEROP_HEADFUL``
    Set to show the browser window.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import websockets

from pyevp.issuer import SigningKey

ROOT = Path(__file__).resolve().parent.parent
ISSUER = "https://pyevp.dev"
ISSUER_PORT = 8000  # the tunnel's ingress points here
RP_PORT = 8001
RP = f"http://localhost:{RP_PORT}"
EMAIL = "test@pyevp.dev"
CDP_PORT = 9333
ATTEMPTS = 3

# Uvicorn's access log line for Chrome's issuance request.
ISSUANCE_LOG = re.compile(r'"POST /email-verification/issuance HTTP/[\d.]+" (\d{3})')

# Chrome asks once per address before its first issuance ("verify this email
# automatically?"). The prompt is browser UI that DevTools cannot click, so the
# profile starts with the answer Chrome stores after the user accepts.
PREFERENCES = {
    "autofill": {
        "email_verification_state": {
            EMAIL: {"allowed": True, "issuer_site": ISSUER, "timestamp": "13435404633497937"}
        }
    },
    # Keep the "save password?" bubble out of the way after the issuer login.
    "credentials_enable_service": False,
    "profile": {"password_manager_enabled": False},
}


class InteropError(Exception):
    pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def fetch_json(url: str) -> Any:
    # Cloudflare's bot protection answers urllib's default User-Agent with 403.
    request = urllib.request.Request(url, headers={"User-Agent": "pyevp-interop"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def wait_for(description: str, check, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        with contextlib.suppress(OSError, ValueError):
            if check():
                return
        if time.monotonic() > deadline:
            raise InteropError(f"timed out waiting for {description}")
        time.sleep(1)


@contextlib.contextmanager
def process(name: str, args: list[str], out: Path, **kwargs: Any) -> Iterator[None]:
    with (out / f"{name}.log").open("w") as logfile:
        proc = subprocess.Popen(args, stdout=logfile, stderr=subprocess.STDOUT, **kwargs)
        try:
            yield
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()


class IssuerLog:
    """Follows the issuer's access log: the only place a token fetch is visible.

    The page cannot see it: Chrome fills the hidden field only when the form is submitted.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0

    def skip_to_end(self) -> None:
        self._offset = self._path.stat().st_size

    def _new_lines(self) -> list[str]:
        with self._path.open("rb") as file:
            file.seek(self._offset)
            data = file.read()
        complete = data[: data.rfind(b"\n") + 1]  # leave a partly written line for later
        self._offset += len(complete)
        return complete.decode(errors="replace").splitlines()

    async def wait_for_token(self, timeout: float) -> None:
        """Wait until the issuer has answered Chrome's issuance request."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self._new_lines():
                if match := ISSUANCE_LOG.search(line):
                    if match[1] != "200":
                        raise InteropError(f"issuer answered the issuance request with {match[1]}")
                    log("issuer issued a token")
                    # Chrome still binds the token to its key; that is local and quick.
                    await asyncio.sleep(1)
                    return
            await asyncio.sleep(0.5)
        raise InteropError("Chrome did not request a token from the issuer")


class DevTools:
    """Just enough of the Chrome DevTools protocol for one page."""

    def __init__(self, ws: websockets.ClientConnection) -> None:
        self._ws = ws
        self._next_id = 0

    async def send(self, method: str, **params: Any) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        await self._ws.send(json.dumps({"id": request_id, "method": method, "params": params}))
        while True:
            message = json.loads(await asyncio.wait_for(self._ws.recv(), 30))
            if message.get("id") != request_id:
                continue  # an event; we poll page state instead
            if "error" in message:
                raise InteropError(f"{method}: {message['error']}")
            return message.get("result", {})

    async def evaluate(self, expression: str) -> Any:
        result = await self.send(
            "Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True
        )
        return result.get("result", {}).get("value")

    async def navigate(self, url: str) -> None:
        await self.send("Page.navigate", url=url)
        await self.wait_loaded()

    async def wait_loaded(self) -> None:
        for _ in range(150):
            await asyncio.sleep(0.2)
            if await self.evaluate("document.readyState") == "complete":
                return
        raise InteropError("page did not finish loading")

    async def click(self, selector: str) -> None:
        """A trusted click: Chrome inserts the token only on a real form submission."""
        box = await self.evaluate(
            f"JSON.stringify(document.querySelector({json.dumps(selector)})"
            ".getBoundingClientRect())"
        )
        rect = json.loads(box)
        x, y = rect["x"] + rect["width"] / 2, rect["y"] + rect["height"] / 2
        for kind in ("mousePressed", "mouseReleased"):
            await self.send(
                "Input.dispatchMouseEvent", type=kind, x=x, y=y, button="left", clickCount=1
            )

    async def key(self, key: str, code: int) -> None:
        for kind in ("rawKeyDown", "keyUp"):
            await self.send(
                "Input.dispatchKeyEvent", type=kind, key=key, code=key, windowsVirtualKeyCode=code
            )

    async def screenshot(self, path: Path) -> None:
        result = await self.send("Page.captureScreenshot", format="png")
        path.write_bytes(base64.b64decode(result["data"]))


async def drive(out: Path, password: str, issuer_log: IssuerLog) -> dict[str, Any]:
    targets = fetch_json(f"http://127.0.0.1:{CDP_PORT}/json")
    page = next(t for t in targets if t["type"] == "page")
    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        tab = DevTools(ws)
        await tab.send("Page.enable")
        try:
            log("logging in to the issuer")
            await tab.navigate(f"{ISSUER}/login")
            await tab.evaluate(
                "(() => { const f = document.forms[0];"
                f" f.email.value = {json.dumps(EMAIL)};"
                f" f.password.value = {json.dumps(password)}; f.submit(); }})()"
            )
            await asyncio.sleep(1)
            await tab.wait_loaded()
            text = await tab.evaluate("document.body.innerText")
            if f"Logged in as {EMAIL}" not in text:
                raise InteropError(f"issuer login failed: {text!r}")

            for attempt in range(1, ATTEMPTS):
                result = await submit_form(tab, issuer_log)
                if result.get("verified"):
                    return result
                # The token arrived too late for this submission; try a fresh form.
                log(f"attempt {attempt} was not verified: {result}")
            return await submit_form(tab, issuer_log)
        finally:
            with contextlib.suppress(Exception):
                await tab.screenshot(out / "final.png")


async def submit_form(tab: DevTools, issuer_log: IssuerLog) -> dict[str, Any]:
    log("filling in the relying party's form")
    await tab.navigate(RP)
    issuer_log.skip_to_end()
    await tab.evaluate("document.querySelector('input[name=email]').focus()")
    await tab.send("Input.insertText", text=EMAIL)
    await tab.key("Tab", 9)  # Chrome starts the check when the field loses focus
    await issuer_log.wait_for_token(timeout=60)

    log("submitting")
    await tab.click("button")
    await asyncio.sleep(1)
    await tab.wait_loaded()
    text = await tab.evaluate("document.body.innerText")
    try:
        return json.loads(text)
    except ValueError:
        raise InteropError(f"unexpected RP response: {text!r}") from None


def run(out: Path) -> None:
    chrome = os.environ.get("CHROME", "google-chrome")
    kid = f"interop-{secrets.token_hex(4)}"
    key = SigningKey.generate("Ed25519", kid=kid)
    password = secrets.token_urlsafe(16)

    tmp = Path(tempfile.mkdtemp(prefix="pyevp-interop-"))
    try:
        key_file = tmp / "signing-key.json"
        key_file.write_text(json.dumps(key.private_jwk()))
        key_file.chmod(0o600)
        profile = tmp / "profile"
        (profile / "Default").mkdir(parents=True)
        (profile / "Default" / "Preferences").write_text(json.dumps(PREFERENCES))

        base_env = {**os.environ}
        base_env.pop("PYEVP_TUNNEL_TOKEN", None)
        issuer_env = {
            **base_env,
            "EVP_ISSUER": ISSUER,
            "EVP_PUBLIC_URL": ISSUER,
            "EVP_EMAIL_DOMAINS": "pyevp.dev",
            "EVP_SIGNING_KEY": str(key_file),
            "EVP_DEMO_USERS": json.dumps({EMAIL: password}),
            "SESSION_SECRET": secrets.token_hex(32),
        }
        rp_env = {**base_env, "EVP_ORIGIN": RP, "SESSION_SECRET": secrets.token_hex(32)}
        uvicorn_args = [sys.executable, "-m", "uvicorn", "app:app", "--port"]
        chrome_args = [
            chrome,
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={CDP_PORT}",
            "--enable-features=EmailVerificationProtocol",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1280,900",
        ]
        if not os.environ.get("INTEROP_HEADFUL"):
            chrome_args.append("--headless=new")
        chrome_args.append("about:blank")

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                process(
                    "issuer",
                    [*uvicorn_args, str(ISSUER_PORT), "--proxy-headers"],
                    out,
                    cwd=ROOT / "examples" / "issuer_fastapi",
                    env=issuer_env,
                )
            )
            stack.enter_context(
                process(
                    "rp",
                    [*uvicorn_args, str(RP_PORT)],
                    out,
                    cwd=ROOT / "examples" / "fastapi",
                    env=rp_env,
                )
            )
            if token := os.environ.get("PYEVP_TUNNEL_TOKEN"):
                stack.enter_context(
                    process(
                        "cloudflared",
                        ["cloudflared", "tunnel", "--no-autoupdate", "run"],
                        out,
                        env={**base_env, "TUNNEL_TOKEN": token},
                    )
                )

            # Another connector (a developer's laptop) could be serving pyevp.dev too.
            # Seeing this run's key id proves the tunnel reaches this issuer.
            log(f"waiting for {ISSUER} to serve kid {kid}")
            wait_for(
                f"{ISSUER} to serve this run's key",
                lambda: any(
                    k.get("kid") == kid
                    for k in fetch_json(f"{ISSUER}/email-verification/jwks")["keys"]
                ),
                timeout=90,
            )

            stack.enter_context(process("chrome", chrome_args, out))
            wait_for("Chrome", lambda: fetch_json(f"http://127.0.0.1:{CDP_PORT}/json/version"))
            version = fetch_json(f"http://127.0.0.1:{CDP_PORT}/json/version")["Browser"]
            log(f"driving {version}")

            result = asyncio.run(drive(out, password, IssuerLog(out / "issuer.log")))
            log(f"relying party answered {result}")
            if result != {"email": EMAIL, "verified": True, "issuer": ISSUER}:
                raise InteropError(f"token was not verified: {result}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    out = Path(os.environ.get("INTEROP_OUT") or tempfile.mkdtemp(prefix="pyevp-interop-out-"))
    out.mkdir(parents=True, exist_ok=True)
    try:
        run(out)
    except (InteropError, urllib.error.URLError) as exc:
        log(f"FAILED: {exc} (logs in {out})")
        return 1
    log("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
