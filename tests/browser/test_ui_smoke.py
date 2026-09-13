"""Browser UI smoke suite — real control plane + Playwright."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytest.importorskip("playwright")
from playwright.sync_api import expect, sync_playwright  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _raw_http_ok(host: str, port: int, path: str) -> bool:
    """Probe without urllib/httpx/requests — those may be monkeypatched by prior tests."""
    try:
        with socket.create_connection((host, port), timeout=1.0) as sock:
            sock.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            chunks: list[bytes] = []
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                chunks.append(part)
                if len(b"".join(chunks)) > 8192:
                    break
        head = b"".join(chunks).split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
        return head.startswith("HTTP/1.") and " 200 " in head
    except OSError:
        return False


@pytest.fixture(scope="module")
def control_plane():
    # Undo any leftover runtime patches from earlier unit tests in this process.
    try:
        import varden

        varden.unpatch_runtime()
    except Exception:
        pass

    port = _free_port()
    db = ROOT / ".tmp" / f"ui-smoke-{port}.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        db.unlink()
    auth_db = db.with_suffix(".auth.db")
    if auth_db.exists():
        auth_db.unlink()
    policy = db.with_suffix(".policy.json")
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}\n', encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "VARDEN_ENV": "dev",
            "VARDEN_ENABLE_DEV_BOOTSTRAP": "true",
            "VARDEN_DB_PATH": str(db),
            "VARDEN_AUTH_DB_PATH": str(auth_db),
            "VARDEN_POLICY_FILE": str(policy),
            "VARDEN_HOST": "127.0.0.1",
            "VARDEN_PORT": str(port),
            "VARDEN_CONFIG": "",
            "PYTHONUNBUFFERED": "1",
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "varden.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 45
    last_err = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            pytest.fail(f"control plane exited early ({proc.returncode}): {out[-2000:]}")
        try:
            if _raw_http_ok("127.0.0.1", port, "/ui/bootstrap"):
                break
            last_err = "tcp up but bootstrap not 200 yet"
        except Exception as exc:  # noqa: BLE001 — probe until ready
            last_err = repr(exc)
            time.sleep(0.25)
        else:
            time.sleep(0.25)
    else:
        proc.kill()
        out = ""
        try:
            if proc.stdout:
                out = proc.stdout.read()
        except Exception:
            pass
        pytest.fail(f"control plane did not become ready: {last_err}\nserver output:\n{out[-2000:]}")

    yield {"base": base, "port": port, "proc": proc, "db": db}
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    for path in (db, auth_db, policy):
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass


@pytest.fixture(scope="module")
def browser_page(control_plane):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        console_errors: list[str] = []
        page_errors: list[str] = []
        failed_requests: list[str] = []

        page.on(
            "console",
            lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
        )
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on(
            "requestfailed",
            lambda req: failed_requests.append(f"{req.method} {req.url} :: {req.failure}"),
        )

        yield {
            "page": page,
            "base": control_plane["base"],
            "console_errors": console_errors,
            "page_errors": page_errors,
            "failed_requests": failed_requests,
        }
        context.close()
        browser.close()


ROUTES = [
    ("/ui", "Trace and flow mission control"),
    ("/ui/rules", "Policy workspace"),
    ("/ui/impact", "Rule impact intelligence"),
    ("/ui/coverage-gaps", "Policy coverage gaps"),
    ("/ui/web-shield", "Web Shield"),
    ("/ui/authority", "Authority & Provenance"),
]


@pytest.mark.parametrize("path,heading", ROUTES)
def test_ui_route_renders(browser_page, path, heading, tmp_path):
    page = browser_page["page"]
    base = browser_page["base"]
    browser_page["console_errors"].clear()
    browser_page["page_errors"].clear()
    browser_page["failed_requests"].clear()
    url = f"{base}{path}"
    try:
        response = page.goto(url, wait_until="networkidle", timeout=30000)
        assert response is not None
        assert response.ok, f"{url} -> {response.status}"

        root = page.locator("#root")
        expect(root).not_to_be_empty(timeout=15000)
        expect(page.locator("h1")).to_contain_text(heading, timeout=15000)

        # Static assets loaded
        css = page.evaluate(
            "() => [...document.styleSheets].some(s => (s.href||'').includes('/static/app/assets/app.css'))"
        )
        assert css is True
        js_ok = page.evaluate(
            "() => [...document.scripts].some(s => (s.src||'').includes('/static/app/assets/app.js'))"
        )
        assert js_ok is True

        # Direct refresh still works
        page.reload(wait_until="networkidle")
        expect(page.locator("h1")).to_contain_text(heading, timeout=15000)

        unexpected_console = [
            e
            for e in browser_page["console_errors"]
            if "favicon" not in e.lower() and "devtools" not in e.lower()
        ]
        assert not browser_page["page_errors"], browser_page["page_errors"]
        assert not unexpected_console, unexpected_console
        critical_fails = [
            f
            for f in browser_page["failed_requests"]
            if "/static/app/assets/" in f or "/ui/bootstrap" in f
        ]
        assert not critical_fails, critical_fails
    except Exception:
        shot = tmp_path / f"fail-{path.strip('/').replace('/', '_') or 'ui'}.png"
        page.screenshot(path=str(shot), full_page=True)
        raise


def test_ui_bootstrap_and_navigation(browser_page):
    page = browser_page["page"]
    base = browser_page["base"]
    page.goto(f"{base}/ui", wait_until="networkidle")
    expect(page.locator("h1")).to_contain_text("Trace and flow mission control")

    # Sidebar navigation (buttons, not anchors)
    page.locator("nav.nav").get_by_role("button", name="Rules Workspace").click()
    expect(page.locator("h1")).to_contain_text("Policy workspace", timeout=15000)

    page.locator("nav.nav").get_by_role("button", name="Web Shield").click()
    expect(page.locator("h1")).to_contain_text("Web Shield", timeout=15000)

    page.locator("nav.nav").get_by_role("button", name="Authority & Provenance").click()
    expect(page.locator("h1")).to_contain_text("Authority", timeout=15000)

    # Bootstrap should have populated a session credential input
    token_input = page.locator('input[aria-label="Control-plane API key or bearer token"]')
    expect(token_input).to_have_value(re.compile(r".+"), timeout=5000)


def test_ui_bootstrap_endpoint_dev_mode(control_plane):
    # Use stdlib http.client after ensuring runtime patches are cleared.
    try:
        import varden

        varden.unpatch_runtime()
    except Exception:
        pass
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", control_plane["port"], timeout=5)
    conn.request("GET", "/ui/bootstrap")
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()
    assert resp.status == 200
    data = json.loads(body)
    assert data["auth"]["mode"] == "bootstrap"
    assert data["auth"].get("ephemeral") is True
    assert data["auth"].get("token")
    assert "dashboard" in data
