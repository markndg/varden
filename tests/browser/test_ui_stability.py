"""Geometry and coverage-gap checks for the dashboard.

These tests use the built UI served by ``python -m varden.api``.
Rebuild ``frontend`` before running them after a UI change.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHOTS = ROOT / "data" / "reports" / "ui-stability"

pytest.importorskip("playwright")
from playwright.sync_api import expect, sync_playwright  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http(host: str, port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> bytes:
    head = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}", "Connection: close"]
    payload = body or b""
    extra = dict(headers or {})
    if payload:
        extra.setdefault("Content-Type", "application/json")
        extra["Content-Length"] = str(len(payload))
    for key, value in extra.items():
        head.append(f"{key}: {value}")
    raw = ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + payload
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(raw)
        chunks: list[bytes] = []
        while True:
            part = sock.recv(8192)
            if not part:
                break
            chunks.append(part)
    return b"".join(chunks)


@pytest.fixture(scope="module")
def control_plane(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ui-stability")
    port = _free_port()
    policy = tmp / "policy.json"
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}\n', encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "VARDEN_ENV": "dev",
            "VARDEN_ENABLE_DEV_BOOTSTRAP": "true",
            "VARDEN_DB_PATH": str(tmp / "varden.db"),
            "VARDEN_AUTH_DB_PATH": str(tmp / "auth.db"),
            "VARDEN_POLICY_FILE": str(policy),
            "VARDEN_HOST": "127.0.0.1",
            "VARDEN_PORT": str(port),
            "VARDEN_CONFIG": "",
            "VARDEN_TI_ENABLED": "false",
            "PYTHONUNBUFFERED": "1",
        }
    )
    output: list[str] = []

    def _pump(stream) -> None:
        for line in stream:
            output.append(line)

    proc = subprocess.Popen(
        [sys.executable, "-m", "varden.api"],
        cwd=str(tmp),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    threading.Thread(target=_pump, args=(proc.stdout,), daemon=True).start()
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"control plane exited: {''.join(output)[-2000:]}")
        try:
            body = _http("127.0.0.1", port, "GET", "/health/live")
        except OSError:
            time.sleep(0.2)
            continue
        if b" 200 " in body.split(b"\r\n", 1)[0]:
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"control plane did not become ready: {''.join(output)[-2000:]}")
    yield {"base": f"http://127.0.0.1:{port}", "port": port, "proc": proc}
    proc.send_signal(__import__("signal").SIGINT)
    try:
        proc.wait(timeout=12)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _agent_key(port: int) -> str:
    body = _http("127.0.0.1", port, "GET", "/health").decode("latin1", errors="ignore")
    marker = '"bootstrap_agent_api_key":"'
    start = body.find(marker)
    assert start >= 0, body[-400:]
    return body[start + len(marker):].split('"', 1)[0]


def _bounds(page):
    return page.evaluate(
        """() => {
          const panel = document.querySelector('[data-testid="graph-panel"]');
          const sidebar = document.querySelector('.sidebar');
          const nodes = [...document.querySelectorAll('[data-testid^="pa-node-"]')];
          const panelBox = panel.getBoundingClientRect();
          const sideBox = sidebar.getBoundingClientRect();
          const escaped = [];
          for (const node of nodes) {
            const box = node.getBoundingClientRect();
            const outsidePanel = box.width < 1 || box.left < panelBox.left - 1 || box.right > panelBox.right + 1
              || box.top < panelBox.top - 1 || box.bottom > panelBox.bottom + 1;
            const overlapsNav = box.left < sideBox.right - 1 && box.right > sideBox.left + 1
              && box.top < sideBox.bottom - 1 && box.bottom > sideBox.top + 1;
            if (outsidePanel || overlapsNav) {
              escaped.push({ id: node.getAttribute('data-testid'), outsidePanel, overlapsNav });
            }
          }
          return { count: nodes.length, escaped, panel: { w: panelBox.width, h: panelBox.height } };
        }"""
    )


def test_coverage_empty_then_populated(control_plane):
    SHOTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"{control_plane['base']}/ui/coverage-gaps", wait_until="load")
        expect(page.locator("h1")).to_contain_text("Policy coverage gaps", timeout=15000)
        empty = page.locator('[data-testid="coverage-empty"]')
        expect(empty).to_contain_text("No observed events", timeout=15000)
        expect(empty).to_contain_text("not proof")
        page.screenshot(path=str(SHOTS / "coverage-empty.png"), full_page=True)

        key = _agent_key(control_plane["port"])
        payload = json.dumps(
            {
                "action": {
                    "type": "tool_call",
                    "tool": "gap-fixture-tool",
                    "method": "run",
                    "agent_name": "gap-fixture-agent",
                    "trace_id": "gap-fixture-trace",
                    "args": {"command": "uncovered"},
                },
                "decision": {"action": "allow", "reason": "no applicable policy"},
                "status": "allowed",
            }
        ).encode()
        logged = _http(
            "127.0.0.1",
            control_plane["port"],
            "POST",
            "/v1/actions/log",
            payload,
            {"x-api-key": key},
        )
        assert b" 200 " in logged.split(b"\r\n", 1)[0], logged[:400]

        page.goto(f"{control_plane['base']}/ui/coverage-gaps", wait_until="load")
        expect(page.get_by_text("gap-fixture-tool").first).to_be_visible(timeout=15000)
        expect(page.locator('[data-testid="coverage-empty"]')).to_have_count(0)
        page.screenshot(path=str(SHOTS / "coverage-populated.png"), full_page=True)
        assert not errors, errors
        browser.close()


def test_predictive_graph_stays_inside_the_viewport(control_plane):
    SHOTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"{control_plane['base']}/ui/predictive", wait_until="load")
        expect(page.locator("h1")).to_contain_text("Predictive Authority", timeout=15000)
        page.locator('[data-testid="load-demo"]').evaluate("el => el.click()")
        expect(page.locator('[data-testid^="pa-node-"]').first).to_be_visible(timeout=15000)
        bounds = _bounds(page)
        assert bounds["count"] >= 3, bounds
        assert bounds["escaped"] == [], bounds
        doc_overflow = page.evaluate(
            "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 2"
        )
        assert doc_overflow, "predictive page overflows the viewport horizontally"
        page.screenshot(path=str(SHOTS / "predictive-desktop.png"), full_page=True)

        page.locator(".sidebar .nav__item").first.hover()
        expect(page.locator('[data-testid="pa-tooltip"]')).to_have_count(0)

        page.locator('[data-testid^="pa-node-"]').first.hover()
        tip = page.locator('[data-testid="pa-tooltip"]')
        expect(tip).to_be_visible()
        relation = page.evaluate(
            """() => {
              const tip = document.querySelector('[data-testid="pa-tooltip"]').getBoundingClientRect();
              const panel = document.querySelector('[data-testid="graph-panel"]').getBoundingClientRect();
              const side = document.querySelector('.sidebar').getBoundingClientRect();
              return {
                inside: tip.left >= panel.left - 1 && tip.right <= panel.right + 1 && tip.top >= panel.top - 1 && tip.bottom <= panel.bottom + 1,
                overlapsNav: tip.left < side.right && tip.right > side.left && tip.top < side.bottom && tip.bottom > side.top,
              };
            }"""
        )
        assert relation["inside"], relation
        assert not relation["overlapsNav"], relation

        page.locator('[data-testid="predictive-graph"]').dispatch_event("wheel", {"deltaY": 200})
        page.locator('[data-testid="mode-before"]').evaluate("el => el.click()")
        page.locator('[data-testid="mode-trajectory"]').evaluate("el => el.click()")
        page.locator("button", has_text="Fit").evaluate("el => el.click()")
        again = _bounds(page)
        assert again["count"] >= 1
        assert again["escaped"] == [], again

        page.locator('[data-testid="toggle-inspector"]').evaluate("el => el.click()")
        expect(page.locator('[data-testid="evidence-inspector"]')).to_have_count(0)
        page.locator('[data-testid="toggle-inspector"]').evaluate("el => el.click()")
        expect(page.locator('[data-testid="evidence-inspector"]')).to_be_visible()

        page.set_viewport_size({"width": 1000, "height": 800})
        page.locator('[data-testid="load-demo"]').evaluate("el => el.click()")
        expect(page.locator('[data-testid^="pa-node-"]').first).to_be_visible(timeout=15000)
        narrow = _bounds(page)
        assert narrow["escaped"] == [], narrow
        visible = page.evaluate(
            """() => {
              const panel = document.querySelector('[data-testid="graph-panel"]').getBoundingClientRect();
              return panel.left >= -1 && panel.right <= window.innerWidth + 1 && panel.width > 200;
            }"""
        )
        assert visible, "graph panel is outside the narrow viewport"
        page.screenshot(path=str(SHOTS / "predictive-narrow.png"), full_page=True)
        assert not errors, errors
        browser.close()


ROUTES = [
    ("/ui", "Trace and flow mission control"),
    ("/ui/impact", "Rule impact intelligence"),
    ("/ui/rules", "Policy workspace"),
    ("/ui/coverage-gaps", "Policy coverage gaps"),
    ("/ui/web-shield", "Web Shield"),
    ("/ui/authority", "Authority & Provenance"),
    ("/ui/predictive", "Predictive Authority"),
    ("/ui/threat-intelligence", "Threat Intelligence"),
]


def test_page_headers_stay_content_sized(control_plane):
    """Short titles must not stretch into empty header panels, and the page must not scroll sideways."""
    shots = ROOT / "data" / "reports" / "ui-consistency" / "after"
    shots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        for path, heading in ROUTES:
            page.goto(f"{control_plane['base']}{path}", wait_until="load")
            expect(page.locator("h1")).to_contain_text(heading, timeout=15000)
            page.wait_for_timeout(250)
            slug = path.strip("/").replace("/", "-") or "ui"
            page.screenshot(path=str(shots / f"{slug}-1440.png"))
            geometry = page.evaluate(
                """() => {
                  const header = document.querySelector('[data-testid="page-header"]');
                  const box = header.getBoundingClientRect();
                  const doc = document.documentElement;
                  const kpis = [...document.querySelectorAll('.metricsRow .metricCard')];
                  const tops = kpis.map((node) => Math.round(node.getBoundingClientRect().top));
                  const sameRow = tops.length < 2 || Math.max(...tops) - Math.min(...tops) < 12;
                  return {
                    headerH: Math.round(box.height),
                    overflow: doc.scrollWidth > doc.clientWidth + 2,
                    scrollW: doc.scrollWidth,
                    clientW: doc.clientWidth,
                    kpiCount: kpis.length,
                    kpiSameRow: sameRow,
                  };
                }"""
            )
            assert geometry["headerH"] < 180, (path, geometry)
            assert not geometry["overflow"], (path, geometry)
            if path == "/ui":
                assert geometry["kpiCount"] == 5, geometry
                assert geometry["kpiSameRow"], geometry
        page.set_viewport_size({"width": 768, "height": 900})
        for path, heading in ROUTES:
            page.goto(f"{control_plane['base']}{path}", wait_until="load")
            expect(page.locator("h1")).to_contain_text(heading, timeout=15000)
            narrow = page.evaluate(
                """() => {
                  const header = document.querySelector('[data-testid="page-header"]').getBoundingClientRect();
                  const doc = document.documentElement;
                  return { headerH: Math.round(header.height), overflow: doc.scrollWidth > doc.clientWidth + 2 };
                }"""
            )
            assert narrow["headerH"] < 240, (path, narrow)
            assert not narrow["overflow"], (path, narrow)
        assert not errors, errors
        browser.close()
