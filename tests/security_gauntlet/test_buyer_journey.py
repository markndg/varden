"""Smoke the buyer page. Skips until the UI bundle and Playwright are present."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "demos" / "security-gauntlet" / "frontend" / "dist"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("playwright.sync_api")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(not (DIST / "index.html").is_file(), reason="gauntlet UI has not been built")
def test_buyer_can_run_prompt_injection_and_see_a_real_verdict():
    from playwright.sync_api import sync_playwright
    import uvicorn

    from demos.security_gauntlet_loader import load_runner
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles

    runner = load_runner()
    runs: dict[str, dict] = {}
    app = FastAPI()

    @app.get("/api/capabilities")
    def capabilities():
        return {"checkout": runner.git_commit(), "version": runner.varden_version(), "os_enforcement_in_this_tree": False}

    @app.get("/api/scenarios")
    def scenarios():
        return {"scenarios": [{"id": "prompt-injection", "title": "Prompt injection and authority escalation"}]}

    @app.post("/api/scenarios/{scenario_id}/run")
    def run(scenario_id: str):
        if scenario_id != "prompt-injection":
            raise HTTPException(status_code=404)
        record = runner.run_scenario(scenario_id)
        runs[record["run_id"]] = record
        return record

    @app.get("/api/runs/{run_id}/report.html", response_class=HTMLResponse)
    def report(run_id: str):
        return HTMLResponse(runner.render_html(runs[run_id]))

    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="ui")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except Exception as exc:
                if "Executable doesn't exist" in str(exc):
                    pytest.skip("Playwright Chromium is not installed. CI runs playwright install before this test.")
                raise
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
            page.get_by_role("button", name="Execute baseline and protected run").click()
            page.get_by_text("Overall scenario outcome: VERIFIED_PREVENTED").wait_for(timeout=30_000)
            body = page.inner_text("body")
            assert "Baseline execution: OBSERVED_ONLY" in body
            assert "Protected execution (untrusted_export): VERIFIED_PREVENTED" in body
            assert "Overall scenario outcome: VERIFIED_PREVENTED" in body
            assert "OS enforcement in this tree: no" in body
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
