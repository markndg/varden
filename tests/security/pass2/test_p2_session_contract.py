"""P0-5: guarded sessions must fail closed, and env vars must not weaken them.

Baseline: with VARDEN_FAIL_MODE=closed and VARDEN_MONITOR_FAIL_MODE unset,
the shim defaulted to fail_mode=open and created the marker file while the
control plane on port 9 was down.
"""

from __future__ import annotations

import json
import stat
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from varden.runtime.coverage import _CATALOG
from varden_monitor.session_contract import build_contract, verify_key

SECRET = "session-signing-secret"


def _install_tool(tmp_path: Path, marker: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "markertool"
    tool.write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\n", encoding="utf-8")
    tool.chmod(tool.stat().st_mode | stat.S_IEXEC)


def _arm(
    monkeypatch,
    tmp_path: Path,
    marker: Path,
    *,
    mode: str = "guarded",
    fail_mode: str = "closed",
    session_id: str = "sess-1",
    contract_session: str | None = None,
    ttl: int = 3600,
    now: float | None = None,
    tamper: bool = False,
    base_url: str = "http://127.0.0.1:9",
) -> dict:
    _install_tool(tmp_path, marker)
    contract = build_contract(
        master_secret=SECRET,
        session_id=contract_session or session_id,
        principal="tester",
        mode=mode,
        fail_mode=fail_mode,
        trace_id="trace-1",
        orig_path=str(tmp_path / "bin"),
        ttl_seconds=ttl,
        now=now,
    )
    if tamper:
        contract["signature"] = "0" * 64
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setenv("VARDEN_SESSION_CONTRACT", str(path))
    monkeypatch.setenv("VARDEN_SESSION_VERIFY_KEY", verify_key(SECRET).hex())
    monkeypatch.setenv("VARDEN_SESSION_ID", session_id)
    monkeypatch.setenv("VARDEN_SESSION_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VARDEN_BASE_URL", base_url)
    monkeypatch.setenv("VARDEN_MODE", mode)
    monkeypatch.setenv("VARDEN_FAIL_MODE", fail_mode)
    monkeypatch.delenv("VARDEN_MONITOR_FAIL_MODE", raising=False)
    monkeypatch.delenv("VARDEN_SESSION_PASSIVE", raising=False)
    monkeypatch.setenv("VARDEN_SESSION_ORIG_PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.setattr(sys, "argv", ["shim_runner", "markertool"])
    return contract


def _run() -> int:
    from varden_monitor.shim_runner import main

    return main()


def test_guarded_command_does_not_run_when_control_plane_is_down(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker)
    assert _run() == 126
    assert not marker.exists()


def test_environment_cannot_downgrade_guarded_to_observe(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker)
    monkeypatch.setenv("VARDEN_MODE", "observe")
    monkeypatch.setenv("VARDEN_MONITOR_FAIL_MODE", "open")
    assert _run() == 126
    assert not marker.exists()
    audit = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert audit["event"] == "override_rejected"
    assert audit["contract_mode"] == "guarded"
    assert audit["authoritative_decision"] is None


def test_invalid_contract_cannot_permit_execution(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker, tamper=True)
    assert _run() == 126
    assert not marker.exists()


def test_expired_contract_cannot_permit_execution(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker, now=time.time() - 7200, ttl=60)
    assert _run() == 126
    assert not marker.exists()


def test_contract_for_another_session_cannot_be_reused(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker, contract_session="sess-other")
    assert _run() == 126
    assert not marker.exists()


def test_missing_contract_cannot_permit_execution(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker)
    monkeypatch.delenv("VARDEN_SESSION_CONTRACT")
    assert _run() == 126
    assert not marker.exists()


def test_observe_mode_still_runs_when_the_control_plane_is_down(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _arm(monkeypatch, tmp_path, marker, mode="observe", fail_mode="open")
    assert _run() == 0
    assert marker.exists()


def test_malformed_guard_response_does_not_execute(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("content-length") or 0)
            self.rfile.read(length)
            if self.path.endswith("/confirm"):
                body = b'{"ok": true}'
            else:
                body = b'{"decision": {"action": "not-a-real-action"}}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread_started = True
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        marker = tmp_path / "ran"
        port = server.server_address[1]
        _arm(monkeypatch, tmp_path, marker, base_url=f"http://127.0.0.1:{port}")
        _run()
        assert not marker.exists()
    finally:
        if thread_started:
            server.shutdown()


def test_session_shim_is_not_reported_as_full_enforcement():
    surface = next(item for item in _CATALOG if item["name"] == "subprocess")
    assert surface["default_status"] != "ENFORCED"
    assert any("not an OS sandbox" in note for note in surface["limitations"])


def test_control_plane_rejects_an_unregistered_or_forged_contract(tmp_path):
    from tests.runtime.helpers import make_app_client

    contract = build_contract(
        master_secret="dev-secret",
        session_id="sess-1",
        principal="tester",
        mode="guarded",
        fail_mode="closed",
        trace_id="trace-1",
        orig_path=str(tmp_path),
    )
    client, _app = make_app_client(str(tmp_path))
    key = client.get("/health").json()["bootstrap_api_key"]
    forged = dict(contract)
    forged["signature"] = "0" * 64
    rejected = client.post("/runtime/session/contract", headers={"x-api-key": key}, json=forged)
    assert rejected.status_code == 403
    registered = client.post("/runtime/session/contract", headers={"x-api-key": key}, json=contract)
    assert registered.status_code == 200
    confirmed = client.post("/runtime/session/contract/confirm", headers={"x-api-key": key}, json=contract)
    assert confirmed.status_code == 200
    assert confirmed.json()["fail_mode"] == "closed"
