"""P0-1: secret redaction must remove values, not rename keys.

Baseline (before the structural redactor): redact({"password": "hunter2"})
returned {"[REDACTED]": "hunter2"}. The secret stayed visible.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.classification import ClassifierEngine
from varden.redaction import MAX_DEPTH, redact, sensitive_key
from varden.stores import EventStore

CANARY = "varden-canary-p01-7c91e4"
SECRET = "hunter2-canary"


def test_nested_values_are_redacted_at_arbitrary_depth():
    payload = {"outer": [{"note": {"password": SECRET, "ok": "visible"}}]}
    out = redact(payload)
    assert out["outer"][0]["note"]["ok"] == "visible"
    assert SECRET not in json.dumps(out)
    assert out["outer"][0]["note"]["password"].startswith("[REDACTED:password:")


def test_mixed_case_sensitive_keys():
    out = redact({"PassWord": SECRET, "X-API-KEY": "abcd"})
    assert SECRET not in json.dumps(out)
    assert "abcd" not in json.dumps(out)
    assert "PassWord" in out


def test_sensitive_value_under_a_benign_key():
    token = "sk-" + "a" * 20
    out = redact({"note": token, "title": "quarterly report"})
    assert out["title"] == "quarterly report"
    assert token not in json.dumps(out)
    assert out["note"].startswith("[REDACTED:openai_key:")


def test_benign_session_field_is_kept():
    assert sensitive_key("session") is False
    out = redact({"session": "checkout", "session_id": "abc-123"})
    assert out["session"] == "checkout"
    assert out["session_id"] == "abc-123"


def test_classifier_sees_the_unredacted_value():
    raw = {"args": {"password": SECRET}}
    assert ClassifierEngine().classify(raw)["secrets"] is True
    assert SECRET not in json.dumps(redact(raw))


def test_correlation_is_tenant_scoped_and_not_a_plaintext_digest():
    import hashlib

    left = redact({"password": SECRET}, tenant_id="a", master_secret="x" * 32)
    right = redact({"password": SECRET}, tenant_id="b", master_secret="x" * 32)
    assert left["password"] != right["password"]
    digest = hashlib.sha256(SECRET.encode()).hexdigest()[:4]
    assert digest not in left["password"]


@settings(max_examples=40, deadline=None)
@given(
    st.recursive(
        st.one_of(st.text(max_size=20), st.integers(min_value=-5, max_value=5), st.booleans(), st.none()),
        lambda children: st.one_of(
            st.lists(children, max_size=3),
            st.dictionaries(st.sampled_from(["password", "note", "token", "title"]), children, max_size=3),
        ),
        max_leaves=12,
    )
)
def test_hypothesis_redaction_never_returns_a_password_value(value):
    planted = {"wrapper": value, "password": SECRET}
    rendered = json.dumps(redact(planted))
    assert SECRET not in rendered


def test_depth_and_width_are_bounded():
    node: dict = {"password": SECRET}
    for _ in range(MAX_DEPTH + 5):
        node = {"child": node}
    out = redact(node)
    assert SECRET not in json.dumps(out)
    huge = {"note": "a" * 20_000}
    assert "a" * 20_000 not in json.dumps(redact(huge))


def test_http_canary_does_not_reach_storage_or_sse():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        with TemporaryDirectory() as tmp:
            client, app = make_app_client(tmp)
            key = client.get("/health").json()["bootstrap_api_key"]
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            import httpx

            httpx.get(
                f"http://127.0.0.1:{port}/probe",
                headers={"Authorization": f"Bearer {CANARY}", "X-Request": "ok"},
            )
            events = client.get("/events", headers={"x-api-key": key}).json()
            assert events["items"], "guarded HTTP call did not persist an event"
            detail_id = events["items"][0]["id"]
            detail = client.get(f"/events/{detail_id}", headers={"x-api-key": key}).json()
            trace_id = detail["event"]["trace_id"]
            trace = client.get(f"/traces/{trace_id}", headers={"x-api-key": key}).json()
            published = json.dumps(app.state.event_broker.last_message)
            blob = Path(tmp, "varden.db").read_bytes()
            for body in (json.dumps(events), json.dumps(detail), json.dumps(trace), published):
                assert CANARY not in body
            assert CANARY.encode() not in blob
            varden.unpatch_runtime()
    finally:
        server.shutdown()


def test_subprocess_environment_values_are_not_transmitted():
    with TemporaryDirectory() as tmp:
        client, _app = make_app_client(tmp)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        marker = Path(tmp) / "ran"
        subprocess.run(
            ["/bin/sh", "-c", f"touch {marker}"],
            env={"PATH": "/bin:/usr/bin", "VARDEN_CANARY_ENV": CANARY},
            check=True,
        )
        assert marker.exists()
        events = client.get("/events", headers={"x-api-key": key}).text
        assert CANARY not in events
        assert "VARDEN_CANARY_ENV" in events
        assert "env_keys" in events
        varden.unpatch_runtime()


def test_migration_rewrites_rows_and_keeps_a_verifiable_chain():
    secret = "migration-signing-secret"
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "varden.db")
        store = EventStore(db)
        first = store.log(
            {
                "timestamp": 1.0,
                "action": {"type": "tool_call", "tool": "echo", "args": {"password": CANARY}},
                "decision": {"action": "allow"},
                "status": "allowed",
                "tenant_id": "oss",
            }
        )
        second = store.log(
            {
                "timestamp": 2.0,
                "action": {"type": "tool_call", "tool": "echo", "args": {"note": "kept"}},
                "decision": {"action": "allow"},
                "status": "allowed",
                "tenant_id": "oss",
            }
        )
        from varden.audit_migrate import redact_migrate, verify_manifest

        manifest = redact_migrate(db, master_secret=secret)
        assert manifest["affected_records"] >= 1
        assert manifest["rewritten"] is True
        assert verify_manifest(db, master_secret=secret)
        assert store.verify_integrity()["valid"] is True
        rows = store.list_events_ascending()
        assert [row["id"] for row in rows] == [first, second]
        rendered = json.dumps(rows)
        assert CANARY not in rendered
        assert "kept" in rendered
        assert "WAL" in manifest["remanence"]


def test_redact_does_not_raise_with_the_secret_in_the_message():
    class Bad:
        def __str__(self):
            raise RuntimeError(CANARY)

    try:
        out = redact({"note": Bad()})
    except Exception as exc:  # pragma: no cover - must not happen
        pytest.fail(f"redaction raised {type(exc).__name__}")
    assert CANARY not in json.dumps(out)
    assert os.environ.get("VARDEN_CANARY_ENV") != CANARY
