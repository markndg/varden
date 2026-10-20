"""P0-1: Predictive Authority snapshots use the shared redactor before hashing.

The hash is the SHA-256 of the canonical bytes that are stored. A second
redaction pass after that hash is not applied.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from varden.db import connect, init_db
from varden.models import Action, EventRecord
from varden.predictive_authority.persistence import load_historical_predictive_event, persist_predictive_snapshot
from varden.predictive_authority.registry import reset_authority_registry
from varden.predictive_authority.snapshot import (
    HISTORICAL_SCHEMA_VERSION,
    build_historical_snapshot,
    redact_value,
    snapshot_content_hash,
)
from varden.predictive_authority.snapshot_store import PredictiveSnapshotStore
from varden.stores import EventStore
from tests.predictive_authority.helpers import allow_decision, fresh_engine, untrusted_meta

CANARY = "sk-vardenp01snapshotcanary"
PASSWORD = "hunter2-snapshot"


def _result(summary: dict) -> SimpleNamespace:
    return SimpleNamespace(
        recommendation=None,
        explanation=None,
        delta=None,
        findings=[],
        final_decision=SimpleNamespace(action="allow"),
        existing_decision="allow",
        analysis_status="complete",
        analysis_incomplete_reason=None,
        error=None,
        config=SimpleNamespace(mode="observe"),
        facts=SimpleNamespace(summary=summary),
        before_snapshot={"note": "stable"},
        after_snapshot={"note": "stable"},
        budget=None,
        elapsed_ms=1,
    )


def _build(summary: dict, *, tenant: str = "default") -> dict:
    return build_historical_snapshot(
        result=_result(summary),
        graph={"nodes": [{"label": "café"}], "edges": [], "truncated": False},
        tenant_id=tenant,
        trace_id="snap-trace",
    )


def test_nested_sensitive_keys_are_redacted():
    snap = _build({"outer": {"password": PASSWORD, "items": [{"api_key": CANARY}]}})
    assert PASSWORD not in json.dumps(snap)
    assert CANARY not in json.dumps(snap)
    assert snap["action_summary"]["outer"]["password"].startswith("[REDACTED:password:")
    assert snap["action_summary"]["outer"]["items"][0]["api_key"].startswith("[REDACTED:")


def test_credentials_under_benign_keys_are_redacted():
    snap = _build({"comment": CANARY})
    assert CANARY not in json.dumps(snap)
    assert snap["action_summary"]["comment"].startswith("[REDACTED:openai_key:")


def test_stored_blob_and_hash_match_and_reject_a_changed_byte(tmp_path):
    snap = _build({"comment": CANARY, "kept": "weather"})
    db = str(tmp_path / "pa.db")
    store = PredictiveSnapshotStore(db)
    store.save(event_id=1, tenant_id="default", snapshot=snap, content_hash=snap["content_hash"])
    raw = (tmp_path / "pa.db").read_bytes()
    assert CANARY.encode() not in raw
    assert b"weather" in raw
    loaded = store.get(1, tenant_id="default")
    assert loaded is not None
    assert loaded["integrity"] == "ok"
    assert loaded["content_hash"] == snap["content_hash"]
    with connect(db) as conn:
        blob = conn.execute("SELECT snapshot_json FROM predictive_snapshots WHERE event_id=1").fetchone()[0]
        assert hashlib.sha256(blob.encode("utf-8")).hexdigest() == snap["content_hash"]
        flipped = blob.replace("weather", "weatheR", 1)
        conn.execute("UPDATE predictive_snapshots SET snapshot_json=? WHERE event_id=1", (flipped,))
        conn.commit()
    assert store.get(1)["integrity"] == "failed"


def test_redaction_is_idempotent_and_order_independent():
    payload = {"b": PASSWORD, "a": {"token": "abc", "note": "café"}}
    once = redact_value(payload, tenant_id="tenant-a")
    twice = redact_value(once, tenant_id="tenant-a")
    assert once == twice
    left = redact_value({"z": CANARY, "a": 1}, tenant_id="default")
    right = redact_value({"a": 1, "z": CANARY}, tenant_id="default")
    assert snapshot_content_hash({"schema_version": 2, **left}) == snapshot_content_hash({"schema_version": 2, **right})


def test_api_and_export_do_not_reveal_secrets(tmp_path):
    reset_authority_registry()
    db = str(tmp_path / "api.db")
    init_db(db)
    engine = fresh_engine(mode="observe", max_depth=2)
    action = Action(
        type="http_request",
        tool="requests.get",
        url="https://example.test/weather",
        args={"headers": {"Authorization": f"Bearer {CANARY}"}, "note": "public"},
        metadata=untrusted_meta(),
        trace_id="api-snap",
        tenant_id="default",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    assert CANARY in json.dumps(action.args)
    assert CANARY not in json.dumps(result.historical_snapshot)
    events = EventStore(db)
    event_id = events.log(
        EventRecord.new(
            action={
                "tool": "requests.get",
                "trace_id": "api-snap",
                "metadata": {"predictive_authority": {"snapshot_content_hash": result.historical_snapshot["content_hash"]}},
            },
            decision=final.to_dict(),
            status="allowed",
            tenant_id="default",
            trace_id="api-snap",
        ).to_dict()
    )
    action._varden_pa_snapshot = result.historical_snapshot
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="default")
    view = load_historical_predictive_event(event_store=events, db_path=db, event_id=event_id, tenant_id="default")
    exported = json.dumps(view)
    assert view["availability"] == "ok"
    assert CANARY not in exported
    assert CANARY.encode() not in (tmp_path / "api.db").read_bytes()


def test_existing_clean_snapshot_remains_verifiable(tmp_path):
    snap = _build({"kept": "forecast"})
    store = PredictiveSnapshotStore(str(tmp_path / "clean.db"))
    store.save(event_id=4, tenant_id="default", snapshot=snap, content_hash=snap["content_hash"])
    loaded = store.get(4)
    assert loaded["integrity"] == "ok"
    assert loaded["trusted"] is True
    assert loaded["action_summary"]["kept"] == "forecast"


def test_historical_plaintext_is_withheld_and_migration_keeps_the_commitment(tmp_path):
    db = str(tmp_path / "hist.db")
    init_db(db)
    body = {
        "schema_version": HISTORICAL_SCHEMA_VERSION,
        "final_decision": "allow",
        "password": PASSWORD,
        "note": "keep-me",
    }
    original = snapshot_content_hash(body)
    body["content_hash"] = original
    events = EventStore(db)
    event_id = events.log(
        EventRecord.new(
            action={"tool": "old", "metadata": {"predictive_authority": {"snapshot_content_hash": original, "has_snapshot": True}}},
            decision={"action": "allow"},
            status="allowed",
            tenant_id="default",
            trace_id="hist",
        ).to_dict()
    )
    with connect(db) as conn:
        conn.execute(
            """
            INSERT INTO predictive_snapshots(event_id, tenant_id, created_at, schema_version, content_hash, snapshot_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, "default", 1.0, 1, original, json.dumps(body, sort_keys=True, separators=(",", ":"))),
        )
        conn.commit()
    store = PredictiveSnapshotStore(db)
    loaded = store.get(event_id, tenant_id="default")
    assert loaded["integrity"] == "ok"
    assert loaded["redaction_status"] == "historical_plaintext_withheld"
    assert PASSWORD not in json.dumps(loaded)
    view = load_historical_predictive_event(event_store=events, db_path=db, event_id=event_id, tenant_id="default")
    assert view["availability"] == "ok"
    assert PASSWORD not in json.dumps(view)
    report = store.migrate_plaintext(tenant_id="default")
    assert report["migrated"] == 1
    migrated = store.get(event_id, tenant_id="default")
    assert migrated["integrity"] == "ok"
    assert PASSWORD not in json.dumps(migrated)
    with connect(db) as conn:
        logical = conn.execute("SELECT snapshot_json, content_hash FROM predictive_snapshots").fetchone()
    assert PASSWORD not in logical["snapshot_json"]
    assert logical["content_hash"] != original
    assert store.migration_links(event_id, original_hash=original, replacement_hash=logical["content_hash"])
    again = load_historical_predictive_event(event_store=events, db_path=db, event_id=event_id, tenant_id="default")
    assert again["availability"] == "ok"
    assert PASSWORD not in json.dumps(again)


def test_deep_snapshot_is_bounded_and_marker_is_not_a_password_hash():
    nested: dict = {"leaf": PASSWORD}
    for _ in range(40):
        nested = {"wrap": nested}
    redacted = redact_value(nested, tenant_id="default")
    assert PASSWORD not in json.dumps(redacted)
    marker = redact_value({"password": PASSWORD}, tenant_id="default")["password"]
    assert marker.startswith("[REDACTED:password:")
    assert hashlib.sha256(PASSWORD.encode()).hexdigest()[:4] not in marker
