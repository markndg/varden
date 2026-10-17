"""P0-1: historical audit migration is a logical rewrite, not secure erasure."""

from __future__ import annotations

import json
import sqlite3

import pytest

from varden.audit_migrate import redact_migrate, verify_manifest
from varden.stores import EventStore

CANARY = "sk-migrationcanaryvalue0001"
SECRET = "migration-signing-secret"


def _db(tmp_path) -> str:
    return str(tmp_path / "varden.db")


def _seed(db: str) -> tuple[int, int]:
    store = EventStore(db)
    first = store.log(
        {
            "timestamp": 1.0,
            "action": {"type": "tool_call", "tool": "echo", "args": {"password": CANARY}},
            "decision": {"action": "allow"},
            "status": "allowed",
            "tenant_id": "default",
        }
    )
    second = store.log(
        {
            "timestamp": 2.0,
            "action": {"type": "tool_call", "tool": "echo", "args": {"note": "kept"}},
            "decision": {"action": "allow"},
            "status": "allowed",
            "tenant_id": "default",
        }
    )
    return first, second


def test_migration_is_idempotent_and_the_manifest_is_signed(tmp_path):
    db = _db(tmp_path)
    _seed(db)
    before = EventStore(db).verify_integrity()
    assert before["valid"] is True
    first = redact_migrate(db, master_secret=SECRET)
    assert CANARY not in json.dumps(EventStore(db).list_events_ascending())
    assert verify_manifest(db, master_secret=SECRET) is True
    assert verify_manifest(db, master_secret="wrong-secret-value!!") is False
    second = redact_migrate(db, master_secret=SECRET)
    assert second["replacement_head"] == first["replacement_head"]
    assert second["affected_records"] == 0
    assert EventStore(db).verify_integrity()["valid"] is True
    with sqlite3.connect(db) as conn:
        payload, signature = conn.execute(
            "SELECT payload_json, signature FROM audit_migration_manifests ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.execute(
            "UPDATE audit_migration_manifests SET payload_json = ? WHERE id = (SELECT MAX(id) FROM audit_migration_manifests)",
            (payload.replace("redact-migrate", "tampered"),),
        )
        conn.commit()
    assert verify_manifest(db, master_secret=SECRET) is False
    assert signature


def test_interrupted_migration_rolls_back(tmp_path, monkeypatch):
    db = _db(tmp_path)
    _seed(db)
    original = EventStore(db).verify_integrity()
    calls = {"n": 0}
    real = __import__("varden.audit_migrate", fromlist=["compute_event_hash"]).compute_event_hash

    def fail_on_second(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("interrupted")
        return real(*args, **kwargs)

    monkeypatch.setattr("varden.audit_migrate.compute_event_hash", fail_on_second)
    with pytest.raises(RuntimeError):
        redact_migrate(db, master_secret=SECRET)
    store = EventStore(db)
    assert store.verify_integrity() == original or store.verify_integrity()["valid"] is True
    rendered = json.dumps(store.list_events_ascending())
    assert CANARY in rendered
    with sqlite3.connect(db) as conn:
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'audit_migration_manifests'"
        ).fetchone()
    assert table is None or conn_count(db) == 0


def conn_count(db: str) -> int:
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT COUNT(*) FROM audit_migration_manifests").fetchone()
    return int(row[0])


def test_migration_does_not_claim_wal_erasure(tmp_path):
    db = _db(tmp_path)
    _seed(db)
    manifest = redact_migrate(db, master_secret=SECRET)
    assert "WAL" in manifest["remanence"]
    assert "secure erasure" in manifest["remanence"]
    logical = json.dumps(EventStore(db).list_events_ascending())
    assert CANARY not in logical
