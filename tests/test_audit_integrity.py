"""Tamper-evident audit integrity tests."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from varden.audit_integrity import (
    GENESIS_PREV_HASH,
    compute_event_hash,
    policy_fingerprint,
    verify_event_chain,
)
from varden.cli import main as varden_main
from varden.stores import EventStore


def _event(i: int, **overrides):
    base = {
        "timestamp": 1000.0 + i,
        "action": {"type": "tool_call", "tool": f"t{i}", "metadata": {"n": i}},
        "decision": {"action": "allow", "reason": "ok", "matched_rule": None},
        "status": "allowed",
        "input_payload": {"x": i},
        "output_payload": None,
        "error": None,
        "replayable": False,
        "replay_key": None,
        "workflow_id": None,
        "agent_name": "test",
        "parent_event_id": None,
        "trace_id": f"tr-{i}",
        "tenant_id": "tenant-a",
    }
    base.update(overrides)
    return base


def test_valid_chain_and_cli(tmp_path, capsys):
    db = tmp_path / "varden.db"
    store = EventStore(str(db))
    for i in range(5):
        store.log(_event(i))
    result = store.verify_integrity()
    assert result["valid"] is True
    assert result["chained_events"] == 5
    assert result["legacy_events"] == 0
    assert result["integrity_failures"] == 0
    assert varden_main(["audit", "verify", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "Chained events" in out


def test_genesis_prev_hash(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    eid = store.log(_event(0))
    ev = store.get_event(eid)
    assert ev["prev_hash"] == GENESIS_PREV_HASH
    assert ev["event_hash"] == compute_event_hash(
        {k: v for k, v in ev.items() if k not in {"id", "event_hash", "prev_hash"}},
        None,
    )


@pytest.mark.parametrize(
    "field,mutator",
    [
        ("decision", lambda e: {**e, "decision": {**e["decision"], "action": "block"}}),
        ("action", lambda e: {**e, "action": {**e["action"], "tool": "tampered"}}),
        ("timestamp", lambda e: {**e, "timestamp": 999999.0}),
        (
            "provenance",
            lambda e: {
                **e,
                "action": {
                    **e["action"],
                    "metadata": {**(e["action"].get("metadata") or {}), "provenance": {"tampered": True}},
                },
            },
        ),
        (
            "authority",
            lambda e: {
                **e,
                "action": {
                    **e["action"],
                    "metadata": {**(e["action"].get("metadata") or {}), "authority": {"forged": True}},
                },
            },
        ),
        (
            "policy_fingerprint",
            lambda e: {
                **e,
                "action": {
                    **e["action"],
                    "metadata": {
                        **(e["action"].get("metadata") or {}),
                        "audit_integrity": {"policy_fingerprint": "deadbeef"},
                    },
                },
            },
        ),
    ],
)
def test_tamper_detects_field_changes(tmp_path, field, mutator):
    store = EventStore(str(tmp_path / "varden.db"))
    ids = [store.log(_event(i)) for i in range(3)]
    # Tamper middle event in DB
    mid = store.get_event(ids[1])
    tampered = mutator(mid)
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        "UPDATE events SET action_json=?, decision_json=?, timestamp=? WHERE id=?",
        (
            json.dumps(tampered["action"]),
            json.dumps(tampered["decision"]),
            tampered["timestamp"],
            ids[1],
        ),
    )
    conn.commit()
    conn.close()
    result = store.verify_integrity()
    assert result["valid"] is False
    assert result["integrity_failures"] >= 1


def test_tamper_previous_and_event_hash(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    ids = [store.log(_event(i)) for i in range(3)]
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("UPDATE events SET prev_hash=? WHERE id=?", ("00" * 32, ids[1]))
    conn.commit()
    assert store.verify_integrity()["valid"] is False
    conn.execute("UPDATE events SET event_hash=? WHERE id=?", ("11" * 32, ids[2]))
    conn.commit()
    conn.close()
    assert store.verify_integrity()["valid"] is False


def test_delete_middle_event(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    ids = [store.log(_event(i)) for i in range(4)]
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("DELETE FROM events WHERE id=?", (ids[1],))
    conn.commit()
    conn.close()
    result = store.verify_integrity()
    assert result["valid"] is False


def test_reorder_via_prev_swap(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    ids = [store.log(_event(i)) for i in range(3)]
    events = store.list_events_ascending()
    # Swap hashes to simulate reorder confusion
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    a, b = events[1], events[2]
    conn.execute(
        "UPDATE events SET event_hash=?, prev_hash=? WHERE id=?",
        (b["event_hash"], b["prev_hash"], a["id"]),
    )
    conn.execute(
        "UPDATE events SET event_hash=?, prev_hash=? WHERE id=?",
        (a["event_hash"], a["prev_hash"], b["id"]),
    )
    conn.commit()
    conn.close()
    assert store.verify_integrity()["valid"] is False


def test_inserted_fabricated_event(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    store.log(_event(0))
    store.log(_event(1))
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        """INSERT INTO events (
            timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
            replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            123.0,
            json.dumps({"tool": "fake"}),
            json.dumps({"action": "allow"}),
            "allowed",
            None,
            None,
            None,
            0,
            None,
            None,
            "evil",
            None,
            "x",
            "tenant-a",
            "aa" * 32,
            "bb" * 32,
        ),
    )
    conn.commit()
    conn.close()
    assert store.verify_integrity()["valid"] is False


def test_legacy_unchained_then_chained(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        """INSERT INTO events (
            timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
            replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            1.0,
            json.dumps({"tool": "legacy"}),
            json.dumps({"action": "allow"}),
            "allowed",
            None,
            None,
            None,
            0,
            None,
            None,
            "legacy",
            None,
            "l",
            "tenant-a",
            None,
            None,
        ),
    )
    conn.commit()
    conn.close()
    store.log(_event(10))
    store.log(_event(11))
    result = store.verify_integrity()
    assert result["valid"] is True
    assert result["legacy_events"] == 1
    assert result["chained_events"] == 2
    assert result["chain_segments"] == 1


def test_concurrent_writes_linear_chain(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))

    def write(i: int):
        store.log(_event(i, trace_id=f"c-{i}"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(40)))
    result = store.verify_integrity()
    assert result["valid"] is True
    assert result["chained_events"] == 40
    # Unique prev hashes among non-genesis (no duplicate chain heads)
    events = store.list_events_ascending()
    prevs = [e["prev_hash"] for e in events]
    assert prevs[0] == GENESIS_PREV_HASH
    assert len(prevs) == len(set(prevs))  # each prev appears once in a linear chain


def test_policy_fingerprint_stable():
    p1 = {"block": [{"tool": "x"}], "allow": [], "warn": []}
    p2 = {"warn": [], "allow": [], "block": [{"tool": "x"}]}
    assert policy_fingerprint(p1) == policy_fingerprint(p2)


def test_cli_fail_exit_code(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    eid = store.log(_event(0))
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("UPDATE events SET event_hash=? WHERE id=?", ("ff" * 32, eid))
    conn.commit()
    conn.close()
    assert varden_main(["audit", "verify", "--db", str(tmp_path / "varden.db")]) == 1


def test_integrity_failure_does_not_change_decision(tmp_path):
    """INVARIANT 8: verify failure is observational."""
    store = EventStore(str(tmp_path / "varden.db"))
    eid = store.log(_event(0, decision={"action": "allow", "reason": "ok"}))
    before = store.get_event(eid)
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("UPDATE events SET event_hash=? WHERE id=?", ("ee" * 32, eid))
    conn.commit()
    conn.close()
    assert store.verify_integrity()["valid"] is False
    after = store.get_event(eid)
    assert after["decision"]["action"] == before["decision"]["action"]
