"""Hardening pass: audit txn safety, legacy transitions, fingerprints, verifier, TOCTOU."""

from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from varden.audit_integrity import (
    GENESIS_PREV_HASH,
    HASH_VERSION,
    UNSUPPORTED_HASH_VERSION,
    canonicalize_policy_for_fingerprint,
    format_verify_report,
    policy_fingerprint,
    verify_event_chain,
)
from varden.cli import main as varden_main
from varden.runtime.filesystem import classify_path, is_path_contained, resolve_filesystem_target
from varden.stores import EventStore


def _event(i: int, **overrides):
    base = {
        "timestamp": 1000.0 + i,
        "action": {
            "type": "tool_call",
            "tool": f"t{i}",
            "metadata": {"audit_integrity": {"hash_version": HASH_VERSION, "n": i}},
        },
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


@pytest.mark.parametrize(
    "hook_name",
    [
        "after_begin",
        "after_read_head",
        "before_serialize",
        "before_hash",
        "after_hash",
        "before_insert",
        "after_insert",
        "before_commit",
    ],
)
def test_failed_write_leaves_chain_valid(tmp_path, hook_name):
    store = EventStore(str(tmp_path / "varden.db"))
    store.log(_event(0))
    store.log(_event(1))
    before = store.verify_integrity()
    assert before["valid"] is True
    head = store.list_events_ascending()[-1]["event_hash"]

    def boom(**kwargs):
        raise RuntimeError(f"injected:{hook_name}")

    store._log_hooks = {hook_name: boom}
    with pytest.raises(RuntimeError, match="injected"):
        store.log(_event(99))
    store._log_hooks = {}

    after = store.verify_integrity()
    assert after["valid"] is True
    assert after["chained_events"] == 2
    assert store.list_events_ascending()[-1]["event_hash"] == head

    store.log(_event(2))
    final = store.verify_integrity()
    assert final["valid"] is True
    assert final["chained_events"] == 3
    events = store.list_events_ascending()
    assert events[2]["prev_hash"] == events[1]["event_hash"]


def test_concurrent_one_fails_one_succeeds(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    store.log(_event(0))
    fail_once = {"n": 0}

    def maybe_fail(**kwargs):
        fail_once["n"] += 1
        if fail_once["n"] == 1:
            raise RuntimeError("injected:concurrent")

    results = {"ok": 0, "err": 0}

    def worker(i: int):
        local = EventStore(str(tmp_path / "varden.db"))
        if i == 0:
            local._log_hooks = {"before_insert": maybe_fail}
        try:
            local.log(_event(10 + i, trace_id=f"c-{i}"))
            results["ok"] += 1
        except RuntimeError:
            results["err"] += 1
        finally:
            local._log_hooks = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(8)))
    assert results["err"] >= 1
    assert results["ok"] >= 1
    assert store.verify_integrity()["valid"] is True


def test_all_legacy_pass(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    for i in range(3):
        conn.execute(
            """INSERT INTO events (
                timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
                replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (float(i), "{}", "{}", "allowed", None, None, None, 0, None, None, "l", None, "t", "tenant-a", None, None),
        )
    conn.commit()
    conn.close()
    result = store.verify_integrity()
    assert result["valid"] is True
    assert result["legacy_events"] == 3
    assert result["chained_events"] == 0


def test_chained_then_null_hash_fails(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    store.log(_event(0))
    store.log(_event(1))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        """INSERT INTO events (
            timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
            replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (9.0, "{}", "{}", "allowed", None, None, None, 0, None, None, "fake", None, "x", "tenant-a", None, None),
    )
    conn.commit()
    conn.close()
    result = store.verify_integrity()
    assert result["valid"] is False
    assert any(f["reason"] == "unexpected_unchained_after_chain" for f in result["failures"])
    assert "FAIL" in format_verify_report(result)


def test_legacy_then_chained_then_fake_legacy_fails(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        """INSERT INTO events (
            timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
            replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (1.0, "{}", "{}", "allowed", None, None, None, 0, None, None, "legacy", None, "l", "tenant-a", None, None),
    )
    conn.commit()
    conn.close()
    store.log(_event(10))
    store.log(_event(11))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute(
        """INSERT INTO events (
            timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
            replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (12.0, "{}", "{}", "allowed", None, None, None, 0, None, None, "fake", None, "f", "tenant-a", None, None),
    )
    conn.commit()
    conn.close()
    assert store.verify_integrity()["valid"] is False


def test_fingerprint_same_for_dict_order_and_irrelevant_fields():
    a = {"block": [{"tool": "x"}], "allow": [], "warn": [], "logging_level": "debug", "pid": 123}
    b = {"warn": [], "allow": [], "block": [{"tool": "x"}], "dashboard": True}
    assert policy_fingerprint(a) == policy_fingerprint(b)


def test_fingerprint_path_and_string_equivalence():
    a = {"block": [{"path": Path("/tmp/a")}], "allow": []}
    b = {"block": [{"path": "/tmp/a"}], "allow": []}
    assert policy_fingerprint(a) == policy_fingerprint(b)


def test_fingerprint_differs_for_security_changes():
    base = {"block": [{"tool": "x"}], "allow": [], "warn": []}
    assert policy_fingerprint(base) != policy_fingerprint({"block": [{"tool": "y"}], "allow": [], "warn": []})
    assert policy_fingerprint(base) != policy_fingerprint(
        {"block": [{"tool": "x"}], "allow": [], "warn": [], "require_approval": [{"tool": "x"}]}
    )
    assert policy_fingerprint({"block": [{"tool": "a"}, {"tool": "b"}], "allow": []}) != policy_fingerprint(
        {"block": [{"tool": "b"}, {"tool": "a"}], "allow": []}
    )
    assert policy_fingerprint(base, fail_mode="closed") != policy_fingerprint(base, fail_mode="open")
    assert policy_fingerprint(base, mode="guarded") != policy_fingerprint(base, mode="observe")
    assert policy_fingerprint(base, require_coverage=["http"]) != policy_fingerprint(
        base, require_coverage=["http", "mcp"]
    )


def test_fingerprint_canonical_structure_excludes_noise():
    payload = canonicalize_policy_for_fingerprint(
        {"block": [], "allow": [], "timestamp": 1, "cache": {"x": 1}},
        mode="guarded",
        fail_mode="closed",
    )
    assert "timestamp" not in payload
    assert "cache" not in payload
    assert payload["mode"] == "guarded"
    assert payload["fail_mode"] == "closed"


def test_toctou_parent_symlink_mutation_detected_on_recheck(monkeypatch):
    """Re-check after policy evaluation observes parent symlink replacement."""
    import varden
    from varden.runtime import filesystem as fs_mod
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    policy = {
        "block": [
            {"type": "filesystem", "field:metadata.filesystem.classification": {"in": ["secrets", "system"]}},
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    with TemporaryDirectory() as td:
        client, _ = make_app_client(td, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        ws = Path(td) / "ws"
        safe = ws / "safe_dir"
        safe.mkdir(parents=True)
        (safe / "notes.txt").write_text("ok", encoding="utf-8")
        outside = Path(td) / "outside"
        outside.mkdir()
        (outside / "id_rsa").write_text("SECRET", encoding="utf-8")
        (outside / "notes.txt").write_text("escaped", encoding="utf-8")

        real_classify = fs_mod.classify_path
        state = {"n": 0}

        def classify_and_mutate(path, **kwargs):
            info = real_classify(path, **kwargs)
            state["n"] += 1
            # After the initial check classification, swap the parent for a symlink.
            if state["n"] == 1 and safe.exists() and not safe.is_symlink():
                aside = ws / "safe_dir_aside"
                safe.rename(aside)
                safe.symlink_to(outside)
            return info

        monkeypatch.setattr(fs_mod, "classify_path", classify_and_mutate)

        prev = os.getcwd()
        try:
            os.chdir(ws)
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            # notes.txt was benign at check time; after mutation it may escape.
            # Opening id_rsa through the mutated parent must be blocked on re-check.
            with pytest.raises(varden.VardenBlockedError):
                open(safe / "id_rsa", "r", encoding="utf-8").read()
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_toctou_effective_target_changes_across_two_resolutions(tmp_path):
    """Document residual race class: parent replacement changes effective target."""
    ws = tmp_path / "workspace"
    safe = ws / "safe_dir"
    safe.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "child.txt").write_text("x", encoding="utf-8")
    t1 = resolve_filesystem_target(safe / "child.txt", workspace=str(ws))
    assert t1.inside_workspace is True
    aside = ws / "aside"
    safe.rename(aside)
    safe.symlink_to(outside)
    t2 = resolve_filesystem_target(safe / "child.txt", workspace=str(ws))
    assert t2.symlink_involved is True
    assert t2.inside_workspace is False


def test_claim_traversal_cannot_escape(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "x").write_text("x", encoding="utf-8")
    t = resolve_filesystem_target(ws / "a" / ".." / ".." / "secret" / "x", workspace=str(ws))
    assert t.inside_workspace is False
    assert not is_path_contained(t.effective_path, ws)


def test_claim_symlink_escape_observed(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "id_rsa").write_text("x", encoding="utf-8")
    link = ws / "out"
    link.symlink_to(outside)
    info = classify_path(link / "id_rsa", workspace=str(ws), mode="r")
    assert info["classification"] == "secrets"
    assert info.get("canonical_target", {}).get("inside_workspace") is False


def test_verifier_rejects_malformed_and_unsupported(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    eid = store.log(_event(0))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("UPDATE events SET event_hash=? WHERE id=?", ("abcd", eid))
    conn.commit()
    r = store.verify_integrity()
    assert r["valid"] is False
    assert any(f["reason"] == "invalid_hash_length" for f in r["failures"])
    conn.execute("UPDATE events SET event_hash=? WHERE id=?", ("z" * 64, eid))
    conn.commit()
    r = store.verify_integrity()
    assert any(f["reason"] == "non_hex_hash" for f in r["failures"])
    conn.close()

    events = [
        {
            "id": 1,
            "timestamp": 1.0,
            "action": {"metadata": {"audit_integrity": {"hash_version": "99"}}},
            "decision": {"action": "allow"},
            "status": "allowed",
            "input_payload": None,
            "output_payload": None,
            "error": None,
            "replayable": False,
            "replay_key": None,
            "workflow_id": None,
            "agent_name": "a",
            "parent_event_id": None,
            "trace_id": "t",
            "tenant_id": "t",
            "event_hash": "a" * 64,
            "prev_hash": GENESIS_PREV_HASH,
        }
    ]
    result = verify_event_chain(events)
    assert result["valid"] is False
    assert any(f["reason"] == UNSUPPORTED_HASH_VERSION for f in result["failures"])
    assert varden_main(["audit", "verify", "--db", str(tmp_path / "varden.db")]) == 1


def test_invalid_genesis_fails(tmp_path):
    store = EventStore(str(tmp_path / "varden.db"))
    store.log(_event(0))
    conn = sqlite3.connect(str(tmp_path / "varden.db"))
    conn.execute("UPDATE events SET prev_hash=? WHERE id=1", ("b" * 64,))
    conn.commit()
    conn.close()
    r = store.verify_integrity()
    assert r["valid"] is False
