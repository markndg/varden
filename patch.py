from pathlib import Path
base = Path('/mnt/data/sentinel_work')

# auth.py
(base/'sentinel'/'auth.py').write_text('''from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid
from .db import connect, init_db

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}

class LocalAuth:
    def __init__(self, db_path: str, signing_secret: str):
        self.db_path = db_path
        self.signing_secret = signing_secret
        init_db(db_path)
        if not self.list_signing_keys():
            self.add_signing_key(signing_secret, active=True)

    def create_tenant(self, name: str):
        tenant_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO tenants(tenant_id,name,created_at) VALUES (?,?,?)", (tenant_id, name, time.time()))
            conn.commit()
        return {"tenant_id": tenant_id, "name": name}

    def get_tenant_by_name(self, name: str):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM tenants WHERE name = ? ORDER BY created_at ASC LIMIT 1", (name,)).fetchone()
            return dict(row) if row else None

    def ensure_tenant(self, name: str):
        return self.get_tenant_by_name(name) or self.create_tenant(name)

    def create_user(self, username: str, tenant_id: str, role: str = "viewer"):
        user_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO users(user_id,username,tenant_id,role,created_at) VALUES (?,?,?,?,?)",
                         (user_id, username, tenant_id, role, time.time()))
            conn.commit()
        return {"user_id": user_id, "username": username, "tenant_id": tenant_id, "role": role}

    def get_user(self, username: str, tenant_id: str):
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND tenant_id = ? ORDER BY created_at ASC LIMIT 1",
                (username, tenant_id),
            ).fetchone()
            return dict(row) if row else None

    def ensure_user(self, username: str, tenant_id: str, role: str = "viewer"):
        user = self.get_user(username, tenant_id)
        if user:
            if user.get("role") != role:
                with connect(self.db_path) as conn:
                    conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, user["user_id"]))
                    conn.commit()
                user["role"] = role
            return user
        return self.create_user(username, tenant_id, role=role)

    def create_api_key(self, key: str | None = None, tenant_id: str | None = None, role: str = "viewer"):
        raw = key or secrets.token_urlsafe(24)
        key_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO api_keys(key_hash,tenant_id,role,created_at,revoked,revoked_at) VALUES (?,?,?,?,0,NULL)",
                         (key_hash, tenant_id, role, time.time()))
            conn.commit()
        return {"api_key": raw, "tenant_id": tenant_id, "role": role}

    def authenticate_api_key(self, api_key: str):
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
            if not row:
                return None
            rec = dict(row)
            return None if rec["revoked"] else rec

    def add_signing_key(self, secret: str, active: bool = True):
        key_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO signing_keys(key_id,secret,created_at,active) VALUES (?,?,?,?)",
                         (key_id, secret, time.time(), 1 if active else 0))
            conn.commit()
        return {"key_id": key_id, "active": active}

    def list_signing_keys(self):
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM signing_keys ORDER BY created_at DESC").fetchall()]

    def _active_signing_key(self):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def issue_bearer_token(self, user_id: str, tenant_id: str, role: str, expires_in: int = 3600):
        signing = self._active_signing_key()
        payload = {"user_id": user_id, "tenant_id": tenant_id, "role": role, "exp": int(time.time()) + expires_in, "kid": signing["key_id"]}
        body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("utf-8").rstrip("=")
        sig = hmac.new(signing["secret"].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def verify_bearer_token(self, token: str):
        try:
            body, sig = token.split(".", 1)
            payload = json.loads(base64.urlsafe_b64decode((body + "=" * (-len(body) % 4)).encode("utf-8")).decode("utf-8"))
            if payload.get("exp", 0) < int(time.time()):
                return None
            for key in self.list_signing_keys():
                if key["key_id"] != payload.get("kid"):
                    continue
                expected = hmac.new(key["secret"].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, expected):
                    return payload
            return None
        except Exception:
            return None

    def require_role(self, api_key: str | None = None, bearer_token: str | None = None, min_role: str = "viewer"):
        record = self.authenticate_api_key(api_key) if api_key else self.verify_bearer_token(bearer_token) if bearer_token else None
        if not record:
            return False, "invalid credentials", None
        if ROLES[record["role"]] < ROLES[min_role]:
            return False, "insufficient role", record
        return True, "ok", record
''', encoding='utf-8')

# stores.py
(base/'sentinel'/'stores.py').write_text('''from __future__ import annotations
import hashlib, json, time
from collections import Counter, defaultdict
from .db import connect, init_db

def stable_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)

class EventStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def _latest_hash(self):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            return row["event_hash"] if row else None

    def log(self, event: dict):
        prev_hash = self._latest_hash()
        event_hash = hashlib.sha256((stable_json(event) + (prev_hash or "")).encode("utf-8")).hexdigest()
        event["prev_hash"] = prev_hash
        event["event_hash"] = event_hash
        with connect(self.db_path) as conn:
            cur = conn.execute(
                '''INSERT INTO events (
                    timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
                    replayable, replay_key, workflow_id, agent_name, parent_event_id, tenant_id, event_hash, prev_hash
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    event["timestamp"],
                    json.dumps(event["action"], ensure_ascii=False),
                    json.dumps(event["decision"], ensure_ascii=False),
                    event["status"],
                    json.dumps(event.get("input_payload"), ensure_ascii=False),
                    json.dumps(event.get("output_payload"), ensure_ascii=False),
                    event.get("error"),
                    1 if event.get("replayable") else 0,
                    event.get("replay_key"),
                    event.get("workflow_id"),
                    event.get("agent_name"),
                    event.get("parent_event_id"),
                    event.get("tenant_id"),
                    event_hash,
                    prev_hash,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def list_events(self, limit: int = 50, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute("SELECT * FROM events WHERE tenant_id = ? ORDER BY id DESC LIMIT ?", (tenant_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                out.append({
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "action": json.loads(r["action_json"]),
                    "decision": json.loads(r["decision_json"]),
                    "status": r["status"],
                    "input_payload": json.loads(r["input_payload_json"]) if r["input_payload_json"] else None,
                    "output_payload": json.loads(r["output_payload_json"]) if r["output_payload_json"] else None,
                    "error": r["error"],
                    "replayable": bool(r["replayable"]),
                    "replay_key": r["replay_key"],
                    "workflow_id": r["workflow_id"],
                    "agent_name": r["agent_name"],
                    "parent_event_id": r["parent_event_id"],
                    "tenant_id": r["tenant_id"],
                    "event_hash": r["event_hash"],
                    "prev_hash": r["prev_hash"],
                })
            return out

    def list_alerts(self, limit: int = 50, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute("SELECT * FROM alerts WHERE tenant_id = ? ORDER BY id DESC LIMIT ?", (tenant_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def log_alert(self, alert: dict, sinks: list[str]):
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO alerts(created_at,event_id,tenant_id,severity,title,message,sink,delivered,acknowledged,acknowledged_at,acknowledged_by,note) VALUES (?,?,?,?,?,?,?,1,0,NULL,NULL,NULL)",
                (time.time(), alert.get("event_id"), alert.get("tenant_id"), alert["severity"], alert["title"], alert["message"], ",".join(sinks)),
            )
            conn.commit()
            return int(cur.lastrowid)

    def acknowledge_alert(self, alert_id: int, user: str, note: str | None = None):
        with connect(self.db_path) as conn:
            conn.execute("UPDATE alerts SET acknowledged=1, acknowledged_at=?, acknowledged_by=?, note=? WHERE id=?",
                         (time.time(), user, note, alert_id))
            conn.commit()
            return {"acknowledged": True, "alert_id": alert_id}

    def metrics(self, tenant_id: str | None = None):
        events = self.list_events(limit=1000, tenant_id=tenant_id)
        alerts = self.list_alerts(limit=1000, tenant_id=tenant_id)
        return {
            "total_events": len(events),
            "blocked_events": sum(1 for e in events if e["status"] == "blocked"),
            "warned_events": sum(1 for e in events if e["status"] == "warned"),
            "local_routes": sum(1 for e in events if e["action"].get("route_target") == "local_blaze"),
            "open_alerts": sum(1 for a in alerts if not a["acknowledged"]),
        }

    def dashboard_summary(self, tenant_id: str | None = None):
        events = self.list_events(limit=1000, tenant_id=tenant_id)
        alerts = self.list_alerts(limit=200, tenant_id=tenant_id)
        metrics = self.metrics(tenant_id=tenant_id)

        buckets = defaultdict(lambda: {"timestamp": 0, "total": 0, "blocked": 0, "warned": 0, "allowed": 0})
        tool_counts = Counter()
        route_counts = Counter()
        status_counts = Counter()
        agent_counts = Counter()
        classifier_counts = Counter()
        latest_risk = []

        for e in reversed(events):
            minute = int(e["timestamp"] // 60) * 60
            bucket = buckets[minute]
            bucket["timestamp"] = minute
            bucket["total"] += 1
            bucket[e["status"]] = bucket.get(e["status"], 0) + 1
            action = e.get("action") or {}
            decision = e.get("decision") or {}
            tool = action.get("tool") or "unknown"
            tool_counts[tool] += 1
            route_counts[decision.get("route_target") or action.get("route_target") or "cloud"] += 1
            status_counts[e["status"]] += 1
            if action.get("agent_name"):
                agent_counts[action["agent_name"]] += 1
            for name, flag in (action.get("classifiers") or {}).items():
                if flag:
                    classifier_counts[name] += 1
            latest_risk.append({
                "timestamp": e["timestamp"],
                "tool": tool,
                "status": e["status"],
                "risk_score": action.get("risk_score", 0),
            })

        recent_events = []
        for e in events[:12]:
            action = e.get("action") or {}
            decision = e.get("decision") or {}
            recent_events.append({
                "id": e["id"],
                "timestamp": e["timestamp"],
                "tool": action.get("tool"),
                "agent_name": action.get("agent_name"),
                "status": e["status"],
                "risk_score": action.get("risk_score", 0),
                "route_target": decision.get("route_target") or action.get("route_target") or "cloud",
                "reason": decision.get("reason"),
                "workflow_id": e.get("workflow_id"),
            })

        return {
            "generated_at": time.time(),
            "metrics": metrics,
            "timeline": sorted(buckets.values(), key=lambda x: x["timestamp"])[-30:],
            "status_breakdown": dict(status_counts),
            "route_breakdown": dict(route_counts),
            "top_tools": [{"tool": k, "count": v} for k, v in tool_counts.most_common(8)],
            "top_agents": [{"agent": k, "count": v} for k, v in agent_counts.most_common(6)],
            "classifier_hits": [{"classifier": k, "count": v} for k, v in classifier_counts.most_common(8)],
            "recent_events": recent_events,
            "recent_alerts": alerts[:8],
            "latest_risk": latest_risk[-20:],
        }

class WorkflowStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def create(self, workflow_id: str, name: str, tenant_id: str | None, status: str = "active"):
        with connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO workflow_sessions(workflow_id,name,tenant_id,created_at,closed_at,status) VALUES (?,?,?,?,NULL,?)",
                         (workflow_id, name, tenant_id, time.time(), status))
            conn.commit()

    def close(self, workflow_id: str):
        with connect(self.db_path) as conn:
            conn.execute("UPDATE workflow_sessions SET closed_at=?, status='closed' WHERE workflow_id=?", (time.time(), workflow_id))
            conn.commit()

    def list_by_tenant(self, tenant_id: str | None, limit: int = 50):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute("SELECT * FROM workflow_sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM workflow_sessions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
''', encoding='utf-8')

# app_factory.py
(base/'sentinel'/'app_factory.py').write_text('''from __future__ import annotations
import json, time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from .alerts import AlertEngine, BackgroundWorker, ConsoleSink, FileSink
from .auth import LocalAuth
from .blaze import BlazeRuntime
from .classification import ClassifierEngine
from .config import AppConfig
from .export import EvidenceExporter
from .health import HealthChecks
from .idempotency import IdempotencyStore
from .intelligence import DecisionIntelligence
from .metrics import MetricsExporter
from .models import Action, EventRecord, WorkflowSession
from .policy import PolicyEngine
from .queue import SQLiteQueue
from .redaction import redact
from .ratelimit import RateLimiter
from .stores import EventStore, WorkflowStore

def create_app(config: AppConfig) -> FastAPI:
    event_store = EventStore(config.db_path)
    workflow_store = WorkflowStore(config.db_path)
    auth = LocalAuth(config.auth_db_path, config.signing_secret)
    policy = PolicyEngine(config.db_path, json.loads(Path(config.policy_file).read_text(encoding="utf-8")) if Path(config.policy_file).exists() else None)
    idem = IdempotencyStore(config.db_path)
    queue = SQLiteQueue(config.db_path)
    exporter = EvidenceExporter(event_store)
    classifier = ClassifierEngine()
    intelligence = DecisionIntelligence()
    blaze = BlazeRuntime(config.blaze_command)
    metrics = MetricsExporter(event_store)
    health = HealthChecks(config.db_path, config.auth_db_path)
    alerts = AlertEngine([ConsoleSink(), FileSink("sentinel_alerts.jsonl")])
    background = BackgroundWorker(event_store, alerts, poll_interval=config.worker_poll_interval)
    limiter = RateLimiter(per_key_limit=config.rate_limit_per_minute, window_seconds=60)

    app = FastAPI(title="Sentinel Integrated Platform", version="1.4.0")

    tenant = auth.ensure_tenant("default")
    user = auth.ensure_user("admin", tenant["tenant_id"], role="admin")
    bootstrap_token = auth.issue_bearer_token(user["user_id"], tenant["tenant_id"], "admin")
    bootstrap_key = auth.create_api_key("admin-demo-key", tenant_id=tenant["tenant_id"], role="admin")

    active_workflow_by_tenant: dict[str, str | None] = {}

    def require(x_api_key=None, authorization=None, role="viewer"):
        token = None
        raw = x_api_key or authorization or "anon"
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
            raw = token
        if not limiter.allow(raw):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        ok, reason, record = auth.require_role(api_key=x_api_key, bearer_token=token, min_role=role)
        if not ok:
            raise HTTPException(status_code=403, detail=reason)
        return record

    def enrich_action(action: Action, payload):
        action.classifiers = classifier.classify(payload)
        action = intelligence.enrich(action)
        action.route_target = blaze.route(action.classifiers, action.risk_score).target if config.route_sensitive_to_local else "cloud"
        return action

    def record_tool(tool_name: str, args: list, kwargs: dict, tenant_id: str, agent_name: str | None = None, workflow_id: str | None = None):
        action = Action(
            type="tool_call",
            tool=tool_name,
            args={"args": args, "kwargs": kwargs},
            agent_name=agent_name,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
        )
        action = enrich_action(action, {"args": args, "kwargs": kwargs})
        decision = policy.evaluate(action)
        decision.route_target = action.route_target
        if decision.action == "block":
            event_store.log(EventRecord.new(
                action=action.to_dict(), decision=decision.to_dict(), status="blocked",
                input_payload={"args": args, "kwargs": kwargs}, replayable=False,
                replay_key=tool_name, workflow_id=action.workflow_id, agent_name=agent_name, tenant_id=action.tenant_id,
                error=f"[Sentinel BLOCKED] {decision.reason}",
            ).to_dict())
            raise HTTPException(status_code=403, detail=f"[Sentinel BLOCKED] {decision.reason}")
        result = blaze.execute_local({"args": args, "kwargs": kwargs}) if action.route_target == "local_blaze" else {"status": "cloud_ok"}
        event_store.log(EventRecord.new(
            action=action.to_dict(), decision=decision.to_dict(), status="warned" if decision.action == "warn" else "allowed",
            input_payload={"args": args, "kwargs": kwargs}, output_payload=result, replayable=False,
            replay_key=tool_name, workflow_id=action.workflow_id, agent_name=agent_name, tenant_id=action.tenant_id
        ).to_dict())
        return result

    @app.on_event("startup")
    def startup():
        background.start()

    @app.on_event("shutdown")
    def shutdown():
        background.stop()

    @app.get("/")
    def root():
        return RedirectResponse(url="/ui")

    @app.get("/health")
    def health_summary():
        return {
            "status": "ok",
            "bootstrap_api_key": bootstrap_key["api_key"],
            "bootstrap_bearer_token": bootstrap_token,
            "tenant_id": tenant["tenant_id"],
            "metrics": event_store.metrics(tenant["tenant_id"]),
        }

    @app.get("/health/live")
    def live():
        return health.liveness()

    @app.get("/health/ready")
    def ready():
        return health.readiness()

    @app.get("/diagnostics")
    def diagnostics(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin")
        return health.diagnostics()

    @app.get("/metrics", response_class=PlainTextResponse)
    def prometheus(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        return metrics.render_prometheus(tenant_id=record["tenant_id"])

    @app.get("/ui", response_class=HTMLResponse)
    def ui():
        return (Path(__file__).parent / "web" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/dashboard/overview")
    def dashboard_overview(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        summary = event_store.dashboard_summary(tenant_id=record["tenant_id"])
        summary["workflows"] = workflow_store.list_by_tenant(record["tenant_id"], limit=8)
        summary["jobs"] = queue.list_jobs(limit=8)
        summary["policy_versions"] = policy.list_versions(limit=8)
        return summary

    @app.get("/policy")
    def get_policy(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst")
        return policy.get_policy()

    @app.get("/policy/templates")
    def get_policy_templates(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst")
        return policy.templates()

    @app.post("/policy/validate")
    def validate_policy(candidate: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst")
        return policy.validate(candidate)

    @app.put("/policy")
    def put_policy(candidate: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin")
        if idempotency_key:
            cached = idem.get(idempotency_key)
            if cached is not None:
                return cached
        validation = policy.validate(candidate)
        if not validation["valid"]:
            raise HTTPException(status_code=400, detail=validation)
        policy.update_policy(candidate)
        Path(config.policy_file).write_text(json.dumps(candidate, indent=2), encoding="utf-8")
        snapshot_id = policy.snapshot("manual-update", created_by="control-plane", status="draft")
        response = {"status": "updated", "snapshot_id": snapshot_id}
        if idempotency_key:
            idem.put(idempotency_key, response)
        return response

    @app.get("/policy/versions")
    def versions(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst")
        return policy.list_versions()

    @app.post("/policy/publish/{version_id}")
    def publish(version_id: int, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin")
        return policy.publish(version_id)

    @app.get("/events")
    def events(limit: int = 50, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        rows = event_store.list_events(limit=limit, tenant_id=record["tenant_id"])
        for r in rows:
            r["input_payload"] = redact(r["input_payload"])
            r["output_payload"] = redact(r["output_payload"])
        return rows

    @app.get("/alerts")
    def alerts_route(limit: int = 50, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        return event_store.list_alerts(limit=limit, tenant_id=record["tenant_id"])

    @app.post("/alerts/{alert_id}/ack")
    def ack_alert(alert_id: int, note: str = "", x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst")
        return event_store.acknowledge_alert(alert_id, user=str(record.get("user_id", "unknown")), note=note)

    @app.post("/workflows/start")
    def start_workflow(name: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        wf = WorkflowSession(name=name, tenant_id=record["tenant_id"])
        active_workflow_by_tenant[record["tenant_id"]] = wf.workflow_id
        workflow_store.create(wf.workflow_id, wf.name, wf.tenant_id, status="active")
        return wf.to_dict()

    @app.post("/workflows/close")
    def close_workflow(workflow_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        if active_workflow_by_tenant.get(record["tenant_id"]) == workflow_id:
            active_workflow_by_tenant[record["tenant_id"]] = None
        workflow_store.close(workflow_id)
        return {"closed": workflow_id}

    @app.get("/workflows")
    def workflows(limit: int = 50, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        return workflow_store.list_by_tenant(record["tenant_id"], limit=limit)

    @app.post("/jobs/enqueue")
    def enqueue(job_type: str, payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin")
        return {"job_id": queue.enqueue(job_type, payload, tenant_id=record["tenant_id"])}

    @app.get("/jobs")
    def jobs(limit: int = 100, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin")
        return queue.list_jobs(limit=limit)

    @app.get("/metrics/json")
    def metrics_json(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        return event_store.metrics(tenant_id=record["tenant_id"])

    @app.get("/export/bundle")
    def export_bundle(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin")
        return exporter.export_bundle("evidence_bundle.json", tenant_id=record["tenant_id"])

    @app.get("/export/csv")
    def export_csv(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin")
        return {"path": exporter.export_events_csv("events_export.csv", tenant_id=record["tenant_id"])}

    @app.get("/export/verify-chain")
    def verify_chain(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin")
        return exporter.verify_chain(tenant_id=record["tenant_id"])

    @app.post("/demo/tool")
    def demo_tool(tool_name: str, payload: dict, workflow_id: str | None = None, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer")
        active_workflow = workflow_id or active_workflow_by_tenant.get(record["tenant_id"])
        return record_tool(tool_name, payload.get("args", []), payload.get("kwargs", {}), tenant_id=record["tenant_id"], workflow_id=active_workflow, agent_name="demo")

    return app
''', encoding='utf-8')

# dashboard HTML
(base/'sentinel'/'web'/'dashboard.html').write_text('''<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sentinel Integrated Platform</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{--bg:#07111f;--bg2:#0b1730;--panel:#101b33;--panel2:#142444;--line:#25375f;--text:#eff4ff;--muted:#9cb2df;--accent:#6da8ff;--accent2:#7cf0d2;--danger:#ff6e7d;--warn:#ffbf69;--ok:#6be6a8;--shadow:0 20px 60px rgba(0,0,0,.25)}
    *{box-sizing:border-box} html,body{height:100%} body{margin:0;color:var(--text);font-family:Inter,ui-sans-serif,Arial,sans-serif;background:radial-gradient(circle at top left,#122a56 0,#091327 30%,#060c19 100%)}
    header{position:sticky;top:0;z-index:10;display:flex;justify-content:space-between;align-items:center;gap:18px;padding:18px 24px;border-bottom:1px solid rgba(255,255,255,.08);background:rgba(6,12,25,.7);backdrop-filter:blur(14px)}
    .brand h1{margin:0;font-size:24px}.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}
    .toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.toolbar input{min-width:320px}
    .wrap{padding:20px;display:grid;grid-template-columns:300px 1fr;gap:18px}
    .stack{display:grid;gap:18px}.card{background:linear-gradient(180deg,rgba(20,36,68,.92),rgba(11,20,38,.94));border:1px solid rgba(255,255,255,.08);border-radius:20px;box-shadow:var(--shadow);overflow:hidden}.card .inner{padding:16px}
    .section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.section-title h2{margin:0;font-size:15px}.muted{color:var(--muted)}
    .actions{display:grid;gap:10px}.btn{width:100%;padding:11px 12px;border-radius:14px;border:1px solid rgba(255,255,255,.08);background:#102042;color:var(--text);cursor:pointer;font-weight:700;transition:.18s transform,.18s background}.btn:hover{transform:translateY(-1px);background:#17305f}.btn.primary{background:linear-gradient(180deg,#4f81ff,#2d5cc8)}.btn.secondary{background:linear-gradient(180deg,#153b53,#112b45)}
    input,textarea,select{width:100%;padding:11px 12px;border-radius:14px;border:1px solid rgba(255,255,255,.08);background:#0c1730;color:var(--text)} textarea{min-height:190px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
    .metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px}.stat{padding:16px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));border:1px solid rgba(255,255,255,.07)}.stat .label{font-size:12px;color:var(--muted)}.stat .value{font-size:34px;font-weight:800;margin-top:8px}.delta{font-size:12px;margin-top:8px}
    .main-grid{display:grid;grid-template-columns:1.35fr .95fr;gap:18px}.sub-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.row2{display:grid;grid-template-columns:1.1fr .9fr;gap:18px}
    .chart{height:240px;position:relative}.bars{display:flex;align-items:flex-end;gap:8px;height:220px;padding-top:20px}.bar{flex:1;display:flex;flex-direction:column;justify-content:flex-end;gap:4px;min-width:0}.bar span{display:block;border-radius:10px 10px 4px 4px}.bar .total{background:linear-gradient(180deg,#6da8ff,#3f6fe0)}.bar .blocked{background:linear-gradient(180deg,#ff8a99,#e64f68)}.bar .warned{background:linear-gradient(180deg,#ffd08a,#f4a83d)}.bar .x{font-size:10px;color:var(--muted);text-align:center;padding-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .donut-wrap{display:grid;grid-template-columns:170px 1fr;gap:16px;align-items:center}.donut{width:160px;height:160px;position:relative;margin:auto}.donut svg{transform:rotate(-90deg)}.legend{display:grid;gap:10px}.legend .item{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border:1px solid rgba(255,255,255,.07);border-radius:14px;background:rgba(255,255,255,.03)}
    .pill{display:inline-flex;align-items:center;gap:8px;border-radius:999px;padding:5px 10px;background:rgba(255,255,255,.06);font-size:12px}.dot{width:9px;height:9px;border-radius:999px;display:inline-block}.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.block{background:var(--danger)}.dot.info{background:var(--accent)}
    table{width:100%;border-collapse:collapse} th,td{padding:11px 10px;text-align:left;border-bottom:1px solid rgba(255,255,255,.06);font-size:13px} th{color:var(--muted);font-weight:700} tbody tr:hover{background:rgba(255,255,255,.03)}
    .status{padding:4px 9px;border-radius:999px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}.status.allowed{background:rgba(107,230,168,.15);color:#8ff0bb}.status.warned{background:rgba(255,191,105,.15);color:#ffd18f}.status.blocked{background:rgba(255,110,125,.14);color:#ff9ca8}
    .flow{position:relative;min-height:250px;padding:16px}.flow-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;position:relative;z-index:2}.node{padding:14px;border-radius:18px;border:1px solid rgba(255,255,255,.09);background:rgba(255,255,255,.04)}.node strong{display:block;font-size:14px}.node .big{font-size:26px;font-weight:800;margin-top:8px}.flow svg{position:absolute;inset:0;z-index:1;pointer-events:none}
    pre{margin:0;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;font-size:12px;line-height:1.5;background:#0c1730;border:1px solid rgba(255,255,255,.08);padding:12px;border-radius:14px}
    .toast{position:fixed;right:18px;bottom:18px;min-width:260px;max-width:420px;padding:14px 16px;border-radius:16px;background:#112347;border:1px solid rgba(255,255,255,.09);box-shadow:var(--shadow);display:none}.toast.show{display:block}.toast.error{border-color:rgba(255,110,125,.4)}.toast.success{border-color:rgba(107,230,168,.4)}
    .tiny{font-size:11px;color:var(--muted)}
    @media (max-width:1200px){.wrap{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.main-grid,.sub-grid,.row2,.donut-wrap{grid-template-columns:1fr}.toolbar input{min-width:0;width:100%}}
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>Sentinel Integrated Platform</h1>
    <p>Runtime governance for agent actions, policy decisions, lineage, and operational flow</p>
  </div>
  <div class="toolbar">
    <input id="token" placeholder="Paste API key or bearer token">
    <button class="btn primary" onclick="refreshAll()">Refresh</button>
  </div>
</header>
<div class="wrap">
  <div class="stack">
    <div class="card"><div class="inner">
      <div class="section-title"><h2>Runbook</h2><span class="pill"><span class="dot info"></span><span id="envState">Connecting</span></span></div>
      <div class="actions">
        <button class="btn primary" onclick="refreshAll()">Refresh all datasets</button>
        <button class="btn" onclick="runDemo('delete_database')">Run blocked demo</button>
        <button class="btn secondary" onclick="runDemo('send_report', {text:'internal password token api_key secret=abcd1234 confidential'})">Run warn demo</button>
        <button class="btn secondary" onclick="runDemo('list_files', {path:'/tmp'})">Run allowed demo</button>
        <button class="btn" onclick="loadPolicyEditor()">Load policy into editor</button>
        <button class="btn" onclick="verifyChain()">Verify audit chain</button>
      </div>
    </div></div>

    <div class="card"><div class="inner">
      <div class="section-title"><h2>Platform health</h2><span class="tiny">Bootstrap auth auto-load in dev</span></div>
      <pre id="health"></pre>
    </div></div>

    <div class="card"><div class="inner">
      <div class="section-title"><h2>Policy editor</h2><span class="tiny">Validate and save without leaving the dashboard</span></div>
      <textarea id="policy"></textarea>
      <div class="actions" style="margin-top:12px">
        <button class="btn" onclick="validatePolicy()">Validate policy</button>
        <button class="btn primary" onclick="savePolicy()">Save policy</button>
      </div>
    </div></div>

    <div class="card"><div class="inner">
      <div class="section-title"><h2>Exports & diagnostics</h2></div>
      <pre id="exports"></pre>
    </div></div>
  </div>

  <div class="stack">
    <div class="metrics">
      <div class="stat"><div class="label">Total events</div><div id="m_total" class="value">0</div><div class="delta">All observed action decisions</div></div>
      <div class="stat"><div class="label">Blocked</div><div id="m_blocked" class="value">0</div><div class="delta">Prevented before tool execution</div></div>
      <div class="stat"><div class="label">Warned</div><div id="m_warned" class="value">0</div><div class="delta">Allowed with policy pressure</div></div>
      <div class="stat"><div class="label">Local routes</div><div id="m_local" class="value">0</div><div class="delta">Local Blaze execution target</div></div>
      <div class="stat"><div class="label">Open alerts</div><div id="m_alerts" class="value">0</div><div class="delta">Unacknowledged signals</div></div>
    </div>

    <div class="main-grid">
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Decision timeline</h2><span class="tiny">Events by minute</span></div>
        <div id="timeline" class="chart"></div>
      </div></div>
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Status distribution</h2><span class="tiny">Allowed vs warned vs blocked</span></div>
        <div id="statusDonut" class="donut-wrap"></div>
      </div></div>
    </div>

    <div class="row2">
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Runtime flow</h2><span class="tiny">Observed execution path</span></div>
        <div id="flowPanel" class="flow"></div>
      </div></div>
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Top tools and classifier hits</h2><span class="tiny">Pressure points across the runtime</span></div>
        <div class="sub-grid">
          <div><table><thead><tr><th>Tool</th><th>Count</th></tr></thead><tbody id="topTools"></tbody></table></div>
          <div><table><thead><tr><th>Classifier</th><th>Hits</th></tr></thead><tbody id="classifierHits"></tbody></table></div>
        </div>
      </div></div>
    </div>

    <div class="sub-grid">
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Recent events</h2><span class="tiny">Newest decisions with risk and route</span></div>
        <table>
          <thead><tr><th>Time</th><th>Tool</th><th>Status</th><th>Risk</th><th>Route</th></tr></thead>
          <tbody id="recentEvents"></tbody>
        </table>
      </div></div>
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Operational tables</h2><span class="tiny">Alerts, workflows, jobs, and policy versions</span></div>
        <div class="sub-grid">
          <div><table><thead><tr><th colspan="3">Alerts</th></tr></thead><tbody id="alertRows"></tbody></table></div>
          <div><table><thead><tr><th colspan="3">Workflows</th></tr></thead><tbody id="workflowRows"></tbody></table></div>
          <div><table><thead><tr><th colspan="3">Jobs</th></tr></thead><tbody id="jobRows"></tbody></table></div>
          <div><table><thead><tr><th colspan="3">Policy versions</th></tr></thead><tbody id="versionRows"></tbody></table></div>
        </div>
      </div></div>
    </div>

    <div class="sub-grid">
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Raw events</h2><span class="tiny">Full detail for forensics</span></div>
        <pre id="eventsRaw"></pre>
      </div></div>
      <div class="card"><div class="inner">
        <div class="section-title"><h2>Templates & versions</h2><span class="tiny">Reference policies and history</span></div>
        <pre id="templates"></pre>
        <pre id="versions" style="margin-top:12px"></pre>
      </div></div>
    </div>
  </div>
</div>
<div id="toast" class="toast"></div>
<script>
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
function showToast(message, kind='success'){ const t=document.getElementById('toast'); t.textContent=message; t.className='toast show '+kind; setTimeout(()=>t.className='toast', 3200); }
function headers(){ const token=document.getElementById('token').value.trim(); if(!token) return {}; if(token.includes('.')) return {'Authorization':'Bearer '+token}; return {'x-api-key':token}; }
async function fetchJson(url, options={}){ const r = await fetch(url, {headers:{...headers(), ...(options.headers||{})}, ...options}); const contentType = r.headers.get('content-type') || ''; const body = contentType.includes('application/json') ? await r.json() : await r.text(); if(!r.ok){ const detail = typeof body === 'string' ? body : (body.detail || JSON.stringify(body)); throw new Error(detail || ('HTTP '+r.status)); } return body; }
async function getJson(url){ return fetchJson(url); }
async function putJson(url, body){ return fetchJson(url,{method:'PUT',headers:{'Content-Type':'application/json','Idempotency-Key':'ui-policy-save'},body:JSON.stringify(body)}); }
async function postJson(url, body){ return fetchJson(url,{method:'POST',headers:{'Content-Type':'application/json'},body: body ? JSON.stringify(body) : undefined}); }
function setRows(id, rows, empty='No data'){ const el=document.getElementById(id); el.innerHTML = rows.length ? rows.join('') : `<tr><td class="muted" colspan="5">${empty}</td></tr>`; }
function renderTableRows(items, cols){ return items.map(item => `<tr>${cols.map(c => `<td>${typeof c === 'function' ? c(item) : (item[c] ?? '')}</td>`).join('')}</tr>`); }
function renderTimeline(points){ const el=document.getElementById('timeline'); if(!points?.length){ el.innerHTML='<div class="muted">No timeline data yet</div>'; return; } const max = Math.max(...points.map(p => p.total), 1); el.innerHTML = `<div class="bars">${points.map(p => { const totalH = Math.max(12, Math.round((p.total/max)*160)); const blockedH = Math.max(0, Math.round(((p.blocked||0)/max)*160)); const warnedH = Math.max(0, Math.round(((p.warned||0)/max)*160)); return `<div class="bar" title="${fmtTime(p.timestamp)} • total ${p.total}"><span class="blocked" style="height:${blockedH}px"></span><span class="warned" style="height:${warnedH}px"></span><span class="total" style="height:${Math.max(4,totalH-blockedH-warnedH)}px"></span><div class="x">${fmtTime(p.timestamp)}</div></div>`; }).join('')}</div>`; }
function renderDonut(data){ const el=document.getElementById('statusDonut'); const total = (data.allowed||0)+(data.warned||0)+(data.blocked||0); const entries = [ ['allowed', data.allowed||0, '#6be6a8'], ['warned', data.warned||0, '#ffbf69'], ['blocked', data.blocked||0, '#ff6e7d'] ]; if(!total){ el.innerHTML='<div class="muted">No status data yet</div>'; return; } let offset = 0; const r = 62, c = 2*Math.PI*r; const circles = entries.map(([name,val,color])=>{ const len = (val/total)*c; const dash = `${len} ${c-len}`; const circle = `<circle cx="80" cy="80" r="${r}" fill="none" stroke="${color}" stroke-width="16" stroke-linecap="round" stroke-dasharray="${dash}" stroke-dashoffset="${-offset}"/>`; offset += len; return circle; }).join(''); el.innerHTML = `<div class="donut"><svg viewBox="0 0 160 160"><circle cx="80" cy="80" r="${r}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="16"/>${circles}</svg><div style="position:absolute;inset:0;display:grid;place-items:center;text-align:center"><div><div class="tiny">Events</div><div style="font-size:32px;font-weight:800">${total}</div></div></div></div><div class="legend">${entries.map(([name,val,color])=>`<div class="item"><div><span class="dot" style="background:${color}"></span> <span style="text-transform:capitalize">${name}</span></div><strong>${val}</strong></div>`).join('')}</div>`; }
function renderFlow(summary){ const metrics = summary.metrics||{}; const routes = summary.route_breakdown||{}; const cloud = Object.entries(routes).filter(([k])=>k!=='local_blaze').reduce((a,[,v])=>a+v,0); const local = routes.local_blaze || 0; const blocked = metrics.blocked_events || 0; const warned = metrics.warned_events || 0; const allowed = Math.max((metrics.total_events||0) - blocked - warned, 0); document.getElementById('flowPanel').innerHTML = `<svg viewBox="0 0 900 250" preserveAspectRatio="none"><path d="M160 125 C240 125, 250 55, 340 55" stroke="rgba(109,168,255,.65)" stroke-width="8" fill="none"/><path d="M160 125 C240 125, 250 195, 340 195" stroke="rgba(255,110,125,.55)" stroke-width="8" fill="none"/><path d="M500 55 C590 55, 600 55, 690 55" stroke="rgba(107,230,168,.65)" stroke-width="8" fill="none"/><path d="M500 195 C590 195, 600 195, 690 195" stroke="rgba(255,191,105,.65)" stroke-width="8" fill="none"/></svg><div class="flow-grid"><div class="node"><strong>Observed actions</strong><div class="big">${metrics.total_events||0}</div><div class="tiny">Agent tool decisions recorded</div></div><div class="node"><strong>Policy engine</strong><div class="big">${blocked+warned}</div><div class="tiny">Non-trivial policy touches</div></div><div class="node"><strong>Allowed routes</strong><div class="big">${allowed}</div><div class="tiny">Actions permitted to continue</div></div><div class="node"><strong>Destinations</strong><div class="big">${local+cloud}</div><div class="tiny">${local} local Blaze / ${cloud} cloud</div></div></div>`; }
function renderOverview(summary){ const m = summary.metrics||{}; document.getElementById('m_total').textContent = m.total_events || 0; document.getElementById('m_blocked').textContent = m.blocked_events || 0; document.getElementById('m_warned').textContent = m.warned_events || 0; document.getElementById('m_local').textContent = m.local_routes || 0; document.getElementById('m_alerts').textContent = m.open_alerts || 0; renderTimeline(summary.timeline||[]); renderDonut(summary.status_breakdown||{}); renderFlow(summary); setRows('topTools', renderTableRows(summary.top_tools||[], ['tool','count'])); setRows('classifierHits', renderTableRows(summary.classifier_hits||[], ['classifier','count'])); setRows('recentEvents', renderTableRows(summary.recent_events||[], [e => fmtTime(e.timestamp), e => `<strong>${e.tool||'n/a'}</strong><div class="tiny">${e.reason||''}</div>`, e => `<span class="status ${e.status}">${e.status}</span>`, e => e.risk_score ?? 0, e => e.route_target || 'cloud'])); setRows('alertRows', renderTableRows(summary.recent_alerts||[], [a => a.severity || 'info', a => a.title || '', a => a.acknowledged ? 'Acked' : 'Open']), 'No alerts'); setRows('workflowRows', renderTableRows(summary.workflows||[], [w => w.name || '', w => w.status || '', w => w.workflow_id ? w.workflow_id.slice(0,8) : '']), 'No workflows'); setRows('jobRows', renderTableRows(summary.jobs||[], [j => j.job_type || '', j => j.status || '', j => j.id || '']), 'No jobs'); setRows('versionRows', renderTableRows(summary.policy_versions||[], [v => v.id || '', v => v.status || '', v => v.version_name || '']), 'No versions'); }
async function loadHealth(){ const h = await getJson('/health'); document.getElementById('health').textContent = JSON.stringify(h, null, 2); if(!document.getElementById('token').value && h.bootstrap_api_key){ document.getElementById('token').value = h.bootstrap_api_key; } document.getElementById('envState').textContent = h.status === 'ok' ? 'Live' : 'Issue'; }
async function loadOverview(){ const summary = await getJson('/dashboard/overview'); renderOverview(summary); document.getElementById('eventsRaw').textContent = JSON.stringify(summary.recent_events || [], null, 2); return summary; }
async function loadPolicyEditor(){ document.getElementById('policy').value = JSON.stringify(await getJson('/policy'), null, 2); }
async function loadTemplates(){ document.getElementById('templates').textContent = JSON.stringify(await getJson('/policy/templates'), null, 2); }
async function loadVersions(){ document.getElementById('versions').textContent = JSON.stringify(await getJson('/policy/versions'), null, 2); }
async function validatePolicy(){ const res = await postJson('/policy/validate', JSON.parse(document.getElementById('policy').value)); showToast(res.valid ? 'Policy is valid' : ('Policy invalid: ' + (res.errors||[]).join(', ')), res.valid ? 'success' : 'error'); }
async function savePolicy(){ const res = await putJson('/policy', JSON.parse(document.getElementById('policy').value)); showToast(`Policy saved. Snapshot ${res.snapshot_id}`); await loadVersions(); }
async function verifyChain(){ const res = await getJson('/export/verify-chain'); document.getElementById('exports').textContent = JSON.stringify(res, null, 2); showToast('Audit chain verified'); }
async function runDemo(tool, kwargs={}){ try{ await postJson('/demo/tool?tool_name='+encodeURIComponent(tool), {args:[], kwargs}); showToast(`Demo ${tool} completed`); } catch(err){ showToast(String(err.message || err), 'error'); } await refreshAll(); }
async function refreshAll(){ try{ await loadHealth(); await Promise.all([loadPolicyEditor(), loadTemplates(), loadVersions()]); await loadOverview(); } catch(err){ console.error(err); showToast(String(err.message || err), 'error'); document.getElementById('envState').textContent = 'Error'; } }
window.addEventListener('load', refreshAll);
</script>
</body>
</html>
''', encoding='utf-8')

# README
(base/'README.md').write_text('''# Sentinel Integrated Platform

Sentinel is a unified runtime governance platform for agentic systems. This release bundles:

- FastAPI control plane and operator dashboard
- local auth with bootstrap API key for first-run access
- SQLite-backed events, alerts, workflows, jobs, policy versions, and audit chain
- runtime policy evaluation for tool actions
- health, metrics, exports, rate limiting, redaction, and alerting
- production-style dashboard with timeline, charts, flow, tables, and policy editing

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # on Windows use .venv\\Scripts\\activate
pip install -e .
cp examples/policy.json policy.json
python -m sentinel.api --config examples/dev.env
```

Then open:

- dashboard: `http://127.0.0.1:8000/`
- health: `http://127.0.0.1:8000/health`
- prometheus metrics: `http://127.0.0.1:8000/metrics`

The dashboard auto-loads the bootstrap API key from `/health` in dev mode.

## Smoke tests

Blocked action:

```bash
curl -X POST "http://127.0.0.1:8000/demo/tool?tool_name=delete_database" \
  -H "x-api-key: admin-demo-key" \
  -H "Content-Type: application/json" \
  -d '{"args":[],"kwargs":{"target":"prod"}}'
```

Allowed action:

```bash
curl -X POST "http://127.0.0.1:8000/demo/tool?tool_name=list_files" \
  -H "x-api-key: admin-demo-key" \
  -H "Content-Type: application/json" \
  -d '{"args":[],"kwargs":{"path":"/tmp"}}'
```

## Notes

- `/` now redirects to the dashboard.
- blocked actions return HTTP 403 instead of an internal server error.
- the dashboard includes structured charts and operational tables without removing raw forensic views.
''', encoding='utf-8')

# tests
(base/'tests'/'test_api_behaviour.py').write_text('''from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from sentinel.app_factory import create_app
from sentinel.config import AppConfig


def make_client(tmpdir: str):
    policy_path = Path(tmpdir) / 'policy.json'
    policy_path.write_text('{"block":[{"type":"tool_call","tool":"delete_database"}],"warn":[{"classifier:internal":true}],"monitor":[],"allow":[]}', encoding='utf-8')
    cfg = AppConfig(
        env='dev',
        db_path=str(Path(tmpdir) / 'sentinel.db'),
        auth_db_path=str(Path(tmpdir) / 'sentinel_auth.db'),
        policy_file=str(policy_path),
        signing_secret='dev-secret',
        rate_limit_per_minute=1000,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_root_redirects_to_ui():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        r = client.get('/', follow_redirects=False)
        assert r.status_code in {302, 307}
        assert r.headers['location'] == '/ui'


def test_blocked_demo_returns_403():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get('/health').json()['bootstrap_api_key']
        r = client.post('/demo/tool?tool_name=delete_database', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'target': 'prod'}})
        assert r.status_code == 403
        assert 'BLOCKED' in r.text


def test_dashboard_overview_returns_metrics():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get('/health').json()['bootstrap_api_key']
        client.post('/demo/tool?tool_name=list_files', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'path': '/tmp'}})
        r = client.get('/dashboard/overview', headers={'x-api-key': key})
        assert r.status_code == 200
        body = r.json()
        assert 'metrics' in body
        assert body['metrics']['total_events'] >= 1
''', encoding='utf-8')
