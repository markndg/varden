from __future__ import annotations

import asyncio
import json
import shutil
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .alerts import AlertEngine, BackgroundWorker, ConsoleSink, FileSink
from .auth import LocalAuth, OSS_TENANT_ID
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
from .ratelimit import BucketConfig, RateLimiter
from .stores import EventStore, WorkflowStore


class EventStreamBroker:
    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    async def subscribe(self):
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self._subscribers.discard(queue)

    def publish(self, message: dict[str, Any]):
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except Exception:
                pass



def create_app(config: AppConfig) -> FastAPI:
    event_store = EventStore(config.db_path)
    workflow_store = WorkflowStore(config.db_path)
    auth = LocalAuth(config.auth_db_path, config.signing_secret)
    initial_policy = json.loads(Path(config.policy_file).read_text(encoding="utf-8")) if Path(config.policy_file).exists() else None
    policy = PolicyEngine(config.db_path, initial_policy)
    idem = IdempotencyStore(config.db_path)
    queue = SQLiteQueue(config.db_path)
    exporter = EvidenceExporter(event_store)
    classifier = ClassifierEngine()
    intelligence = DecisionIntelligence()
    blaze = BlazeRuntime(config.blaze_command)
    metrics = MetricsExporter(event_store)
    health = HealthChecks(config.db_path, config.auth_db_path)
    alerts = AlertEngine([ConsoleSink(), FileSink("varden_alerts.jsonl")])
    background = BackgroundWorker(event_store, alerts, poll_interval=config.worker_poll_interval)
    limiter = RateLimiter(
        default=BucketConfig(rate_per_window=config.rate_limit_per_minute, window_seconds=60, burst_multiplier=2.0),
        scoped={
            "read": BucketConfig(rate_per_window=config.read_rate_limit_per_minute, window_seconds=60, burst_multiplier=2.0),
            "write": BucketConfig(rate_per_window=config.write_rate_limit_per_minute, window_seconds=60, burst_multiplier=1.5),
            "ingest": BucketConfig(rate_per_window=config.ingest_rate_limit_per_minute, window_seconds=60, burst_multiplier=2.0),
            "stream": BucketConfig(rate_per_window=config.stream_connect_rate_limit_per_minute, window_seconds=60, burst_multiplier=1.5),
        },
    )
    broker = EventStreamBroker()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        background.start()
        try:
            yield
        finally:
            background.stop()

    app = FastAPI(title="Varden Integrated Platform", version="3.0.0", lifespan=lifespan)

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web"), name="static")

    tenant = auth.ensure_tenant(OSS_TENANT_ID)
    user = auth.ensure_user("admin", OSS_TENANT_ID, role="admin")
    bootstrap_token = auth.issue_bearer_token(user["user_id"], OSS_TENANT_ID, "admin")
    bootstrap_key = auth.create_api_key("admin-demo-key", tenant_id=OSS_TENANT_ID, role="admin")

    current_scan_mode = {"value": config.scan_mode}
    active_workflow_by_tenant: dict[str, str | None] = {}


    def _filter_rows(rows, *, status=None, tool=None, agent=None, search=None, since=None, until=None):
        items = []
        search_l = search.lower() if search else None
        for row in rows:
            action = row.get("action") or {}
            if status and row.get("status") != status:
                continue
            if tool and action.get("tool") != tool:
                continue
            if agent and action.get("agent_name") != agent:
                continue
            ts = row.get("timestamp") or 0
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
            if search_l:
                blob = json.dumps(row, ensure_ascii=False).lower()
                if search_l not in blob:
                    continue
            items.append(row)
        return items

    def _paginate(rows, offset=0, limit=50):
        total = len(rows)
        return {"total": total, "offset": offset, "limit": limit, "items": rows[offset:offset+limit]}

    def dashboard_bootstrap_payload(tenant_id: str):
        summary = event_store.dashboard_summary(tenant_id=tenant_id)
        summary["workflows"] = workflow_store.list_by_tenant(tenant_id, limit=8)
        summary["jobs"] = queue.list_jobs(limit=8)
        summary["policy_versions"] = policy.list_versions(limit=8)
        summary["config"] = {
            "auth_mode": config.auth_mode,
            "env": config.env,
            "public_base_url": config.public_base_url,
            "scan_mode": current_scan_mode["value"],
            "available_scan_modes": ["fast", "deep"],
            "scan_mode_change_supported": True,
            "notes": {
                "fast": "Lowest overhead. Runs classifiers and risk enrichment only when active policy requires them.",
                "deep": "Full inspection on every observed action for maximum coverage at higher latency.",
            },
        }
        summary["alerts"] = _paginate(event_store.list_alerts(limit=20, tenant_id=tenant_id), offset=0, limit=20)
        recent = summary.get("recent_events") or []
        trace_ids = []
        for row in recent:
            trace_id = row.get("trace_id") or (row.get("action") or {}).get("trace_id")
            if trace_id and trace_id not in trace_ids:
                trace_ids.append(trace_id)
        trace_catalogue = event_store.list_recent_traces(limit=12, tenant_id=tenant_id)
        summary["trace_catalogue"] = trace_catalogue
        recent_trace_lookup = {row.get("trace_id"): row for row in trace_catalogue if row and row.get("trace_id")}
        summary["recent_traces"] = [recent_trace_lookup.get(tid) or event_store.trace_summary(tid, tenant_id=tenant_id, limit=30) for tid in trace_ids[:5]]
        summary["recent_traces"] = [row for row in summary["recent_traces"] if row]
        if not summary["recent_traces"]:
            summary["recent_traces"] = trace_catalogue[:5]
        return summary

    def _format_rule_field_label(field_name: str):
        if not field_name:
            return "condition"
        if field_name.startswith("classifier:"):
            return f"classifier {field_name.split(':', 1)[1].replace('_', ' ')}"
        if field_name.startswith("field:"):
            field_name = field_name.split(':', 1)[1]
        return field_name.replace(".", " → ").replace("_", " ")

    def _format_rule_value(value):
        if isinstance(value, dict):
            return ", ".join(f"{k}={_format_rule_value(v)}" for k, v in list(value.items())[:3])
        if isinstance(value, list):
            preview = ", ".join(_format_rule_value(v) for v in value[:3])
            return preview + ("…" if len(value) > 3 else "")
        text = str(value)
        return text if len(text) <= 72 else text[:69] + "…"

    def _describe_match(row: dict):
        field = _format_rule_field_label(row.get("field"))
        operator = row.get("operator")
        expected = row.get("expected")
        actual = row.get("actual")
        if operator == "contains":
            return f"{field} contains {_format_rule_value(expected)}"
        if operator == "in":
            return f"{field} matches allowed set {_format_rule_value(expected)}"
        if operator == "gte":
            return f"{field} is ≥ {_format_rule_value(expected)} (actual {_format_rule_value(actual)})"
        if operator == "lte":
            return f"{field} is ≤ {_format_rule_value(expected)} (actual {_format_rule_value(actual)})"
        if operator == "exists":
            return f"{field} {'exists' if expected else 'is absent'}"
        return f"{field} is {_format_rule_value(expected)}"

    def _derive_rule_label(matched_rule, decision: dict, matched_fields: list[dict]):
        if isinstance(matched_rule, str) and matched_rule:
            return matched_rule
        if isinstance(matched_rule, dict):
            for key in ("title", "name", "description", "reason"):
                if matched_rule.get(key):
                    return matched_rule.get(key)
        if decision.get("rule_name"):
            return decision.get("rule_name")
        if decision.get("triggered_rule"):
            return decision.get("triggered_rule")
        if matched_fields:
            return _describe_match(matched_fields[0])
        return None

    def build_explainability(event: dict):
        action = event.get("action") or {}
        decision = event.get("decision") or {}
        matched_rule = decision.get("matched_rule")
        matched_fields = []
        if matched_rule:
            try:
                matched_fields = policy.explain_match(normalize_action(action, event.get("tenant_id") or OSS_TENANT_ID), matched_rule)
            except Exception:
                matched_fields = []

        def _humanize_risk_reason(reason: str):
            labels = {
                "tool_call": "tool invocation observed",
                "http_request": "HTTP call observed",
                "llm_call": "LLM call observed",
                "destructive_tool": "destructive tool usage",
                "network_tool": "network egress tool used",
                "database_query": "database/SQL activity detected",
                "suspicious_domain": "suspicious external domain",
                "external_domain": "external destination",
                "contains_secrets": "secrets detected",
                "contains_internal_data": "internal data detected",
                "contains_pii": "PII detected",
                "financial_data": "financial data detected",
                "unsafe_keywords": "unsafe terms detected",
                "sql_dangerous": "dangerous SQL pattern",
                "sql_unbounded_write": "unbounded SQL write",
                "sql_privilege_change": "SQL privilege change",
                "sql_schema_enumeration": "schema enumeration",
                "sql_sensitive_table": "sensitive table access",
                "sql_select_star": "SELECT * query shape",
                "sql_missing_limit": "missing LIMIT on SQL query",
                "sql_union_access": "UNION-based SQL access",
                "sql_multi_statement": "multi-statement SQL",
                "sql_comment_obfuscation": "SQL obfuscation/comment markers",
                "sql_suspect": "suspect SQL structure",
                "warned_by_policy": "warning policy applied",
                "blocked_by_policy": "blocking policy applied",
                "repeated_warn_pattern": "repeated warn pattern in recent activity",
                "repeated_block_pattern": "repeated block pattern in recent activity",
                "burst_same_tool": "burst of same tool usage",
                "workflow_activity_burst": "busy workflow pattern",
                "multi_tool_trace": "multi-tool trace behaviour",
                "multi_domain_trace": "multi-domain trace behaviour",
                "prior_warn_in_trace": "prior warning already present in trace",
                "prior_block_in_trace": "prior blocking already present in trace",
                "suspicious_sequence": "suspicious multi-step sequence",
            }
            return labels.get(reason, reason.replace('_', ' '))

        rule_label = _derive_rule_label(matched_rule, decision, matched_fields)
        rule_match_summary = "; ".join(_describe_match(row) for row in matched_fields[:3]) if matched_fields else None
        risk_score = int(action.get("risk_score") or 0)
        risk_reasons = action.get("risk_reasons") or []
        inherited_decision_context = bool(matched_rule and not matched_fields and not risk_score)
        direct_rule_trigger = bool(matched_fields)
        if inherited_decision_context:
            event_role = "follow_on"
            event_role_label = "Follow-on trace step"
            score_summary = "No new risk was added on this step. The decision context was carried forward from an earlier warned/blocked event in the same trace."
        elif risk_score > 0:
            event_role = "decision_source"
            event_role_label = "Primary scored decision step"
            human_reasons = [_humanize_risk_reason(reason) for reason in risk_reasons[:4]]
            score_summary = f"Scored {risk_score}/100 because {', '.join(human_reasons)}." if human_reasons else f"Scored {risk_score}/100 based on observed action risk."
        else:
            event_role = "neutral"
            event_role_label = "Recorded trace step"
            score_summary = "No explicit risk score was added on this step."
        if direct_rule_trigger:
            trigger_summary = f"Policy fired because {rule_match_summary}." if rule_match_summary else "Policy fired on this step."
        elif inherited_decision_context:
            trigger_summary = "This step inherits the earlier warn/block decision context rather than matching a new rule condition itself."
        else:
            trigger_summary = decision.get("reason") or "No explicit rule-field explanation was captured for this event."
        return {
            "decision_action": decision.get("action") or event.get("status"),
            "effective_action": decision.get("effective_action") or decision.get("action") or event.get("status"),
            "reason": decision.get("reason"),
            "matched_rule": matched_rule,
            "rule_label": rule_label,
            "rule_match_summary": rule_match_summary,
            "trigger_summary": trigger_summary,
            "inherited_decision_context": inherited_decision_context,
            "direct_rule_trigger": direct_rule_trigger,
            "event_role": event_role,
            "event_role_label": event_role_label,
            "matched_fields": matched_fields,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "risk_reason_labels": [_humanize_risk_reason(reason) for reason in risk_reasons],
            "score_summary": score_summary,
            "classifiers": action.get("classifiers") or {},
            "route_target": decision.get("route_target") or action.get("route_target") or "cloud",
            "scan": (action.get("metadata") or {}).get("scan") or {},
            "decision_latency_ms": (action.get("metadata") or {}).get("decision_latency_ms", 0),
        }

    def run_demo_scenarios(tenant_id: str):
        scenarios = [
            {"name": "allow", "payload": {"type": "http_request", "tool": "httpx", "url": "https://example.com/health", "method": "POST", "args": {"body": {"title": "public status heartbeat", "notes": "availability green and latency normal"}}, "agent_name": "allowed-demo-agent", "trace_id": "demo-trace-allow"}, "raw": {"title": "public status heartbeat", "notes": "availability green and latency normal"}},
            {"name": "warn", "payload": {"type": "http_request", "tool": "httpx", "url": "https://partner.example/api/report", "method": "POST", "args": {"body": {"title": "Q2 incident review", "notes": "internal only customer data for internal review", "owner": "ops@example.com"}}, "agent_name": "flagged-demo-agent", "trace_id": "demo-trace-warn"}, "raw": {"title": "Q2 incident review", "notes": "internal only customer data for internal review", "owner": "ops@example.com"}},
            {"name": "block", "payload": {"type": "tool_call", "tool": "delete_database", "args": {"args": ["prod-customer-db"], "kwargs": {}}, "agent_name": "blocked-demo-agent", "trace_id": "demo-trace-block"}, "raw": {"args": ["prod-customer-db"], "kwargs": {}}},
        ]
        out = []
        for scenario in scenarios:
            action, decision = evaluate_action(scenario["payload"], scenario["raw"], tenant_id)
            status = status_from_decision(decision.action)
            event_id = persist_event(action=action, decision=decision, status=status, input_payload=scenario["raw"], replay_key=action.tool, error=f"[Varden BLOCKED] {decision.reason}" if status == "blocked" else None)
            out.append({"name": scenario["name"], "event_id": event_id, "status": status, "trace_id": action.trace_id})
        return out

    def status_from_decision(action: str | None) -> str:
        text = str(action or "").strip().lower()
        if text in {"block", "blocked"}:
            return "blocked"
        if text in {"warn", "warned"}:
            return "warned"
        if text == "monitor":
            return "monitor"
        return "allowed"

    def require(x_api_key=None, authorization=None, role="viewer", scope: str = "read"):
        token = None
        raw = x_api_key or authorization or "anon"
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
            raw = token
        key = raw
        if not limiter.allow(key, scope=scope):
            retry_after = limiter.retry_after(key, scope=scope)
            raise HTTPException(status_code=429, detail={"message": "rate limit exceeded", "scope": scope, "retry_after_seconds": retry_after})
        ok, reason, record = auth.require_role(api_key=x_api_key, bearer_token=token, min_role=role)
        if not ok:
            raise HTTPException(status_code=403, detail=reason)
        return record

    def normalize_action(payload: dict[str, Any], tenant_id: str) -> Action:
        metadata = payload.get("metadata") or {}
        args = payload.get("args") or {}
        url = payload.get("url")
        domain = payload.get("domain") or (urlparse(url).netloc if url else None)
        return Action(
            type=payload.get("type", "tool_call"),
            tool=payload.get("tool"),
            method=payload.get("method"),
            url=url,
            domain=domain,
            args=args,
            metadata=metadata,
            agent_name=payload.get("agent_name"),
            workflow_id=payload.get("workflow_id"),
            parent_event_id=payload.get("parent_event_id"),
            trace_id=payload.get("trace_id") or metadata.get("trace_id") or payload.get("workflow_id"),
            tenant_id=payload.get("tenant_id") or tenant_id,
        )

    def enrich_action(action: Action, payload: Any) -> Action:
        meta = dict(action.metadata or {})
        meta.setdefault("scan", {})["mode"] = current_scan_mode["value"]
        start = time.perf_counter()
        if current_scan_mode["value"] == "deep":
            action.classifiers = classifier.classify(payload)
            action = intelligence.enrich(action)
            meta["scan"]["depth"] = "deep"
        else:
            if policy.requires_classifiers():
                action.classifiers = classifier.classify(payload)
            else:
                action.classifiers = {}
            # Always compute lightweight base risk so warned/blocked actions are never shown as riskless.
            action = intelligence.enrich(action)
            meta["scan"]["depth"] = "fast"
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        meta["decision_latency_ms"] = round(elapsed_ms, 3)
        action.metadata = meta
        action.route_target = blaze.route(action.classifiers, action.risk_score).target if config.route_sensitive_to_local else "cloud"
        return action

    def persist_event(*, action: Action, decision, status: str, input_payload=None, output_payload=None, error=None, replay_key=None):
        event_id = event_store.log(EventRecord.new(
            action=action.to_dict(),
            decision=decision.to_dict() if hasattr(decision, 'to_dict') else decision,
            status=status,
            input_payload=input_payload,
            output_payload=output_payload,
            replayable=False,
            replay_key=replay_key,
            workflow_id=action.workflow_id,
            agent_name=action.agent_name,
            parent_event_id=action.parent_event_id,
            trace_id=action.trace_id,
            tenant_id=action.tenant_id,
            error=error,
        ).to_dict())
        event_row = event_store.get_event(event_id, tenant_id=action.tenant_id) or {}
        action_row = event_row.get("action") or {}
        decision_row = event_row.get("decision") or {}
        broker.publish({
            "type": "event",
            "event_id": event_id,
            "tenant_id": action.tenant_id,
            "status": status,
            "tool": action.tool,
            "workflow_id": action.workflow_id,
            "agent_name": action.agent_name,
            "timestamp": time.time(),
            "event": {
                "id": event_id,
                "timestamp": event_row.get("timestamp", time.time()),
                "tool": action_row.get("tool"),
                "agent_name": action_row.get("agent_name"),
                "status": event_row.get("status", status),
                "risk_score": action_row.get("risk_score", 0),
                "route_target": decision_row.get("route_target") or action_row.get("route_target") or "cloud",
                "reason": decision_row.get("reason"),
                "workflow_id": event_row.get("workflow_id"),
                "domain": action_row.get("domain"),
                "classifiers": action_row.get("classifiers") or {},
            },
        })
        return event_id

    def evaluate_action(payload: dict[str, Any], raw_payload: Any, tenant_id: str):
        action = normalize_action(payload, tenant_id)
        action = enrich_action(action, raw_payload)
        decision = policy.evaluate(action)
        recent_events = event_store.list_events(limit=120, tenant_id=tenant_id)
        trace_events = event_store.list_trace_events(action.trace_id, tenant_id=tenant_id, limit=60) if action.trace_id else []
        action = intelligence.apply_decision_context(action, decision, recent_events=recent_events, trace_events=trace_events)
        decision.route_target = action.route_target
        return action, decision

    def record_tool(tool_name: str, args: list, kwargs: dict, tenant_id: str, agent_name: str | None = None, workflow_id: str | None = None):
        action_payload = {
            "type": "tool_call",
            "tool": tool_name,
            "args": {"args": args, "kwargs": kwargs},
            "agent_name": agent_name,
            "workflow_id": workflow_id,
            "tenant_id": tenant_id,
        }
        action, decision = evaluate_action(action_payload, {"args": args, "kwargs": kwargs}, tenant_id)
        if decision.action == "block":
            persist_event(action=action, decision=decision, status="blocked", input_payload={"args": args, "kwargs": kwargs}, replay_key=tool_name, error=f"[Varden BLOCKED] {decision.reason}")
            raise HTTPException(status_code=403, detail=f"[Varden BLOCKED] {decision.reason}")
        result = blaze.execute_local({"args": args, "kwargs": kwargs}) if action.route_target == "local_blaze" else {"status": "cloud_ok"}
        persist_event(action=action, decision=decision, status=status_from_decision(decision.action), input_payload={"args": args, "kwargs": kwargs}, output_payload=result, replay_key=tool_name)
        return result

    @app.get("/")
    def root():
        return RedirectResponse(url="/ui")

    @app.get("/health")
    def health_summary():
        return {
            "status": "ok",
            "bootstrap_api_key": bootstrap_key["api_key"] if config.enable_dev_bootstrap else None,
            "bootstrap_bearer_token": bootstrap_token if config.enable_dev_bootstrap else None,
            "tenant_id": OSS_TENANT_ID,
            "metrics": event_store.metrics(OSS_TENANT_ID),
            "public_base_url": config.public_base_url,
            "auth_mode": config.auth_mode,
            "env": config.env,
            "scan_mode": current_scan_mode["value"],
        }

    @app.get("/sdk/bootstrap")
    def sdk_bootstrap():
        return {
            "base_url": config.public_base_url,
            "bootstrap_api_key": bootstrap_key["api_key"],
            "tenant_id": OSS_TENANT_ID,
            "default_policy": policy.get_policy(),
            "scan_mode": current_scan_mode["value"],
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
        record = require(x_api_key, authorization, "viewer", scope="read")
        return metrics.render_prometheus(tenant_id=record["tenant_id"])

    @app.get("/ui", response_class=HTMLResponse)
    def ui():
        return (Path(__file__).parent / "web" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/ui/rules", response_class=HTMLResponse)
    def ui_rules():
        return (Path(__file__).parent / "web" / "rules.html").read_text(encoding="utf-8")

    @app.get("/ui/decision/{event_id}", response_class=HTMLResponse)
    def ui_decision(event_id: int):
        return (Path(__file__).parent / "web" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/runtime/config")
    def runtime_config(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        return {
            "scan_mode": current_scan_mode["value"],
            "env": config.env,
            "auth_mode": config.auth_mode,
            "public_base_url": config.public_base_url,
            "available_scan_modes": ["fast", "deep"],
            "scan_mode_change_supported": True,
            "notes": {
                "fast": "Lowest overhead. Runs classifiers and risk enrichment only when active policy requires them.",
                "deep": "Full inspection on every observed action for maximum coverage at higher latency."
            }
        }

    @app.get("/dashboard/bootstrap")
    def dashboard_bootstrap(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return dashboard_bootstrap_payload(record["tenant_id"])

    @app.get("/ui/bootstrap")
    def ui_bootstrap(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        """Return everything the UI needs in one shaped payload.

        In local/dev bootstrap mode the UI can start with no prior token and receive a
        bootstrap API key plus the initial dashboard snapshot in a single round-trip.
        In normal mode this endpoint behaves like the authenticated dashboard bootstrap.
        """
        if config.enable_dev_bootstrap and not x_api_key and not authorization:
            payload = dashboard_bootstrap_payload(OSS_TENANT_ID)
            return {
                "auth": {
                    "mode": "bootstrap",
                    "token": bootstrap_key["api_key"],
                    "token_type": "api_key",
                    "tenant_id": OSS_TENANT_ID,
                    "role": bootstrap_key.get("role", "admin"),
                },
                "dashboard": payload,
            }
        record = require(x_api_key, authorization, "viewer", scope="read")
        return {
            "auth": {
                "mode": "authenticated",
                "token": x_api_key or (authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None),
                "token_type": "bearer" if authorization and authorization.lower().startswith("bearer ") else "api_key",
                "tenant_id": record["tenant_id"],
                "role": record.get("role", "viewer"),
            },
            "dashboard": dashboard_bootstrap_payload(record["tenant_id"]),
        }

    @app.post("/runtime/config/scan-mode")
    def set_scan_mode(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin", scope="write")
        mode = str((payload or {}).get("scan_mode", "")).strip().lower()
        if mode not in {"fast", "deep"}:
            raise HTTPException(status_code=400, detail="scan_mode must be fast or deep")
        previous = current_scan_mode["value"]
        current_scan_mode["value"] = mode
        broker.publish({"type": "config", "key": "scan_mode", "value": current_scan_mode["value"], "timestamp": time.time()})
        return {"ok": True, "previous_scan_mode": previous, "scan_mode": current_scan_mode["value"]}


    @app.get("/stream/updates")
    async def stream_updates(token: str | None = None):
        record = require(x_api_key=token, authorization=(f"Bearer {token}" if token and '.' in token else None), role="viewer")

        async def event_generator():
            queue = await broker.subscribe()
            try:
                yield ': connected\n\n'
                while True:
                    try:
                        message = await asyncio.wait_for(queue.get(), timeout=20.0)
                        if message.get("tenant_id") and message.get("tenant_id") != record["tenant_id"]:
                            continue
                        yield f"data: {json.dumps(message)}\n\n"
                    except asyncio.TimeoutError:
                        yield ': keepalive\n\n'
            finally:
                broker.unsubscribe(queue)

        return StreamingResponse(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})

    @app.get("/dashboard/overview")
    def dashboard_overview(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return dashboard_bootstrap_payload(record["tenant_id"])

    @app.get("/events/{event_id}")
    def event_detail(event_id: int, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        event = event_store.get_event(event_id, tenant_id=record["tenant_id"])
        if not event:
            raise HTTPException(status_code=404, detail="event not found")
        event["input_payload"] = redact(event.get("input_payload"))
        event["output_payload"] = redact(event.get("output_payload"))
        neighbors = event_store.get_event_neighbors(event_id, tenant_id=record["tenant_id"])
        workflow_events = []
        if event.get("workflow_id"):
            workflow_events = event_store.list_workflow_events(event["workflow_id"], tenant_id=record["tenant_id"], limit=30)
            for row in workflow_events:
                row["input_payload"] = redact(row.get("input_payload"))
                row["output_payload"] = redact(row.get("output_payload"))
        action = event.get("action") or {}
        decision = event.get("decision") or {}
        explainability = build_explainability(event)
        trace = event_store.trace_summary(event.get('trace_id'), tenant_id=record['tenant_id'], limit=60) if event.get('trace_id') else None
        return {"event": event, "neighbors": neighbors, "workflow_events": workflow_events, "trace": trace, "explainability": explainability}

    @app.get("/traces/{trace_id}")
    def trace_detail(trace_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        trace = event_store.trace_summary(trace_id, tenant_id=record["tenant_id"], limit=200)
        if not trace:
            raise HTTPException(status_code=404, detail="trace not found")
        for row in trace.get("events") or []:
            row["input_payload"] = redact(row.get("input_payload"))
            row["output_payload"] = redact(row.get("output_payload"))
        return trace

    @app.get("/traces")
    def trace_list(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), limit: int = 20):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return {"items": event_store.list_recent_traces(limit=limit, tenant_id=record["tenant_id"])}

    @app.post("/sdk/guard")
    @app.post("/v1/actions/guard")
    def sdk_guard(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        action_payload = payload.get("action") or {}
        raw_payload = payload.get("payload") or action_payload.get("args") or {}
        action, decision = evaluate_action(action_payload, raw_payload, record["tenant_id"])
        status = status_from_decision(decision.action)
        event_id = persist_event(action=action, decision=decision, status=status, input_payload=raw_payload, replay_key=action.tool, error=f"[Varden BLOCKED] {decision.reason}" if status == "blocked" else None)
        response = {"event_id": event_id, "decision": decision.to_dict(), "action": action.to_dict()}
        if decision.action == "block":
            raise HTTPException(status_code=403, detail=response)
        return response

    @app.post("/sdk/log")
    @app.post("/v1/actions/log")
    def sdk_log(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        action_payload = payload.get("action") or {}
        decision_payload = payload.get("decision") or {"action": "allow", "reason": "sdk log"}
        action = normalize_action(action_payload, record["tenant_id"])
        status = payload.get("status") or status_from_decision(decision_payload.get("action"))
        event_id = persist_event(action=action, decision=decision_payload, status=status, input_payload=payload.get("input_payload"), output_payload=payload.get("output_payload"), error=payload.get("error"), replay_key=action.tool)
        return {"logged": True, "event_id": event_id}

    @app.get("/policy")
    def get_policy(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst", scope="read")
        return policy.get_policy()

    @app.get("/policy/templates")
    def get_policy_templates(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst", scope="read")
        return policy.templates()

    @app.post("/policy/validate")
    def validate_policy(candidate: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst", scope="write")
        return policy.validate(candidate)

    @app.post("/policy/simulate")
    def simulate_policy(candidate: dict, trace_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        validation = policy.validate(candidate)
        if not validation["valid"]:
            raise HTTPException(status_code=400, detail=validation)
        trace_events = event_store.list_trace_events(trace_id, tenant_id=record["tenant_id"], limit=200)
        if not trace_events:
            raise HTTPException(status_code=404, detail="trace not found")
        return {"trace_id": trace_id, **policy.simulate_trace(trace_events, candidate)}

    @app.put("/policy")
    def put_policy(candidate: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin", scope="write")
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
        require(x_api_key, authorization, "analyst", scope="read")
        return policy.list_versions()

    @app.post("/policy/publish/{version_id}")
    def publish(version_id: int, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin", scope="write")
        return policy.publish(version_id)

    @app.get("/events")
    def events(limit: int = 50, offset: int = 0, status: str | None = None, tool: str | None = None, agent: str | None = None, search: str | None = None, since: float | None = None, until: float | None = None, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        rows = event_store.list_events(limit=max(limit + offset, 200), tenant_id=record["tenant_id"])
        for r in rows:
            r["input_payload"] = redact(r["input_payload"])
            r["output_payload"] = redact(r["output_payload"])
        rows = _filter_rows(rows, status=status, tool=tool, agent=agent, search=search, since=since, until=until)
        return _paginate(rows, offset=offset, limit=limit)

    @app.get("/alerts")
    def alerts_route(limit: int = 50, offset: int = 0, severity: str | None = None, only_open: bool = False, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        rows = event_store.list_alerts(limit=max(limit + offset, 200), tenant_id=record["tenant_id"])
        if severity:
            rows = [r for r in rows if r.get("severity") == severity]
        if only_open:
            rows = [r for r in rows if not r.get("acknowledged")]
        return _paginate(rows, offset=offset, limit=limit)

    @app.post("/alerts/{alert_id}/ack")
    def ack_alert(alert_id: int, note: str = "", x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        return event_store.acknowledge_alert(alert_id, user=str(record.get("user_id", "unknown")), note=note)

    @app.post("/workflows/start")
    def start_workflow(name: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="write")
        wf = WorkflowSession(name=name, tenant_id=record["tenant_id"])
        active_workflow_by_tenant[record["tenant_id"]] = wf.workflow_id
        workflow_store.create(wf.workflow_id, wf.name, wf.tenant_id, status="active")
        return wf.to_dict()

    @app.post("/workflows/close")
    def close_workflow(workflow_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="write")
        if active_workflow_by_tenant.get(record["tenant_id"]) == workflow_id:
            active_workflow_by_tenant[record["tenant_id"]] = None
        workflow_store.close(workflow_id)
        return {"closed": workflow_id}

    @app.get("/workflows")
    def workflows(limit: int = 50, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return workflow_store.list_by_tenant(record["tenant_id"], limit=limit)

    @app.post("/jobs/enqueue")
    def enqueue(job_type: str, payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin", scope="write")
        return {"job_id": queue.enqueue(job_type, payload, tenant_id=record["tenant_id"])}

    @app.get("/jobs")
    def jobs(limit: int = 100, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "admin", scope="read")
        return queue.list_jobs(limit=limit)

    @app.get("/metrics/json")
    def metrics_json(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return event_store.metrics(tenant_id=record["tenant_id"])


    @app.post("/demo/tool")
    def demo_tool(tool_name: str, payload: dict, workflow_id: str | None = None, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="write")
        active_workflow = workflow_id or active_workflow_by_tenant.get(record["tenant_id"])
        return record_tool(tool_name, payload.get("args", []), payload.get("kwargs", {}), tenant_id=record["tenant_id"], workflow_id=active_workflow, agent_name="demo")

    @app.post("/demo/run")
    def demo_run(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="write")
        return {"scenarios": run_demo_scenarios(record["tenant_id"]), "dashboard": dashboard_bootstrap_payload(record["tenant_id"])}

    return app
