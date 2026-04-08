from __future__ import annotations
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

    def _row_to_event(self, r):
        return {
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
            "trace_id": r["trace_id"],
            "tenant_id": r["tenant_id"],
            "event_hash": r["event_hash"],
            "prev_hash": r["prev_hash"],
        }

    def log(self, event: dict):
        prev_hash = self._latest_hash()
        event_hash = hashlib.sha256((stable_json(event) + (prev_hash or "")).encode("utf-8")).hexdigest()
        event["prev_hash"] = prev_hash
        event["event_hash"] = event_hash
        with connect(self.db_path) as conn:
            cur = conn.execute(
                """INSERT INTO events (
                    timestamp, action_json, decision_json, status, input_payload_json, output_payload_json, error,
                    replayable, replay_key, workflow_id, agent_name, parent_event_id, trace_id, tenant_id, event_hash, prev_hash
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    event.get("trace_id"),
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
            return [self._row_to_event(r) for r in rows]

    def get_event(self, event_id: int, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                row = conn.execute("SELECT * FROM events WHERE id=? AND tenant_id=?", (event_id, tenant_id)).fetchone()
            else:
                row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            return self._row_to_event(row) if row else None

    def list_workflow_events(self, workflow_id: str, tenant_id: str | None = None, limit: int = 200):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM events WHERE workflow_id=? AND tenant_id=? ORDER BY id DESC LIMIT ?",
                    (workflow_id, tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM events WHERE workflow_id=? ORDER BY id DESC LIMIT ?", (workflow_id, limit)).fetchall()
            return [self._row_to_event(r) for r in rows]

    def get_event_neighbors(self, event_id: int, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                prev_row = conn.execute(
                    "SELECT id FROM events WHERE tenant_id=? AND id < ? ORDER BY id DESC LIMIT 1",
                    (tenant_id, event_id),
                ).fetchone()
                next_row = conn.execute(
                    "SELECT id FROM events WHERE tenant_id=? AND id > ? ORDER BY id ASC LIMIT 1",
                    (tenant_id, event_id),
                ).fetchone()
            else:
                prev_row = conn.execute("SELECT id FROM events WHERE id < ? ORDER BY id DESC LIMIT 1", (event_id,)).fetchone()
                next_row = conn.execute("SELECT id FROM events WHERE id > ? ORDER BY id ASC LIMIT 1", (event_id,)).fetchone()
        return {
            "previous_event_id": prev_row["id"] if prev_row else None,
            "next_event_id": next_row["id"] if next_row else None,
        }


    def list_trace_events(self, trace_id: str, tenant_id: str | None = None, limit: int = 200):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM events WHERE trace_id=? AND tenant_id=? ORDER BY id ASC LIMIT ?",
                    (trace_id, tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM events WHERE trace_id=? ORDER BY id ASC LIMIT ?", (trace_id, limit)).fetchall()
            return [self._row_to_event(r) for r in rows]


    def list_recent_traces(self, limit: int = 12, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT trace_id, MAX(id) AS last_id FROM events WHERE tenant_id=? AND trace_id IS NOT NULL AND trace_id != '' GROUP BY trace_id ORDER BY last_id DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT trace_id, MAX(id) AS last_id FROM events WHERE trace_id IS NOT NULL AND trace_id != '' GROUP BY trace_id ORDER BY last_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        summaries = []
        for row in rows:
            summary = self.trace_summary(row["trace_id"], tenant_id=tenant_id, limit=200)
            if summary:
                summaries.append(summary)
        return summaries

    def trace_summary(self, trace_id: str, tenant_id: str | None = None, limit: int = 200):
        rows = self.list_trace_events(trace_id, tenant_id=tenant_id, limit=limit)
        if not rows:
            return None
        nodes = []
        edges = []
        seen = set()
        statuses = Counter()
        tools = Counter()
        agents = Counter()
        for idx, row in enumerate(rows):
            action = row.get("action") or {}
            decision = row.get("decision") or {}
            node = {
                "id": row.get("id"),
                "label": action.get("tool") or action.get("type") or f"event-{row.get('id')}",
                "status": row.get("status"),
                "risk_score": action.get("risk_score", 0),
                "agent_name": action.get("agent_name"),
                "type": action.get("type"),
                "domain": action.get("domain"),
                "decision": decision.get("effective_action") or decision.get("action"),
            }
            nodes.append(node)
            statuses[row.get("status") or "unknown"] += 1
            if action.get("tool"):
                tools[action.get("tool")] += 1
            if action.get("agent_name"):
                agents[action.get("agent_name")] += 1
            parent_id = row.get("parent_event_id")
            if parent_id:
                edge = (parent_id, row.get("id"))
                if edge not in seen:
                    seen.add(edge)
                    edges.append({"source": parent_id, "target": row.get("id"), "kind": "parent"})
            elif idx > 0:
                edge = (rows[idx - 1].get("id"), row.get("id"))
                if edge not in seen:
                    seen.add(edge)
                    edges.append({"source": rows[idx - 1].get("id"), "target": row.get("id"), "kind": "sequence"})
        return {
            "trace_id": trace_id,
            "events": rows,
            "graph": {"nodes": nodes, "edges": edges},
            "summary": {
                "event_count": len(rows),
                "statuses": dict(statuses),
                "tools": dict(tools.most_common(8)),
                "agents": dict(agents.most_common(8)),
                "start_timestamp": rows[0].get("timestamp"),
                "end_timestamp": rows[-1].get("timestamp"),
            },
        }

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
        latencies = [float(((e.get("action") or {}).get("metadata") or {}).get("decision_latency_ms", 0)) for e in events if ((e.get("action") or {}).get("metadata") or {}).get("decision_latency_ms") is not None]
        latencies = [v for v in latencies if v >= 0]
        latencies_sorted = sorted(latencies)
        p95 = latencies_sorted[int(len(latencies_sorted)*0.95)-1] if latencies_sorted else 0.0
        avg = round(sum(latencies)/len(latencies), 3) if latencies else 0.0
        return {
            "total_events": len(events),
            "blocked_events": sum(1 for e in events if e["status"] == "blocked"),
            "warned_events": sum(1 for e in events if e["status"] == "warned"),
            "local_routes": sum(1 for e in events if e["action"].get("route_target") == "local_blaze"),
            "open_alerts": sum(1 for a in alerts if not a["acknowledged"]),
            "avg_decision_latency_ms": avg,
            "p95_decision_latency_ms": round(p95, 3),
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
        domain_counts = Counter()
        method_counts = Counter()
        risk_buckets = Counter()
        latest_risk = []
        decision_latency_points = []

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
            if action.get("domain"):
                domain_counts[action["domain"]] += 1
            if action.get("method"):
                method_counts[action["method"]] += 1
            for name, flag in (action.get("classifiers") or {}).items():
                if flag:
                    classifier_counts[name] += 1
            risk_score = int(action.get("risk_score", 0) or 0)
            if risk_score >= 80:
                risk_buckets["high"] += 1
            elif risk_score >= 40:
                risk_buckets["medium"] += 1
            else:
                risk_buckets["low"] += 1
            latest_risk.append({
                "timestamp": e["timestamp"],
                "tool": tool,
                "status": e["status"],
                "risk_score": risk_score,
            })
            latency = float(((action.get("metadata") or {}).get("decision_latency_ms", 0)) or 0)
            decision_latency_points.append({"timestamp": e["timestamp"], "latency_ms": round(latency, 3), "status": e["status"]})

        recent_events = []
        for e in events[:16]:
            action = e.get("action") or {}
            decision = e.get("decision") or {}
            matched_rule = decision.get("matched_rule")
            matched_rule_label = matched_rule if isinstance(matched_rule, str) else (matched_rule or {}).get("title") or (matched_rule or {}).get("name") or (matched_rule or {}).get("description") or (matched_rule or {}).get("reason")
            if not matched_rule_label and e.get("status") in {"blocked", "warned"}:
                matched_rule_label = decision.get("reason") or f"{e.get('status')} policy"
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
                "domain": action.get("domain"),
                "classifiers": action.get("classifiers") or {},
                "matched_rule": matched_rule,
                "matched_rule_label": matched_rule_label,
            })

        total_events = metrics.get("total_events", 0) or 0
        blocked_events = metrics.get("blocked_events", 0) or 0
        warned_events = metrics.get("warned_events", 0) or 0
        allowed_events = max(total_events - blocked_events - warned_events, 0)
        coverage = {
            "blocked_pct": round((blocked_events / total_events) * 100, 1) if total_events else 0.0,
            "warned_pct": round((warned_events / total_events) * 100, 1) if total_events else 0.0,
            "allowed_pct": round((allowed_events / total_events) * 100, 1) if total_events else 0.0,
        }
        posture = "guarded" if blocked_events else "observing" if warned_events else "clean"

        insights = []
        if blocked_events:
            insights.append({
                "severity": "high",
                "title": "Active blocking observed",
                "message": f"Sentinel blocked {blocked_events} action{'s' if blocked_events != 1 else ''}. Review high-risk tools and matched rules.",
            })
        if classifier_counts:
            top_name, top_count = classifier_counts.most_common(1)[0]
            insights.append({
                "severity": "medium",
                "title": "Sensitive classifier activity",
                "message": f"Classifier '{top_name}' fired {top_count} times. Consider tightening destination or route policy.",
            })
        if metrics.get("avg_decision_latency_ms", 0) > 15:
            insights.append({
                "severity": "medium",
                "title": "Inspection latency elevated",
                "message": f"Average decision time is {metrics['avg_decision_latency_ms']} ms. Consider fast mode for lower overhead.",
            })
        if not insights:
            insights.append({
                "severity": "low",
                "title": "Healthy posture",
                "message": "No elevated risk patterns detected in the current event window.",
            })

        return {
            "generated_at": time.time(),
            "metrics": metrics,
            "coverage": coverage,
            "posture": posture,
            "timeline": sorted(buckets.values(), key=lambda x: x["timestamp"])[-30:],
            "status_breakdown": dict(status_counts),
            "route_breakdown": dict(route_counts),
            "top_tools": [{"tool": k, "count": v} for k, v in tool_counts.most_common(8)],
            "top_agents": [{"agent": k, "count": v} for k, v in agent_counts.most_common(6)],
            "top_domains": [{"domain": k, "count": v} for k, v in domain_counts.most_common(6)],
            "http_methods": [{"method": k, "count": v} for k, v in method_counts.most_common(6)],
            "risk_distribution": dict(risk_buckets),
            "classifier_hits": [{"classifier": k, "count": v} for k, v in classifier_counts.most_common(8)],
            "recent_events": recent_events,
            "recent_alerts": alerts[:8],
            "latest_risk": latest_risk[-20:],
            "decision_latency_points": decision_latency_points[-40:],
            "scan_performance": {"avg_decision_latency_ms": metrics.get("avg_decision_latency_ms", 0.0), "p95_decision_latency_ms": metrics.get("p95_decision_latency_ms", 0.0)},
            "insights": insights,
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
