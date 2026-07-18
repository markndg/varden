from __future__ import annotations

import json
import time
import uuid
from typing import Any

from varden.db import connect, init_db
from varden.models import Action, EventRecord
from varden.redaction import redact_webmcp_output, redact_webmcp_value

from .engine import scan_output, scan_registration
from .layers.capability import infer_capability_profile
from .models import ScanContext, WebMCPToolDefinition
from .sanitize import sanitize_tool

REGISTRATION_BURST_WINDOW_SECONDS = 300.0
CONFIG_VERSION = "1"

# Maps a Varden policy bucket (see varden/policy.py MODES) to the enforcement
# vocabulary used in event metadata. Kept as a plain dict (not an enum) so it
# stays trivially serialisable and diffable against the JS/extension side.
POLICY_TO_ENFORCEMENT = {
    "block": "block",
    "require_approval": "require_approval",
    "sanitise": "sanitise",
    "warn": "warn",
    "monitor": "monitor",
    "allow": "allow",
}


def _version_gte(reported: str, minimum: str) -> bool:
    """Loose semver comparison for extension/server capability negotiation.

    Non-numeric / empty components compare as 0 so a missing or malformed
    extension_version is treated as older than any real minimum rather than
    crashing the health endpoint.
    """

    def parts(value: str) -> list[int]:
        out: list[int] = []
        for piece in str(value or "0").split("."):
            digits = "".join(ch for ch in piece if ch.isdigit())
            out.append(int(digits) if digits else 0)
        while len(out) < 3:
            out.append(0)
        return out[:3]

    return parts(reported) >= parts(minimum)


def _webmcp_agent_label(owner_origin: str | None) -> str:
    """Varden's dashboard (Overview recent activity, Decision page, Sankey
    flows) shows ``action.agent_name`` wherever it needs a human-readable
    "who did this" label, and falls back to "unknown agent" when it's unset.
    Web Shield events have no traditional AI-agent identity to report — the
    actual browser agent consuming a WebMCP tool is unobservable from the
    server side (see docs/web-shield-limitations.md) — but they do always
    have a genuinely identifying source: the website that registered/exposed
    the tool. Using that origin (not the tool name, which varies per
    registration and would fragment per-origin pattern detection like
    "repeated warn pattern from the same agent") as the label means every
    webmcp.* event gets a concrete, per-site, groupable name instead of
    "unknown agent", without ever claiming to know which AI agent was
    actually driving it.
    """

    if not owner_origin:
        return "webmcp:unknown-origin"
    host = owner_origin.split("://", 1)[-1].strip("/") or owner_origin
    return f"webmcp:{host}"


def _row_to_tool(row) -> dict[str, Any]:
    return {
        "identity_key": row["identity_key"],
        "owner_origin": row["owner_origin"],
        "top_origin": row["top_origin"],
        "tool_name": row["tool_name"],
        "api_surface": row["api_surface"],
        "exact_hash": row["exact_hash"],
        "canonical_hash": row["canonical_hash"],
        "structural_hash": row["structural_hash"] if "structural_hash" in row.keys() else None,
        "tool": json.loads(row["tool_json"]),
        "risk_score": row["risk_score"],
        "risk_band": row["risk_band"],
        "findings": json.loads(row["findings_json"] or "[]"),
        "trust_state": row["trust_state"],
        "status": row["status"],
        "registration_count": row["registration_count"],
        "first_seen_at": row["first_seen_at"],
        "last_seen_at": row["last_seen_at"],
        "updated_at": row["updated_at"],
    }


class WebShieldStore:
    """Persistence + orchestration for Varden Web Shield.

    Mirrors :class:`varden.mcp_inventory.McpInventoryStore`'s shape (discover
    → normalise → store → gap-analyse) but for browser-supplied WebMCP tool
    registrations instead of local MCP config files, and additionally owns
    the approval/trust workflows unique to a live browser integration.

    Security-relevant activity is logged through the *existing* Varden event
    model (``EventStore.log`` via ``Action``/``Decision``/``EventRecord``)
    with ``trace_id`` set to the browser session id, so it appears in the
    existing ``/events`` and ``/traces/{id}`` views for free. Dedicated
    tables only exist for state the generic event log cannot answer
    efficiently: current identity/hash registry, session registry, local
    trust decisions, and the approval state machine.
    """

    def __init__(self, db_path: str, event_store, policy_engine):
        self.db_path = db_path
        init_db(db_path)
        self.event_store = event_store
        self.policy_engine = policy_engine

    # ---------------------------------------------------------------- trust

    def get_trust(self, tenant_id: str | None, origin: str) -> str | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT state, expires_at FROM webshield_trust WHERE tenant_id IS ? AND origin = ?",
                (tenant_id, origin),
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] and row["expires_at"] < time.time():
                return None
            return row["state"]

    def set_trust(self, tenant_id: str | None, origin: str, state: str, *, created_by: str | None = None, expires_at: float | None = None) -> dict[str, Any]:
        if state not in {"trusted", "blocked"}:
            raise ValueError("state must be 'trusted' or 'blocked'")
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO webshield_trust (tenant_id, origin, state, created_at, created_by, expires_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(tenant_id, origin) DO UPDATE SET state=excluded.state, created_at=excluded.created_at,
                     created_by=excluded.created_by, expires_at=excluded.expires_at""",
                (tenant_id, origin, state, time.time(), created_by, expires_at),
            )
            conn.commit()
        return {"origin": origin, "state": state, "expires_at": expires_at}

    def remove_trust(self, tenant_id: str | None, origin: str) -> bool:
        with connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM webshield_trust WHERE tenant_id IS ? AND origin = ?", (tenant_id, origin))
            conn.commit()
            return cur.rowcount > 0

    def list_trust(self, tenant_id: str | None) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM webshield_trust WHERE tenant_id IS ? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # -------------------------------------------------------------- sessions

    def touch_session(
        self, tenant_id: str | None, session_id: str, *, tab_id: str | None = None, top_origin: str | None = None,
        extension_version: str | None = None, sdk_version: str | None = None, connected: bool = True,
        protection_mode: str = "connected",
    ) -> None:
        now = time.time()
        with connect(self.db_path) as conn:
            existing = conn.execute("SELECT session_id FROM webshield_sessions WHERE session_id = ?", (session_id,)).fetchone()
            if existing:
                conn.execute(
                    """UPDATE webshield_sessions SET last_seen_at=?, tab_id=COALESCE(?,tab_id), top_origin=COALESCE(?,top_origin),
                       extension_version=COALESCE(?,extension_version), sdk_version=COALESCE(?,sdk_version),
                       connected=?, protection_mode=? WHERE session_id=?""",
                    (now, tab_id, top_origin, extension_version, sdk_version, 1 if connected else 0, protection_mode, session_id),
                )
            else:
                conn.execute(
                    """INSERT INTO webshield_sessions
                       (session_id, tenant_id, tab_id, top_origin, started_at, last_seen_at, extension_version, sdk_version, connected, protection_mode)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (session_id, tenant_id, tab_id, top_origin, now, now, extension_version, sdk_version, 1 if connected else 0, protection_mode),
                )
            conn.commit()

    def list_sessions(self, tenant_id: str | None, limit: int = 200) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM webshield_sessions WHERE tenant_id IS ? ORDER BY last_seen_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def session_summary(self, tenant_id: str | None, session_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            session_row = conn.execute(
                "SELECT * FROM webshield_sessions WHERE tenant_id IS ? AND session_id = ?", (tenant_id, session_id)
            ).fetchone()
            if not session_row:
                return None
        events = self.list_events(tenant_id, session_id=session_id, limit=500)
        tools_seen = {e["tool_name"] for e in events if e.get("tool_name")}
        by_status = {}
        for e in events:
            by_status[e.get("policy_decision") or "allow"] = by_status.get(e.get("policy_decision") or "allow", 0) + 1
        return {
            "session": dict(session_row),
            "tool_count": len(tools_seen),
            "event_count": len(events),
            "decision_breakdown": by_status,
            "highest_risk": max((e.get("risk_score") or 0 for e in events), default=0),
            "recent_events": events[:20],
        }

    # ----------------------------------------------------------- lifecycle context

    def _get_tool_row(self, tenant_id: str | None, identity_key: str):
        with connect(self.db_path) as conn:
            return conn.execute(
                "SELECT * FROM webshield_tools WHERE tenant_id IS ? AND identity_key = ?", (tenant_id, identity_key)
            ).fetchone()

    def get_tool_by_identity(self, tenant_id: str | None, identity_key: str) -> dict[str, Any] | None:
        row = self._get_tool_row(tenant_id, identity_key)
        return _row_to_tool(row) if row else None

    # ------------------------------------------------------ registration instances
    #
    # docs/web-shield-hardening-review.md #6: ``webshield_tools`` is keyed
    # purely by logical identity (owner_origin + normalised name) and holds
    # exactly one row per identity — fine as a "latest known state" summary,
    # but insufficient as the sole record of truth, because two different
    # frames (or two different sessions) registering a tool with the same
    # name silently overwrite each other's row/history. ``webshield_tool_instances``
    # is the source of truth for "is this the same registration, or a new
    # one", scoped by (tenant, identity_key, session_id, frame_id) — never by
    # a page-supplied instance identifier.

    def _get_active_instance(self, tenant_id: str | None, identity_key: str, session_id: str | None, frame_id: str | None) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                """SELECT * FROM webshield_tool_instances
                   WHERE tenant_id IS ? AND identity_key = ? AND session_id IS ? AND frame_id IS ? AND status='active'
                   ORDER BY id DESC LIMIT 1""",
                (tenant_id, identity_key, session_id, frame_id),
            ).fetchone()
            return dict(row) if row else None

    def _upsert_instance(
        self, tenant_id: str | None, *, instance_id: str, identity_key: str, owner_origin: str, tool_name: str,
        session_id: str | None, frame_id: str | None, registration_source: str | None,
        exact_hash: str, canonical_hash: str, structural_hash: str, tool_json: str, is_new: bool,
    ) -> None:
        now = time.time()
        with connect(self.db_path) as conn:
            if is_new:
                conn.execute(
                    """INSERT INTO webshield_tool_instances
                       (tenant_id, instance_id, identity_key, owner_origin, tool_name, session_id, frame_id,
                        registration_source, exact_hash, canonical_hash, structural_hash, tool_json, status,
                        legacy_instance, first_seen_at, last_seen_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'active', 0, ?, ?)""",
                    (tenant_id, instance_id, identity_key, owner_origin, tool_name, session_id, frame_id,
                     registration_source, exact_hash, canonical_hash, structural_hash, tool_json, now, now),
                )
            else:
                conn.execute(
                    """UPDATE webshield_tool_instances SET exact_hash=?, canonical_hash=?, structural_hash=?,
                       tool_json=?, status='active', last_seen_at=? WHERE tenant_id IS ? AND instance_id=?""",
                    (exact_hash, canonical_hash, structural_hash, tool_json, now, tenant_id, instance_id),
                )
            conn.commit()

    def list_instances(self, tenant_id: str | None, identity_key: str) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM webshield_tool_instances WHERE tenant_id IS ? AND identity_key = ? ORDER BY first_seen_at ASC",
                (tenant_id, identity_key),
            ).fetchall()
        return [
            {
                "instance_id": r["instance_id"],
                "session_id": r["session_id"],
                "frame_id": r["frame_id"],
                "registration_source": r["registration_source"],
                "exact_hash": r["exact_hash"],
                "canonical_hash": r["canonical_hash"],
                "structural_hash": r["structural_hash"],
                "status": r["status"],
                "legacy_instance": bool(r["legacy_instance"]),
                "first_seen_at": r["first_seen_at"],
                "last_seen_at": r["last_seen_at"],
            }
            for r in rows
        ]

    def _existing_tool_names(self, tenant_id: str | None, owner_origin: str, exclude_identity_key: str) -> list[str]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT tool_name FROM webshield_tools WHERE tenant_id IS ? AND owner_origin = ? AND identity_key != ? AND status='active'",
                (tenant_id, owner_origin, exclude_identity_key),
            ).fetchall()
            return [r["tool_name"] for r in rows]

    def _recent_registration_count(self, tenant_id: str | None, owner_origin: str, window_seconds: float = REGISTRATION_BURST_WINDOW_SECONDS) -> int:
        cutoff = time.time() - window_seconds
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT action_json, timestamp FROM events WHERE tenant_id IS ? AND timestamp >= ? AND action_json LIKE '%webmcp.tool_%'",
                (tenant_id, cutoff),
            ).fetchall()
        count = 0
        for row in rows:
            try:
                action = json.loads(row["action_json"])
            except json.JSONDecodeError:
                continue
            if action.get("type") in {"webmcp.tool_registered", "webmcp.tool_registration_changed", "webmcp.tool_unregistered"}:
                if (action.get("metadata") or {}).get("owner_origin") == owner_origin:
                    count += 1
        return count

    def _prior_violation_count(self, tenant_id: str | None, owner_origin: str) -> int:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT action_json FROM events WHERE tenant_id IS ? AND action_json LIKE '%webmcp.%' AND action_json LIKE ?",
                (tenant_id, f"%{owner_origin}%"),
            ).fetchall()
        count = 0
        for row in rows:
            try:
                action = json.loads(row["action_json"])
            except json.JSONDecodeError:
                continue
            metadata = action.get("metadata") or {}
            if metadata.get("owner_origin") == owner_origin and metadata.get("risk_band") in {"high", "critical"}:
                count += 1
        return count

    # ------------------------------------------------------------ event logging

    def _log_event(
        self, tenant_id: str | None, event_type: str, *, session_id: str | None, tool_name: str | None,
        owner_origin: str | None, risk_score: int, metadata: dict[str, Any], retroactive: bool = False,
    ) -> dict[str, Any]:
        policy_decision = "allow"
        matched_rule = None
        agent_name = _webmcp_agent_label(owner_origin)
        try:
            action = Action(
                type=event_type,
                tool=tool_name,
                domain=owner_origin,
                metadata=metadata,
                risk_score=int(risk_score),
                trace_id=session_id,
                tenant_id=tenant_id,
                agent_name=agent_name,
            )
            decision = self.policy_engine.evaluate(action)
            policy_decision = decision.action
            matched_rule = decision.matched_rule
        except Exception:
            action = Action(type=event_type, tool=tool_name, domain=owner_origin, metadata=metadata, risk_score=int(risk_score), trace_id=session_id, tenant_id=tenant_id, agent_name=agent_name)
            decision = None

        requested_enforcement = POLICY_TO_ENFORCEMENT.get(policy_decision, policy_decision)
        already_completed = metadata.get("phase") == "invocation_completed"
        if already_completed:
            achieved_enforcement = "observed_only"
            limitation = "The action had already completed before this event was received; only detection/audit was possible."
        elif retroactive and requested_enforcement != "allow":
            # These events (context/method replacement, extension tamper) are
            # inherently forensic: by the time Varden can observe them, the
            # thing they describe has already happened in the page. There is
            # nothing left to block/approve/sanitise, only to detect and audit.
            achieved_enforcement = "unavailable"
            limitation = "This event describes something that already happened in the page (e.g. the WebMCP surface or extension wrapper was replaced/defeated); Varden detected and recorded it but could not retroactively prevent it."
        else:
            achieved_enforcement = requested_enforcement
            limitation = None
            if requested_enforcement in {"block", "require_approval", "sanitise"} and metadata.get("enforcement_capable") is False:
                achieved_enforcement = "unavailable"
                limitation = "The calling integration reported it could not enforce this decision (e.g. it captured an unwrapped reference)."

        metadata = dict(metadata)
        metadata["policy_decision"] = policy_decision
        metadata["requested_enforcement"] = requested_enforcement
        metadata["achieved_enforcement"] = achieved_enforcement
        metadata["enforcement_limitation"] = limitation
        if matched_rule:
            metadata["matched_rule"] = matched_rule

        action.metadata = metadata
        status_map = {"block": "blocked", "warn": "warned", "monitor": "monitor", "allow": "allowed"}
        status = status_map.get(policy_decision, "monitor") if policy_decision in status_map else "monitor"
        if policy_decision in {"require_approval", "sanitise"}:
            status = "warned"

        record = EventRecord.new(
            action=action.to_dict(),
            decision=(decision.to_dict() if decision else {"action": policy_decision, "reason": "policy unavailable"}),
            status=status,
            trace_id=session_id,
            tenant_id=tenant_id,
            # EventRecord has its own top-level agent_name column (distinct
            # from action.agent_name) that the events table indexes and that
            # Overview/Sankey read directly (see stores.py::_row_to_event) —
            # it must be set here too, not just on the nested action, or
            # those views keep showing "unknown agent" for every webmcp.*
            # event regardless of what Action.agent_name says.
            agent_name=agent_name,
        )
        event_id = self.event_store.log(record.to_dict())
        result = record.to_dict()
        result["id"] = event_id
        return result

    # -------------------------------------------------------------- registration

    def register_tool(
        self, tenant_id: str | None, *, session_id: str, tool: WebMCPToolDefinition, tab_id: str | None = None,
        frame_id: str | None = None, is_third_party_frame: bool = False, script_source_origin: str | None = None,
        session_started_at: float | None = None, session_already_active: bool = False,
        extension_version: str | None = None, sdk_version: str | None = None, enforcement_capable: bool = True,
    ) -> dict[str, Any]:
        self.touch_session(tenant_id, session_id, tab_id=tab_id, top_origin=tool.top_origin, extension_version=extension_version, sdk_version=sdk_version)

        identity_key = tool.identity_key()
        existing = self._get_tool_row(tenant_id, identity_key)  # logical-tool aggregate (dashboard "latest known state")
        # Instance identity (docs/web-shield-hardening-review.md #6): scoped by
        # session_id + frame_id, never by anything the page supplies. This is
        # what "first_seen" and metadata-drift ("did THIS registration's
        # metadata change") must be evaluated against — not the shared
        # aggregate row, which a *different* frame's registration could have
        # last written.
        existing_instance = self._get_active_instance(tenant_id, identity_key, session_id, frame_id)
        first_seen = existing_instance is None
        trust_state = self.get_trust(tenant_id, tool.owner_origin)

        context = ScanContext(
            is_third_party_frame=is_third_party_frame,
            https=tool.owner_origin.startswith("https://"),
            session_started_at=session_started_at,
            session_already_active=session_already_active,
            existing_tool_names=self._existing_tool_names(tenant_id, tool.owner_origin, identity_key),
            previous_exact_hash=existing_instance["exact_hash"] if existing_instance else None,
            previous_canonical_hash=existing_instance["canonical_hash"] if existing_instance else None,
            first_seen=first_seen,
            registration_count_recent=self._recent_registration_count(tenant_id, tool.owner_origin),
            trust_state=trust_state,
            prior_violation_count=self._prior_violation_count(tenant_id, tool.owner_origin),
        )
        result = scan_registration(tool, context)
        sanitized = sanitize_tool(tool)
        exact_hash, canonical_hash, structural_hash = result.exact_hash, result.canonical_hash, result.structural_hash
        tool_json = json.dumps(tool.to_dict(), default=str)

        metadata_changed = bool(existing_instance) and existing_instance["canonical_hash"] != canonical_hash
        event_type = "webmcp.tool_registered" if first_seen else (
            "webmcp.tool_registration_changed" if metadata_changed else "webmcp.tool_registered"
        )

        instance_id = existing_instance["instance_id"] if existing_instance else str(uuid.uuid4())
        self._upsert_instance(
            tenant_id, instance_id=instance_id, identity_key=identity_key, owner_origin=tool.owner_origin,
            tool_name=tool.name, session_id=session_id, frame_id=frame_id, registration_source=tool.registration_source,
            exact_hash=exact_hash, canonical_hash=canonical_hash, structural_hash=structural_hash,
            tool_json=tool_json, is_new=existing_instance is None,
        )

        now = time.time()
        with connect(self.db_path) as conn:
            if existing:
                conn.execute(
                    """UPDATE webshield_tools SET exact_hash=?, canonical_hash=?, structural_hash=?, tool_json=?, risk_score=?, risk_band=?,
                       findings_json=?, trust_state=?, status='active', registration_count=registration_count+1,
                       last_seen_at=?, updated_at=? WHERE id=?""",
                    (exact_hash, canonical_hash, structural_hash, tool_json, result.risk.score, result.risk.band,
                     json.dumps([f.to_dict() for f in result.findings]), trust_state, now, now, existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO webshield_tools
                       (tenant_id, identity_key, owner_origin, top_origin, tool_name, api_surface, exact_hash, canonical_hash, structural_hash,
                        tool_json, risk_score, risk_band, findings_json, trust_state, status, registration_count,
                        first_seen_at, last_seen_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',1,?,?,?)""",
                    (tenant_id, identity_key, tool.owner_origin, tool.top_origin, tool.name, tool.api_surface,
                     exact_hash, canonical_hash, structural_hash, tool_json, result.risk.score, result.risk.band,
                     json.dumps([f.to_dict() for f in result.findings]), trust_state, now, now, now),
                )
            conn.commit()

        metadata = {
            "session_id": session_id, "tab_id": tab_id, "frame_id": frame_id,
            "top_origin": tool.top_origin, "owner_origin": tool.owner_origin,
            "script_source_origin": script_source_origin, "tool_name": tool.name, "identity_key": identity_key,
            "instance_id": instance_id,
            "exact_hash": exact_hash, "canonical_hash": canonical_hash,
            "previous_exact_hash": context.previous_exact_hash, "previous_canonical_hash": context.previous_canonical_hash,
            "phase": "registration", "api_surface": tool.api_surface,
            "findings": [f.to_dict() for f in result.findings],
            "finding_categories": sorted({f.category for f in result.findings}),
            "finding_rule_ids": sorted({f.rule_id for f in result.findings}),
            "risk_band": result.risk.band, "risk_drivers": [d.to_dict() for d in result.risk.drivers],
            "capability": result.capability.to_dict(),
            "mutates_state": result.capability.mutates_state,
            "declared_readonly": result.capability.declared_readonly,
            "sensitive_schema_fields": result.capability.sensitive_schema_fields,
            "first_seen": first_seen, "metadata_changed": metadata_changed,
            "is_third_party_frame": is_third_party_frame,
            "same_origin": tool.owner_origin == tool.top_origin,
            "trust_state": trust_state,
            "sanitizer_blocked": sanitized.blocked, "sanitizer_diff": sanitized.diff,
            "sanitizer_unrepairable_fields": sanitized.unrepairable_fields,
            "extension_version": extension_version, "sdk_version": sdk_version,
            "enforcement_capable": enforcement_capable,
        }
        event = self._log_event(tenant_id, event_type, session_id=session_id, tool_name=tool.name, owner_origin=tool.owner_origin, risk_score=result.risk.score, metadata=metadata)
        return {
            "event": event, "identity_key": identity_key, "instance_id": instance_id,
            "scan": result.to_dict(), "sanitizer": sanitized.to_dict(),
            "first_seen": first_seen, "metadata_changed": metadata_changed,
        }

    def unregister_tool(
        self, tenant_id: str | None, *, session_id: str, identity_key: str,
        frame_id: str | None = None, enforcement_capable: bool = True,
    ) -> dict[str, Any]:
        """Mark the matching registration instance(s) inactive.

        When ``frame_id`` is supplied (the normal extension/SDK path), only
        the instance scoped to this exact session+frame is targeted, so one
        frame unregistering its tool never affects another frame's identical-
        named registration (docs/web-shield-hardening-review.md #6). Callers
        that omit ``frame_id`` (legacy callers, or a session-wide cleanup)
        fall back to targeting every instance for this identity_key in this
        session — never instances belonging to other sessions.
        """

        now = time.time()
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM webshield_tools WHERE tenant_id IS ? AND identity_key=?", (tenant_id, identity_key)).fetchone()
            if frame_id is not None:
                conn.execute(
                    "UPDATE webshield_tool_instances SET status='unregistered', last_seen_at=? WHERE tenant_id IS ? AND identity_key=? AND session_id IS ? AND frame_id IS ? AND status='active'",
                    (now, tenant_id, identity_key, session_id, frame_id),
                )
            else:
                conn.execute(
                    "UPDATE webshield_tool_instances SET status='unregistered', last_seen_at=? WHERE tenant_id IS ? AND identity_key=? AND session_id IS ? AND status='active'",
                    (now, tenant_id, identity_key, session_id),
                )
            remaining_active = conn.execute(
                "SELECT COUNT(*) AS n FROM webshield_tool_instances WHERE tenant_id IS ? AND identity_key=? AND status='active'",
                (tenant_id, identity_key),
            ).fetchone()["n"]
            if row and remaining_active == 0:
                conn.execute("UPDATE webshield_tools SET status='inactive', updated_at=? WHERE id=?", (now, row["id"]))
            conn.commit()
        tool_name = row["tool_name"] if row else None
        owner_origin = row["owner_origin"] if row else None
        recent_count = self._recent_registration_count(tenant_id, owner_origin) if owner_origin else 0
        metadata = {
            "session_id": session_id, "identity_key": identity_key, "frame_id": frame_id,
            "tool_name": tool_name, "owner_origin": owner_origin,
            "phase": "lifecycle", "risk_band": "guarded" if recent_count > 5 else "low",
            "registration_count_recent": recent_count, "enforcement_capable": enforcement_capable,
            "remaining_active_instances": remaining_active,
        }
        event = self._log_event(tenant_id, "webmcp.tool_unregistered", session_id=session_id, tool_name=tool_name, owner_origin=owner_origin, risk_score=20 if recent_count > 5 else 0, metadata=metadata)
        return {"event": event, "remaining_active_instances": remaining_active}

    def record_context_replaced(self, tenant_id: str | None, *, session_id: str, top_origin: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = {"session_id": session_id, "top_origin": top_origin, "phase": "lifecycle", "risk_band": "high", "details": redact_webmcp_value(details or {})}
        event = self._log_event(tenant_id, "webmcp.context_replaced", session_id=session_id, tool_name=None, owner_origin=top_origin, risk_score=65, metadata=metadata, retroactive=True)
        return {"event": event}

    def record_surface_changed(self, tenant_id: str | None, *, session_id: str, owner_origin: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = {"session_id": session_id, "owner_origin": owner_origin, "phase": "lifecycle", "risk_band": "guarded", "details": redact_webmcp_value(details or {})}
        event = self._log_event(tenant_id, "webmcp.surface_changed", session_id=session_id, tool_name=None, owner_origin=owner_origin, risk_score=25, metadata=metadata)
        return {"event": event}

    def record_tamper_detected(self, tenant_id: str | None, *, session_id: str, top_origin: str | None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = {"session_id": session_id, "top_origin": top_origin, "phase": "lifecycle", "risk_band": "critical", "details": redact_webmcp_value(details or {}), "enforcement_capable": False}
        event = self._log_event(tenant_id, "webmcp.extension_tamper_detected", session_id=session_id, tool_name=None, owner_origin=top_origin, risk_score=85, metadata=metadata, retroactive=True)
        return {"event": event}

    # -------------------------------------------------------------- invocation

    def record_invocation_request(
        self, tenant_id: str | None, *, session_id: str, identity_key: str, args: dict[str, Any] | None = None,
        extension_version: str | None = None, sdk_version: str | None = None, enforcement_capable: bool = True,
    ) -> dict[str, Any]:
        row = self._get_tool_row(tenant_id, identity_key)
        tool_name = row["tool_name"] if row else identity_key
        owner_origin = row["owner_origin"] if row else None
        risk_score = row["risk_score"] if row else 0
        risk_band = row["risk_band"] if row else "low"
        first_seen = bool(row) and int(row["registration_count"] or 0) <= 1
        capability = {}
        if row:
            capability = infer_capability_profile(WebMCPToolDefinition(**json.loads(row["tool_json"]))).to_dict()
        redacted_args = redact_webmcp_value(args or {})
        metadata = {
            "session_id": session_id, "identity_key": identity_key, "tool_name": tool_name, "owner_origin": owner_origin,
            "phase": "invocation_request", "risk_band": risk_band, "args": redacted_args,
            "trust_state": self.get_trust(tenant_id, owner_origin) if owner_origin else None,
            "extension_version": extension_version, "sdk_version": sdk_version, "enforcement_capable": enforcement_capable,
            "first_seen": first_seen, "mutates_state": capability.get("mutates_state", False),
            "declared_readonly": capability.get("declared_readonly"),
            "mentions_payment": capability.get("mentions_payment", False),
            "mentions_credential": capability.get("mentions_credential", False),
            "sensitive_schema_fields": capability.get("sensitive_schema_fields", []),
        }
        event = self._log_event(tenant_id, "webmcp.tool_invocation_requested", session_id=session_id, tool_name=tool_name, owner_origin=owner_origin, risk_score=risk_score, metadata=metadata)
        return {"event": event, "risk_score": risk_score, "risk_band": risk_band}

    def record_invocation_completed(
        self, tenant_id: str | None, *, session_id: str, identity_key: str, status: str = "success",
        latency_ms: float | None = None, error: str | None = None,
    ) -> dict[str, Any]:
        row = self._get_tool_row(tenant_id, identity_key)
        tool_name = row["tool_name"] if row else identity_key
        owner_origin = row["owner_origin"] if row else None
        risk_score = row["risk_score"] if row else 0
        metadata = {
            "session_id": session_id, "identity_key": identity_key, "tool_name": tool_name, "owner_origin": owner_origin,
            "phase": "invocation_completed", "risk_band": row["risk_band"] if row else "low",
            "invocation_status": status, "latency_ms": latency_ms, "error": error,
        }
        event = self._log_event(tenant_id, "webmcp.tool_invocation_completed", session_id=session_id, tool_name=tool_name, owner_origin=owner_origin, risk_score=risk_score, metadata=metadata)
        return {"event": event}

    # ------------------------------------------------------------------ output

    def scan_tool_output(
        self, tenant_id: str | None, *, session_id: str, identity_key: str, output_text: str,
        contains_user_generated_content: bool = False, enforcement_capable: bool = True,
    ) -> dict[str, Any]:
        row = self._get_tool_row(tenant_id, identity_key)
        tool_name = row["tool_name"] if row else identity_key
        owner_origin = row["owner_origin"] if row else None
        trust_state = self.get_trust(tenant_id, owner_origin) if owner_origin else None

        findings, risk = scan_output(output_text, owner_origin=owner_origin or "", contains_user_generated_content=contains_user_generated_content, trust_state=trust_state)

        redacted_summary = redact_webmcp_output(output_text)
        metadata = {
            "session_id": session_id, "identity_key": identity_key, "tool_name": tool_name, "owner_origin": owner_origin,
            "phase": "output", "risk_band": risk.band, "findings": [f.to_dict() for f in findings],
            "finding_categories": sorted({f.category for f in findings}),
            "output_summary": redacted_summary, "output_length": len(output_text or ""),
            "contains_user_generated_content": contains_user_generated_content,
            "enforcement_capable": enforcement_capable,
        }
        event = self._log_event(tenant_id, "webmcp.tool_output_scanned", session_id=session_id, tool_name=tool_name, owner_origin=owner_origin, risk_score=risk.score, metadata=metadata)

        # `outcome` is a Web-Shield-specific refinement (sanitise/truncate/
        # quarantine/block) of the *policy's own decision*, not a second,
        # independent judgement. If no Web Shield policy rule matched (the
        # feature is not enabled — see docs/web-shield-architecture.md §"Non-
        # goals"), the requested enforcement is "allow" and the outcome is
        # always "allow" too, regardless of risk band: risk scoring supplies
        # evidence, policy determines the action.
        requested = event["action"]["metadata"]["requested_enforcement"]
        if requested == "block":
            outcome = "block"
        elif requested == "sanitise":
            outcome = {"critical": "block", "high": "quarantine", "suspicious": "sanitise", "guarded": "truncate"}.get(risk.band, "allow")
        elif requested == "require_approval":
            outcome = "quarantine"
        else:  # warn, monitor, allow: never withhold or alter content, only annotate/audit
            outcome = "allow"
        event["action"]["metadata"]["output_outcome"] = outcome

        return {"event": event, "findings": [f.to_dict() for f in findings], "risk": risk.to_dict(), "outcome": outcome, "sanitized_output": redacted_summary if outcome in {"sanitise", "truncate"} else None}

    # ------------------------------------------------------------ cross-origin

    def record_cross_origin_flow(
        self, tenant_id: str | None, *, session_id: str, from_origin: str, to_origin: str,
        tool_name: str | None = None, reason: str | None = None,
    ) -> dict[str, Any]:
        risk_score = 55 if from_origin != to_origin else 10
        metadata = {
            "session_id": session_id, "from_origin": from_origin, "to_origin": to_origin, "tool_name": tool_name,
            "phase": "cross_origin", "risk_band": "high" if risk_score >= 40 else "low", "reason": reason,
        }
        event = self._log_event(tenant_id, "webmcp.cross_origin_flow", session_id=session_id, tool_name=tool_name, owner_origin=from_origin, risk_score=risk_score, metadata=metadata)
        return {"event": event}

    # -------------------------------------------------------------- inventory

    def list_tools(self, tenant_id: str | None, limit: int = 200) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM webshield_tools WHERE tenant_id IS ? ORDER BY last_seen_at DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
            return [_row_to_tool(r) for r in rows]

    def tool_detail(self, tenant_id: str | None, identity_key: str) -> dict[str, Any] | None:
        row = self._get_tool_row(tenant_id, identity_key)
        if not row:
            return None
        events = self.list_events(tenant_id, identity_key=identity_key, limit=500)
        return {
            "tool": _row_to_tool(row),
            "logical_tool_id": identity_key,
            "instances": self.list_instances(tenant_id, identity_key),
            "timeline": events,
            "invocation_history": [e for e in events if e.get("phase", "").startswith("invocation")],
            "output_findings": [f for e in events if e.get("phase") == "output" for f in (e.get("findings") or [])],
        }

    def list_events(
        self, tenant_id: str | None, *, session_id: str | None = None, identity_key: str | None = None,
        event_type: str | None = None, owner_origin: str | None = None, limit: int = 200,
    ) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM events WHERE tenant_id IS ? AND trace_id = ? ORDER BY id DESC LIMIT ?",
                    (tenant_id, session_id, max(limit, 500)),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events WHERE tenant_id IS ? AND action_json LIKE '%\"webmcp.%' ORDER BY id DESC LIMIT ?",
                    (tenant_id, max(limit * 5, 1000)),
                ).fetchall()

        results = []
        for row in rows:
            try:
                action = json.loads(row["action_json"])
            except json.JSONDecodeError:
                continue
            if not str(action.get("type", "")).startswith("webmcp."):
                continue
            metadata = action.get("metadata") or {}
            if identity_key and metadata.get("identity_key") != identity_key:
                continue
            if event_type and action.get("type") != event_type:
                continue
            if owner_origin and metadata.get("owner_origin") != owner_origin:
                continue
            decision = json.loads(row["decision_json"]) if row["decision_json"] else {}
            results.append({
                "id": row["id"], "timestamp": row["timestamp"], "event_type": action.get("type"),
                "session_id": row["trace_id"], "tool_name": action.get("tool"), "owner_origin": action.get("domain"),
                "risk_score": action.get("risk_score", 0), "risk_band": metadata.get("risk_band"),
                "policy_decision": metadata.get("policy_decision"), "requested_enforcement": metadata.get("requested_enforcement"),
                "achieved_enforcement": metadata.get("achieved_enforcement"), "enforcement_limitation": metadata.get("enforcement_limitation"),
                "findings": metadata.get("findings", []), "phase": metadata.get("phase"), "metadata": metadata,
                "status": row["status"], "matched_rule": decision.get("matched_rule"),
            })
            if len(results) >= limit:
                break
        return results

    # -------------------------------------------------------------- overview

    def overview(self, tenant_id: str | None) -> dict[str, Any]:
        tools = self.list_tools(tenant_id, limit=2000)
        sessions = self.list_sessions(tenant_id, limit=2000)
        events = self.list_events(tenant_id, limit=2000)
        origins = {t["owner_origin"] for t in tools}
        by_type: dict[str, int] = {}
        for e in events:
            by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
        return {
            "protected_sessions": len(sessions),
            "origins_observed": len(origins),
            "tools_registered": len(tools),
            "new_tools_24h": sum(1 for t in tools if t["first_seen_at"] > time.time() - 86400),
            "metadata_changes_24h": by_type.get("webmcp.tool_registration_changed", 0),
            "critical_findings": sum(1 for t in tools if t["risk_band"] == "critical"),
            "blocked_registrations": sum(1 for e in events if e.get("policy_decision") == "block" and e.get("phase") == "registration"),
            "sanitised_registrations": sum(1 for e in events if e.get("policy_decision") == "sanitise"),
            "approval_requests": len(self.list_approvals(tenant_id, status="pending")),
            "contaminated_outputs": sum(1 for e in events if e.get("phase") == "output" and e.get("findings")),
            "cross_origin_alerts": by_type.get("webmcp.cross_origin_flow", 0),
            "event_type_breakdown": by_type,
        }

    # ------------------------------------------------------------- approvals

    def create_approval(
        self, tenant_id: str | None, *, session_id: str, identity_key: str, tool_name: str, owner_origin: str,
        args: dict[str, Any] | None, risk_score: int, risk_band: str, reason: str, expires_at: float | None = None,
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        args_summary = redact_webmcp_value(args or {})
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO webshield_approvals
                   (tenant_id, request_id, session_id, identity_key, tool_name, owner_origin, args_summary_json,
                    risk_score, risk_band, reason, status, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?,?)""",
                (tenant_id, request_id, session_id, identity_key, tool_name, owner_origin, json.dumps(args_summary, default=str),
                 risk_score, risk_band, reason, time.time(), expires_at),
            )
            conn.commit()
        metadata = {
            "session_id": session_id, "identity_key": identity_key, "tool_name": tool_name, "owner_origin": owner_origin,
            "phase": "approval", "risk_band": risk_band, "request_id": request_id, "args": args_summary, "reason": reason,
        }
        self._log_event(tenant_id, "webmcp.approval_requested", session_id=session_id, tool_name=tool_name, owner_origin=owner_origin, risk_score=risk_score, metadata=metadata)
        return self.get_approval(tenant_id, request_id)

    def get_approval(self, tenant_id: str | None, request_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM webshield_approvals WHERE tenant_id IS ? AND request_id=?", (tenant_id, request_id)).fetchone()
            return dict(row) if row else None

    def list_approvals(self, tenant_id: str | None, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM webshield_approvals WHERE tenant_id IS ? AND status=? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM webshield_approvals WHERE tenant_id IS ? ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)
                ).fetchall()
            return [dict(r) for r in rows]

    VALID_APPROVAL_DECISIONS = {"allow_once", "allow_session", "trust_origin", "deny_once", "block_origin"}

    def resolve_approval(self, tenant_id: str | None, request_id: str, decision: str, *, resolved_by: str | None = None) -> dict[str, Any]:
        if decision not in self.VALID_APPROVAL_DECISIONS:
            raise ValueError(f"invalid decision: {decision}")
        approval = self.get_approval(tenant_id, request_id)
        if not approval:
            raise KeyError("approval not found")
        if approval["status"] != "pending":
            raise ValueError(f"approval already resolved with status={approval['status']}")

        status_map = {
            "allow_once": "allowed_once", "allow_session": "allowed_session", "trust_origin": "allowed_trusted",
            "deny_once": "denied", "block_origin": "blocked_origin",
        }
        now = time.time()
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE webshield_approvals SET status=?, resolved_at=?, resolved_by=? WHERE tenant_id IS ? AND request_id=?",
                (status_map[decision], now, resolved_by, tenant_id, request_id),
            )
            conn.commit()

        if decision == "trust_origin":
            self.set_trust(tenant_id, approval["owner_origin"], "trusted", created_by=resolved_by)
        elif decision == "block_origin":
            self.set_trust(tenant_id, approval["owner_origin"], "blocked", created_by=resolved_by)

        return self.get_approval(tenant_id, request_id)

    # ------------------------------------------------------------- config

    def config(self, tenant_id: str | None) -> dict[str, Any]:
        from .risk import RISK_PROFILE_VERSION

        policy = self.policy_engine.get_policy() or {}
        # Web Shield is "enabled" only when the operator has imported a pack
        # (or written rules) that actually match webmcp.* events. Empty
        # require_approval/sanitise buckets alone do not count — those exist
        # as empty lists in every modern policy file and must not silently
        # flip this flag.
        has_webmcp_rule = False
        for bucket in ("block", "require_approval", "sanitise", "warn", "monitor", "allow"):
            for rule in policy.get(bucket) or []:
                if isinstance(rule, dict) and str(rule.get("type") or "").startswith("webmcp."):
                    has_webmcp_rule = True
                    break
            if has_webmcp_rule:
                break
        return {
            "config_version": CONFIG_VERSION,
            "enabled": has_webmcp_rule,
            "mode": "enforce" if has_webmcp_rule else "observe",
            "risk_profile_version": RISK_PROFILE_VERSION,
            # Capability negotiation (docs/web-shield-hardening-review.md #15):
            # an older extension connecting to a hardened server can read
            # these fields and decide whether it can operate safely, rather
            # than silently misbehaving. Clients that do not understand a
            # required capability must treat the connection as incompatible.
            "protocol": {
                "page_channel_version": 1,
                "min_extension_version": "0.1.0",
                "server_features": [
                    "idempotency_scoped",
                    "pre_parse_body_limits",
                    "registration_instances",
                    "three_hash_canonicalisation",
                    "component_risk_scoring",
                    "fail_closed_sanitisation",
                ],
            },
            "capabilities": {
                "registration_scan": True, "invocation_scan": True, "output_scan": True,
                "sanitisation": True, "approvals": True, "local_trust": True,
                "cross_origin_correlation": True,
                "registration_instances": True,
                "component_risk_scoring": True,
                "observed_untrusted_classification": True,
            },
        }

    def record_extension_health(self, tenant_id: str | None, *, session_id: str, extension_version: str, connected: bool, protection_mode: str, tab_id: str | None = None, top_origin: str | None = None) -> dict[str, Any]:
        self.touch_session(tenant_id, session_id, tab_id=tab_id, top_origin=top_origin, extension_version=extension_version, connected=connected, protection_mode=protection_mode)
        cfg = self.config(tenant_id)
        # Explicit compatibility result for older extensions that report a
        # version below min_extension_version — never silently operate.
        min_version = ((cfg.get("protocol") or {}).get("min_extension_version") or "0.0.0")
        compatible = _version_gte(extension_version or "0.0.0", min_version)
        return {
            "ok": True,
            "server_config_version": CONFIG_VERSION,
            "compatible": compatible,
            "compatibility": {
                "compatible": compatible,
                "min_extension_version": min_version,
                "reported_extension_version": extension_version,
                "reason": None if compatible else (
                    f"extension version {extension_version!r} is below the server's "
                    f"minimum supported version {min_version!r}; upgrade the extension "
                    "or it will operate in a degraded/unsupported state"
                ),
                "protocol": cfg.get("protocol"),
            },
        }
