from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import connect, init_db
from .exceptions import PolicyViolation
from .models import Action, Decision
from .server_owned import action_fingerprint
from .rules.token_budget import (
    TokenBudgetRule,
    compute_cost_usd,
    normalize_model_name,
    resolve_output_limit,
)

_BUCKETS = ("block", "warn", "monitor", "allow")
STATUS_RESERVED = "reserved"
STATUS_RECONCILED = "reconciled"
STATUS_EXPIRED_CHARGED = "expired_charged"
STATUS_CANCELLED = "cancelled_verified"
_UNTRUSTED_RELEASE = {"blocked", "failed", "not_executed"}
_DEFAULT_RESERVATION_TTL = 36 * 3600
_DEFAULT_RETENTION_SECONDS = 90 * 24 * 3600
# Decisions that still allow the model call to proceed. A reservation created
# for any other final decision is released only because the server denied
# execution before the side effect.
BUDGET_EXECUTES = {"allow", "warn", "warned", "monitor", "sanitise"}


def _utc_now() -> float:
    return time.time()


def _next_reset_at(window: str, now: float | None = None) -> float | None:
    if window == "session":
        return None
    ts = now if now is not None else _utc_now()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if window == "daily":
        start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if dt > start:
            start = start + timedelta(days=1)
        return start.timestamp()
    if window == "monthly":
        year, month = dt.year, dt.month
        if month == 12:
            year += 1
            month = 1
        else:
            month += 1
        return datetime(year, month, 1, tzinfo=timezone.utc).timestamp()
    return None


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten_text(v) for v in value)
    return str(value)


def extract_model_from_payload(action: Action, raw_payload: Any) -> str:
    args = action.args or {}
    for candidate in (
        args.get("model"),
        (args.get("kwargs") or {}).get("model"),
        (args.get("args") or [None])[0] if isinstance(args.get("args"), list) and args.get("args") else None,
    ):
        if candidate:
            return normalize_model_name(str(candidate))
    text = _flatten_text(raw_payload if raw_payload is not None else args)
    for token in ("claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5", "gpt-4o"):
        if token in text.lower():
            return token
    return ""


def estimate_input_tokens(raw_payload: Any, action: Action) -> int:
    text = _flatten_text(raw_payload if raw_payload is not None else action.args)
    # Conservative estimate (~25% above len/4) to reduce pre-check underestimation.
    return max(1, (len(text) * 3 + 9) // 10)


def estimate_output_tokens(raw_payload: Any, action: Action, model: str) -> int:
    kwargs = (action.args or {}).get("kwargs") or {}
    if not isinstance(kwargs, dict):
        kwargs = {}
    for key in ("max_tokens", "max_output_tokens", "max_completion_tokens"):
        if kwargs.get(key) is not None:
            try:
                return max(0, int(kwargs[key]))
            except (TypeError, ValueError):
                pass
    payload_kwargs = raw_payload if isinstance(raw_payload, dict) else {}
    if isinstance(payload_kwargs.get("kwargs"), dict):
        for key in ("max_tokens", "max_output_tokens", "max_completion_tokens"):
            if payload_kwargs["kwargs"].get(key) is not None:
                try:
                    return max(0, int(payload_kwargs["kwargs"][key]))
                except (TypeError, ValueError):
                    pass
    return resolve_output_limit(model)


def estimate_llm_cost(
    action: Action,
    raw_payload: Any,
    rule: TokenBudgetRule,
) -> tuple[str, int, int, float]:
    model = extract_model_from_payload(action, raw_payload) or "unknown"
    input_tokens = estimate_input_tokens(raw_payload, action)
    output_tokens = estimate_output_tokens(raw_payload, action, model)
    cost = compute_cost_usd(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model_costs=rule.model_costs,
    )
    return model, input_tokens, output_tokens, cost


def extract_usage_from_log_payload(
    output_payload: Any,
    input_payload: Any = None,
    *,
    fallback_model: str = "",
) -> tuple[str, int, int] | None:
    payload = output_payload if isinstance(output_payload, dict) else {}
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else None
    if usage is None and isinstance(input_payload, dict):
        usage = input_payload.get("usage") if isinstance(input_payload.get("usage"), dict) else None
    if not usage:
        return None
    input_tokens = int(
        usage.get("input_tokens")
        or usage.get("prompt_tokens")
        or usage.get("input")
        or 0
    )
    output_tokens = int(
        usage.get("output_tokens")
        or usage.get("completion_tokens")
        or usage.get("output")
        or 0
    )
    model = normalize_model_name(
        str(payload.get("model") or usage.get("model") or fallback_model or "")
    )
    if input_tokens <= 0 and output_tokens <= 0:
        return None
    return model, input_tokens, output_tokens


def _rule_fingerprint(rule: dict[str, Any]) -> str:
    return json.dumps(rule, sort_keys=True, default=str)


class TokenBudgetStore:
    def __init__(
        self,
        db_path: str,
        *,
        clock=None,
        reservation_ttl: float = _DEFAULT_RESERVATION_TTL,
        retention_seconds: float = _DEFAULT_RETENTION_SECONDS,
    ):
        self.db_path = db_path
        self._clock = clock or time.time
        self.reservation_ttl = float(reservation_ttl)
        self.retention_seconds = float(retention_seconds)
        init_db(db_path)

    def _now(self) -> float:
        return float(self._clock())

    def _counter_scope(
        self,
        rule: TokenBudgetRule,
        *,
        tenant_id: str | None,
        principal_hash: str | None,
    ) -> tuple[str, str] | None:
        """Server-owned counter identity.

        A session limit is the authenticated principal's cumulative spend
        inside one tenant. A daily or monthly limit is the tenant's calendar
        spend, shared by every principal in that tenant. Trace and workflow
        ids are correlation data and are not part of this identity.
        """
        tenant = (tenant_id or "").strip()
        principal = (principal_hash or "").strip()
        if rule.window == "session":
            if not tenant or not principal:
                return None
            return tenant, principal
        if rule.window in {"daily", "monthly"}:
            if not tenant:
                return None
            return tenant, ""
        return None

    def _scope_failure(self, rule: TokenBudgetRule, amount_usd: float) -> Decision:
        detail = {**rule.to_dict(), "enforced": False, "scope": "missing"}
        if rule.hard_cap:
            raise PolicyViolation(
                "token budget scope could not be established",
                rule=detail,
                projected_usd=amount_usd,
                current_usd=0.0,
                limit_usd=rule.limit_usd,
            )
        return Decision(
            action="warn",
            reason="token budget scope was not established; soft cap was not enforced",
            matched_rule=detail,
            effective_action="warn",
        )

    @staticmethod
    def _window_identity(window: str, now: float, *, tenant_id: str = "", principal_hash: str = "") -> str:
        dt = datetime.fromtimestamp(now, tz=timezone.utc)
        if window == "daily":
            return dt.strftime("daily:%Y-%m-%d")
        if window == "monthly":
            return dt.strftime("monthly:%Y-%m")
        return f"session:{tenant_id}:{principal_hash}"

    def _reset_row_if_due(self, conn: sqlite3.Connection, row: sqlite3.Row, now: float) -> sqlite3.Row:
        reset_at = row["reset_at"]
        window_id = row["window_id"] if "window_id" in row.keys() else None
        tenant_key = row["tenant_id"] if "tenant_id" in row.keys() and row["tenant_id"] else ""
        principal_key = row["principal_hash"] if "principal_hash" in row.keys() and row["principal_hash"] else ""
        if not window_id:
            window_id = self._window_identity(row["window"], now, tenant_id=tenant_key, principal_hash=principal_key)
            conn.execute("UPDATE token_budgets SET window_id = ? WHERE id = ?", (window_id, row["id"]))
            row = conn.execute("SELECT * FROM token_budgets WHERE id = ?", (row["id"],)).fetchone()
        if reset_at is not None and now >= float(reset_at):
            # The open counter is archived, then zeroed. Reservation rows are
            # not touched: they stay attributed to window_id above.
            self._add_charge(
                conn,
                policy_id=row["policy_id"],
                window=row["window"],
                window_id=row["window_id"],
                trace_id="",
                workflow_id="",
                tenant_id=tenant_key,
                principal_hash=principal_key,
                delta=float(row["current_usd"] or 0),
                limit_usd=float(row["limit_usd"] or 0),
                closed_at=now,
            )
            new_reset = _next_reset_at(row["window"], now)
            new_window = self._window_identity(row["window"], now, tenant_id=tenant_key, principal_hash=principal_key)
            conn.execute(
                """
                UPDATE token_budgets
                SET current_usd = 0, reserved_usd = 0, reset_at = ?, window_id = ?
                WHERE id = ?
                """,
                (new_reset, new_window, row["id"]),
            )
            return conn.execute("SELECT * FROM token_budgets WHERE id = ?", (row["id"],)).fetchone()
        return row

    def _add_charge(
        self,
        conn: sqlite3.Connection,
        *,
        policy_id: str,
        window: str,
        window_id: str,
        trace_id: str | None,
        workflow_id: str | None,
        tenant_id: str = "",
        principal_hash: str = "",
        delta: float,
        limit_usd: float,
        closed_at: float | None = None,
    ) -> None:
        if not delta:
            return
        conn.execute(
            """
            INSERT INTO token_budget_window_charges(
              policy_id, window, window_id, trace_id, workflow_id,
              tenant_id, principal_hash, charged_usd, limit_usd, closed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(policy_id, window, window_id, trace_id, workflow_id, tenant_id, principal_hash)
            DO UPDATE SET
              charged_usd = charged_usd + excluded.charged_usd,
              closed_at = COALESCE(token_budget_window_charges.closed_at, excluded.closed_at)
            """,
            (
                policy_id,
                window,
                window_id,
                trace_id or "",
                workflow_id or "",
                tenant_id or "",
                principal_hash or "",
                float(delta),
                float(limit_usd),
                closed_at,
            ),
        )

    def _budget_row(
        self,
        conn: sqlite3.Connection,
        *,
        policy_id: str,
        window: str,
        tenant_id: str,
        principal_hash: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT * FROM token_budgets
            WHERE policy_id = ? AND window = ?
              AND COALESCE(tenant_id, '') = ?
              AND COALESCE(principal_hash, '') = ?
              AND COALESCE(trace_id, '') = ''
              AND COALESCE(workflow_id, '') = ''
            """,
            (policy_id, window, tenant_id or "", principal_hash or ""),
        ).fetchone()

    @staticmethod
    def _counter_principal(window: str, principal_hash: str | None) -> str:
        if window in {"daily", "monthly"}:
            return ""
        return principal_hash or ""

    def _settle(
        self,
        conn: sqlite3.Connection,
        reservation: sqlite3.Row,
        amount: float,
        new_status: str,
        now: float,
        evidence: dict[str, Any],
        *,
        expected_status: str,
        reported_usd: float | None,
    ) -> bool:
        """Move one reservation to a terminal state exactly once.

        ``amount`` is the delta applied to the original window. The caller
        computes it so a late report adds only the difference from the
        estimate already charged.
        """
        updated = conn.execute(
            """
            UPDATE token_budget_reservations
            SET status = ?, reported_usd = ?, charged_usd = ?, evidence_json = ?
            WHERE id = ? AND status = ?
            """,
            (
                new_status,
                reported_usd,
                float(reservation["charged_usd"] or 0) + float(amount),
                json.dumps(evidence, sort_keys=True),
                reservation["id"],
                expected_status,
            ),
        )
        if updated.rowcount != 1:
            return False
        counter_principal = self._counter_principal(reservation["window"], reservation["principal_hash"])
        budget = self._budget_row(
            conn,
            policy_id=reservation["policy_id"],
            window=reservation["window"],
            tenant_id=reservation["tenant_id"] or "",
            principal_hash=counter_principal,
        )
        same_window = budget is not None and budget["window_id"] == reservation["window_id"]
        if same_window:
            current = float(budget["current_usd"] or 0) + float(amount)
            reserved_live = float(budget["reserved_usd"] or 0)
            if expected_status == STATUS_RESERVED:
                reserved_live = max(0.0, reserved_live - float(reservation["reserved_usd"] or 0))
            conn.execute(
                "UPDATE token_budgets SET current_usd = ?, reserved_usd = ? WHERE id = ?",
                (current, reserved_live, budget["id"]),
            )
        else:
            limit = float(budget["limit_usd"] or 0) if budget is not None else 0.0
            self._add_charge(
                conn,
                policy_id=reservation["policy_id"],
                window=reservation["window"],
                window_id=reservation["window_id"],
                trace_id="",
                workflow_id="",
                tenant_id=reservation["tenant_id"] or "",
                principal_hash=counter_principal,
                delta=float(amount),
                limit_usd=limit,
                closed_at=now,
            )
        return True

    def _expire_due(self, conn: sqlite3.Connection, now: float) -> int:
        rows = conn.execute(
            """
            SELECT * FROM token_budget_reservations
            WHERE status = ? AND deadline_at <= ?
            ORDER BY id
            """,
            (STATUS_RESERVED, now),
        ).fetchall()
        count = 0
        for row in rows:
            if self._settle(
                conn,
                row,
                float(row["reserved_usd"] or 0),
                STATUS_EXPIRED_CHARGED,
                now,
                {"reason": "deadline", "policy": "charge_reserved_estimate"},
                expected_status=STATUS_RESERVED,
                reported_usd=None,
            ):
                count += 1
        return count

    def expire_due(self) -> int:
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            count = self._expire_due(conn, self._now())
            conn.commit()
            return count

    def list_reservations(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM token_budget_reservations ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def historical_charge(self, policy_id: str, window_id: str) -> float:
        with connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(charged_usd), 0)
                FROM token_budget_window_charges
                WHERE policy_id = ? AND window_id = ?
                """,
                (policy_id, window_id),
            ).fetchone()
        return float(row[0] or 0)

    def cleanup_resolved(self) -> int:
        """Drop settled ledger rows past retention. Open reservations stay."""
        cutoff = self._now() - self.retention_seconds
        with connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                DELETE FROM token_budget_reservations
                WHERE status IN (?, ?, ?) AND created_at < ?
                """,
                (STATUS_RECONCILED, STATUS_EXPIRED_CHARGED, STATUS_CANCELLED, cutoff),
            )
            conn.commit()
            return int(cursor.rowcount or 0)

    def release_verified(self, reservation_ids: list[int], *, reason: str) -> int:
        """Release holds only for a server decision that prevented execution."""
        if not reservation_ids:
            return 0
        released = 0
        now = self._now()
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            for reservation_id in reservation_ids:
                row = conn.execute(
                    "SELECT * FROM token_budget_reservations WHERE id = ?",
                    (int(reservation_id),),
                ).fetchone()
                if row is None or row["status"] != STATUS_RESERVED:
                    continue
                updated = conn.execute(
                    """
                    UPDATE token_budget_reservations
                    SET status = ?, charged_usd = 0, evidence_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        STATUS_CANCELLED,
                        json.dumps({"reason": reason, "server_verified": True}, sort_keys=True),
                        row["id"],
                        STATUS_RESERVED,
                    ),
                )
                if updated.rowcount != 1:
                    continue
                budget = self._budget_row(
                    conn,
                    policy_id=row["policy_id"],
                    window=row["window"],
                    tenant_id=row["tenant_id"] or "",
                    principal_hash=self._counter_principal(row["window"], row["principal_hash"]),
                )
                if budget is not None and budget["window_id"] == row["window_id"]:
                    reserved_live = max(0.0, float(budget["reserved_usd"] or 0) - float(row["reserved_usd"] or 0))
                    conn.execute(
                        "UPDATE token_budgets SET reserved_usd = ? WHERE id = ?",
                        (reserved_live, budget["id"]),
                    )
                released += 1
            conn.commit()
        return released

    def bind_guard_event(
        self,
        guard_event_id: int,
        *,
        tenant_id: str,
        principal_hash: str,
        trace_id: str | None = None,
        reservation_ids: list[int] | None = None,
    ) -> bool:
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            if reservation_ids:
                cursor = conn.execute(
                    f"""
                    UPDATE token_budget_reservations
                    SET guard_event_id = ?, principal_hash = ?
                    WHERE id IN ({",".join("?" for _ in reservation_ids)})
                      AND status = ?
                      AND guard_event_id IS NULL
                      AND tenant_id = ?
                      AND (principal_hash IS NULL OR principal_hash = ?)
                    """,
                    (
                        int(guard_event_id),
                        principal_hash,
                        *[int(item) for item in reservation_ids],
                        STATUS_RESERVED,
                        tenant_id,
                        principal_hash,
                    ),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE token_budget_reservations
                    SET guard_event_id = ?, principal_hash = ?
                    WHERE id = (
                      SELECT id FROM token_budget_reservations
                      WHERE status = ? AND guard_event_id IS NULL
                        AND tenant_id = ?
                        AND (principal_hash IS NULL OR principal_hash = ?)
                        AND (
                          COALESCE(trace_id, '') = COALESCE(?, '')
                          OR COALESCE(workflow_id, '') = COALESCE(?, '')
                        )
                      ORDER BY id DESC
                      LIMIT 1
                    )
                    """,
                    (int(guard_event_id), principal_hash, STATUS_RESERVED, tenant_id, principal_hash, trace_id, trace_id),
                )
            conn.commit()
            return cursor.rowcount == 1

    def _scope_matches(self, reservation: sqlite3.Row, *, tenant_id: str | None, principal_hash: str | None) -> bool:
        if tenant_id is not None and reservation["tenant_id"] != tenant_id:
            return False
        if principal_hash is not None and (reservation["principal_hash"] or "") != principal_hash:
            return False
        return True

    def list_active_budgets(
        self,
        *,
        policy_rules: dict[str, dict[str, Any]] | None = None,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        now = self._now()
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._expire_due(conn, now)
            if tenant_id is None:
                rows = conn.execute("SELECT * FROM token_budgets ORDER BY id DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM token_budgets WHERE tenant_id = ? ORDER BY id DESC",
                    (tenant_id,),
                ).fetchall()
            out: list[dict[str, Any]] = []
            for row in rows:
                row = self._reset_row_if_due(conn, row, now)
                item = dict(row)
                rule = (policy_rules or {}).get(str(row["policy_id"] or ""), {})
                if rule:
                    item["limit_usd"] = float(rule.get("limit_usd") or item.get("limit_usd") or 0)
                out.append(item)
            conn.commit()
        return out

    def pre_check(
        self,
        action: Action,
        raw_payload: Any,
        rules: list[TokenBudgetRule],
        *,
        tenant_id: str | None = None,
        principal_hash: str | None = None,
        reservation_ids: list[int] | None = None,
    ) -> Decision | None:
        if action.type != "llm_call" or not rules:
            return None
        for rule in rules:
            if not rule.enabled:
                continue
            model, input_tokens, output_tokens, projected = estimate_llm_cost(action, raw_payload, rule)
            decision = self._check_rule(
                rule,
                action,
                projected,
                post=False,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                tool_name=action.tool,
                reserve=True,
                tenant_id=tenant_id if tenant_id is not None else action.tenant_id,
                principal_hash=principal_hash,
                reservation_ids=reservation_ids,
            )
            if decision:
                return decision
        return None

    def claim_usage_report(self, guard_event_id: int) -> bool:
        """Legacy helper. Accounting completion is the reservation transition.

        This does not reserve the right to reconcile. ``post_record`` is
        idempotent on the reservation row, inside one transaction.
        """
        del guard_event_id
        return True

    def post_record(
        self,
        action: Action,
        *,
        input_payload: Any,
        output_payload: Any,
        rules: list[TokenBudgetRule],
        guard_event_id: int | None = None,
        tenant_id: str | None = None,
        principal_hash: str | None = None,
        client_status: str | None = None,
    ) -> bool:
        if action.type != "llm_call" or not rules:
            return False
        resolved_tenant = tenant_id if tenant_id is not None else action.tenant_id
        fallback_model = extract_model_from_payload(action, input_payload)
        malformed = False
        try:
            usage = extract_usage_from_log_payload(output_payload, input_payload, fallback_model=fallback_model)
        except (TypeError, ValueError):
            usage = None
            malformed = True
        prepared: list[dict[str, Any]] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if self._counter_scope(rule, tenant_id=resolved_tenant, principal_hash=principal_hash) is None:
                self._scope_failure(rule, 0.0)
                continue
            estimate_model, est_in, est_out, estimate_cost = estimate_llm_cost(action, input_payload or action.args, rule)
            if usage:
                model, input_tokens, output_tokens = usage
                cost = compute_cost_usd(
                    model=model or estimate_model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    model_costs=rule.model_costs,
                )
            else:
                model, input_tokens, output_tokens, cost = estimate_model, est_in, est_out, estimate_cost
            prepared.append(
                {
                    "rule": rule,
                    "cost": cost,
                    "estimate_cost": estimate_cost,
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                }
            )
        if not prepared:
            return False
        violation: PolicyViolation | None = None
        accounted = False
        for attempt in range(3):
            try:
                with connect(self.db_path) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    now = self._now()
                    self._expire_due(conn, now)
                    outcomes: list[str | None] = []
                    pending: PolicyViolation | None = None
                    for item in prepared:
                        outcome, pending_violation = self._apply_post(
                            conn,
                            rule=item["rule"],
                            action=action,
                            amount_usd=float(item["cost"]),
                            estimate_cost=float(item["estimate_cost"]),
                            model=item["model"],
                            input_tokens=int(item["input_tokens"]),
                            output_tokens=int(item["output_tokens"]),
                            tenant_id=resolved_tenant,
                            principal_hash=principal_hash,
                            guard_event_id=guard_event_id,
                            client_status=client_status,
                            usage_present=usage is not None,
                            usage_malformed=malformed,
                            now=now,
                        )
                        outcomes.append(outcome)
                        if outcome == "rejected":
                            break
                        if pending_violation is not None and pending is None:
                            pending = pending_violation
                    if "rejected" in outcomes:
                        conn.rollback()
                        return False
                    conn.commit()
                violation = pending
                accounted = "accounted" in outcomes
                break
            except sqlite3.OperationalError:
                if attempt < 2:
                    continue
                raise
        if violation is not None:
            raise violation
        return accounted

    def _apply_post(
        self,
        conn: sqlite3.Connection,
        *,
        rule: TokenBudgetRule,
        action: Action,
        amount_usd: float,
        estimate_cost: float,
        model: str,
        input_tokens: int,
        output_tokens: int,
        tenant_id: str | None,
        principal_hash: str | None,
        guard_event_id: int | None,
        client_status: str | None,
        usage_present: bool,
        usage_malformed: bool,
        now: float,
    ) -> tuple[str | None, PolicyViolation | None]:
        """Apply one rule's reconciliation. The caller commits or rolls back."""
        scope = self._counter_scope(rule, tenant_id=tenant_id, principal_hash=principal_hash)
        if scope is None:
            self._scope_failure(rule, amount_usd)
            return "ignored", None
        tenant_key, principal_key = scope
        row = self._ensure_budget_row(conn, rule, tenant_key, principal_key, now)
        if row is None:
            return None, None
        current_usd = float(row["current_usd"])
        found = self._lookup_reservation(
            conn,
            rule,
            trace_id=action.trace_id,
            workflow_id=action.workflow_id,
            guard_event_id=guard_event_id,
            tenant_id=tenant_id,
            principal_hash=principal_hash,
        )
        evidence_base = {
            "client_status": client_status,
            "usage_present": usage_present,
            "usage_malformed": usage_malformed,
        }
        if found == "rejected":
            return "rejected", None
        if found is not None and not usage_present and str(client_status or "") in _UNTRUSTED_RELEASE:
            evidence = {
                **evidence_base,
                "accepted": False,
                "reason": "client execution claim is not server evidence",
            }
            conn.execute(
                """
                UPDATE token_budget_reservations
                SET evidence_json = ?
                WHERE id = ? AND status = ?
                """,
                (json.dumps(evidence, sort_keys=True), found["id"], STATUS_RESERVED),
            )
            return "ignored", None
        if found is not None and found["status"] == STATUS_RESERVED:
            self._record_usage_event(
                conn, action, now, model, input_tokens, output_tokens, amount_usd, action.tool,
                tenant_id=tenant_key, principal_hash=principal_hash,
            )
            self._settle(
                conn,
                found,
                float(amount_usd),
                STATUS_RECONCILED,
                now,
                {**evidence_base, "policy": "charge_verified_or_estimate"},
                expected_status=STATUS_RESERVED,
                reported_usd=float(amount_usd) if usage_present else None,
            )
            return "accounted", None
        if (
            found is not None
            and found["status"] == STATUS_EXPIRED_CHARGED
            and usage_present
            and found["reported_usd"] is None
        ):
            delta = float(amount_usd) - float(found["charged_usd"] or 0)
            self._record_usage_event(
                conn, action, now, model, input_tokens, output_tokens, amount_usd, action.tool,
                tenant_id=tenant_key, principal_hash=principal_hash,
            )
            self._settle(
                conn,
                found,
                delta,
                STATUS_RECONCILED,
                now,
                {**evidence_base, "policy": "late_report_replaces_estimate"},
                expected_status=STATUS_EXPIRED_CHARGED,
                reported_usd=float(amount_usd),
            )
            return "accounted", None
        if found is not None:
            return "ignored", None
        if guard_event_id is not None:
            return None, None
        # No ledger row matches this report. Do not spend another call's hold.
        open_hold = conn.execute(
            """
            SELECT id FROM token_budget_reservations
            WHERE policy_id = ? AND window = ? AND status = ? AND tenant_id = ?
              AND COALESCE(principal_hash, '') = COALESCE(?, '')
            LIMIT 1
            """,
            (rule.id, rule.window, STATUS_RESERVED, tenant_key, principal_hash or ""),
        ).fetchone()
        if open_hold is not None:
            return "ignored", None
        self._record_usage_event(
            conn, action, now, model, input_tokens, output_tokens, amount_usd, action.tool,
            tenant_id=tenant_key, principal_hash=principal_hash,
        )
        new_current = current_usd + amount_usd
        conn.execute(
            """
            UPDATE token_budgets
            SET current_usd = ?, limit_usd = ?
            WHERE id = ?
            """,
            (new_current, rule.limit_usd, row["id"]),
        )
        violation = None
        if rule.hard_cap and new_current > float(rule.limit_usd):
            violation = PolicyViolation(
                "token budget exceeded after usage recorded",
                rule=rule.to_dict(),
                projected_usd=amount_usd,
                current_usd=new_current,
                limit_usd=rule.limit_usd,
            )
        return "accounted", violation

    def _ensure_budget_row(
        self,
        conn: sqlite3.Connection,
        rule: TokenBudgetRule,
        tenant_id: str,
        principal_hash: str,
        now: float,
    ) -> sqlite3.Row | None:
        row = self._budget_row(
            conn,
            policy_id=rule.id,
            window=rule.window,
            tenant_id=tenant_id,
            principal_hash=principal_hash,
        )
        if row is None:
            reset_at = _next_reset_at(rule.window, now)
            window_id = self._window_identity(rule.window, now, tenant_id=tenant_id, principal_hash=principal_hash)
            conn.execute(
                """
                INSERT INTO token_budgets(
                  policy_id, trace_id, workflow_id, window, limit_usd,
                  current_usd, reserved_usd, reset_at, window_id, tenant_id, principal_hash
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (rule.id, None, None, rule.window, rule.limit_usd, 0.0, 0.0, reset_at, window_id, tenant_id, principal_hash),
            )
            row = self._budget_row(
                conn,
                policy_id=rule.id,
                window=rule.window,
                tenant_id=tenant_id,
                principal_hash=principal_hash,
            )
        if row is None:
            return None
        row = self._reset_row_if_due(conn, row, now)
        if float(row["limit_usd"]) != float(rule.limit_usd):
            conn.execute("UPDATE token_budgets SET limit_usd = ? WHERE id = ?", (rule.limit_usd, row["id"]))
            row = self._budget_row(
                conn,
                policy_id=rule.id,
                window=rule.window,
                tenant_id=tenant_id,
                principal_hash=principal_hash,
            )
        return row

    def _lookup_reservation(
        self,
        conn: sqlite3.Connection,
        rule: TokenBudgetRule,
        *,
        trace_id: str | None,
        workflow_id: str | None,
        guard_event_id: int | None,
        tenant_id: str | None,
        principal_hash: str | None,
    ) -> sqlite3.Row | None | str:
        if guard_event_id is not None:
            found = conn.execute(
                """
                SELECT * FROM token_budget_reservations
                WHERE guard_event_id = ? AND policy_id = ?
                """,
                (int(guard_event_id), rule.id),
            ).fetchone()
            if found is None:
                other = conn.execute(
                    "SELECT id FROM token_budget_reservations WHERE guard_event_id = ?",
                    (int(guard_event_id),),
                ).fetchone()
                if other is None:
                    return "rejected"
                return None
            if not self._scope_matches(found, tenant_id=tenant_id, principal_hash=principal_hash):
                return "rejected"
            return found
        query = """
            SELECT * FROM token_budget_reservations
            WHERE policy_id = ? AND window = ? AND status = ?
              AND COALESCE(trace_id, '') = COALESCE(?, '')
              AND COALESCE(workflow_id, '') = COALESCE(?, '')
        """
        params: list[Any] = [rule.id, rule.window, STATUS_RESERVED, trace_id, workflow_id]
        if tenant_id is not None:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if principal_hash is not None:
            query += " AND principal_hash = ?"
            params.append(principal_hash)
        query += " ORDER BY id LIMIT 1"
        return conn.execute(query, params).fetchone()

    def _check_rule(
        self,
        rule: TokenBudgetRule,
        action: Action,
        amount_usd: float,
        *,
        post: bool,
        model: str,
        input_tokens: int,
        output_tokens: int,
        tool_name: str | None,
        reserve: bool = False,
        estimate_cost: float = 0.0,
        tenant_id: str | None = None,
        principal_hash: str | None = None,
        reservation_ids: list[int] | None = None,
        guard_event_id: int | None = None,
        client_status: str | None = None,
        usage_present: bool = False,
    ) -> Decision | str | None:
        scope = self._counter_scope(
            rule,
            tenant_id=tenant_id if tenant_id is not None else action.tenant_id,
            principal_hash=principal_hash,
        )
        if scope is None:
            return self._scope_failure(rule, amount_usd)
        tenant_key, principal_key = scope
        if post:
            raise RuntimeError("usage reconciliation is performed by post_record")

        for attempt in range(3):
            try:
                with connect(self.db_path) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    now = self._now()
                    self._expire_due(conn, now)
                    row = self._ensure_budget_row(conn, rule, tenant_key, principal_key, now)
                    if row is None:
                        conn.commit()
                        return None

                    current_usd = float(row["current_usd"])
                    reserved_usd = float(row["reserved_usd"] if "reserved_usd" in row.keys() else 0)

                    projected_total = current_usd + reserved_usd + amount_usd
                    if projected_total <= float(rule.limit_usd):
                        if reserve:
                            window_id = row["window_id"] or self._window_identity(
                                rule.window, now, tenant_id=tenant_key, principal_hash=principal_key
                            )
                            conn.execute(
                                "UPDATE token_budgets SET reserved_usd = ?, limit_usd = ?, window_id = ? WHERE id = ?",
                                (reserved_usd + amount_usd, rule.limit_usd, window_id, row["id"]),
                            )
                            fingerprint = action_fingerprint(action.to_dict())
                            cursor = conn.execute(
                                """
                                INSERT INTO token_budget_reservations(
                                  tenant_id, principal_hash, policy_id, window, window_id,
                                  trace_id, workflow_id, action_fingerprint, reserved_usd,
                                  charged_usd, created_at, deadline_at, status, evidence_json
                                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                                """,
                                (
                                    tenant_key,
                                    principal_hash,
                                    rule.id,
                                    rule.window,
                                    window_id,
                                    action.trace_id,
                                    action.workflow_id,
                                    fingerprint,
                                    float(amount_usd),
                                    0.0,
                                    now,
                                    now + self.reservation_ttl,
                                    STATUS_RESERVED,
                                    "{}",
                                ),
                            )
                            if reservation_ids is not None and cursor.lastrowid is not None:
                                reservation_ids.append(int(cursor.lastrowid))
                        conn.commit()
                        return None

                    conn.commit()
                    matched = rule.to_dict()
                    if rule.hard_cap:
                        raise PolicyViolation(
                            "token budget exceeded",
                            rule=matched,
                            projected_usd=amount_usd,
                            current_usd=current_usd + reserved_usd,
                            limit_usd=rule.limit_usd,
                        )
                    return Decision(
                        action="warn",
                        reason="token budget exceeded (soft cap)",
                        matched_rule=matched,
                        effective_action="warn",
                    )
            except sqlite3.OperationalError:
                if attempt < 2:
                    continue
                raise
        return None

    def _record_usage_event(
        self,
        conn: sqlite3.Connection,
        action: Action,
        now: float,
        model: str,
        input_tokens: int,
        output_tokens: int,
        amount_usd: float,
        tool_name: str | None,
        *,
        tenant_id: str | None = None,
        principal_hash: str | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO token_events(
              trace_id, workflow_id, timestamp, model, input_tokens, output_tokens,
              cost_usd, tool_name, tenant_id, principal_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                action.trace_id or "",
                action.workflow_id,
                now,
                model,
                input_tokens,
                output_tokens,
                amount_usd,
                tool_name,
                tenant_id,
                principal_hash,
            ),
        )


def simulate_budget_trace(
    trace_events: list[dict[str, Any]],
    rules: list[TokenBudgetRule],
) -> dict[str, Any]:
    """Stateless budget replay for policy simulation (no DB writes)."""
    from .models import Action

    spend: dict[tuple[str, str, str, str], float] = {}
    violations: list[dict[str, Any]] = []
    for row in trace_events:
        action_data = dict(row.get("action") or {})
        if action_data.get("type") != "llm_call":
            continue
        action = Action(
            type="llm_call",
            tool=action_data.get("tool"),
            args=action_data.get("args") or {},
            workflow_id=action_data.get("workflow_id"),
            trace_id=action_data.get("trace_id"),
        )
        raw = row.get("input_payload") or action_data.get("args") or {}
        usage = extract_usage_from_log_payload(row.get("output_payload"), raw)
        for rule in rules:
            if not rule.enabled:
                continue
            # Preview uses the same scope as enforcement: one bucket per rule
            # window, not a client trace or workflow id.
            key = (rule.id, rule.window, "authenticated", "")
            trace_id, workflow_id = action.trace_id, action.workflow_id
            if usage:
                model, in_tok, out_tok = usage
                cost = compute_cost_usd(
                    model=model,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    model_costs=rule.model_costs,
                )
            else:
                _, in_tok, out_tok, cost = estimate_llm_cost(action, raw, rule)
            spend[key] = spend.get(key, 0.0) + cost
            if spend[key] > float(rule.limit_usd):
                violations.append(
                    {
                        "event_id": row.get("id"),
                        "rule_id": rule.id,
                        "window": rule.window,
                        "trace_id": trace_id,
                        "workflow_id": workflow_id,
                        "spend_usd": spend[key],
                        "limit_usd": rule.limit_usd,
                        "hard_cap": rule.hard_cap,
                    }
                )
    return {"violations": violations, "spend_by_key": {f"{k[0]}:{k[1]}": v for k, v in spend.items()}}


def merge_budget_rules_into_policy(current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = {**current}
    for bucket in _BUCKETS:
        merged.setdefault(bucket, [])
    existing = list(merged.get("budget_rules") or [])
    seen = {_rule_fingerprint(r) for r in existing}
    for rule in incoming.get("budget_rules") or []:
        key = _rule_fingerprint(rule)
        if key not in seen:
            existing.append(rule)
            seen.add(key)
    merged["budget_rules"] = existing
    return merged
