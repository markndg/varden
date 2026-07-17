from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import connect, init_db
from .exceptions import PolicyViolation
from .models import Action, Decision
from .rules.token_budget import (
    TokenBudgetRule,
    compute_cost_usd,
    normalize_model_name,
    resolve_output_limit,
)

logger = logging.getLogger("varden.token_budget")

_BUCKETS = ("block", "warn", "monitor", "allow")


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
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def _budget_key(self, rule: TokenBudgetRule, action: Action) -> tuple[str | None, str | None]:
        if rule.window == "session":
            return action.trace_id or action.workflow_id, None
        return None, action.workflow_id or action.trace_id

    def _reset_row_if_due(self, conn: sqlite3.Connection, row: sqlite3.Row, now: float) -> sqlite3.Row:
        reset_at = row["reset_at"]
        if reset_at is not None and now >= float(reset_at):
            new_reset = _next_reset_at(row["window"], now)
            conn.execute(
                "UPDATE token_budgets SET current_usd = 0, reserved_usd = 0, reset_at = ? WHERE id = ?",
                (new_reset, row["id"]),
            )
            return conn.execute("SELECT * FROM token_budgets WHERE id = ?", (row["id"],)).fetchone()
        return row

    def list_active_budgets(self, *, policy_rules: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        now = _utc_now()
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT * FROM token_budgets ORDER BY id DESC").fetchall()
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
            )
            if decision:
                return decision
        return None

    def post_record(
        self,
        action: Action,
        *,
        input_payload: Any,
        output_payload: Any,
        rules: list[TokenBudgetRule],
    ) -> None:
        if action.type != "llm_call" or not rules:
            return
        fallback_model = extract_model_from_payload(action, input_payload)
        usage = extract_usage_from_log_payload(output_payload, input_payload, fallback_model=fallback_model)
        for rule in rules:
            if not rule.enabled:
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
            self._check_rule(
                rule,
                action,
                cost,
                post=True,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                tool_name=action.tool,
                reserve=False,
                estimate_cost=estimate_cost,
            )

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
    ) -> Decision | None:
        trace_id, workflow_id = self._budget_key(rule, action)
        if rule.window == "session" and not trace_id:
            logger.warning("session budget %s skipped: missing trace_id/workflow_id", rule.id)
            return None
        if rule.window in {"daily", "monthly"} and not workflow_id:
            logger.warning("%s budget %s skipped: missing workflow_id/trace_id", rule.window, rule.id)
            return None

        for attempt in range(3):
            try:
                with connect(self.db_path) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    now = _utc_now()
                    row = conn.execute(
                        """
                        SELECT * FROM token_budgets
                        WHERE policy_id = ? AND window = ?
                          AND COALESCE(trace_id, '') = COALESCE(?, '')
                          AND COALESCE(workflow_id, '') = COALESCE(?, '')
                        """,
                        (rule.id, rule.window, trace_id, workflow_id),
                    ).fetchone()
                    if row is None:
                        reset_at = _next_reset_at(rule.window, now)
                        conn.execute(
                            """
                            INSERT INTO token_budgets(
                              policy_id, trace_id, workflow_id, window, limit_usd, current_usd, reserved_usd, reset_at
                            ) VALUES (?,?,?,?,?,?,?,?)
                            """,
                            (rule.id, trace_id, workflow_id, rule.window, rule.limit_usd, 0.0, 0.0, reset_at),
                        )
                        row = conn.execute(
                            """
                            SELECT * FROM token_budgets
                            WHERE policy_id = ? AND window = ?
                              AND COALESCE(trace_id, '') = COALESCE(?, '')
                              AND COALESCE(workflow_id, '') = COALESCE(?, '')
                            """,
                            (rule.id, rule.window, trace_id, workflow_id),
                        ).fetchone()
                    if row is None:
                        conn.commit()
                        return None

                    row = self._reset_row_if_due(conn, row, now)
                    if float(row["limit_usd"]) != float(rule.limit_usd):
                        conn.execute(
                            "UPDATE token_budgets SET limit_usd = ? WHERE id = ?",
                            (rule.limit_usd, row["id"]),
                        )

                    current_usd = float(row["current_usd"])
                    reserved_usd = float(row["reserved_usd"] if "reserved_usd" in row.keys() else 0)

                    if post:
                        release = min(float(estimate_cost or amount_usd), reserved_usd)
                        reserved_usd = max(0.0, reserved_usd - release)
                        current_usd += amount_usd
                        conn.execute(
                            """
                            INSERT INTO token_events(
                              trace_id, workflow_id, timestamp, model, input_tokens, output_tokens, cost_usd, tool_name
                            ) VALUES (?,?,?,?,?,?,?,?)
                            """,
                            (
                                action.trace_id or trace_id or "",
                                action.workflow_id or workflow_id,
                                now,
                                model,
                                input_tokens,
                                output_tokens,
                                amount_usd,
                                tool_name,
                            ),
                        )
                        conn.execute(
                            """
                            UPDATE token_budgets
                            SET current_usd = ?, reserved_usd = ?, limit_usd = ?
                            WHERE id = ?
                            """,
                            (current_usd, reserved_usd, rule.limit_usd, row["id"]),
                        )
                        conn.commit()
                        if rule.hard_cap and current_usd > float(rule.limit_usd):
                            raise PolicyViolation(
                                "token budget exceeded after usage recorded",
                                rule=rule.to_dict(),
                                projected_usd=amount_usd,
                                current_usd=current_usd,
                                limit_usd=rule.limit_usd,
                            )
                        return None

                    projected_total = current_usd + reserved_usd + amount_usd
                    if projected_total <= float(rule.limit_usd):
                        if reserve:
                            reserved_usd += amount_usd
                            conn.execute(
                                """
                                UPDATE token_budgets
                                SET reserved_usd = ?, limit_usd = ?
                                WHERE id = ?
                                """,
                                (reserved_usd, rule.limit_usd, row["id"]),
                            )
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
            store = TokenBudgetStore.__new__(TokenBudgetStore)
            trace_id, workflow_id = store._budget_key(rule, action)
            if rule.window == "session" and not trace_id:
                continue
            if rule.window in {"daily", "monthly"} and not workflow_id:
                continue
            key = (rule.id, rule.window, trace_id or "", workflow_id or "")
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
