"""Threat-intelligence service.

Orchestrates fetch, normalisation, contracts, applicability, candidates,
replay, and approval. It does not sit on the firewall decision path.
"""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import replace
from typing import Any, Callable

from . import lifecycle
from .applicability import InstallationFacts, assess_contract, facts_from_attestation, telemetry_flags
from .approval import ApprovalError, apply_approved_rule, next_states_after_approval, rule_present
from .candidates import generate_candidate, validate_candidate
from .config import ThreatIntelConfig
from .contracts import build_contract, validate_contract
from .http_client import IntelHttpError, SafeHttpClient
from .models import ExternalId, ThreatIntelligenceItem, validate_item
from .replay import replay_candidate
from .sources import build_sources
from .store import ThreatIntelStore

FactsProvider = Callable[[], InstallationFacts]


class ThreatIntelService:
    def __init__(
        self,
        config: ThreatIntelConfig,
        *,
        store: ThreatIntelStore | None = None,
        policy_engine: Any = None,
        event_store: Any = None,
        http_client: SafeHttpClient | None = None,
        facts_provider: FactsProvider | None = None,
        sources: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.store = store or ThreatIntelStore(config.db_path)
        self.policy_engine = policy_engine
        self.event_store = event_store
        self.client = http_client or SafeHttpClient(
            timeout=config.request_timeout_seconds,
            max_bytes=config.max_response_bytes,
            max_attempts=config.max_attempts,
            backoff_base_seconds=config.backoff_base_seconds,
            backoff_cap_seconds=config.backoff_cap_seconds,
            jitter_ratio=config.jitter_ratio,
            user_agent=config.user_agent,
        )
        self.sources = sources or build_sources(config)
        self._facts_provider = facts_provider
        self._lock = threading.Lock()
        self._checking = False
        self._last_check_error: str | None = None

    def status(self) -> dict[str, Any]:
        self._drop_stale_protected_claims()
        sources = self._source_views()
        last_seen = float(self.store.get_meta("last_seen", "0") or 0)
        fresh = self.store.items_updated_since(last_seen)
        affecting = [doc for doc in fresh if doc.get("applicability") == "EXPOSED"]
        review = [doc for doc in fresh if doc.get("applicability") == "REVIEW"]
        inventory = self.store.inventory()
        next_due = [row.get("next_due") for row in sources if isinstance(row.get("next_due"), (int, float))]
        last_success = [row.get("last_success") for row in sources if isinstance(row.get("last_success"), (int, float))]
        empty_reason = actionable_empty_reason(inventory)
        return {
            "enabled": self.config.enabled,
            "watcher": self._watcher(sources),
            "watcher_meaning": "Watcher health only. LIVE does not mean this installation is protected.",
            "protection_claim": False,
            "checking": self._checking,
            "last_check_error": self._last_check_error,
            "last_success": max(last_success) if last_success else None,
            "next_check": min(next_due) if next_due else None,
            "counts": {
                "total": inventory["total"],
                "mapped": inventory["mapped"],
                "unmapped": inventory["total"] - inventory["mapped"],
                "protected": inventory["protected"],
                "exposed": inventory["exposed"],
                "review": inventory["review"],
                "not_applicable": inventory["not_applicable"],
                "candidates_awaiting": inventory["candidates_awaiting"],
                "actionable": inventory["actionable"],
                "enforced": inventory["enforced"],
            },
            "count_meanings": {
                "total": "Stored threat records. This is not the upstream catalog size.",
                "mapped": "Records whose structured identifiers select a Varden contract.",
                "unmapped": "Records with no supported contract. Review is not a failed lookup.",
                "protected": "Invariant proven on every applicable required surface. Distinct from mapped.",
                "exposed": "A required surface applies and the invariant is not proven.",
                "review": "No contract, or a contract whose evidence is not sufficient to decide.",
                "not_applicable": "A contract exists and none of its required surfaces apply here.",
                "candidates_awaiting": "Possible candidate rules waiting for explicit approval. Not active policy.",
                "actionable": "Records with a possible candidate or an approved rule already in policy.",
            },
            "actionable_empty_reason": empty_reason,
            "actionable_empty_message": ACTIONABLE_EMPTY_MESSAGES.get(empty_reason or ""),
            "new_items": len(fresh),
            "affecting_this_runtime": len(affecting),
            "needs_review": len(review),
            "sources": sources,
            "rule_activation": "explicit_approval_required",
        }

    def source_views(self) -> list[dict[str, Any]]:
        return self._source_views()

    def check(self, source_id: str | None = None, *, installation: InstallationFacts | None = None) -> dict[str, Any]:
        if not self.config.enabled:
            return {"enabled": False, "fetched": False, "watcher": "DISABLED", "sources": []}
        ids = [source_id] if source_id else list(self.sources)
        if source_id and source_id not in self.sources:
            raise KeyError(source_id)
        results = []
        with self._lock:
            self._checking = True
            try:
                for sid in ids:
                    results.append(self._check_one(sid, installation=installation))
            finally:
                self._checking = False
        self.store.prune(max_items=self.config.retention_items)
        return {"enabled": True, "fetched": True, "watcher": self.status()["watcher"], "sources": results}

    def ingest_raw(
        self,
        source_id: str,
        raw_items: list[dict[str, Any]],
        *,
        baseline: bool = False,
        installation: InstallationFacts | None = None,
        source_version: str = "",
        rollback: bool = False,
    ) -> dict[str, Any]:
        """Process already-fetched records. Used by the pipeline and by tests."""
        source = self.sources[source_id]
        seen: set[str] = set()
        ordered: list[dict[str, Any]] = []
        for raw in raw_items:
            key = json_identity(raw)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(raw)
        outcomes = []
        facts = installation if installation is not None else self._facts()
        for raw in ordered:
            item = source.normalize(raw)
            if item is None:
                outcomes.append({"status": "skipped"})
                continue
            if source_version and not item.source_version:
                item.source_version = source_version
            item.fetched_at = time.time()
            outcomes.append(self._advance(item, baseline=baseline, facts=facts, rollback=rollback))
        return {"source": source_id, "outcomes": outcomes, "rollback": rollback}

    def list_items(self, **filters: Any) -> dict[str, Any]:
        view = filters.pop("view", None)
        actionable = bool(filters.pop("actionable", False) or view == "actionable")
        if "q" in filters and not filters.get("query"):
            filters["query"] = filters.pop("q")
        else:
            filters.pop("q", None)
        page = self.store.query_items(actionable=actionable, **filters)
        return {
            "items": [_public_item(doc) for doc in page["items"]],
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
        }

    def show(self, item_id: str) -> dict[str, Any]:
        doc = self._require(item_id)
        if doc.get("lifecycle") in lifecycle.LOCKED:
            self._refresh_assessment(doc)
            self.store.save_item(doc)
        doc = dict(doc)
        doc["audit"] = self.store.list_audit(item_id, limit=50)
        doc["rule_active"] = doc.get("lifecycle") == lifecycle.ENFORCED
        doc["protection_claim"] = doc.get("applicability") == "PROTECTED"
        return doc

    def contract_for(self, item_id: str) -> dict[str, Any]:
        doc = self._require(item_id)
        return {"item_id": item_id, "contract": doc.get("contract"), "lifecycle": doc.get("lifecycle")}

    def candidate_for(self, item_id: str) -> dict[str, Any]:
        doc = self._require(item_id)
        candidate = doc.get("candidate") or {}
        return {
            "item_id": item_id,
            "candidate": candidate,
            "rule_active": False if doc.get("lifecycle") != lifecycle.ENFORCED else True,
            "lifecycle": doc.get("lifecycle"),
        }

    def replay(self, item_id: str) -> dict[str, Any]:
        doc = self._require(item_id)
        candidate = doc.get("candidate") or {}
        if not candidate.get("possible"):
            report = replay_candidate(candidate=candidate, events=[], policy=self._policy(), limit=self.config.replay_max_events)
            return {"item_id": item_id, "replay": report}
        report = self._replay(candidate)
        doc["replay"] = report
        doc["updated_at"] = time.time()
        self.store.save_item(doc)
        return {"item_id": item_id, "replay": report}

    def approve(
        self,
        item_id: str,
        *,
        actor: str,
        expected_content_hash: str | None = None,
        expected_candidate_id: str | None = None,
    ) -> dict[str, Any]:
        """Publish the template rule for this item.

        The stored candidate is not the authority. Approval rebuilds the
        contract from the record's structured ids, re-checks the installation,
        and writes only the current Varden template. A displayed hash that no
        longer matches is rejected so a poll cannot swap the record underneath
        an open investigation.
        """
        with self._lock:
            doc = self._require(item_id)
            candidate = doc.get("candidate") or {}
            if not candidate.get("possible") or not isinstance(candidate.get("rule"), dict):
                raise ApprovalError("this item has no candidate rule to approve")
            if doc.get("lifecycle") not in {lifecycle.AWAITING_APPROVAL, lifecycle.APPROVED, lifecycle.OBSERVE, lifecycle.ENFORCED}:
                raise ApprovalError(f"cannot approve from lifecycle {doc.get('lifecycle')}")
            if self.policy_engine is None:
                raise ApprovalError("policy engine is not configured")
            if expected_content_hash and expected_content_hash != doc.get("raw_content_hash"):
                raise ApprovalError("the intelligence record changed after it was shown; reassess before approval")
            if expected_candidate_id and expected_candidate_id != candidate.get("id"):
                raise ApprovalError("the candidate changed after it was shown; reassess before approval")
            previous = doc.get("lifecycle")
            if previous in {lifecycle.ENFORCED, lifecycle.OBSERVE, lifecycle.APPROVED}:
                current_policy = self._policy()
                rule_id = str((candidate.get("rule") or {}).get("id") or "")
                if rule_id and rule_present(current_policy, rule_id):
                    self.store.audit(
                        kind="duplicate_approval",
                        item_id=item_id,
                        actor=actor,
                        previous_state=previous,
                        new_state=previous,
                        detail={"threat": _threat_ref(doc), "contract": _contract_ref(doc), "candidate": candidate.get("id"), "rewritten": False},
                    )
                    return {"item_id": item_id, "lifecycle": previous, "result": {"rule_id": rule_id, "already_present": True}, "idempotent": True, "rule_active": previous == lifecycle.ENFORCED}
            rule, bucket = self._rule_cleared_for_approval(doc)
            result = apply_approved_rule(
                policy_engine=self.policy_engine,
                policy_file=self.config.policy_file,
                rule=rule,
                bucket=bucket,
                actor=actor,
            )
            if previous in {lifecycle.ENFORCED, lifecycle.OBSERVE, lifecycle.APPROVED}:
                doc["updated_at"] = time.time()
                self._refresh_assessment(doc)
                self.store.save_item(doc)
                self.store.audit(
                    kind="approval_republish",
                    item_id=item_id,
                    actor=actor,
                    previous_state=previous,
                    new_state=previous,
                    detail={"result": result, "rewritten": False},
                )
                return {"item_id": item_id, "lifecycle": previous, "result": result, "idempotent": False, "rule_active": previous == lifecycle.ENFORCED}
            current = previous
            for new in next_states_after_approval(bucket):
                current = self._step(doc, current, new, actor=actor, reason="operator_approved", detail={"result": result})
            doc["lifecycle"] = current
            doc["rule_active"] = current == lifecycle.ENFORCED
            doc["approved_rule"] = {"id": result.get("rule_id"), "bucket": result.get("bucket"), "snapshot_id": result.get("snapshot_id")}
            doc["updated_at"] = time.time()
            self._refresh_assessment(doc)
            self.store.save_item(doc)
            return {"item_id": item_id, "lifecycle": current, "result": result, "idempotent": result.get("already_present", False), "rule_active": doc["rule_active"]}

    def decide(self, item_id: str, action: str, *, actor: str) -> dict[str, Any]:
        with self._lock:
            return self._decide_locked(item_id, action, actor=actor)

    def _decide_locked(self, item_id: str, action: str, *, actor: str) -> dict[str, Any]:
        doc = self._require(item_id)
        previous = str(doc.get("lifecycle") or lifecycle.DISCOVERED)
        target = {
            "dismiss": lifecycle.DISMISSED,
            "not_applicable": lifecycle.NOT_APPLICABLE,
            "review": lifecycle.REVIEW,
        }.get(action)
        if target is None:
            raise ApprovalError(f"unknown decision {action}")
        if previous == target:
            self.store.audit(
                kind="duplicate_decision",
                item_id=item_id,
                actor=actor,
                previous_state=previous,
                new_state=target,
                detail={"action": action},
            )
            return {"item_id": item_id, "lifecycle": target, "idempotent": True}
        new = self._step(doc, previous, target, actor=actor, reason=f"operator_{action}", detail={"action": action})
        doc["lifecycle"] = new
        if action == "not_applicable":
            doc["applicability"] = "NOT_APPLICABLE"
        doc["updated_at"] = time.time()
        self.store.save_item(doc)
        return {"item_id": item_id, "lifecycle": new, "idempotent": False, "rule_active": False}

    def mark_seen(self) -> dict[str, Any]:
        now = time.time()
        self.store.set_meta("last_seen", str(now))
        return {"last_seen": now}

    def _check_one(self, source_id: str, *, installation: InstallationFacts | None) -> dict[str, Any]:
        source = self.sources[source_id]
        meta = source.metadata()
        state = self.store.get_source(source_id) or {"source_id": source_id}
        now = time.time()
        state["last_attempt"] = now
        if meta.implementation == "scaffold" or not meta.fetch_url:
            health = source.health()
            state.update({"health": health.get("state", "unsupported"), "detail": health.get("detail"), "implementation": meta.implementation})
            self.store.save_source(source_id, state)
            return {"source": source_id, "fetched": False, "health": state.get("health"), "detail": state.get("detail")}
        try:
            batch = source.fetch_since(state.get("cursor"), self.client)
        except IntelHttpError as exc:
            failures = int(state.get("consecutive_failures") or 0) + 1
            delay = min(self.config.backoff_cap_seconds, self.config.backoff_base_seconds * (2 ** (failures - 1)))
            state.update(
                {
                    "health": "error",
                    "detail": f"{exc.code}: {exc}",
                    "consecutive_failures": failures,
                    "next_due": now + delay,
                    "last_error": str(exc),
                }
            )
            self._last_check_error = state["detail"]
            self.store.save_source(source_id, state)
            self.store.audit(kind="source_error", item_id=None, actor=None, previous_state=None, new_state="ERROR", detail={"source": source_id, "error": exc.code})
            return {"source": source_id, "fetched": False, "health": "error", "detail": state["detail"]}
        health = source.health()
        interval = self.config.interval_for(source_id)
        state.update(
            {
                "cursor": batch.next_cursor,
                "etag": batch.etag,
                "last_modified": batch.last_modified,
                "content_hash": batch.content_hash,
                "source_version": batch.source_version,
                "parser_version": meta.parser_version,
                "health": health.get("state", "healthy"),
                "detail": health.get("detail"),
                "last_success": now,
                "next_due": now + interval,
                "consecutive_failures": 0,
                "rollback": batch.rollback,
                "notes": batch.notes,
                "implementation": meta.implementation,
                "interval_seconds": interval,
            }
        )
        self.store.save_source(source_id, state)
        if batch.rollback:
            self.store.audit(
                kind="source_rollback",
                item_id=None,
                actor=None,
                previous_state=None,
                new_state=None,
                detail={"source": source_id, "notes": batch.notes, "version": batch.source_version},
            )
        if batch.unchanged:
            return {"source": source_id, "fetched": True, "unchanged": True, "health": state["health"], "items": 0}
        ingested = self.ingest_raw(
            source_id,
            batch.items,
            baseline=batch.baseline and self.config.suppress_baseline_notifications,
            installation=installation,
            source_version=batch.source_version,
            rollback=batch.rollback,
        )
        return {
            "source": source_id,
            "fetched": True,
            "unchanged": False,
            "baseline": batch.baseline,
            "health": state["health"],
            "items": len(ingested["outcomes"]),
            "rollback": batch.rollback,
        }

    def _advance(self, item: ThreatIntelligenceItem, *, baseline: bool, facts: InstallationFacts, rollback: bool) -> dict[str, Any]:
        errors = validate_item(item.to_dict())
        if errors:
            self.store.audit(kind="normalize_error", item_id=item.id, actor=None, previous_state=None, new_state=lifecycle.ERROR, detail={"errors": errors})
            return {"id": item.id, "status": "error", "errors": errors}
        existing = self.store.get_item(item.id)
        if existing and existing.get("raw_content_hash") == item.raw_content_hash and not item.withdrawn:
            return {"id": item.id, "status": "unchanged", "lifecycle": existing.get("lifecycle")}
        if existing and existing.get("lifecycle") in lifecycle.LOCKED and existing.get("raw_content_hash") != item.raw_content_hash:
            previous = existing.get("lifecycle")
            existing["upstream_changed_while_enforced"] = True
            existing["pending_upstream_hash"] = item.raw_content_hash
            existing["updated_at"] = time.time()
            self.store.save_item(existing)
            self.store.audit(
                kind="upstream_changed_while_enforced",
                item_id=item.id,
                actor=None,
                previous_state=previous,
                new_state=previous,
                detail={"pending_upstream_hash": item.raw_content_hash, "rule_left_unchanged": True},
            )
            return {"id": item.id, "status": "held", "lifecycle": previous}
        doc = item.to_dict()
        doc["baseline"] = bool(baseline)
        doc["updated_at"] = time.time()
        doc["lifecycle_history"] = list((existing or {}).get("lifecycle_history") or [])
        doc["related"] = self._related(item)
        state = lifecycle.DISCOVERED
        state = self._step(doc, state, lifecycle.NORMALIZED, actor=None, reason="normalized")
        if item.withdrawn:
            state = self._step(doc, state, lifecycle.SOURCE_WITHDRAWN, actor=None, reason="source_withdrew")
            doc["lifecycle"] = state
            doc["applicability"] = None
            self.store.save_item(doc)
            return {"id": item.id, "status": "withdrawn", "lifecycle": state}
        contract = build_contract(item)
        contract_errors = validate_contract(contract)
        if contract_errors:
            state = self._step(doc, state, lifecycle.ERROR, actor=None, reason="contract_invalid", detail={"errors": contract_errors})
            doc["lifecycle"] = state
            doc["contract_errors"] = contract_errors
            self.store.save_item(doc)
            return {"id": item.id, "status": "error", "errors": contract_errors}
        doc["contract"] = contract
        if contract.get("review_only"):
            assessment = assess_contract(contract, facts)
            doc["assessment"] = assessment
            doc["applicability"] = "REVIEW"
            state = self._step(doc, state, lifecycle.REVIEW, actor=None, reason="no_deterministic_contract", detail={"reasons": assessment.get("reasons")})
            doc["lifecycle"] = state
            doc["candidate"] = None
            self.store.save_item(doc)
            return {"id": item.id, "status": "review", "lifecycle": state, "applicability": "REVIEW"}
        state = self._step(doc, state, lifecycle.CONTRACT_GENERATED, actor=None, reason="contract_generated")
        assessment = assess_contract(contract, facts)
        doc["assessment"] = assessment
        doc["applicability"] = assessment.get("result")
        state = self._step(doc, state, lifecycle.ASSESSED, actor=None, reason="assessed", detail={"result": assessment.get("result")})
        if assessment.get("result") == "NOT_APPLICABLE":
            state = self._step(doc, state, lifecycle.NOT_APPLICABLE, actor=None, reason="not_applicable")
            doc["lifecycle"] = state
            doc["candidate"] = None
            self.store.save_item(doc)
            return {"id": item.id, "status": "not_applicable", "lifecycle": state}
        if assessment.get("result") == "REVIEW":
            state = self._step(doc, state, lifecycle.REVIEW, actor=None, reason="applicability_review", detail={"reasons": assessment.get("reasons")})
            doc["lifecycle"] = state
            doc["candidate"] = None
            self.store.save_item(doc)
            return {"id": item.id, "status": "review", "lifecycle": state}
        if assessment.get("result") == "PROTECTED":
            doc["lifecycle"] = state
            doc["candidate"] = generate_candidate(item=doc, contract=contract, assessment=assessment, policy=facts.policy)
            self.store.save_item(doc)
            return {"id": item.id, "status": "protected", "lifecycle": state, "applicability": "PROTECTED"}
        candidate = generate_candidate(item=doc, contract=contract, assessment=assessment, policy=facts.policy)
        candidate_errors = validate_candidate(candidate)
        doc["candidate"] = candidate
        if candidate_errors or not candidate.get("possible"):
            state = self._step(doc, state, lifecycle.REVIEW, actor=None, reason=candidate.get("reason_code") or "no_candidate", detail={"errors": candidate_errors})
            doc["lifecycle"] = state
            self.store.save_item(doc)
            return {"id": item.id, "status": "review", "lifecycle": state, "reason": candidate.get("reason_code")}
        state = self._step(doc, state, lifecycle.CANDIDATE, actor=None, reason="candidate_generated")
        report = self._replay(candidate)
        doc["replay"] = report
        state = self._step(doc, state, lifecycle.BACKTESTED, actor=None, reason="replayed", detail={"replay_status": report.get("status")})
        state = self._step(doc, state, lifecycle.AWAITING_APPROVAL, actor=None, reason="awaiting_operator")
        doc["lifecycle"] = state
        doc["rule_active"] = False
        self.store.save_item(doc)
        return {"id": item.id, "status": "awaiting_approval", "lifecycle": state, "applicability": "EXPOSED", "rollback": rollback}

    def _replay(self, candidate: dict[str, Any]) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        if self.event_store is not None:
            events = self.event_store.list_events_ascending(limit=self.config.replay_max_events + 1)
        return replay_candidate(
            candidate=candidate,
            events=events,
            policy=self._policy(),
            limit=self.config.replay_max_events,
        )

    def _drop_stale_protected_claims(self) -> None:
        """A stored PROTECTED result is not durable. Re-check it against live policy."""
        for doc in self.store.list_items(applicability="PROTECTED", limit=500):
            before = doc.get("applicability")
            self._refresh_assessment(doc)
            if doc.get("applicability") != before:
                doc["updated_at"] = time.time()
                self.store.save_item(doc)

    def _rule_cleared_for_approval(self, doc: dict[str, Any]) -> tuple[dict[str, Any], str]:
        from varden.policy import RULE_META_KEYS

        item = _item_for_mapping(doc)
        contract = build_contract(item)
        stored = doc.get("contract") or {}
        if contract.get("id") != stored.get("id") or contract.get("proof") != stored.get("proof"):
            raise ApprovalError("stale candidate: the contract for this record no longer matches the Varden mapping")
        if contract.get("review_only") or not contract.get("id"):
            raise ApprovalError("this record has no deterministic contract to enforce")
        facts = replace(self._facts(), policy=self._policy())
        assessment = assess_contract(contract, facts)
        if doc.get("lifecycle") == lifecycle.AWAITING_APPROVAL and assessment.get("result") != "EXPOSED":
            raise ApprovalError(
                f"assumptions changed: applicability is now {assessment.get('result')}; reassess before approval"
            )
        fresh = generate_candidate(item=doc, contract=contract, assessment=assessment, policy=facts.policy)
        if not fresh.get("possible") or not isinstance(fresh.get("rule"), dict):
            raise ApprovalError("assumptions changed: a candidate rule is no longer justified")
        stored_rule = (doc.get("candidate") or {}).get("rule") or {}
        fresh_rule = fresh["rule"]

        def predicates(rule: dict[str, Any]) -> dict[str, Any]:
            return {
                key: value
                for key, value in rule.items()
                if key not in RULE_META_KEYS and value is not None and value != ""
            }

        if predicates(stored_rule) != predicates(fresh_rule) or stored_rule.get("id") != fresh_rule.get("id"):
            raise ApprovalError("stale candidate: the stored rule does not match the current Varden template")
        if str((doc.get("candidate") or {}).get("expected_action")) != str(fresh.get("expected_action")):
            raise ApprovalError("stale candidate: the expected action changed")
        return fresh_rule, str(fresh["expected_action"])

    def _refresh_assessment(self, doc: dict[str, Any]) -> None:
        """Re-read policy after approval so a stored EXPOSED reason cannot outlive the rule."""
        contract = doc.get("contract")
        if not isinstance(contract, dict) or not contract.get("id"):
            return
        facts = replace(self._facts(), policy=self._policy())
        assessment = assess_contract(contract, facts)
        doc["assessment"] = assessment
        doc["applicability"] = assessment.get("result")

    def _facts(self) -> InstallationFacts:
        if self._facts_provider is not None:
            return self._facts_provider()
        attestation = None
        try:
            from varden.runtime.coverage import get_coverage_registry

            attestation = get_coverage_registry().attestation()
        except Exception:
            attestation = {"surfaces": []}
        events: list[dict[str, Any]] = []
        if self.event_store is not None:
            try:
                events = self.event_store.list_events_ascending(limit=200)
            except Exception:
                events = []
        provenance, authority, classification = telemetry_flags(events)
        return facts_from_attestation(
            attestation,
            self._policy(),
            provenance_seen=provenance,
            authority_seen=authority,
            classification_seen=classification,
        )

    def _policy(self) -> dict[str, Any]:
        if self.policy_engine is None:
            return {"block": [], "warn": [], "monitor": [], "allow": []}
        return self.policy_engine.get_policy()

    def _step(
        self,
        doc: dict[str, Any],
        current: str,
        new: str,
        *,
        actor: str | None,
        reason: str,
        detail: dict[str, Any] | None = None,
    ) -> str:
        updated = lifecycle.transition(current, new)
        entry = {"from": current, "to": updated, "at": time.time(), "reason": reason, "actor": actor}
        doc.setdefault("lifecycle_history", []).append(entry)
        payload = {"reason": reason, "threat": _threat_ref(doc), "contract": _contract_ref(doc), "candidate": (doc.get("candidate") or {}).get("id")}
        if detail:
            payload.update(detail)
        self.store.audit(
            kind="lifecycle",
            item_id=doc.get("id"),
            actor=actor,
            previous_state=current,
            new_state=updated,
            detail=payload,
        )
        return updated

    def _related(self, item: ThreatIntelligenceItem) -> list[dict[str, Any]]:
        related: list[dict[str, Any]] = []
        seen: set[str] = set()
        for weakness in item.weaknesses:
            for other in self.store.find_by_weakness(weakness.id):
                if other.get("id") == item.id or other.get("id") in seen:
                    continue
                seen.add(str(other.get("id")))
                related.append(
                    {
                        "id": other.get("id"),
                        "source": other.get("source"),
                        "source_id": other.get("source_id"),
                        "relation": "shares_weakness",
                        "weakness": weakness.id,
                    }
                )
        for other in self.store.find_by_hash(item.raw_content_hash, exclude=item.id):
            if other.get("id") in seen:
                continue
            seen.add(str(other.get("id")))
            related.append(
                {
                    "id": other.get("id"),
                    "source": other.get("source"),
                    "source_id": other.get("source_id"),
                    "relation": "duplicate_content",
                }
            )
        return related

    def _require(self, item_id: str) -> dict[str, Any]:
        doc = self.store.get_item(item_id)
        if doc is None:
            raise KeyError(item_id)
        return doc

    def _source_views(self) -> list[dict[str, Any]]:
        stored = {row.get("source_id"): row for row in self.store.list_sources()}
        by_source = self.store.counts_by_source()
        views = []
        for source_id, source in self.sources.items():
            meta = source.metadata().to_dict()
            state = stored.get(source_id) or {}
            health = state.get("health") or source.health().get("state") or "unknown"
            counts = by_source.get(source_id) or {"stored": 0, "mapped": 0}
            indexed, indexed_scope = _indexed_scope(source_id, state, meta)
            views.append(
                {
                    **meta,
                    "health": health,
                    "detail": state.get("detail") or source.health().get("detail"),
                    "last_success": state.get("last_success"),
                    "last_attempt": state.get("last_attempt"),
                    "next_due": state.get("next_due"),
                    "interval_seconds": state.get("interval_seconds") or meta["default_interval_seconds"],
                    "source_version": state.get("source_version"),
                    "parser_version": meta["parser_version"],
                    "rollback": bool(state.get("rollback")),
                    "etag": state.get("etag"),
                    "records_stored": counts["stored"],
                    "records_mapped": counts["mapped"],
                    "records_indexed": indexed if indexed is not None else counts["stored"],
                    "records_indexed_scope": indexed_scope,
                    "unsupported": meta.get("implementation") == "scaffold" or health == "unsupported",
                }
            )
        return views

    def _watcher(self, sources: list[dict[str, Any]]) -> str:
        if not self.config.enabled:
            return "DISABLED"
        if self._checking:
            return "CHECKING"
        implemented = [row for row in sources if row.get("implementation") != "scaffold"]
        if not implemented:
            return "OFFLINE"
        if not any(row.get("last_success") for row in implemented):
            if any(row.get("health") == "error" for row in implemented):
                return "ERROR"
            return "OFFLINE"
        errors = [row for row in implemented if row.get("health") == "error"]
        healthy = [row for row in implemented if row.get("health") == "healthy"]
        if errors and healthy:
            return "DEGRADED"
        if errors and not healthy:
            return "ERROR"
        if healthy:
            return "LIVE"
        return "DEGRADED"


def _item_for_mapping(doc: dict[str, Any]) -> ThreatIntelligenceItem:
    """Rebuild the fields contract selection reads. Prose is not consulted."""
    techniques = [
        ExternalId(str(row.get("system") or ""), str(row.get("id") or ""))
        for row in (doc.get("techniques") or [])
        if isinstance(row, dict)
    ]
    weaknesses = [
        ExternalId(str(row.get("system") or "cwe"), str(row.get("id") or ""))
        for row in (doc.get("weaknesses") or [])
        if isinstance(row, dict)
    ]
    return ThreatIntelligenceItem(
        id=str(doc.get("id") or ""),
        source=str(doc.get("source") or ""),
        source_id=str(doc.get("source_id") or ""),
        title="",
        description="",
        published_at=None,
        modified_at=None,
        severity=str(doc.get("severity") or "unknown"),
        techniques=techniques,
        weaknesses=weaknesses,
        raw_content_hash=str(doc.get("raw_content_hash") or ""),
        upstream_url=str(doc.get("upstream_url") or ""),
        source_version=str(doc.get("source_version") or ""),
    )


def _threat_ref(doc: dict[str, Any]) -> dict[str, Any]:
    return {"id": doc.get("id"), "source": doc.get("source"), "source_id": doc.get("source_id"), "hash": doc.get("raw_content_hash")}


def _contract_ref(doc: dict[str, Any]) -> dict[str, Any] | None:
    contract = doc.get("contract") or {}
    if not contract:
        return None
    return {"id": contract.get("id"), "version": contract.get("version"), "review_only": contract.get("review_only")}


def _public_item(doc: dict[str, Any]) -> dict[str, Any]:
    contract = doc.get("contract") or {}
    candidate = doc.get("candidate") or {}
    contract_id = contract.get("id") or None
    return {
        "id": doc.get("id"),
        "source": doc.get("source"),
        "source_id": doc.get("source_id"),
        "title": doc.get("title"),
        "severity": doc.get("severity"),
        "published_at": doc.get("published_at"),
        "modified_at": doc.get("modified_at"),
        "lifecycle": doc.get("lifecycle"),
        "applicability": doc.get("applicability"),
        "has_contract": bool(contract_id),
        "contract_id": contract_id,
        "contract_version": contract.get("version"),
        "review_only": bool(contract.get("review_only")),
        "review_reason": contract.get("review_reason"),
        "mapping_ids": list(contract.get("mapping_ids") or []),
        "has_candidate": bool(candidate.get("possible")),
        "candidate_id": candidate.get("id"),
        "candidate_reason_code": candidate.get("reason_code") or "",
        "rule_active": doc.get("lifecycle") == lifecycle.ENFORCED,
        "baseline": bool(doc.get("baseline")),
        "updated_at": doc.get("updated_at"),
        "surfaces": contract.get("enforcement_surfaces") or [],
        "upstream_changed_while_enforced": bool(doc.get("upstream_changed_while_enforced")),
    }


ACTIONABLE_EMPTY_MESSAGES = {
    "EMPTY_DATABASE": "No threat intelligence is stored yet.",
    "UNMAPPED_ONLY": "Stored intelligence has no supported Varden contract, so no candidate can be offered.",
    "NO_ATTESTED_CAPABILITY": (
        "No candidate rules are currently available. The connected runtime has not attested "
        "the capabilities required to evaluate these contracts."
    ),
    "COVERAGE_GAP": (
        "Mapped contracts are exposed because coverage is incomplete. A candidate rule is not "
        "offered when the gap is coverage rather than a missing policy predicate."
    ),
    "NEEDS_ASSESSMENT": "Mapped contracts are waiting on assessment evidence. None are ready for a candidate rule.",
    "NO_CANDIDATE": "No candidate rules are currently available.",
}


def actionable_empty_reason(inventory: dict[str, int]) -> str | None:
    """Why the actionable view is empty. None when a candidate or installed rule exists."""
    if inventory.get("actionable", 0) > 0:
        return None
    if inventory.get("total", 0) == 0:
        return "EMPTY_DATABASE"
    mapped = inventory.get("mapped", 0)
    if mapped == 0:
        return "UNMAPPED_ONLY"
    if mapped == inventory.get("mapped_not_applicable", 0):
        return "NO_ATTESTED_CAPABILITY"
    if inventory.get("mapped_exposed", 0) > 0 and inventory.get("candidates_awaiting", 0) == 0:
        return "COVERAGE_GAP"
    if inventory.get("mapped_review", 0) > 0:
        return "NEEDS_ASSESSMENT"
    return "NO_CANDIDATE"


def _indexed_scope(source_id: str, state: dict[str, Any], meta: dict[str, Any]) -> tuple[int | None, str]:
    """How many upstream records were seen, without treating a filtered query as the whole catalog."""
    if meta.get("implementation") == "scaffold" or (state.get("health") or "") == "unsupported":
        return 0, "unsupported"
    cursor = state.get("cursor") if isinstance(state.get("cursor"), dict) else {}
    if source_id == "atlas" and isinstance(cursor.get("technique_ids"), list):
        return len(cursor["technique_ids"]), "techniques_in_upstream_document"
    if source_id == "cwe" and isinstance(cursor.get("index"), dict):
        return len(cursor["index"]), "weaknesses_in_upstream_catalog"
    if source_id == "nvd" and state.get("last_success"):
        return None, "records_retrieved"
    return None, "not_fetched"


def json_identity(raw: dict[str, Any]) -> str:
    import json

    material = raw.get("stix") or raw.get("cve") or raw.get("weakness") or raw.get("entry") or raw
    if isinstance(material, dict):
        ident = material.get("external_id") or material.get("id") or material.get("name")
        if ident:
            return str(ident)
    return json.dumps(raw, sort_keys=True, default=str)[:500]


def copy_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(policy)
