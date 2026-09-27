"""Tamper-evident audit integrity (hash chain) for Varden security events.

This is NOT a blockchain / ledger / new database. It strengthens the existing
``events`` table hash fields so recorded decisions can be verified later.

Scheme (hash_version = "1"):
    previous_hash is concatenated *outside* the canonical JSON object.

    event_hash = SHA-256( canonical_json(security_fields) + "\\n" + previous_hash )

    The first chained event uses GENESIS_PREV_HASH as previous_hash.
    event_hash / prev_hash / id are excluded from the hashed payload.

Legacy transition model (single chained era):
    zero or more LEGACY_UNCHAINED rows (NULL event_hash)
        →
    CHAINED genesis (prev_hash = GENESIS)
        →
    subsequent CHAINED rows only

Once chaining begins, a later NULL/unhashed row is a verification failure
(``unexpected_unchained_after_chain``), not a second legacy region.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

HASH_VERSION = "1"
SUPPORTED_HASH_VERSIONS = frozenset({HASH_VERSION})
GENESIS_PREV_HASH = "0" * 64
INTEGRITY_LEGACY = "LEGACY_UNCHAINED"
INTEGRITY_CHAINED = "CHAINED"
INTEGRITY_BROKEN = "BROKEN"
UNSUPPORTED_HASH_VERSION = "UNSUPPORTED_HASH_VERSION"

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Fields included in the canonical event preimage (order does not matter: sort_keys).
_HASH_BODY_KEYS = (
    "timestamp",
    "action",
    "decision",
    "status",
    "input_payload",
    "output_payload",
    "error",
    "replayable",
    "replay_key",
    "workflow_id",
    "agent_name",
    "parent_event_id",
    "trace_id",
    "tenant_id",
)

# Policy fingerprint: SECURITY-RELEVANT top-level keys only.
# Rule list order under block/warn/monitor/allow/require_approval is preserved
# because first-match semantics are order-sensitive.
_POLICY_FINGERPRINT_KEYS = frozenset(
    {
        "block",
        "warn",
        "monitor",
        "allow",
        "require_approval",
        "rules",
        "version",
        "name",
        "mode",
        "fail_mode",
        "require_coverage",
        "allow_uncovered",
        "predictive_authority",
    }
)

# Explicitly excluded / ignored when present on a wider config object:
# timestamps, object ids, logging verbosity, dashboard prefs, PIDs, counters,
# temporary paths, cache data — see canonicalize_policy_for_fingerprint.


def stable_json(value: Any) -> str:
    """Deterministic JSON for hashing (sorted keys, compact separators)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _canonical_policy_value(value: Any) -> Any:
    """Recursively canonicalise policy values for fingerprinting.

    - dict keys sorted (via stable_json later); nested values canonicalised
    - lists preserve order (semantic for first-match rule lists)
    - sets/frozensets become sorted lists (order not semantic)
    - Path → portable string
    """
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {str(k): _canonical_policy_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_policy_value(v) for v in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonical_policy_value(v) for v in value]
        return sorted(items, key=lambda x: stable_json(x))
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float, str)):
        return value
    # Enums and similar
    if hasattr(value, "value") and not isinstance(value, type):
        try:
            return _canonical_policy_value(value.value)
        except Exception:
            pass
    return str(value)


def canonicalize_policy_for_fingerprint(
    policy: Any,
    *,
    mode: str | None = None,
    fail_mode: str | None = None,
    require_coverage: list[str] | None = None,
    allow_uncovered: list[str] | None = None,
) -> dict[str, Any]:
    """Build the security-relevant policy identity object.

    SECURITY-RELEVANT: effective rules (block/warn/monitor/allow/require_approval),
    mode/fail_mode when they change enforcement, require_coverage / allow_uncovered.

    NOT included: object identity, insertion order of maps, timestamps, temp
    paths, logging verbosity, dashboard preferences, PIDs, counters, caches.
    """
    out: dict[str, Any] = {}
    if isinstance(policy, dict):
        for key in sorted(policy.keys()):
            if key in _POLICY_FINGERPRINT_KEYS or str(key).startswith("rule"):
                out[str(key)] = _canonical_policy_value(policy[key])
    elif policy is not None:
        out["policy"] = _canonical_policy_value(policy)
    if mode is not None:
        out["mode"] = str(mode).strip().lower()
    if fail_mode is not None:
        out["fail_mode"] = str(fail_mode).strip().lower()
    if require_coverage is not None:
        out["require_coverage"] = [_canonical_policy_value(x) for x in require_coverage]
    if allow_uncovered is not None:
        # Membership set — order not semantic.
        out["allow_uncovered"] = sorted(str(x).strip().lower() for x in allow_uncovered)
    return out


def policy_fingerprint(
    policy: Any,
    *,
    mode: str | None = None,
    fail_mode: str | None = None,
    require_coverage: list[str] | None = None,
    allow_uncovered: list[str] | None = None,
) -> str:
    """Deterministic fingerprint of effective security-policy identity."""
    if policy is None and mode is None and fail_mode is None and require_coverage is None and allow_uncovered is None:
        return hashlib.sha256(b"policy:none").hexdigest()
    payload = canonicalize_policy_for_fingerprint(
        policy,
        mode=mode,
        fail_mode=fail_mode,
        require_coverage=require_coverage,
        allow_uncovered=allow_uncovered,
    )
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def stamp_policy_fingerprint(
    action: dict[str, Any],
    policy: Any,
    *,
    mode: str | None = None,
    fail_mode: str | None = None,
    require_coverage: list[str] | None = None,
    allow_uncovered: list[str] | None = None,
) -> dict[str, Any]:
    """Attach policy fingerprint into action.metadata (returns shallow-copied action)."""
    out = dict(action or {})
    meta = dict(out.get("metadata") or {})
    integrity = dict(meta.get("audit_integrity") or {})
    integrity["hash_version"] = HASH_VERSION
    integrity["policy_fingerprint"] = policy_fingerprint(
        policy,
        mode=mode,
        fail_mode=fail_mode,
        require_coverage=require_coverage,
        allow_uncovered=allow_uncovered,
    )
    meta["audit_integrity"] = integrity
    out["metadata"] = meta
    return out


def canonical_event_body(event: dict[str, Any]) -> dict[str, Any]:
    """Build the hashable security-event body (excludes id/event_hash/prev_hash)."""
    body: dict[str, Any] = {"hash_version": HASH_VERSION}
    for key in _HASH_BODY_KEYS:
        if key in event:
            body[key] = event.get(key)
    return body


def compute_event_hash(event: dict[str, Any], previous_hash: str | None) -> str:
    """Compute event_hash for ``event`` given the previous chain hash.

    Pass ``previous_hash=None`` for genesis (uses GENESIS_PREV_HASH).
    """
    prev = GENESIS_PREV_HASH if previous_hash is None else previous_hash
    body = canonical_event_body(event)
    preimage = stable_json(body) + "\n" + prev
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def classify_integrity_row(event_hash: str | None) -> str:
    if not event_hash:
        return INTEGRITY_LEGACY
    return INTEGRITY_CHAINED


def _event_declared_hash_version(ev: dict[str, Any]) -> str | None:
    action = ev.get("action")
    if isinstance(action, str):
        try:
            action = json.loads(action)
        except Exception:
            action = None
    if not isinstance(action, dict):
        return None
    meta = action.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    integrity = meta.get("audit_integrity") or {}
    if not isinstance(integrity, dict):
        return None
    ver = integrity.get("hash_version")
    return str(ver) if ver is not None else None


def _validate_hash_token(value: Any, *, field: str, event_id: Any) -> dict[str, Any] | None:
    """Return a failure dict if hash token is malformed; else None."""
    if value is None:
        return {
            "event_id": event_id,
            "reason": f"missing_{field}",
            "field": field,
        }
    text = str(value)
    if len(text) != 64:
        return {
            "event_id": event_id,
            "reason": "invalid_hash_length",
            "field": field,
            "recorded": text[:80],
        }
    if not _HEX64.match(text):
        return {
            "event_id": event_id,
            "reason": "non_hex_hash",
            "field": field,
            "recorded": text[:80],
        }
    return None


def _normalize_event_for_verify(ev: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in ev.items() if k not in {"id", "event_hash", "prev_hash"}}
    for field in ("action", "decision", "input_payload", "output_payload"):
        val = body.get(field)
        if isinstance(val, str):
            try:
                body[field] = json.loads(val)
            except Exception:
                pass
    return body


def verify_event_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify events ordered by ascending id.

    Transition model: optional legacy prefix, then a single chained era.
    Does NOT claim detection of silent tail truncation without an external
    checkpointed chain head.
    """
    events_checked = 0
    chained = 0
    legacy = 0
    failures: list[dict[str, Any]] = []
    segments = 0
    chain_started = False
    expected_prev: str | None = None
    seen_ids: set[Any] = set()
    last_hash: str | None = None

    for ev in events:
        events_checked += 1
        eid = ev.get("id")
        if eid is not None:
            if eid in seen_ids:
                failures.append({"event_id": eid, "reason": "duplicate_event_id"})
            seen_ids.add(eid)

        recorded_hash = ev.get("event_hash")
        recorded_prev = ev.get("prev_hash")

        declared_version = _event_declared_hash_version(ev)
        if declared_version is not None and declared_version not in SUPPORTED_HASH_VERSIONS:
            failures.append(
                {
                    "event_id": eid,
                    "reason": UNSUPPORTED_HASH_VERSION,
                    "hash_version": declared_version,
                }
            )
            # Still advance expected_prev if hash present so subsequent linkage is checked.
            if recorded_hash:
                chain_started = True
                expected_prev = recorded_hash
                chained += 1
            continue

        if not recorded_hash:
            if chain_started:
                failures.append(
                    {
                        "event_id": eid,
                        "reason": "unexpected_unchained_after_chain",
                        "detail": "NULL event_hash after chained era began",
                    }
                )
            else:
                legacy += 1
            continue

        # Malformed hash tokens
        if recorded_prev is None and not chain_started:
            recorded_prev = GENESIS_PREV_HASH
        fail_h = _validate_hash_token(recorded_hash, field="event_hash", event_id=eid)
        if fail_h:
            failures.append(fail_h)
        fail_p = _validate_hash_token(recorded_prev, field="prev_hash", event_id=eid)
        if fail_p:
            failures.append(fail_p)

        if not chain_started:
            segments += 1
            chain_started = True
            if recorded_prev != GENESIS_PREV_HASH:
                failures.append(
                    {
                        "event_id": eid,
                        "reason": "invalid_genesis",
                        "expected_previous_hash": GENESIS_PREV_HASH,
                        "recorded_previous_hash": recorded_prev,
                    }
                )
            body = _normalize_event_for_verify(ev)
            expected_hash = compute_event_hash(body, None)
        else:
            if recorded_prev != expected_prev:
                failures.append(
                    {
                        "event_id": eid,
                        "reason": "previous_hash_mismatch",
                        "expected_previous_hash": expected_prev,
                        "recorded_previous_hash": recorded_prev,
                    }
                )
            body = _normalize_event_for_verify(ev)
            expected_hash = compute_event_hash(body, recorded_prev)

        # Detect exact duplicate payload replayed with same hashes (optional signal)
        if last_hash is not None and recorded_hash == last_hash and recorded_prev == expected_prev:
            failures.append({"event_id": eid, "reason": "duplicated_event_hash"})

        chained += 1
        if recorded_hash != expected_hash:
            failures.append(
                {
                    "event_id": eid,
                    "reason": "event_hash_mismatch",
                    "expected_event_hash": expected_hash,
                    "recorded_event_hash": recorded_hash,
                }
            )
        expected_prev = recorded_hash
        last_hash = recorded_hash

    # More than one genesis segment is invalid under the single-era model.
    if segments > 1:
        failures.append(
            {
                "event_id": None,
                "reason": "multiple_chain_segments",
                "chain_segments": segments,
            }
        )

    return {
        "valid": not failures,
        "events_checked": events_checked,
        "chained_events": chained,
        "legacy_events": legacy,
        "chain_segments": segments,
        "integrity_failures": len(failures),
        "failures": failures,
        "broken_at_event_id": next((f["event_id"] for f in failures if f.get("event_id") is not None), None),
        "notes": [
            "Hash chaining provides tamper evidence, not confidentiality.",
            "Silent tail truncation is not detectable without an external chain-head checkpoint.",
            "Legacy NULL event_hash rows are valid only as a prefix before the chained era.",
            "Once chaining begins, unexpected unchained records fail verification.",
        ],
    }


def format_verify_report(result: dict[str, Any]) -> str:
    lines = [
        "Varden audit integrity",
        "",
        f"Events checked:       {result.get('events_checked', 0):,}",
        f"Chained events:       {result.get('chained_events', 0):,}",
        f"Legacy events:        {result.get('legacy_events', 0):,}",
        f"Chain segments:       {result.get('chain_segments', 0):,}",
        f"Integrity failures:   {result.get('integrity_failures', 0):,}",
        "",
    ]
    if result.get("valid"):
        lines.append("PASS")
    else:
        lines.append("FAIL")
        broken = result.get("broken_at_event_id")
        if broken is not None:
            lines.append("")
            lines.append(f"Chain broken at event {broken}")
        for failure in (result.get("failures") or [])[:8]:
            reason = failure.get("reason")
            lines.append(f"  reason: {reason}")
            if reason == UNSUPPORTED_HASH_VERSION:
                lines.append(f"  hash_version: {failure.get('hash_version')}")
            if failure.get("expected_previous_hash"):
                lines.append(f"  Expected previous hash: {failure['expected_previous_hash']}")
            if failure.get("recorded_previous_hash") is not None:
                lines.append(f"  Recorded previous hash: {failure['recorded_previous_hash']}")
            if failure.get("expected_event_hash"):
                lines.append(f"  Expected event hash: {failure['expected_event_hash']}")
            if failure.get("recorded_event_hash"):
                lines.append(f"  Recorded event hash: {failure['recorded_event_hash']}")
    return "\n".join(lines) + "\n"
