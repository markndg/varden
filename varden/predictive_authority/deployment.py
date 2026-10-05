"""Deployment assumptions for Predictive Authority live state.

Live ``AuthorityState`` is process-local. Cross-process continuity (multiple
workers, process restart) cannot be verified from inside a single Python
process. Enforce mode therefore requires an *explicit* operator declaration
of the supported topology; undeclared deployments fail safe rather than
assuming single-worker completeness.
"""

from __future__ import annotations

import os
from typing import Any, Mapping


_WORKER_ENV_KEYS = ("WEB_CONCURRENCY", "VARDEN_WORKERS", "VARDEN_UVICORN_WORKERS")

# Explicit operator declarations (VARDEN_PA_DEPLOYMENT).
DEPLOY_SINGLE_WORKER = "single_worker"
DEPLOY_MULTI_ALLOWED = "multi_worker_allowed"


def worker_count(env: Mapping[str, str] | None = None) -> int:
    source = env if env is not None else os.environ
    for key in _WORKER_ENV_KEYS:
        raw = source.get(key)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            continue
    return 1


def multi_worker_detected(env: Mapping[str, str] | None = None) -> bool:
    return worker_count(env) > 1


def multi_worker_explicitly_allowed(env: Mapping[str, str] | None = None) -> bool:
    source = env if env is not None else os.environ
    raw = str(source.get("VARDEN_PA_ALLOW_MULTI_WORKER") or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    deployment = str(source.get("VARDEN_PA_DEPLOYMENT") or "").strip().lower()
    return deployment == DEPLOY_MULTI_ALLOWED


def declared_deployment(env: Mapping[str, str] | None = None) -> str | None:
    source = env if env is not None else os.environ
    raw = str(source.get("VARDEN_PA_DEPLOYMENT") or "").strip().lower()
    if raw in {DEPLOY_SINGLE_WORKER, DEPLOY_MULTI_ALLOWED}:
        return raw
    return None


def pa_deployment_status(
    *,
    enforce: bool,
    env: Mapping[str, str] | None = None,
    active_workers: int | None = None,
) -> dict[str, Any]:
    """Return deployment posture for PA live-state assumptions.

    Guarantees possible in an in-process Python library:
    - **Declared single_worker**: process-local history is assumed complete
      for this OS process only unless durable worker leases show otherwise.
    - **Detected multi-worker env without allow**: unsupported → fail-safe.
    - **Durable lease count > 1** (shared DB): unsupported → fail-safe even
      when WEB_CONCURRENCY is unset / each process declares single_worker.
    - **Lease query failure while ContinuityStore bound**: callers must pass
      a conservative ``active_workers >= 2`` (registry does this) so topology
      cannot temporarily allow; also expect process ``continuity_degraded``.
    - **Separate DB paths / unbound ContinuityStore**: leases do **not**
      coordinate; each process is isolated. Do not claim cross-worker safety.
    - **Explicit multi_worker_allowed / VARDEN_PA_ALLOW_MULTI_WORKER**: residual
      risk accepted; not independently verified shared-state safety.
    - **Undeclared**: topology unknown → fail-safe in enforce (cannot verify
      that sibling workers do not hold missing authority history).
    - **Process restart**: with ContinuityStore bound, prior-authority sessions
      fail-safe; full graph replay is not claimed.
      ``cross_restart_continuity_verified`` is always False.
    """
    workers = worker_count(env)
    multi = workers > 1
    lease_multi = bool(active_workers is not None and active_workers > 1)
    allowed = multi_worker_explicitly_allowed(env)
    declared = declared_deployment(env)
    # Durable fail-safe covers restart of sessions that held authority; full
    # shared live-graph continuity is still not claimed.
    cross_restart_verified = False

    unsupported = False
    reason = "SINGLE_WORKER_DECLARED"

    if not enforce:
        reason = "OBSERVE_NO_ENFORCE_ASSUMPTION"
    elif (multi or lease_multi) and not allowed:
        unsupported = True
        reason = "MULTI_WORKER_UNSUPPORTED"
    elif allowed or declared == DEPLOY_MULTI_ALLOWED:
        reason = "MULTI_WORKER_EXPLICITLY_ALLOWED"
    elif declared == DEPLOY_SINGLE_WORKER:
        reason = "SINGLE_WORKER_DECLARED"
    else:
        # Unknown topology: worker env may be unset even with multiple processes.
        unsupported = True
        reason = "DEPLOYMENT_UNDECLARED"

    return {
        "live_state": "process_local",
        "worker_count": workers,
        "active_workers_durable": active_workers,
        "multi_worker_detected": multi or lease_multi,
        "multi_worker_allowed": allowed,
        "deployment_declared": declared,
        "single_worker_required_for_enforce": True,
        "unsupported_multi_worker_enforce": unsupported,
        "cross_restart_continuity_verified": cross_restart_verified,
        "continuity_scope": "process_lifetime_only",
        "reason": reason,
    }
