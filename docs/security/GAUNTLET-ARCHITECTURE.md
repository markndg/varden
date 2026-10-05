# Security Gauntlet — Architecture limitations

Focused fixes cannot safely eliminate these without a larger redesign.

## A1. Process-local Predictive Authority live state

**What:** `AuthorityRegistry` lives in one OS process.  
**Why not a quick fix:** Introducing shared durable live state requires a
consistency model (linearizability vs causal), failure handling for partial
writes, approval/provenance co-location, and multi-writer conflict rules.  
**Current mitigation:** Single-worker requirement; enforce-mode fail-safe when
`WEB_CONCURRENCY`/`VARDEN_WORKERS`/`VARDEN_UVICORN_WORKERS` > 1 unless
`VARDEN_PA_ALLOW_MULTI_WORKER=1`.  
**Proposed design (not implemented):** Control-plane PA state service with
per-session fencing tokens and append-only authority log; workers read-through
with fail-closed on fencing loss.

## A2. Continuity across process restart

**What:** Full live ``AuthorityState`` graphs are process-local and are **not**
replayed after restart.
**Mitigation (implemented):** control-plane SQLite ``ContinuityStore`` persists
tombstones / ``had_authority`` markers / worker leases. Reintroducing a
prior-authority session after restart marks ``continuity_broken`` (fail-safe).
``cross_restart_continuity_verified`` remains **always false** — durable
fail-safes are not verified graph continuity.
**SQLite failure semantics:** any ContinuityStore read/write/lease/attach/bind
failure marks process ``continuity_degraded`` and enforce strengthens to
≥ ``require_approval``. Lease query failure while a store is bound returns a
conservative worker count (≥2) so topology cannot temporarily allow.
**Residual:** engines without a bound store; separate DB paths do not
coordinate; brand-new session keys remain allow when undegraded.

## A2b. Sibling processes each declaring single_worker

**What:** Env detection alone cannot see other OS processes that omit worker
env vars but still share agent identities.
**Mitigation (implemented):** worker leases on a **shared** ContinuityStore DB
detect siblings even when each process declares ``single_worker``.
**Not covered:** processes using **separate** database paths — leases do not
coordinate across DBs; do not claim cross-worker safety in that topology.
**Guarantee:** shared-DB multi-lease → ``MULTI_WORKER_UNSUPPORTED`` fail-safe
unless explicitly allowed.

## A3. Comprehensive interception of all Python / native side effects

**What:** Saved pre-patch references, raw sockets, native extensions, child
processes, and unpatched APIs can bypass interceptors.  
**Why not a quick fix:** Would require OS sandboxing (seccomp, macOS sandbox,
Windows job objects) outside the current product claim.  
**Current mitigation:** Honest coverage registry (`PARTIAL` / `UNCOVERED` /
`UNSUPPORTED`), readiness, posture.  
**Proposed design:** Optional OS-level sandbox backend as a separate
enforcement plane; never claim ENFORCED for surfaces it does not mediate.

## A4. Filesystem TOCTOU at Python interception layer

**What:** Check-to-use races remain possible between policy evaluation and the
underlying syscall.  
**Why not a quick fix:** True TOCTOU freedom needs `*at`/`O_PATH` descriptor
relative operations and/or OS policy.  
**Current mitigation:** Canonicalisation, symlink-aware effective targets,
pre-use re-check; coverage PARTIAL.  
**Proposed design:** Descriptor-relative containment helpers on platforms that
support them; keep PARTIAL until proven.
