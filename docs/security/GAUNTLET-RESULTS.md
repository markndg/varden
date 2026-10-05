# Security Gauntlet — Results

**Working branch:** `harden/security-gauntlet`  
**Baseline commit:** `9536e49f0921126d68da475f10901feb1cdf74fc`  
**Version:** 1.0.1  


## Continuity acceptance gate — final state

| ID | Before | Final behaviour | Status |
|----|--------|-----------------|--------|
| G-PA-EVICT-01 | Accumulated authority could be lost after LRU eviction, weakening `require_approval` → `allow` | Authority-bearing eviction records a continuity tombstone; recreation is treated as incomplete and enforce fails safe | Fixed (fail-safe) |
| G-PA-EVICT-02 | Forgotten bounded tombstones could restore a clean-state `allow` | Tombstone loss marks continuity degraded; durable continuity state preserves the signal across process lifetime/restart | Fixed (fail-safe) |
| G-PA-MULTI-01 | Separate process-local registries could miss authority accumulated by another worker | Shared-DB worker leases detect sibling workers and produce `MULTI_WORKER_UNSUPPORTED` unless explicitly allowed | Fixed when control-plane DB is shared |
| G-PA-RESTART-01 | Restart discarded live authority state and could treat an existing trace as new | Durable `had_authority` state detects reintroduction after restart and produces `SESSION_CONTINUITY_BROKEN` | Fixed (fail-safe; no graph replay) |

**Final continuity model:** live `AuthorityState` graphs remain process-local.
The control-plane `ContinuityStore` persists security-relevant continuity
signals — tombstones, prior-authority markers and worker leases — so loss of
live state can be detected and handled fail-safe.

This is deliberately not described as shared or replayable authority state.
Full graph replay across restart/workers is not implemented, and
`cross_restart_continuity_verified` remains false. Worker coordination requires
a shared control-plane database; separate database paths cannot coordinate.

Evidence: `docs/security/evidence-G-PA-CONTINUITY-GATE.txt` (7 passed).

## G-SDK-MODE-01 enforcement-integrity gate

| Check | Result |
|-------|--------|
| Authoritative config | Locked `CoverageRegistry.enforcement_contract()` (existing registry; no new public mode API) |
| Repeated / nested / failed / async / concurrent `protect`/`activate` | Refuse weaker contracts; same-contract re-entry OK |
| Stale ContextVar / `copy_context` / stale guard refs | Deny side effect still blocked via locked contract |
| Registry `reset` while locked | Refused unless `unpatch_runtime` (`release_enforcement_lock=True`) |
| Expand `allow_uncovered` / mutate mode attrs / surface mark | Contract mode unchanged; deny path still enforces |
| Unsuccessful first activation | Rolls back patches + ContextVar; does not leave lock installed |
| Attestation vs live enforcing | `mode` / `mode_locked` align with `_live_enforcing` for guarded/strict |
| Observe / fail-open benign | Observe allows policy-blocked classification without raise; guarded+fail_open still raises on reachable deny |
| BEFORE reproducer | `test_gauntlet_BEFORE_contextvar_swap_disagrees_with_attestation_labels` retained; fails safely (enforces) after fix |

**Not closed on field immutability alone** — integrity requires denied side effects after each downgrade attempt.

**Remaining gaps (superseded by follow-up):** coverage surface false-ENFORCED and policy alias issues addressed in G-COV-ATTEST-01 / G-POLICY-INT-01 below.

## Follow-up enforcement-integrity gate

| ID | Before | After | Status |
|----|--------|-------|--------|
| G-COV-ATTEST-01 | Restored original + poison mark/check → attestation ENFORCED | Sealed probes; mark/check refuse; attestation UNCOVERED | Fixed |
| G-PATCH-LIFE-01 | Restore loses wrap; foreign wrap undefined | One-shot reconcile to original; no foreign fight; ENFORCED dropped if probe fails | Fixed (in-process limits) |
| G-POLICY-INT-01 | `get_policy()` alias / split snapshot / vacuous PUT | Deepcopy + coherent snapshot; refuse vacuous/partial publish; write-before-swap | Fixed |

Evidence: `docs/security/evidence-G-COV-ATTEST-01.txt`. Full suite (excl. browser/e2e): **768 passed**.

## Durable continuity remediation (follow-up)

| ID | Before | After | Status |
|----|--------|-------|--------|
| G-PA-EVICT-02 | Forgotten in-memory tombstone → allow | Process degrade + durable tombstone/degrade in SQLite | Fixed (fail-safe) |
| G-PA-RESTART-01 | Restart → allow on same trace | ContinuityStore `had_authority` → `SESSION_CONTINUITY_BROKEN` | Fixed (fail-safe; no graph replay) |
| G-PA-MULTI-01 | Sibling `single_worker` processes miss chains | Shared-DB worker leases → `MULTI_WORKER_UNSUPPORTED` | Fixed when DB shared |

**Not claimed:** full shared live AuthorityState / graph replay across workers or restart.

### Eliminated vs inherent limitations

| Eliminated | Inherent (unsupported) |
|------------|------------------------|
| False ENFORCED attestation via mark/poisoned probes | Calling stored pre-patch references / native code |
| Weaker `protect()` replacing live enforcement | Arbitrary malicious code in the same interpreter |
| In-place policy dict alias weakening | Authorized admin policy updates |
| Torn concurrent policy reads mid-evaluate | Multi-process PA without shared state |

### G-PA-EVICT-01

| State | Result |
|-------|--------|
| **BEFORE** | `test_gauntlet_AFTER_eviction_must_not_weaken_enforce_decision` **FAILED** on unfixed code; characterization test showed `shell` weaken `require_approval` → `allow` after LRU eviction. Log: `docs/security/evidence-G-PA-EVICT-01-BEFORE.txt` |
| **AFTER** | Continuity tombstones + enforce fail-safe; AFTER suite **PASSED** including preserved BEFORE characterization (tombstones disabled). Log: `docs/security/evidence-G-PA-EVICT-01-AFTER.txt` |
| **REGRESSION** | Benign fresh `shell` still `allow`; empty sessions still preferred for eviction; observe mode reports `SESSION_CONTINUITY_BROKEN` without blocking; `test_pa_v101_security.py` + Scenario A pass |

### G-PA-MULTI-01

| State | Result |
|-------|--------|
| **BEFORE** | Cross-registry (simulated workers) miss escalates to allow on final hop |
| **AFTER** | `WEB_CONCURRENCY>1` + enforce → `MULTI_WORKER_UNSUPPORTED` + `require_approval` unless opt-in |
| **REGRESSION** | Observe mode does not block; explicit `VARDEN_PA_ALLOW_MULTI_WORKER=1` restores prior behaviour with residual risk |

## Scenarios exercised

| Phase | Scenarios (approx.) | Notes |
|-------|---------------------|-------|
| 0 Baseline | architecture/threat model | `GAUNTLET-BASELINE.md` |
| 1 Bypass | 6 poison metadata variants + explicit config | protected |
| 2 Eviction | 6 tests (BEFORE/AFTER/idle/observe/benign) | fixed |
| 3 Graph | 4 truncation/safety tests (+ existing BA–BC) | protected |
| 4 Coverage | 4 honesty tests | protected |
| 5 Filesystem | 3 containment tests (+ existing suite) | PARTIAL limitation |
| 6 Multi-worker | 4 tests | fail-safe |
| 7 Provenance | 2 chain tests | protected for PA path |
| 8 Negative controls | embedded in eviction/multi-worker | pass |

**Security gauntlet:** **91 tests passed** in the final run under
`tests/security/gauntlet/` (including G-SDK-MODE-01 enforcement-integrity coverage).

## Performance

No unbounded limit removal. Continuity tombstones capped at `2 * max_sessions`.
Graph stress tests reuse existing `build_stress_graph` workloads; p50/p95/p99 not
re-benchmarked in this pass beyond existing `test_pa_performance.py` /
`test_pa_bounded_traversal.py` guards. No remediation introduced unbounded retention.

## Test execution notes

- Gauntlet + `test_pa_v101_security.py` + Scenario A: executed and passing after fixes.
- Full Python suite (excluding browser/e2e): **791 passed** after RC ContinuityStore
  fault-injection hardening (lease atomicity, claim honesty, bind/attach degrade,
  approval integrity tests). Prior: 768 (durable ContinuityStore), 763 (policy
  vacuous PUT), 749 (G-SDK-MODE-01), 729 (demo import protect fix).
- Security gauntlet alone: **91 passed**.
- Package smoke (`tests/test_smoke.py`, `tests/test_clean_wheel_smoke.py`): **4 passed**.
- ContinuityStore lease renew micro-bench (local): ~0.6 ms/op avg; no unbounded growth.
- Playwright / browser / mutation testing: not executed in this pass; do not
  treat unexecuted checks as passing.
- BEFORE evidence for eviction was captured by failing AFTER-invariant tests on
  the original implementation, then re-running after the fix. The characterization
  test continues to reproduce pre-fix weakening by disabling tombstone recording.
- G-SDK-MODE-01 BEFORE characterization (`test_gauntlet_BEFORE_contextvar_swap_*`)
  is retained and asserts post-fix fail-safe (deny still raised).
- RC claim honesty evidence: `docs/security/evidence-RC-CONTINUITY-CLAIMS.txt`.

## Remaining limitations

See `GAUNTLET-ARCHITECTURE.md` and residual risks in `GAUNTLET-FINDINGS.md`:

- Full live-graph replay across restart/workers is **not** implemented;
  ContinuityStore provides fail-closed markers only
  (`cross_restart_continuity_verified` always false)
- Separate ContinuityStore DB paths do not coordinate worker leases
- Multi-worker env detection remains best-effort; shared-DB leases cover
  sibling processes on the same control-plane database
- Filesystem TOCTOU and unsupported surfaces remain PARTIAL / UNCOVERED
- Predictive Authority remains experimental in 1.0.x
- G-SDK-MODE-01: in-process monkeypatch / interpreter compromise remains an
  unsupported trust boundary (not claimed eliminated)
- G-COV-ATTEST-01 / G-PATCH-LIFE-01: pre-saved refs, foreign wrappers, native
  extensions remain uncovered by design
- G-POLICY-INT-01: authorized admin policy updates remain legitimate
- Disk-full / extreme SQLITE_BUSY under default 30s timeout: fail-safe once the
  operation errors; long busy waits are a liveness concern, not a silent-allow path
