# Security Gauntlet — Findings

Branch: `harden/security-gauntlet`. Baseline commit: `9536e49`. Version: 1.0.1.

Status legend: **FIXED** | **PARTIALLY FIXED** | **DOCUMENTED LIMITATION** | **VERIFIED PROTECTED** | **RESIDUAL**

---

## G-PA-EVICT-01 — Session eviction confers greater effective authority

| Field | Detail |
|-------|--------|
| **Severity** | High (within PA `enforce` + stable `trace_id`) |
| **Before / after decision** | `shell`: `require_approval` → after LRU eviction without continuity: `allow` |
| **Attacker-controlled inputs** | Stable `trace_id`; session-cap pressure via many traces |
| **Preconditions** | PA enforce; accumulated untrusted→credential state |
| **Enforcement mode** | PA `enforce` |
| **Real side effect** | Would execute if base policy allows (`allow`) |
| **Root cause** | Eviction discarded live `AuthorityState` with no continuity signal |
| **Remediation** | Per-key tombstones + `continuity_broken` → `failure_mode` |
| **Residual bypass** | Completeness depends on ContinuityStore bind for durable forget paths |
| **Claims change** | Eviction is not a clean slate for accumulated sessions |
| **Status** | **FIXED** (with G-PA-EVICT-02) |
| **Evidence** | `test_pa_session_eviction.py`; `evidence-G-PA-EVICT-01-*.txt` |

---

## G-PA-EVICT-02 — Tombstone table exhaustion restores trust

| Field | Detail |
|-------|--------|
| **Severity** | High |
| **Before / after decision** | With degradation disabled: forgotten tombstone → `allow`. With fix: `require_approval` via `TOMBSTONE_HISTORY_INCOMPLETE` |
| **Attacker-controlled inputs** | Session identity reuse; flood of accumulated-authority sessions |
| **Preconditions** | PA enforce; tombstone cap `2×max_sessions` |
| **Enforcement mode** | PA `enforce` |
| **Real side effect** | BEFORE: yes on allow. AFTER: held by `failure_mode` |
| **Root cause** | Bounded process-local maps cannot distinguish new keys from forgotten tombstones |
| **Remediation** | Process-wide `continuity_degraded` on any tombstone drop; durable `ContinuityStore` also persists tombstones + degrade flag in SQLite so memory forget cannot restore trust |
| **Residual bypass** | Processes without a bound ContinuityStore (unit engines); operator `reset()` clears degrade intentionally |
| **Claims change** | Eviction continuity is fail-safe (not full authority replay) under churn |
| **Status** | **FIXED** (fail-safe; durable when CP DB bound) |
| **Evidence** | `test_continuity_gate.py`; `test_pa_durable_continuity.py` |

---

## G-PA-MULTI-01 — Multi-worker / undeclared topology

| Field | Detail |
|-------|--------|
| **Severity** | High for multi-process enforce |
| **Before / after decision** | Split registries: escalate → `allow` on final hop. Detected multi / undeclared: fail-safe |
| **Attacker-controlled inputs** | Same `trace_id` across processes; optional omission of worker env vars |
| **Preconditions** | PA enforce; ≥2 OS processes |
| **Enforcement mode** | PA `enforce` |
| **Real side effect** | On architectural miss with declared single_worker per process: yes (`allow`) |
| **Root cause** | Process-local state; env detection ≠ topology verification |
| **Remediation** | Require `VARDEN_PA_DEPLOYMENT=single_worker`; undeclared/`WEB_CONCURRENCY>1` fail-safe |
| **Residual bypass** | Sibling processes each declaring `single_worker` still miss chains (proven) |
| **Claims change** | Opt-in ≠ verified shared state; in-process library can only vouch for this process |
| **Status** | **PARTIALLY FIXED** |
| **Evidence** | `test_pa_multi_worker.py`, `test_continuity_gate.py` |

---

## G-PA-BYPASS-01 — Agent metadata enforcement override (1.0.1 regression)

| Field | Detail |
|-------|--------|
| **Severity** | Critical if regressed |
| **Status** | **VERIFIED PROTECTED** |
| **Evidence** | `test_pa_v101_security.py`, `tests/security/gauntlet/test_enforcement_bypass.py` |
| **Notes** | `resolve_config` ignores `action`; alternate nested poison keys do not downgrade enforce |

---

## G-PA-GRAPH-01 — Truncated analysis claimed safe

| Field | Detail |
|-------|--------|
| **Status** | **VERIFIED PROTECTED** |
| **Evidence** | `test_pa_bounded_traversal.py`, `tests/security/gauntlet/test_pa_graph_exhaustion.py` |
| **Notes** | `safe_conclusion` is false when truncated / hazard not observed within budget |

---

## G-COV-01 — PARTIAL satisfying require_coverage

| Field | Detail |
|-------|--------|
| **Status** | **VERIFIED PROTECTED** |
| **Evidence** | `tests/runtime/test_rc_hardening.py`, gauntlet `test_coverage_honesty.py` |

---

## G-FS-01 — Filesystem containment / TOCTOU

| Field | Detail |
|-------|--------|
| **Status** | **PARTIALLY MITIGATED** / **DOCUMENTED LIMITATION** |
| **Evidence** | Symlink/traversal tests pass for intercepted APIs; TOCTOU not eliminated (`docs/runtime-filesystem-containment.md`) |
| **Remediation** | No unsafe claim of race freedom; coverage remains PARTIAL |

---

## G-PA-RESTART-01 — Process restart loses continuity

| Field | Detail |
|-------|--------|
| **Severity** | High for long-lived identities across CP restarts |
| **Before / after decision** | WITHOUT ContinuityStore: post-restart same trace → `allow`. WITH ContinuityStore (create_app binds CP DB): post-restart reintroduction → `SESSION_CONTINUITY_BROKEN` + `failure_mode` |
| **Attacker-controlled inputs** | Reused `trace_id` / session identity after restart |
| **Preconditions** | PA enforce; process exit/restart |
| **Enforcement mode** | PA `enforce` |
| **Real side effect** | BEFORE/unbound: yes on allow. AFTER/bound: held by fail-safe |
| **Root cause** | Empty post-restart live registry ≡ first boot without durable markers |
| **Remediation** | `ContinuityStore` persists `had_authority` / tombstones; new process_id recreating a prior-authority key marks `continuity_broken`. Continuity/topology incomplete reasons force ≥ `require_approval` even when `failure_mode=preserve_existing`. Full live-graph replay across restart is **not** implemented |
| **Residual bypass** | Engines without ContinuityStore; brand-new session keys remain allow (benign) |
| **Claims change** | Claim fail-safe reintroduction when CP DB bound — not verified full authority continuity / graph reload |
| **Status** | **FIXED** (fail-safe with durable store); graph replay remains out of scope |
| **Evidence** | `test_pa_durable_continuity.py`; unbound characterization retained in `test_continuity_gate.py` |

---

## G-SDK-MODE-01 — Live guard weaken after mode lock

| Field | Detail |
|-------|--------|
| **Severity** | High (in-process) |
| **Exploitability** | Code in the protected process that can call `protect()`/`activate()` again, swap `ContextVar`, mutate the guard object, or reset the coverage registry |
| **Affected code** | `varden_sdk/sdk.py` `VardenGuard.activate` / `_live_enforcing` / `unpatch_runtime`; `varden_sdk/patches.py` `_enforcing` / `_fail_closed`; `varden/runtime/coverage.py` `set_session` / `reset` / `enforcement_contract` |
| **Reproduction** | `tests/security/gauntlet/test_sdk_mode_lock.py` (BEFORE characterization + integrity suite) |
| **Expected** | After successful `protect()`, live deny side effects cannot become observational while attestation still claims guarded/strict; unsuccessful activation cannot replace/weaken/detach an existing enforcing guard |
| **Actual (BEFORE)** | `activate()` set `_current_guard` before lock check; second `protect(observe)` swapped the live guard; `product_mode` mutation / ContextVar poison weakened interceptors; `reg.reset()` cleared the lock while patches remained |
| **Authoritative config** | Locked `CoverageRegistry.enforcement_contract()` (`mode`, `fail_mode`, `require_coverage`, `allow_uncovered`, `mode_locked`) — single process-local source of truth. No redundant public mode API added. |
| **Remediation** | Full-contract lock check before ContextVar install; activate rollback on failed first activation; refuse `reset()` while locked unless `release_enforcement_lock=True` (unpatch only); refuse allow_uncovered expansion; `_live_enforcing` / patch helpers prefer locked contract over guard attrs |
| **Integrity audit** | Repeated/nested/failed/async/concurrent `protect`/`activate`; stale/copied ContextVar; existing guard refs; registry reset; surface mark / interceptor-check mutation; attestation vs live deny; guarded/strict and fail-open/fail-closed; benign observe; deterministic BEFORE reproducer retained |
| **Residual gaps** | In-process restoration of originals still bypasses monkeypatches until reconcile/`protect` re-entry (attestation then refuses ENFORCED). Arbitrary malicious code in the same interpreter remains out of scope. Control-plane policy content remains mutable by authorized admins by design. |
| **Status** | **FIXED** (integrity gate) |
| **Claims** | Do not claim that freezing `product_mode` alone closes this class; claim locked enforcement contract + refuse weaker activation + denied side effect still blocked |

---

## G-COV-ATTEST-01 — False ENFORCED via mark / poisoned interceptor probe

| Field | Detail |
|-------|--------|
| **Severity** | High (attestation honesty) |
| **Exploitability** | In-process code that restores originals then calls `reg.mark(ENFORCED)` and/or replaces interceptor checks with `lambda: True` |
| **Affected code** | `varden/runtime/coverage.py` `mark` / `register_interceptor_check` / `verify` / `install_interceptor` |
| **Reproduction** | `tests/security/gauntlet/test_coverage_attestation.py`; evidence `docs/security/evidence-G-COV-ATTEST-01.txt` |
| **Actual (BEFORE)** | After restoring `Session.request`, poison mark+check made attestation report `ENFORCED` while interception was absent (`FALSE_ENFORCED True`) |
| **Remediation** | Sealed interceptor probes; `install_interceptor()` is the only post-lock ENFORCED path; refuse sealed-check replacement; surface fields `installed` / `verified`; attestation/`missing_required` require live verification under lock |
| **Status** | **FIXED** |
| **Residual** | Does not stop malicious code from calling originals directly; only prevents false **attestation** of ENFORCED |

---

## G-PATCH-LIFE-01 — Third-party restore / foreign wrap lifecycle

| Field | Detail |
|-------|--------|
| **Severity** | Medium (coverage honesty + optional loss of http interception) |
| **Affected code** | `varden_sdk/sdk.py` `_WRAPPERS` / `_reconcile_or_install` |
| **Remediation** | Identity-based probes; one-shot re-wrap when target equals stored original; do not fight foreign wrappers (no repatch loops); attestation drops ENFORCED when probe fails |
| **Status** | **FIXED** (within in-process monkeypatch limits) |
| **Residual** | Pre-saved function references, native extensions, and arbitrary interpreter compromise remain unsupported trust boundaries |

---

## G-POLICY-INT-01 — Policy snapshot / alias mutation

| Field | Detail |
|-------|--------|
| **Severity** | Medium–High (in-process / concurrent / admin footgun) |
| **Affected code** | `varden/policy.py` `get_policy` / `update_policy` / `validate(for_publish=)` / `evaluate`; `app_factory` PUT/import/publish |
| **Actual (BEFORE)** | `get_policy()` returned the live dict alias; callers could clear `block` in-place. Concurrent update could skew evaluate vs budget/PA. Vacuous `{}` / empty buckets PUT became silent allow-all. Memory updated before durable file write |
| **Remediation** | Deep-copy store; one snapshot per `evaluate_action`; publish validation refuses missing core buckets and vacuous allow-all unless `allow_vacuous_policy=true` (or deny-by-default); durable file write before memory swap on PUT/import/publish; agent `PUT /policy` remains 403 |
| **Status** | **FIXED** |
| **Residual** | Authorized admin may still weaken policy (legitimate). No file hot-reload (API is live source of truth). MCP wired with an admin key can still PUT (credential wiring). Bootstrap may disclose default policy (recon) |

---

## G-DEMO-IMPORT-01 — Demo import-time `protect()`

| Field | Detail |
|-------|--------|
| **Status** | **FIXED** |
| **Impact** | Importing demo agents activated process-local httpx patches and broke Starlette `TestClient` for later tests |
| **Remediation** | Call `varden.protect()` inside `run()` in demo agents |

---

## RC-CONT-01 — False cross-restart continuity claim when store bound

| Field | Detail |
|-------|--------|
| **Severity** | Medium (attestation / operator honesty) |
| **Before / after** | `cross_restart_continuity_verified=True` whenever ContinuityStore bound → always `False` |
| **Root cause** | Bound fail-safe store conflated with verified graph continuity |
| **Remediation** | Status/stats always report `False`; scope string distinguishes durable fail-safe |
| **Status** | **FIXED** |
| **Evidence** | `evidence-RC-CONTINUITY-CLAIMS.txt`; `test_rc_continuity_faults.py` |

---

## RC-CONT-02 — Lease query failure → temporary single-worker allow

| Field | Detail |
|-------|--------|
| **Severity** | High (within PA enforce + shared DB) |
| **Before / after** | `active_worker_count()` returned `None` on failure (topology skip) → degrade + return `2` |
| **Root cause** | Exception swallowed without degrade / conservative count |
| **Remediation** | `CONTINUITY_STORE_LEASE_FAILED` + conservative multi-worker path; atomic `touch_lease_and_count` (`BEGIN IMMEDIATE`) |
| **Status** | **FIXED** |
| **Evidence** | `test_rc_lease_failure_returns_conservative_worker_count`; concurrent lease race test |

---

## RC-CONT-03 — Attach/bind failures left process undegraded

| Field | Detail |
|-------|--------|
| **Severity** | High |
| **Before / after** | Read-only / corrupt / missing-parent bind could leave enforce without durable fail-safe → `CONTINUITY_STORE_ATTACH_FAILED` / `BIND_FAILED` degrade |
| **Remediation** | `probe()` on attach; `configure_authority_registry` + `create_app` degrade on bind failure |
| **Status** | **FIXED** |
| **Evidence** | `test_rc_readonly_db_attach_degrades_not_crash`; `test_rc_startup_bind_failure_degrades_process` |

---

## Findings table (summary)

| ID | Area | Exploitable? | Evidence | Fix | Regression | Residual risk |
|----|------|--------------|----------|-----|------------|---------------|
| G-PA-EVICT-01 | PA session continuity | Yes | BEFORE/AFTER + tests | Per-key tombstones | pass | Completes only with EVICT-02 |
| G-PA-EVICT-02 | Tombstone exhaustion | Yes | continuity gate + durable tests | Process + durable `continuity_degraded` / tombstones | pass | Operator reset clears |
| G-PA-MULTI-01 | Multi-worker / undeclared | Yes if multi-process | split + lease tests | Declare/env + **DB worker leases** | pass | Separate DBs still miss |
| G-PA-RESTART-01 | Restart continuity | Yes without store | durable recreate tests | ContinuityStore fail-safe on reintroduction | pass | No full graph replay |
| G-PA-BYPASS-01 | Config trust boundary | No (post-1.0.1) | Parametrized poison tests | Already fixed in 1.0.1 | gauntlet | — |
| G-PA-GRAPH-01 | Graph exhaustion | No (honest truncation) | Stress graphs | Existing | gauntlet | Bounds still truncate |
| G-COV-01 | Coverage honesty | No | require_coverage tests | Existing RC | gauntlet | Unsupported surfaces |
| G-COV-ATTEST-01 | False ENFORCED attestation | Yes (in-process) | evidence + `test_coverage_attestation.py` | Sealed probes + install_interceptor | pass | Direct original calls |
| G-PATCH-LIFE-01 | Monkeypatch lifecycle | Yes (restore) | gauntlet lifecycle tests | Reconcile once; no foreign fight | pass | Pre-saved refs / native code |
| G-POLICY-INT-01 | Policy snapshot integrity | Yes (alias/concurrent) | `test_policy_integrity.py` | Deepcopy + coherent snapshot | pass | Admin updates by design |
| G-FS-01 | Filesystem | Partial | Containment tests | PARTIAL attestation | gauntlet | TOCTOU / unpatched APIs |
| G-DEMO-IMPORT-01 | Demo import protect() | Suite pollution (not remote exploit) | Import broke TestClient | protect() moved into run() | full suite | Script-as-main still protects |
| G-SDK-MODE-01 | Live guard after mode lock | Yes (in-process) | ContextVar swap / second protect / reset / setattr / concurrent | Locked `enforcement_contract()` + activate rollback + reset refuse | gauntlet `test_sdk_mode_lock.py` | In-process interpreter compromise |
| RC-CONT-01 | False continuity claim | Attestation lie | evidence-RC-CONTINUITY-CLAIMS | Always `verified=False` | pass | — |
| RC-CONT-02 | Lease fail → allow | Yes (topology skip) | RC fault tests | Degrade + count≥2 + IMMEDIATE | pass | Separate DBs |
| RC-CONT-03 | Bind/attach undegraded | Yes | RC readonly/corrupt/startup | Probe + bind degrade | pass | Disk-full liveness |
