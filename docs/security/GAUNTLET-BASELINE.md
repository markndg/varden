# Security Gauntlet — Baseline

**Branch:** `harden/security-gauntlet`  
**Baseline commit:** `9536e49f0921126d68da475f10901feb1cdf74fc`  
**Package version:** `1.0.1` (`pyproject.toml`)  
**Date:** 2026-10-02  
**OS / Python:** darwin 25.6.0 / CPython 3.13.13  

## Purpose

Adversarial validation of Varden's security guarantees with prove-before-fix
discipline. This document records the pre-remediation architecture, threat
model, and coverage matrix. Findings and remediations are in
[`GAUNTLET-FINDINGS.md`](GAUNTLET-FINDINGS.md) and
[`GAUNTLET-RESULTS.md`](GAUNTLET-RESULTS.md).

## Execution architecture (traced)

| Path | In-process | Gateway | Control plane | Monitor-only |
|------|------------|---------|---------------|--------------|
| `varden.protect()` interceptor install | yes | — | — | observe mode |
| HTTP (`requests`/`httpx`/`urllib`) | yes | — | policy via guard | observe |
| Filesystem patched APIs | yes (PARTIAL) | — | policy | observe |
| Subprocess patched APIs | yes | — | policy | observe |
| MCP tools | — | gateway wrap | policy | — |
| Provenance capture | yes | — | persist | — |
| Predictive Authority | process-local registry | — | evaluate path | observe vs enforce |
| Approvals | — | — | durable | — |
| Coverage / readiness / posture | process-local | — | attestation | reporting |

Primary sources:

- Interceptors / protect: `varden/runtime/` (coverage in `coverage.py`)
- Control-plane evaluate + PA hook: `varden/app_factory.py` (~L671)
- PA engine: `varden/predictive_authority/engine.py`
- PA registry: `varden/predictive_authority/registry.py`
- Policy: `varden/policy.py`
- Filesystem: `varden/runtime/filesystem.py`

## Security-relevant mutable state

| Object | Owner | Lifetime | Persistence | Trust boundary |
|--------|-------|----------|-------------|----------------|
| `AuthorityRegistry` / `AuthorityState` | control-plane process | until eviction / idle / reset | memory only (+ durable PA snapshots in DB) | operator process; not agent-writable config |
| Continuity tombstones | same registry | bounded (`2 * max_sessions`) | memory only | process-local |
| `CoverageRegistry` | agent process after `protect()` | until reset / unpatch | memory | local runtime |
| Policy document | operator | reload | file / config | operator-controlled |
| Approvals | control plane | until consumed | DB | authenticated API |
| Audit chain | control plane | append-only | DB | integrity not confidentiality |
| Session / API credentials | auth DB | key lifetime | DB | not agent-controlled |

## Attacker-controlled inputs (in threat model)

- Agent prompts / tool arguments / tool results
- Untrusted documents and webpages (provenance sources)
- MCP metadata and responses (via gateway)
- Session / trace identifiers supplied on actions (namespacing matters)
- Filesystem contents under attacker-influenced paths inside the agent environment
- Timing / concurrency / session-cap pressure

**Out of model unless a path is demonstrated:** rewriting operator policy files,
forging control-plane API credentials, altering `VARDEN_PA_*` in the control-plane
process environment from the agent.

## Known 1.0.1 fixes already in baseline

Documented in `CHANGELOG.md` / `docs/predictive-authority.md`:

- Agent metadata cannot supply PA config (`resolve_config` ignores `action`)
- Tenant from credential, not payload
- Demo registry isolated from live PA state
- PA read endpoints tenant-scoped
- Session registry bounded with preferential eviction

## Pre-gauntlet baseline tests

Full Python suite was previously green aside from environment-dependent Playwright
failures. Gauntlet work records focused suites under `tests/security/gauntlet/`.

## Coverage matrix (initial)

| Attack class | Status | Evidence / notes |
|--------------|--------|------------------|
| Agent disables PA enforce via metadata | VERIFIED PROTECTED | `tests/predictive_authority/test_pa_v101_security.py`; gauntlet `test_enforcement_bypass.py` |
| Tenant spoof on `/sdk/guard` | VERIFIED PROTECTED | `test_pa_v101_security.py` |
| Demo wipes live PA state | VERIFIED PROTECTED | `test_pa_v101_security.py` |
| PA session eviction → weaker authority | **VERIFIED VULNERABLE** (baseline) | See findings G-PA-EVICT-01; BEFORE evidence preserved |
| Multi-worker PA chain miss | **PARTIALLY MITIGATED** → fail-safe added | Documented limitation; unsupported enforce now fail-safes |
| Process restart loses PA state | DOCUMENTED LIMITATION | No durable continuity tombstones across restart |
| Graph truncation claims safety | VERIFIED PROTECTED | `test_pa_bounded_traversal.py`; gauntlet graph tests |
| `PARTIAL` counted as `ENFORCED` for require_coverage | VERIFIED PROTECTED | `tests/runtime/test_rc_hardening.py`; gauntlet coverage tests |
| Raw sockets / native / saved refs | DOCUMENTED LIMITATION | `docs/runtime-limitations.md` |
| Filesystem TOCTOU elimination | PARTIALLY MITIGATED | Canonical + re-check; PARTIAL attested |
| Symlink / traversal escape (intercepted) | VERIFIED PROTECTED | `tests/runtime/test_filesystem_containment.py` |
| Observe mode claims enforcement | VERIFIED PROTECTED | posture / mode semantics |
| Arbitrary Python execution total mediation | NOT APPLICABLE | Architecture cannot guarantee |
| Cross-boundary provenance laundering | UNVERIFIED → exercised in gauntlet Phase 7 | See findings |
| Clipboard / OS sandbox bypass | NOT APPLICABLE | Out of product scope |

## Security invariants under test

1. Untrusted agent input must not change effective enforcement configuration.
2. Loss of monitoring state must not silently confer greater effective authority.
3. Incomplete analysis must never be silently represented as proof of safety.
4. Coverage must not report ENFORCED when a known relevant path bypasses enforcement.
5. Supported deployments must not silently enforce on incomplete authority history.
