# Changelog

## Unreleased

### Predictive Authority adversarial validation

- Clarified determinism: identical state/evidence/action/policy/bounds → identical
  reachability analysis (not prediction of agent behaviour)
- Hazardous reachability uses authority-relevant hop depth (defeats alias horizon camping)
- Property-scoped trusted declassification metadata; fake sanitisation remains rejected
- AQ/AR: clearing SECRET has operational effect without unrelated provenance false positives;
  retained provenance still fires provenance-sensitive hazards independently
- AS–AU: raw topological vs authority-relevant distance kept distinct (executable regression)
- AV/AW: positive hazard survives TRUNCATED; negative truncation never SAFE
- BA–BC: worst-case traversal benchmarks near `max_visits`; incomplete search never SAFE
- Propagate reachability visit-bound truncation into engine analysis status (fail-safe)
- Large-graph benchmarks report total nodes vs BFS visited + status honestly
- AX: loose order-of-magnitude CI performance smoke guards (separate from benchmarks)
- Enforce config default `failure_mode=require_approval` for truncated analysis
- Determinism + long-horizon adversarial suites (AA–AP)
- Docs: prediction contract, adversarial validation report; UI About + analysis bounds

### Predictive Authority hardening + UI

- First-class edge evidence model (`EvidenceKind` / lifecycle)
- Graph poisoning defence for untrusted MCP self-declarations
- Trusted sanitisation boundaries vs fake sanitisation claims
- Analysis status: complete / truncated / failed (never false-safe)
- Enforce-mode failure default: `require_approval`
- Capability confirm / disprove / revoke with cache invalidation
- Dashboard **Predictive** page (`/ui/predictive`) + `/predictive/*` APIs
- Scenarios P–Y and UI API tests

### Predictive Authority

- Session capability graph with confirmed vs potential capabilities
- Structural AuthorityDelta and bounded hazardous-path reachability
- Modes: `off` (default) / `observe` / `enforce` (strengthen-only)
- Optional authority budget derived from structural units
- CLI: `varden authority status|graph|paths|budget|demo` and `varden predictive …`
- Opt-in policy pack `predictive-authority`
- Docs: `docs/predictive-authority.md`

## v0.4.0

### Filesystem containment hardening

- Canonical / symlink-aware effective filesystem targets for policy decisions
- Path-component containment (no naïve string-prefix checks)
- Rename/replace evaluates source and destination independently
- Pre-use effective-target re-check narrows check/use gaps (TOCTOU not eliminated)
- Fail-closed behaviour on ambiguous security-sensitive path resolution
- Coverage remains truthful PARTIAL; residual TOCTOU documented

### Tamper-evident audit integrity

- Atomic hash-chained appends on the existing `events` store (`BEGIN IMMEDIATE` + rollback safety)
- Deterministic canonical event hashing (`hash_version` 1) with genesis value
- Single chained era after optional legacy prefix; unexpected unchained rows fail verify
- Policy fingerprint is order-stable for rules and excludes volatile config noise
- CLI: `varden audit verify` (exit 0 = PASS, non-zero = FAIL)
- Legacy NULL `event_hash` rows reported as unchained (not retroactively sealed)
- Verifier rejects malformed hashes and unsupported hash versions

### Runtime posture attestation

- Added `varden posture` and `varden posture --json`
- Varden now calculates an authoritative overall enforcement posture
- Separates attestation validity from coverage quality
- Reports structured enforcement gaps and available remediation
- MCP applicability: `NOT_ROUTED` only affects posture when MCP is discovered, required, or gateway-enforced
- Agent Security Skill now consumes Varden posture instead of deriving its own result

### Added — Varden Security Agent Skill

- Agent-native Varden installation and verification workflow (`skills/varden-security`)
- Explicit coverage-aware security posture reporting guidance
- MCP routing and verification guidance
- Provenance/authority inspection workflow
- Hard rules preventing agents from bypassing Varden decisions or fabricating approvals
- Packaged with Varden releases (`varden/skills/…` + root `skills/…`)
- CLI: `varden skill path`, `varden skill install --target <dir>`
- CLI: `varden runtime readiness --json` (machine-readable readiness)
- Note: `varden coverage --json` was already supported; the skill prefers `varden posture --json` when available
