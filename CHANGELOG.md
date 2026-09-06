# Changelog

## Unreleased

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
