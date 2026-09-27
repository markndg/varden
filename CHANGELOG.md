# Changelog

## Unreleased (v0.4.2)

### Security fixes

- **Demo admin key accepted in production.** `admin-demo-key` was minted on every start regardless of
  `VARDEN_ENABLE_DEV_BOOTSTRAP`; a prod deployment accepted it as admin. Demo keys and the bootstrap bearer
  token are now only minted in dev, and are revoked on any start with dev bootstrap disabled.
- **Signing key never rotated.** The auth DB kept signing/verifying bearer tokens with the secret it was first
  created with (often `change-me`). The configured `VARDEN_SIGNING_SECRET` is now always the only active key.
  Outside dev, placeholder or <32-char secrets are refused.
- **Control-plane guard bypass.** Requests whose URL merely *started with* the control-plane base URL skipped
  guarding, so `http://127.0.0.1:8000@evil.example/…` exfiltrated unguarded. Hostnames `test`/`testserver` were
  also exempt. The exemption now requires an exact scheme/host/port origin match and rejects userinfo.
- **Agents held admin credentials.** New ingest-only `agent` role. `/sdk/bootstrap` hands out the agent key;
  ingest endpoints accept it; nothing else does. `GET /auth/whoami`; the SDK warns (guarded) or refuses
  (strict, unless `allow_privileged_key=True`) when the protected process holds a human role.
- **Policy simulation leaked into live decisions.** `simulate_trace` swapped the shared engine's policy
  in place; concurrent `/sdk/guard` calls could be evaluated against the unpublished candidate.
- **`min_risk_score` was an equality check.** Now a threshold (`>=`).
- **`import varden_sdk` failed** when imported first (circular import). `varden` now resolves SDK symbols lazily.

### Policy engine

- `command` predicate: argv-aware matching (program, subcommand, flags, args) through sudo/env/nohup/xargs
  wrappers, `sh -c`/`eval`, pipelines, `;`/`&&`/`||` and `$(...)`. Argv-aware rules added to the destructive,
  baseline, host-shell and deployment packs.
- Strict validation: unknown fields, classifiers, operators and misspelled buckets are errors (with
  suggestions) instead of rules that silently never fire; startup logs problems in the loaded policy.
- `default` / `defaults` (per surface or action type) decisions for deny-by-default policies.
- Outside dev (or with `VARDEN_STRICT_POLICY=true`), a missing, unreadable or invalid policy file stops
  startup instead of logging a warning. `deploy/config/policy.json` ships the baseline pack.
- Docs are explicit that `command` rules are a guardrail; allowlists (`defaults` + `allow`) are the
  recommended enforcement pattern for subprocesses.
- Dashboard rules editor no longer drops `require_approval`, `sanitise`, `default` or `defaults` on save.
- `varden keys create|list|revoke` to provision API keys; `VARDEN_BOOTSTRAP_ADMIN_API_KEY` to seed one.
- Docs: `docs/policy-engine.md`.

## v0.4.1

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
