# Changelog

## Unreleased

### Threat Intelligence

- Added an advisory Threat Intelligence subsystem. It is disabled unless `VARDEN_TI_ENABLED=true` and is not on the firewall decision path.

- External records normalise into threat items, then into versioned security contracts. Contracts are not rules.

- Applicability is `PROTECTED`, `EXPOSED`, `NOT_APPLICABLE`, or `REVIEW`. Partial or unrouted coverage is never reported as protected.

- Candidate rules use Varden's existing policy language and stay inactive until an operator approves them.

- MITRE ATLAS (pinned STIX JSON), NVD CVE API 2.0, and the CWE XML catalog are implemented. OWASP agentic material stays a scaffold unless an operator pins a versioned `owasp-agentic-v1` JSON document. HTML and PDF are not scraped.

- Approval rebuilds the rule from the Varden template and refuses a stored candidate whose predicates, contract, coverage assumptions, or displayed content hash no longer match. A stored `PROTECTED` result is rechecked against the live policy.

- The threat intelligence workspace separates mapped contracts from unmapped records and from runtime protection. Unmapped identifiers stay in review with the stored reason. A healthy watcher is not shown as protection.

## 1.1.0  — Security hardening pass 2 + UI refinement + threat intelligence

Security hardening pass 2 (Phases 1–4) has been merged into main. See docs/security-hardening-pass-2.md for scope and residual limitations.

### Phase 2 — Decision correctness

- Security decisions use one server-bound action identity. Caller domain, surface, and a forged `metadata.identity` do not select the decision. The original values stay on the event for audit.

- HTTP destinations are canonicalized once for policy and for the socket. Userinfo, percent-encoded hosts, ambiguous IP literals, and IPv4-mapped IPv6 are rejected. The original URL is retained.

- MCP methods outside the explicit discovery set require a guard decision before they are forwarded. Discovery still proceeds without one. Direct MCP connections stay `NOT_ROUTED`.

- Cloud metadata destinations are classified as `metadata`. Loopback, private, and generic link-local addresses are not globally blocked. Phase 4 adds socket-level destination binding for supported requests, httpx and urllib transports; unsupported transports, proxies and custom network backends remain outside that binding guarantee.

- An unrecognized action type is `unsupported` unless an explicit rule matches. A malformed type is `unsupported`. `fail_mode=open` does not turn that decision, or an explicit deny, into execution.

- Redirect hops are authorized again before the next connection.

- Malformed URL authorities, including unmatched IPv6 brackets, return a rejection code. They do not escape as parser exceptions, and they do not connect when `fail_mode=open`.

- Valid Unicode DNS names are encoded to ASCII A-labels before hostname checks. Names that do not round-trip, including `ß` mapped to `ss`, are rejected.

- MCP discovery and notification methods are an exact allowlist disjoint from `tools/call`, `resources/read`, and `prompts/get`. Nested params are not a second privileged call.

Custom action types that relied on the implicit allow now need an explicit matching rule.

### Phase 1 — Critical containment

### Predictive snapshots

New Predictive Authority snapshots use the shared redactor and schema version 2. `content_hash` is the SHA-256 of the canonical bytes that are stored. Older snapshots still verify. Plaintext in those rows is withheld from APIs. Replacing one records the original hash; it does not wipe SQLite free pages.

### Budget reservations

Token reservations are a ledger separate from the daily and monthly counters. A window reset does not drop an unreported hold. The hold stays on the window that created it, and the deadline charges that estimate if no verified usage arrives. Client `blocked` or `failed` reports do not cancel it.

Reconciliation of a usage report is one SQLite transaction across every applicable rule. A failure rolls back, so the same guard event can be reported again without a second charge. Session caps are per authenticated principal. Daily and monthly caps are per authenticated tenant. Omitting or rotating a client trace or workflow id does not skip or reset a hard cap. Schema 14 adds those identities to the counters. Older rows keep a null tenant and are not reassigned.

Each guard decision now stores server-owned `budget_evidence` on the audit event, and the reservation stores the rule snapshot used for the estimate. Usage is reconciled from that evidence. Deleting, disabling, or repricing a rule afterwards does not change the hold. A rule added later does not apply to a guard that was recorded as unbudgeted. A missing reservation that the evidence says should exist is `accounting_integrity_failure` (HTTP 409) and is recorded in `token_budget_accounting_findings` (schema 15). It is not reported as successful accounting. A guard with no applicable rule is `legitimately_unbudgeted`. A historical guard with no evidence is `legacy_evidence_insufficient` and is not backfilled. `/sdk/log` returns `accounting_status` next to `usage_accounted`. An SDK that omits `guard_event_id` stays an unverified observation and is not charged. `log_result` returns a 409 integrity body instead of raising, so the model call is not repeated.

Critical containment. Not tagged or published.

### P0-7 — Unauthenticated disclosure

- `GET /health` returns `{"status":"ok"}`. Operational detail is on `GET /health/detail` and requires a viewer credential. It does not return keys or signing material.

- `GET /sdk/bootstrap` no longer returns the policy. Development credentials are returned only for an explicit dev bootstrap on a loopback connection. `X-Forwarded-For` is ignored unless `VARDEN_TRUSTED_PROXY_HOSTS` lists the direct peer.

- Process startup (`AppConfig.from_env`) defaults to `VARDEN_ENV=production` with dev bootstrap off. Local development sets `VARDEN_ENV=dev` and `VARDEN_ENABLE_DEV_BOOTSTRAP=true`.

- Dev mode refuses a non-loopback bind unless `VARDEN_UNSAFE_DEV_BIND=true`. That override does not enable unauthenticated credential disclosure.

- `/docs`, `/redoc` and `/openapi.json` are off outside development unless `VARDEN_ENABLE_API_DOCS=true`.

### Upgrade

```text

VARDEN_ENV=dev

VARDEN_ENABLE_DEV_BOOTSTRAP=true

```

Leave both unset on a production host. Create the first operator key with `varden keys create` or `VARDEN_BOOTSTRAP_ADMIN_API_KEY`.

### P0-6 — Server-owned audit decisions

- `POST /sdk/log` no longer stores a client-supplied decision, matched rule, approval or coverage claim as if the control plane had produced it.

- A log is an authoritative execution report only when it names a guard `event_id` for the same tenant, the same credential, and the same action fingerprint. The stored decision is the one the server recorded at `/sdk/guard`. Anything else is an `unverified_observation`.

- Client `status=blocked` no longer skips token-budget accounting. A repeated report for the same guard event is not charged twice. Omitting the report leaves a ledger reservation. A daily or monthly reset does not delete it; the deadline charges the estimate to the window that created it.

- An older SDK that logs without `guard_event_id` is accepted only as an unverified observation. It cannot create an allow, a block, an approval, or enforced coverage.

### P0-5 — Session fail-closed contracts

- `varden session` set `VARDEN_FAIL_MODE=closed` while the shim read `VARDEN_MONITOR_FAIL_MODE`, which defaulted to `open`. A guarded command ran when the control plane was down.

- Guarded and strict shims now execute only after a signed session contract verifies and the control plane confirms it. A missing, expired, mismatched or altered contract does not run the command. Environment variables cannot downgrade the contract mode or fail mode.

- Observe mode, when that is the mode in the signed contract, still runs if the control plane is down.

- The contract file is not an OS sandbox. The verification key is in the child environment. The same user can replace that key and the contract, point the shim at another confirm URL, skip the shim, or run the real binary. Subprocess coverage stays short of `ENFORCED`.

### P0-3 — Provenance authority

- Client-supplied provenance can no longer assert `internal`, `trusted`, `delegated` or any other privileged trust level. Those claims are recorded as `unknown` with `forged_trust_claim`. `unknown`, `untrusted` and `hostile` stay distinct.

- `provenance_complete` is computed by the server. A client flag cannot mark a source complete.

- `POST /runtime/session/provenance` requires a `gateway` credential. An agent credential receives 403. A gateway that asserts privileged trust also receives 403. Continuity posts from the MCP gateway and host use `VARDEN_GATEWAY_API_KEY` and are skipped when that key is absent.

### P0-1 — Secret redaction

- `redact()` now replaces secret ****values**** in nested objects. The previous implementation renamed keys such as `password` to `[REDACTED]` and left the value in place.

- Markers look like `[REDACTED:authorization:3f9a]`. The suffix is an HMAC under a purpose-separated key, scoped by tenant, so it is not a truncated hash of the secret.

- Guard decisions are still made on the unredacted in-memory action. The stored event, its hash-chain preimage, `/events`, event detail, traces and the SSE payload are the redacted copy.

- The SDK no longer sends HTTP authentication objects, cookie objects or raw header secrets to the control plane. It sends `credential_signals` (field names only). Subprocess interception sends `env_keys` and `env_changed`, not environment values.

- `varden audit redact-migrate` rewrites historical logical rows, rebuilds the hash chain, and writes a signed manifest linking the previous chain head to the replacement head. A failure before commit rolls back. A second run does not move the chain head again. SQLite WAL files, rollback journals, free pages, backups and snapshots can still hold the old plaintext. The command does not securely erase that data. The operator steps are in `docs/security-hardening-pass-2.md`.

## v1.0.3

Security patch on top of 1.0.2. This fix is ****not**** in the published `v1.0.2` tag.

### Security fixes

- ****A delivered deny could still run the tool.**** The SDK and MCP gateway treated a guard response as a transport failure unless the status was HTTP 403 and `decision.action` was exactly `block` or `require_approval`. Reproduced on tags `v1.0.0`, `v1.0.1` and `v1.0.2`: HTTP 200 with `approval_required` executed the protected callable under `fail_mode=closed`, and a 503 body carrying `require_approval` executed it under `fail_mode=open`. Deny decisions are now read only from `decision.action` and `decision.effective_action` on the guard decision object (or that object inside one FastAPI `detail` wrapper). HTTP 403 always denies. A decision slot that is present but not a recognized policy action is not treated as allow. Echoed agent JSON under `args` or `metadata` is not a policy decision. `fail_mode=open` still proceeds when no decision was delivered (disconnect, timeout, unexpected error, or a body with no decision slot). `observe` still records a deny and does not prevent the side effect. `allow`, `warn`, `monitor` and `sanitise` still execute.

- ****An unreadable enforcement contract could fall through to mutable guard state.**** If `enforcement_contract()` raises, interceptors now fail closed instead of consulting `product_mode` / `fail_mode` on the guard object.

## v1.0.2

Security release. ****Upgrade if you run Predictive Authority in**** `enforce` ****mode.****

### Security fixes

- ****Agents could disable Predictive Authority enforcement.**** 1.0.0 read PA configuration from

`action.metadata.predictive_authority_config`, which the protected agent writes, and let it

override the operator's settings. Sending `{"mode": "off"}` turned operator-enabled enforcement

off for that agent's actions. Configuration now comes only from the policy file and

environment. Client-supplied `predictive_authority*` metadata is stripped at ingest.

- ****Action tenant came from the client payload.**** `/sdk/guard` and `/sdk/log` now always use the

credential's tenant.

- ****A viewer could wipe live Predictive Authority state.**** `POST /predictive/demo` reset the

process-wide session registry, discarding every agent's accumulated authority. The demo now

runs in an isolated store.

- ****PA read endpoints honoured any**** `tenant_id` ****query parameter.**** They are now scoped to the

caller's tenant, plus the isolated `demo` tenant.

- ****PA session eviction could weaken enforce decisions.**** Evicting or idle-expiring a session

that had accumulated authority discarded the graph and restarted the same session key from a

clean slate. Eviction of accumulated authority now records a bounded continuity tombstone;

recreate marks `continuity_broken` and enforce applies `failure_mode`.

- ****Tombstone-table exhaustion could restore trust.**** Forgetting a tombstone under the

`2×max_sessions` cap made a reintroduced session key look brand-new (`allow`). Any tombstone

drop now sets process-wide `continuity_degraded` (`TOMBSTONE_HISTORY_INCOMPLETE`) so enforce

fails safe for the process lifetime until operator registry reset. Bounded process-local

state cannot distinguish new keys from forgotten ones.

- ****Multi-worker / undeclared topology.**** Live state is process-local. Enforce requires

`VARDEN_PA_DEPLOYMENT=single_worker` (undeclared → `DEPLOYMENT_UNDECLARED` fail-safe).

Detected worker env > 1 without allow → `MULTI_WORKER_UNSUPPORTED`. Opt-in accepts residual

risk only; sibling processes that each declare single_worker can still miss chains.

- ****Cross-restart continuity is unsupported.**** Claims report

`cross_restart_continuity_verified=false` / `continuity_scope=process_lifetime_only`.

### Fixes

- ****Unbounded memory growth with PA enabled.**** The live session registry never evicted

(\~15 KB per trace id, and the SDK mints one per untraced action). Now bounded by

`VARDEN_PA_MAX_SESSIONS` and `VARDEN_PA_SESSION_IDLE_SECONDS`, with eviction that

preserves sessions carrying accumulated authority.

- ****Web Shield**** `sanitise` ****was recorded as "side effect prevented".**** A sanitised output still

reaches the agent in modified form. It is now recorded as intercepted and sanitised, not

prevented. `require_approval` is unchanged (held, not executed, matching `/sdk/guard`).

- ****Demo agent imports activated**** `varden.protect()`****.**** Importing demo modules for metadata

tests patched process-local `httpx` and broke Starlette `TestClient` for later tests in the

same process. `protect()` now runs inside `run()`.

- ****Live guard could weaken after mode lock.**** `activate()` set `_current_guard` before the

coverage registry lock check, so a second `protect(mode="observe")` swapped the live guard

even when `set_session` refused the downgrade; mutating `product_mode` had the same effect

on interceptors. Lock is checked first, locked mode attributes are immutable, and

interceptors treat the locked registry mode as authoritative.

### Docs

- Predictive Authority is labelled experimental in 1.0.x. There is guidance on sizing the

session cap and on running a single control-plane worker when PA is enabled.

- Security gauntlet baseline/findings/results under `docs/security/GAUNTLET-*.md`.

## v1.0.0

Varden 1.0 establishes the first production/stable release of Varden's runtime security model for AI agents.

This release brings together pre-execution policy enforcement, verifiable runtime posture, provenance-aware authority controls, Predictive Authority, Web Shield integration, hardened production authentication, strict policy validation and tamper-evident audit evidence.

Predictive Authority extends Varden beyond deciding whether an individual action is allowed: Varden can deterministically analyse what authority and sensitive resources become reachable if an action is permitted, and strengthen the existing security decision before the side effect occurs.

### Predictive Authority

- Added deterministic, evidence-backed authority reachability analysis.

- Predictive Authority runs after normal policy evaluation and before audit; it is not a second policy engine.

- Supports `observe` and `enforce` operation.

- `observe` records recommendations without changing the existing policy decision.

- `enforce` may strengthen an existing decision but never weaken it.

- Sequential `AuthorityState` accumulation detects hazardous trajectories as prerequisite authority becomes reachable.

- Added bounded graph analysis with independent node, edge, path, depth and visit limits.

- Incomplete analysis is never interpreted as safe.

- Hazardous paths found during bounded analysis remain valid even when the overall analysis reports `TRUNCATED`.

- Added protection against horizon-camping/evasion at the configured traversal boundary.

- Truncated analysis defaults to `require_approval` where enforcement requires escalation.

- Added deterministic counterfactual and interrupt-point analysis.

- Added evidence records and lifecycle handling for `potential`, `confirmed`, `disproven`, `revoked` and `expired` authority evidence.

- Added persistent predictive snapshots backed by SQLite.

- Added content hashing for persisted predictive event snapshots.

- Added retrieval of predictive state from recorded events.

- Added Predictive Authority policy classifiers:

  - `credential_acquired`

  - `untrusted_to_external_path`

  - `cross_trust_domain_path`

  - `irreversible_action_reachable`

  - `authority_expands`

- Added packaged `predictive-authority` policy pack.

- Added CLI workflows including `varden authority demo`, `varden authority status` and `varden predictive demo`.

- Added Predictive dashboard with current/reachable authority, evidence-backed trajectories, dangerous paths, counterfactuals and enforcement interrupt points.

- Added adversarial validation and performance benchmarks for bounded Predictive Authority analysis.

- Added documentation in `docs/predictive-authority.md`, `docs/predictive-authority-adversarial-validation.md` and `docs/predictive-authority-benchmarks.md`.

### Provenance and authority integration

- Integrated provenance, authority and Predictive Authority into the normal Varden decision path.

- Varden can distinguish authority held by an agent from authority legitimately available to the information influencing an action.

- Improved detection and representation of untrusted-to-privileged authority flows.

- Preserved cross-server MCP causality on the supported host path using trace/session provenance.

- Improved reconstruction of authority/provenance incidents from historical events.

- Added enforcement evidence describing the runtime boundary, interception state, pre-execution decision and whether a blocked side effect was prevented.

- Improved policy match evidence so incidents can identify meaningful rule metadata instead of generic `matched block rule` descriptions.

- Added and expanded incident-path tests covering provenance and authority enforcement.

- Added live block validation confirming that blocked side effects are prevented.

### Web Shield integration

- Unified Web Shield events with Varden's provenance and authority model.

- Normalised Web Shield classification data for provenance processing.

- Web-originated untrusted content can now participate correctly in authority-flow incident analysis.

- Improved Web Shield enforcement evidence.

- Fixed false `Authority classification unavailable` reporting for generic Web Shield blocks.

- Web Shield, policy, provenance and authority now share a consistent incident/evidence path.

### Security hardening

- ****Demo admin key accepted in production.**** `admin-demo-key` was previously minted on every start regardless of `VARDEN_ENABLE_DEV_BOOTSTRAP`; a production deployment could therefore accept it as admin. Demo keys and the bootstrap bearer token are now only minted in development and are revoked on any start with development bootstrap disabled.

- ****Signing key persistence.**** The auth database previously continued signing/verifying bearer tokens with the secret it was first created with, which could be a development placeholder. The configured `VARDEN_SIGNING_SECRET` is now the only active signing key.

- Outside development, placeholder or signing secrets shorter than 32 characters are refused.

- ****Control-plane guard bypass.**** Control-plane exemption now requires an exact scheme/host/port origin match and rejects URL userinfo. Prefix-matching can no longer exempt URLs such as `http\://127.0.0.1:8000\@evil.example/...`.

- Production no longer exempts `test` or `testserver` hosts.

- ****Agent credential separation.**** Added ingest-only `agent` role.

- `/sdk/bootstrap` provides an agent credential rather than an administrator credential.

- Agent credentials are accepted by ingest/decision paths but do not grant human administrative access.

- Added `GET /auth/whoami`.

- The SDK warns in guarded mode when a protected process holds a privileged human credential.

- Strict mode refuses privileged human credentials unless explicitly overridden with `allow_privileged_key=True`.

- ****Policy simulation isolation.**** `simulate_trace` now uses an isolated policy engine instead of temporarily replacing the live shared engine, removing a race where concurrent decisions could be evaluated against an unpublished candidate policy.

- ****Risk threshold correction.**** `min_risk_score` now means greater-than-or-equal threshold (`>=`) rather than equality.

- ****SDK import correction.**** `import varden_sdk` can safely be imported first; Varden SDK symbols are resolved lazily to avoid the previous circular import.

- Added `varden keys create|list|revoke` with explicit roles.

- Added optional `VARDEN_BOOTSTRAP_ADMIN_API_KEY` for initial production administrator provisioning.

- Production startup now fails on invalid or missing policy rather than continuing with an ambiguous security configuration.

### Policy engine

- Added argv-aware `command` predicates supporting program, subcommand, flags and arguments.

- Command analysis handles common wrappers including `sudo`, `env`, `nohup` and `xargs`.

- Added handling for shell forms including `sh -c`, `eval`, pipelines, command separators and command substitution.

- Updated destructive, baseline, host-shell and deployment policy packs to use argv-aware rules where appropriate.

- Added strict policy validation.

- Unknown fields, classifiers, operators and misspelled outcome buckets are now errors rather than silently ineffective rules.

- Validation reports suggestions where appropriate.

- Predictive Authority classifiers are recognised by strict policy validation.

- Added top-level `default` and `defaults` policy decisions.

- Added per-surface and per-action-type fallback decisions for deny-by-default operation.

- Decision fallback resolution is:

  - `defaults[surface]`

  - `defaults[action type]`

  - `default`

  - `allow`

- Explicit block decisions retain precedence.

- Outside development, or when `VARDEN_STRICT_POLICY=true`, a missing, unreadable or invalid policy file prevents startup.

- `deploy/config/policy.json` ships a baseline production policy.

- Documentation now explicitly describes command matching as a policy guardrail rather than an OS security boundary.

- Deny-by-default subprocess policy with explicit allow rules is the recommended stronger enforcement pattern.

- Dashboard policy editing preserves `require_approval`, `sanitise`, `default` and `defaults`.

- Improved policy match reasons by using rule metadata such as reason, title, description, name and ID.

- Added/updated policy engine documentation in `docs/policy-engine.md`.

### Runtime enforcement and posture

- Preserved the enforced runtime boundary across HTTP, subprocess, filesystem, tools and routed MCP surfaces.

- Guarded and strict operation remain fail-closed by default.

- Coverage remains explicit about `ENFORCED`, `PARTIAL`, `NOT_ROUTED` and `UNCOVERED` surfaces.

- Strict readiness can reject discovered relevant surfaces that are not routed/enforced.

- Scoped approvals remain HMAC-signed, single-use and bound to action, resource, authority and trace.

- Production security configuration now distinguishes administrator/human credentials from credentials intended for protected agent processes.

### Audit and evidence

- Predictive Authority decisions and supporting evidence integrate with Varden's existing event/audit path.

- Persisted predictive snapshots include deterministic content hashes.

- Authority and provenance incidents include stronger enforcement evidence.

- Existing SHA-256 hash-chained audit storage and `varden audit verify` remain the integrity mechanism for persistent decision history.

- Varden continues to report the absence of an external signed audit checkpoint rather than claiming external immutability.

### Dashboard

- Added Predictive Authority workspace.

- Added visualisation of observed/current authority versus reachable authority.

- Added dangerous trajectory/path views.

- Added supporting evidence views.

- Added counterfactual analysis.

- Added enforcement interrupt-point visualisation.

- Improved Authority/Provenance incident presentation.

- Removed incorrect authority-classification warnings for generic Web Shield blocks.

- Policy editor now preserves all supported decision buckets and fallback policy configuration.

### Packaging and production

- Added packaged Predictive Authority policy resources.

- Production startup refuses weak signing secrets.

- Production startup refuses missing or invalid policy.

- Development bootstrap credentials are automatically revoked when development bootstrap is disabled.

- Agent processes can be provisioned with dedicated ingest-only credentials.

- Updated package metadata for the 1.0.0 production/stable release.

- Updated project description to reflect runtime security, policy enforcement, provenance and Predictive Authority.

### Validation

The integrated Varden 1.0 tree was validated after merging Predictive Authority, security hardening and provenance/Web Shield integration:

- ****692 Python tests passed****

- ****26 frontend tests passed****

- ****8 browser smoke tests passed****

- ****726 tests passed in total with zero failures****

- Production frontend build completed successfully.

- Predictive Authority includes deterministic, bounded and adversarial validation.

- Security regression coverage includes production authentication, policy validation, runtime enforcement and provenance/authority incident paths.

The Python suite emits one intentional warning when a test explicitly configures `mode=guarded` with `fail_mode=open`; Varden warns because this weakens enforcement when the control plane is unavailable.

### Upgrade notes

Varden 1.0 tightens production behaviour intentionally.

Before upgrading a production deployment:

- Configure `VARDEN_SIGNING_SECRET` with a non-placeholder value of at least 32 characters.

- Ensure a valid policy file is configured.

- Do not use `admin-demo-key` or other development bootstrap credentials in production.

- Provision human administration and protected agent processes with separate credentials.

- Give protected agents `agent`-role credentials rather than administrator credentials.

- Review existing policies for fields, classifiers or operators that were previously accepted but are now rejected by strict validation.

- Review subprocess rules that rely on loose string matching and migrate security-sensitive policy to argv-aware matching and/or deny-by-default allowlists.

- Review `default` / `defaults` behaviour if adopting deny-by-default policy.

- Predictive Authority is opt-in; enabling `observe` does not change policy outcomes, while `enforce` may strengthen existing decisions.

---

## v0.4.1

### Filesystem containment hardening

- Canonical / symlink-aware effective filesystem targets for policy decisions.

- Path-component containment (no naïve string-prefix checks).

- Rename/replace evaluates source and destination independently.

- Pre-use effective-target re-check narrows check/use gaps (TOCTOU not eliminated).

- Fail-closed behaviour on ambiguous security-sensitive path resolution.

- Coverage remains truthfully `PARTIAL`; residual TOCTOU is documented.

### Tamper-evident audit integrity

- Atomic hash-chained appends on the existing `events` store (`BEGIN IMMEDIATE` + rollback safety).

- Deterministic canonical event hashing (`hash_version` 1) with genesis value.

- Single chained era after optional legacy prefix; unexpected unchained rows fail verification.

- Policy fingerprint is order-stable for rules and excludes volatile configuration noise.

- CLI: `varden audit verify` (exit 0 = PASS, non-zero = FAIL).

- Legacy NULL `event_hash` rows are reported as unchained rather than retroactively sealed.

- Verifier rejects malformed hashes and unsupported hash versions.

### Runtime posture attestation

- Added `varden posture` and `varden posture --json`.

- Varden calculates an authoritative overall enforcement posture.

- Separates attestation validity from coverage quality.

- Reports structured enforcement gaps and available remediation.

- MCP applicability: `NOT_ROUTED` only affects posture when MCP is discovered, required or gateway-enforced.

- Agent Security Skill consumes Varden posture instead of deriving its own result.

### Added — Varden Security Agent Skill

- Agent-native Varden installation and verification workflow (`skills/varden-security`).

- Explicit coverage-aware security posture reporting guidance.

- MCP routing and verification guidance.

- Provenance/authority inspection workflow.

- Hard rules preventing agents from bypassing Varden decisions or fabricating approvals.

- Packaged with Varden releases (`varden/skills/...` + root `skills/...`).

- CLI: `varden skill path`, `varden skill install --target <dir>`.

- CLI: `varden runtime readiness --json` for machine-readable readiness.

- `varden coverage --json` remains supported; the skill prefers `varden posture --json` when available.
