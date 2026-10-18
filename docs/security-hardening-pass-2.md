# Security hardening pass 2

Phase 1 is critical containment for release 1.1.0. It is not a published release.

## P0-7 — Endpoint exposure

Unauthenticated `GET /health` is `{"status":"ok"}`. `GET /sdk/bootstrap` returns `base_url` and the OSS `tenant_id`. It does not return policy rules, API keys, or signing secrets.

A development credential is added to that response only when all of the following hold:

- `VARDEN_ENV=dev`
- `VARDEN_ENABLE_DEV_BOOTSTRAP=true`
- the TCP peer is loopback (`127.0.0.1`, `::1`, `localhost`, or the in-process test client)
- `VARDEN_UNSAFE_DEV_BIND` is not set

`X-Forwarded-For` is not a loopback proof. It is read only when the direct peer is listed in `VARDEN_TRUSTED_PROXY_HOSTS`.

`AppConfig.from_env` defaults to production and leaves bootstrap off. Binding dev mode to `0.0.0.0` fails startup unless `VARDEN_UNSAFE_DEV_BIND=true`, and that flag still does not publish the admin key.

Interactive API docs are disabled outside development unless `VARDEN_ENABLE_API_DOCS=true`.

`tests/security/pass2/test_p2_endpoint_exposure.py` keeps the allowlist of unauthenticated routes. A new route that does not call `require` fails that test until the allowlist is updated on purpose.

## P0-6 — Audit evidence

`/sdk/guard` returns `event_id` and stores an `audit_binding` of tenant, principal hash and action fingerprint. `/sdk/log` may cite that id. The server loads its own decision. The client's `decision`, approval id and coverage fields are not the record.

A log that does not match is stored as `unverified_observation`. Incident views label it `OBSERVED` and do not claim the side effect was prevented. That is also how a pre-1.1.0 SDK log is treated. Upgrade the SDK so `record_result` sends `guard_event_id`.

Token accounting for an allowed `llm_call` follows the guard event. Reporting `status=blocked` does not skip it. Reporting the same event twice does not charge it twice. If the agent never reports usage, the pre-check reservation remains and still counts toward the cap.

Usage reconciliation for one guard event is a single SQLite transaction: every applicable rule settles, or none of them do. The reservation status is the completion record. A failed or interrupted reconciliation leaves the hold `reserved`, so a retry can apply the actual usage. A repeated or concurrent report for a settled event does not charge it again. A client `failed` / `blocked` / `not_executed` report without usage does not settle the hold and does not prevent a later usage report from doing so. Missing or non-numeric usage is charged at the reserved estimate once (`reported_usd` stays empty). If SQLite stays locked, accounting raises and `/sdk/log` returns HTTP 503 with `usage_accounted: false` and `accounting_status: "retryable_failure"`. The model call is not run again.

### Guard-time budget evidence

A verified guard event proves the policy decision. It does not prove that budget accounting succeeded. Those are separate facts, along with whether the audit row was stored, whether the client reported an execution, and whether a hold was actually enforced.

`/sdk/guard` writes `metadata.budget_evidence` on the audit event before the event is hashed. The client cannot supply that field: it is server-owned and stripped from inbound metadata. The document names each budget rule considered, the rule snapshot used for the estimate, the reservation id when a hold was taken, and an explicit disposition:

| Guard-time disposition | Meaning |
| --- | --- |
| `reserved` | A hold was created. Later usage must settle that reservation. |
| `warned_not_held` | A soft cap warned and did not reserve. |
| `not_applicable` | The rule was disabled or did not apply. |
| `unbudgeted` | No rule reserved a hold. This is a positive record, not a missing one. |

The same snapshot is stored on the reservation row. Reconciliation prices usage from that snapshot. Deleting the rule, disabling it, or changing its cap or model price afterwards does not move the obligation. A rule added after an unbudgeted guard does not create a hold for that guard.

The reservation row and the audit event are not one transaction. The hold is written first. If the process stops before the guard event is stored, the next usage report that presents this evidence binds the unbound reservation and then settles it. A crash during settlement rolls the charge back and leaves the hold `reserved`.

`/sdk/log` returns `accounting_status` beside `usage_accounted`:

| Status | HTTP | What it means |
| --- | --- | --- |
| `reconciled` | 200 | The guard-time holds were settled, once. |
| `already_reconciled` | 200 | This guard was already settled. No second charge. |
| `legitimately_unbudgeted` | 200 | Guard-time evidence says no hold was required. |
| `warned_not_held` | 200 | A soft cap applied and did not reserve. |
| `pending_usage` | 200 | The client reported that it did not execute, and no usage was present. The hold remains. |
| `accounting_integrity_failure` | 409 | Evidence names a reservation that is missing or belongs to another guard event. Nothing in that report is charged. A redacted row is stored in `token_budget_accounting_findings`. |
| `unverified_guard` | 200 | The log does not match a guard event for this tenant, principal, and action. |
| `legacy_evidence_insufficient` | 200 | The guard event is older than this evidence, or its reservation has no rule snapshot. It is not charged and it is not relabelled unbudgeted. |
| `retryable_failure` | 503 | SQLite stayed locked. The hold is unchanged. |

An integrity failure is HTTP 409 with `logged: true` and `retryable: false`. The SDK returns that body from `log_result` instead of raising, so a caller does not treat it as a reason to repeat the model call. The audit event for the report is already stored.

Schema 15 adds `token_budget_accounting_findings`. It does not rewrite old events and it does not invent `budget_evidence` for them. An SDK that omits `guard_event_id` remains an `unverified_observation` and is not budget-accounted.

### Reservation ledger

Each allowed `llm_call` writes a row in `token_budget_reservations` in the same transaction as the hold. The row keeps the tenant, principal, guard event, action fingerprint, originating window id, estimate, deadline and status (`reserved`, `reconciled`, `expired_charged`, `cancelled_verified`).

A daily or monthly reset archives the open counter and starts the next allowance at zero. It does not delete reservation rows. Unresolved holds stay on the window that created them. At the deadline the reserved estimate is charged to that window. A later usage report adjusts that same window by the difference, once. A second report does not charge again.

Client `blocked`, `failed` and `not_executed` do not cancel a hold. Only a server decision that prevents execution releases one, as `cancelled_verified`. An unknown outcome with no usage is charged at the reserved estimate. Settled rows older than 90 days can be deleted. Rows still `reserved` are not.

### Budget scope

Trace and workflow ids are correlation fields. They do not open a new allowance.

| Window | Counter | Lifetime |
| --- | --- | --- |
| `session` | authenticated tenant + API-key hash | Cumulative. It does not reset when the client changes `trace_id`, and it has no calendar reset. An unreported hold still expires at its deadline. |
| `daily` | authenticated tenant | UTC calendar day, shared by every principal in that tenant. |
| `monthly` | authenticated tenant | UTC calendar month, shared by every principal in that tenant. |

The tenant and principal come from the authenticated credential. A client-supplied tenant, principal, trace, or workflow id is not the key. A hard cap whose tenant (or, for a session cap, principal) cannot be established is denied before execution. The block reason is `token budget scope could not be established`. A soft cap in that state returns a warning with `enforced: false` and does not reserve. The decision is the audit record. It does not contain credentials.

Schema 14 adds `tenant_id` and `principal_hash` to the live counter, historical charges, and token events. The old policy/trace unique index is replaced by one that includes the authenticated scope. Rows that already existed keep a null tenant. They are not given to `default` or to any other tenant, and new traffic does not update them. `GET /token-budgets` and the dashboard return only the caller's tenant. `varden budget status` reads the local database, including those legacy rows.

### Residual risk

The OSS authentication helper stamps every accepted request with the single OSS tenant id. Two API keys in this build therefore share a daily or monthly cap. They do not share a session cap: that follows the key hash. The ledger isolates tenants when the server passes two tenant ids; this build's HTTP layer does not present a second tenant.

A session counter does not reset on a clock. Changing the policy limit is how an operator clears it. Python interception is not an operating-system sandbox.

If a reservation row is removed while the counter still shows its `reserved_usd`, reconciliation does not invent a replacement charge and does not clear that counter by itself. The integrity finding is the operator record. Historical events are left without `budget_evidence`; they are not rewritten to look unbudgeted.

## P0-5 — Session contracts

`varden session` now writes a signed contract (session id, principal hash, mode, fail mode, trace id, original PATH, expiry, contract id, key id) and removes `VARDEN_SIGNING_SECRET` from the child environment. The child gets a purpose-separated verification key (`varden-session-contract-v1`).

Guarded and strict commands run only when:

- the contract signature verifies
- the session id matches
- the contract is unexpired
- the control plane has the contract registered and confirms it
- the process has not asserted a weaker mode or `fail_mode=open`

If the control plane is down, a guarded or strict command does not run. An observe contract still runs. A rejected downgrade is appended to the session audit file with `authoritative_decision: null`.

Start a guarded session only when `VARDEN_SIGNING_SECRET` is set (at least 16 characters) and the control plane accepts `POST /runtime/session/contract`.

### Residual risk

A 0400 contract file is not immutable to another process running as the same user. The verification key is in the child environment. That process can replace the contract and the key, point `VARDEN_BASE_URL` at a server that returns HTTP 200, invoke a binary outside the shim directory, or skip the shim. A contract signed with the attacker's key is rejected only while the original verification key is still the one the shim uses. Subprocess coverage does not become `ENFORCED`. See the subprocess limitations in `varden coverage`.

## P0-3 — Provenance trust boundary

A protected agent must not be able to describe external content as internally trusted.

Client sources are limited to `unknown`, `untrusted` and `hostile`. Any other trust level, including `internal`, is stored as `unknown` and marked `forged_trust_claim`. The originally claimed level is kept only as `claimed_trust_level` evidence. Client `provenance_complete` is ignored. Web Shield `trust_state` values such as `trusted` or `pinned` follow the same rule.

`POST /runtime/session/provenance` accepts only a key with role `gateway`. Create one with the keys CLI (`--role gateway`). Agent keys receive 403. A gateway key that sends `trust_level=internal` (or `trusted` / `delegated`) also receives 403. The MCP gateway and host post session provenance only when `VARDEN_GATEWAY_API_KEY` is set. A gateway credential does not make arbitrary content trusted; it may only record `unknown`, `untrusted` or `hostile`.

### Upgrade

Issue a gateway-role API key for each MCP gateway or host that must record cross-call provenance, and set `VARDEN_GATEWAY_API_KEY`. Agent keys continue to call `/sdk/guard`. They no longer write session provenance.

## P0-1 — Secret redaction and credential confidentiality

`varden/redaction.py` used to rewrite sensitive key names inside serialised JSON and leave the values intact. `{"password": "hunter2"}` became `{"[REDACTED]": "hunter2"}`.

The redactor now walks dictionaries and lists. Sensitive key names are matched case-insensitively, including keys that end in `_token` or `_key`. A field named only `session` is not treated as a secret. Recognised credential shapes (Bearer tokens, `sk-` keys, AWS access key ids, GitHub and Slack tokens, JWTs, PEM private keys) are redacted even under a benign key. High-entropy detection skips UUIDs and hex digests so audit fingerprints stay readable.

The marker is `[REDACTED:<label>:<4 hex>]`. The hex is the first four characters of HMAC-SHA256 over `tenant + label + value`, keyed by HKDF from `VARDEN_SIGNING_SECRET` (or the process signing secret) with purpose `varden-redaction-correlation-v1`. It is not a truncated SHA-256 of the secret. Identifiers differ across tenants.

Order of operations:

1. The raw action is received and canonicalised.
2. Classifiers and policy run on that unredacted object.
3. A separate redacted copy is what gets stored, hashed into the audit chain, and published on `/events`, event detail, traces and SSE.

Predictive Authority snapshots are schema version 2. The builder runs the shared redactor, then stamps `content_hash` as the SHA-256 of those canonical bytes, and the store writes those bytes. Verification hashes the stored text. It does not redact again after the hash.

Schema version 1 rows still verify against their original hash. If that body contains plaintext, the API returns a redacted projection and `redaction_status=historical_plaintext_withheld`. `PredictiveSnapshotStore.migrate_plaintext` writes a redacted replacement and a row in `predictive_snapshot_migrations` that links the original audit hash to the replacement. It does not rewrite the audit chain and it does not erase free pages.

SDK HTTP interception drops `auth` and `cookies` objects and redacts sensitive header values before the guard request. The control plane still receives `metadata.credential_signals`, a list of field names, and treats that as a secrets classification. Subprocess interception sends `env_keys` and `env_changed` and does not send environment values.

### Historical rows

`varden audit redact-migrate` is a logical rewrite. It is safe to run on a stopped database: one transaction rewrites event rows, rebuilds the hash chain, and appends a signed manifest. A failure before commit rolls the transaction back and leaves the previous chain in place. Running it again is idempotent when the redactor does not change the rows; the replacement chain head stays the same.

It is not secure deletion. The command does not vacuum the database, delete backups, or rotate keys.

1. Stop Varden so nothing writes the database during the rewrite.
2. Copy the database, its `-wal` and `-shm` files, and any snapshots to protected storage. Keep that copy until credential rotation and retention review are finished. The copy still contains plaintext.
3. Rotate every credential that may have been written into events, traces, logs, or those backups. Treat the old values as exposed.
4. Run `VARDEN_SIGNING_SECRET=... varden audit redact-migrate --db varden.db`. The secret must be at least 16 characters. The command prints the affected count and a remanence notice. It does not print row contents.
5. Run `varden audit verify --db varden.db` and confirm the chain is valid. The manifest signature covers `original_head` and `replacement_head`.
6. Start Varden and check that ingest, `/events`, and a guarded action still behave as expected.
7. SQLite may still hold old bytes in the WAL, the rollback journal, and free pages. Checkpointing or truncating the WAL shortens the file. It does not prove those bytes are gone from the disk.
8. Find backups and snapshots that contain the pre-migration database and retire them on the retention schedule. Deleting a backup is an operator action.
9. Start Varden only after the verify step succeeded.
10. Submit a fresh action that contains a test credential and confirm `/events` and the database row show a `[REDACTED:...]` marker rather than the credential.

The manifest records that history was rewritten. It does not claim the old plaintext was erased.

### Upgrade

Set `VARDEN_SIGNING_SECRET` before running the migration. Existing bearer tokens, approval tokens and the audit hash algorithm are unchanged. SDK and control plane should both be this version so guard payloads are minimized before they are sent; the server still redacts whatever arrives.
