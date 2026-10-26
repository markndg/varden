# Security hardening pass 2

Phase 1 and phase 2 are unreleased containment on top of 1.0.3. Neither is a published release.

Phase 1 covered endpoint exposure, audit evidence, session contracts, provenance, and secret redaction. Phase 2 covers decision correctness: one action identity, one HTTP destination, MCP authorization for unclassified methods, SSRF canonicalization, and unknown action types.

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

## Phase 2 — Decision correctness

These fixes are on the working tree. They are not tagged and not published.

### P0-2 — Canonical action identity

`PolicyEngine.evaluate` binds one server identity before rules run. The caller's original type, URL, domain, and surface claim stay on `metadata.identity` for audit. Policy, the audit fingerprint, and the HTTP client use the canonical type, host, and URL.

A client `domain`, `metadata.runtime.surface`, `metadata.execution_surface`, or a forged `metadata.identity.issuer` does not choose the decision. The surface is derived from the type and the tool. `http_call` and `https_request` are `http_request`. `shell`, `command`, and `subprocess` are `tool_call` on the subprocess surface. Recognized types are case-insensitive. A filesystem deny matches the filesystem family. An allow does not, so `file_read` and `filesystem` stay distinct.

A URL host and a domain claim that disagree are `block` with `conflicting_destination_identity`. That decision is not replaced by an allow rule.

### P0-4 — URL and domain normalization

`canonicalize_destination` is the only HTTP destination parser used for policy and for the socket. Equivalent forms share one host and one canonical URL:

- scheme and host case
- one trailing dot
- IDNA A-labels
- default ports `:80` and `:443` omitted
- empty path written as `/`
- fragment dropped from the canonical URL

The original string is kept as `identity.original_url`, with userinfo removed from the stored copy. Audit sanitization catches parser failures. An unmatched IPv6 bracket does not raise out of `canonicalize_destination`.

These forms are rejected rather than parsed:

- userinfo (`https://user:pass@host/`)
- a backslash in the URL
- a percent-encoded host
- a missing scheme or host
- an authority the URL parser cannot read, including unmatched IPv6 brackets (`malformed_authority`)
- a bracketed host that is not one IPv6 address (`malformed_ipv6`)
- a port outside 1–65535, or an empty or non-numeric port (`malformed_port`)
- decimal, hex, octal, and short IPv4 literals (`2852039166`, `0x7f000001`, `0177.0.0.1`, `127.1`)
- IPv4-mapped IPv6 (`::ffff:169.254.169.254`)
- ASCII controls
- an invalid IDNA label or noncharacter (`invalid_idna`)
- a Unicode name whose IDNA mapping is not the same name up to ASCII case, including `ß` → `ss`, ideographic dots, and zero-width characters (`ambiguous_idna`)

A Unicode DNS name that round-trips is encoded to its ASCII A-label before the hostname label check. `bücher.example` and `xn--bcher-kva.example` are the same host. The label check runs on that A-label.

`requests`, `httpx`, and `urllib` connect to the canonical URL after the guard decision. A rejected destination does not connect, including when `fail_mode=open` or the control plane returns an allow. Domain rules use host equality. A `contains` check is not destination trust.

### P0-8 — MCP methods that were not classified

The gateway still forwards an explicit discovery set without a policy decision: `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, and the notification names listed in `docs/mcp-gateway.md`. The set is exact and disjoint from `tools/call`, `resources/read`, and `prompts/get`. Forwarding a discovery message does not turn its params into a privileged call. `notifications/tools/call` is not on that list.

Those discovery messages stay available when the control plane is down.

Every other well-formed method is `mcp_call` and must receive a guard decision before the downstream server sees it. `Tools/Call` is `tools/call`. A method with leading or trailing space, or an ASCII control, is rejected and not forwarded. A `tools/call`, `resources/read`, or `prompts/get` with an ambiguous name or URI is not forwarded, including when the policy would allow it. A guard exception is a JSON-RPC error and is not forwarded.

A method that is not in the discovery set can still run when policy allows `mcp_call`. That is a policy decision, not a missing classification. Direct MCP connections that never enter the gateway remain `NOT_ROUTED`. This pass does not mark that path `ENFORCED`.

### P1-5 — SSRF canonicalization

Literal destinations are classified, not globally blocked:

| Category | Examples | Default |
| --- | --- | --- |
| `metadata` | `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.goog`, `metadata.azure.com` | blocked by the metadata template and the baseline and egress packs |
| `loopback` | `127.0.0.1`, `::1` | allowed unless a rule says otherwise |
| `link_local` | other `169.254.0.0/16` and link-local IPv6 | allowed unless a rule says otherwise |
| `private` | RFC1918 and unique-local | allowed unless a rule says otherwise |
| `public` / `hostname` | the rest | allowed unless a rule says otherwise |

Redirects are authorized again before the next connection, up to 30 hops. A 301, 302, or 303 becomes GET and drops the body. A cross-host redirect drops `Authorization` on the requests path. httpx already drops it when it builds the next request, except for an HTTP to HTTPS redirect on the same host.

DNS rebinding is not closed. A hostname is marked `dns_rebinding=open`. A literal IP is `not_applicable`. This pass does not resolve DNS and does not pin the connected address. The check and the later `connect()` can still see different answers.

### P1-13 — Unknown action types

Recognized types and their enforcement owners:

| Type | Owner |
| --- | --- |
| `http_request` | `sdk:http` |
| `tool_call` | `sdk:tool` |
| `llm_call` | `sdk:llm` |
| `filesystem`, `file_read`, `file_write`, `filesystem_read`, `filesystem_write` | `sdk:filesystem` |
| `mcp_call` | `mcp_gateway` |
| `webmcp.*` | `webshield` |

A missing or malformed type is `unsupported`. An unrecognized well-formed type is `unsupported` when no rule matches and the decision would otherwise be the implicit allow, including an explicit `"default": "allow"`. An explicit matching rule still applies, including an explicit allow. A policy `block` stays `block`.

`unsupported` is HTTP 403, audit status `blocked`, and a deny in the SDK. Predictive Authority cannot replace it with `warn` or `allow`. `fail_mode=open` applies only when no decision was delivered. It does not apply to `unsupported`, `block`, or `require_approval`.

A control-plane timeout with `fail_mode=open` is still a transport failure. An ambiguous HTTP destination is not: the SDK records the guard attempt when the control plane answers, and it does not open the socket when enforcement is on, even if that answer is an allow or there is no answer.

### Compatibility

- `guarded_action(type=...)` is unchanged.
- A custom type that previously ran because nothing matched now needs an explicit matching rule, or it is `unsupported`.
- A missing `type` is no longer treated as `tool_call`.
- Userinfo URLs, percent-encoded hosts, ambiguous IP literals, and IPv4-mapped literals are rejected instead of connected.
- Loopback, private, and generic link-local destinations are not blocked by this pass.
- The standalone tree `sdks/python/varden_sdk` was already a different SDK and was not updated. The bundled `varden_sdk` package is the one these tests exercise.

### Tests

`tests/security/pass2/test_p2_decision_correctness.py` covers equivalent URLs, forged identity, surface and domain spoofing, aliases, metadata category, DNS-rebinding marking, redirects, MCP method aliases and discovery, unknown types, and `fail_mode=open`.