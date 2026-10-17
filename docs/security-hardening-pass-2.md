# Security hardening pass 2

Phase 1 is critical containment for release 1.1.0. It is not a published release.

## P0-6 — Audit evidence

`/sdk/guard` returns `event_id` and stores an `audit_binding` of tenant, principal hash and action fingerprint. `/sdk/log` may cite that id. The server loads its own decision. The client's `decision`, approval id and coverage fields are not the record.

A log that does not match is stored as `unverified_observation`. Incident views label it `OBSERVED` and do not claim the side effect was prevented. That is also how a pre-1.1.0 SDK log is treated. Upgrade the SDK so `record_result` sends `guard_event_id`.

Token accounting for an allowed `llm_call` follows the guard event. Reporting `status=blocked` does not skip it. Reporting the same event twice does not charge it twice. If the agent never reports usage, the pre-check reservation remains and still counts toward the cap.

### Residual risk

Daily and monthly budget windows reset `reserved_usd` with `current_usd`. An estimate that was reserved and never reported is dropped at the window boundary rather than folded into the charged total. Session windows do not reset that way.

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

A 0400 contract file is not immutable to another process running as the same user. That process can replace the contract and the verification key, invoke a binary outside the shim directory, or skip the shim. Subprocess coverage therefore does not become `ENFORCED` because a contract signature verified. See the subprocess limitations in `varden coverage`.

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

SDK HTTP interception drops `auth` and `cookies` objects and redacts sensitive header values before the guard request. The control plane still receives `metadata.credential_signals`, a list of field names, and treats that as a secrets classification. Subprocess interception sends `env_keys` and `env_changed` and does not send environment values.

### Historical rows

```bash
VARDEN_SIGNING_SECRET=... varden audit redact-migrate --db varden.db
```

The command counts affected records, rebuilds the chain, and stores a signed manifest (`original_head`, `replacement_head`). Verify the new chain with `varden audit verify`.

Rewriting a row does not wipe SQLite free pages, the WAL, rollback journals, backups or snapshots. Treat those as still sensitive until the storage is destroyed or the volume is securely wiped.

### Upgrade

Set `VARDEN_SIGNING_SECRET` before running the migration. Existing bearer tokens, approval tokens and the audit hash algorithm are unchanged. SDK and control plane should both be this version so guard payloads are minimized before they are sent; the server still redacts whatever arrives.
