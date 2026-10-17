# Security hardening pass 2

Phase 1 is critical containment for release 1.1.0. It is not a published release.

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
