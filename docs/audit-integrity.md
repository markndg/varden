# Tamper-evident audit integrity

Persistent Varden security events are hash-chained.

```bash
varden audit verify
varden audit verify --db /path/to/varden.db
varden audit verify --json
```

Exit codes: `0` = PASS, `1` = integrity failure / verification error, `2` = usage.

## Scheme (`hash_version` = `1`)

```text
event_hash = SHA-256( canonical_json(security_fields) + "\n" + previous_hash )
```

* `previous_hash` is concatenated **outside** the canonical JSON object.
* First chained event uses genesis previous hash (`64` zero hex digits).
* `id`, `event_hash`, and `prev_hash` are excluded from the hashed body.
* Appends use one SQLite transaction:

  ```text
  BEGIN IMMEDIATE
      read committed chain head
      bind immutable payloads
      compute hash
      INSERT
  COMMIT
  ```

  On failure, `ROLLBACK` leaves the chain unchanged. There is no separate
  chain-head table.

## Legacy → chained transition

Valid:

```text
LEGACY*  →  CHAINED_GENESIS  →  CHAINED*
```

Once the chained era begins, a later NULL/`event_hash` row fails verification
(`unexpected_unchained_after_chain`). Multiple independent chain segments are
not treated as legitimate.

Unsupported `hash_version` values fail as `UNSUPPORTED_HASH_VERSION` (not
silently accepted).

## Policy fingerprint

`action.metadata.audit_integrity.policy_fingerprint` covers security-relevant
identity: rule lists (`block`/`warn`/`monitor`/`allow`/`require_approval` —
**order preserved**), plus optional `mode` / `fail_mode` / `require_coverage` /
`allow_uncovered`. Map key order, logging, PIDs, timestamps, and dashboard
prefs are excluded.

## What this is not

* Not a blockchain / distributed ledger
* Not confidentiality or encryption
* Not “tamper-proof”
* Does **not** detect silent tail truncation without an external chain-head
  checkpoint
* Does not change policy decisions (`varden.protect()` unchanged)
