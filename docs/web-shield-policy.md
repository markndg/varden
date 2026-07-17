# Web Shield policy integration

Web Shield does not introduce a second policy engine. It emits ordinary Varden
events with type `webmcp.*`, and those events are evaluated by the exact same
`PolicyEngine` (`varden/policy.py`) used for `tool_call`, `http_request`,
`llm_call` and every other Varden action. If you already understand Varden
policy files, you already understand Web Shield policy.

## What's new, precisely

Two additions were made to the policy engine itself, and they are additive —
neither one changes the evaluation behaviour of an existing policy file that
doesn't use them:

1. **Two new rule buckets**: `require_approval` and `sanitise`, alongside the
   existing `block`, `warn`, `monitor`, `allow`. `MODES` in `varden/policy.py`
   is now `("block", "require_approval", "sanitise", "warn", "monitor",
   "allow")`, evaluated in that precedence order. A policy file that never
   populates these two buckets (i.e. every existing Varden policy file today)
   behaves identically to before.
2. **Dot-notation `metadata.*` predicates**, e.g. `"metadata.risk_band":
   "critical"`. `PolicyEngine._get_field` already supported `field:` and
   `classifier:` prefixes; it now also walks `metadata.a.b.c` paths directly,
   which is how Web Shield's risk band, findings, capability flags and
   lifecycle flags are exposed to rules. This is how `min_risk_score` and
   `field:` predicates already worked for other action types — Web Shield
   just needed nested metadata access.

No changes were made to rule matching operators (`eq`, `contains`,
`startswith`, `endswith`, `in`, `gte`, `lte`, `exists`), to rule precedence, or
to how existing action types are matched.

## Available predicates for `webmcp.*` events

Rules match on an `Action` the same way any other Varden rule does. Useful
fields for Web Shield events:

| Predicate | Type | Meaning |
|---|---|---|
| `type` | string | Event type, e.g. `webmcp.tool_registered` (see the full taxonomy in `docs/web-shield-architecture.md`). |
| `tool` | string | Tool name. |
| `domain` | string | Owner origin of the tool. |
| `min_risk_score` (or `metadata.risk_score` with `gte`) | int | Numeric risk score 0–100. |
| `metadata.risk_band` | string | `low` \| `guarded` \| `suspicious` \| `high` \| `critical`. |
| `metadata.top_origin` | string | Top-level browsing context origin (registration events). |
| `metadata.same_origin` | bool | `owner_origin == top_origin` (registration events). |
| `metadata.is_third_party_frame` | bool | Tool registered from an iframe whose origin differs from the top origin (registration events). |
| `metadata.first_seen` | bool | This tool identity has never been observed before in this tenant. |
| `metadata.metadata_changed` | bool | Same tool identity, but metadata hash differs from the last observation (registration events). |
| `metadata.mutates_state` | bool | Inferred capability profile indicates the tool mutates state (see Layer 4, `layers/capability.py`). |
| `metadata.mentions_payment` | bool | Inferred capability profile references payment/wallet fields (invocation events; nested under `metadata.capability.mentions_payment` for registration events). |
| `metadata.mentions_credential` | bool | Inferred capability profile references credential-shaped fields (invocation events; `metadata.capability.mentions_credential` for registration events). |
| `metadata.sensitive_schema_fields` | list[string] | Schema property names that matched the shared sensitive-field pattern (`varden/redaction.py::SENSITIVE_FIELD_RE`). Use with `{"contains": "..."}` or check length upstream. |
| `metadata.finding_categories` | list[string] | Distinct finding categories from the scan (`instruction_hierarchy_override`, `cross_tool_manipulation`, `unicode_obfuscation`, `lifecycle_anomaly`, …). Use with `{"contains": "lifecycle_anomaly"}` etc. |
| `metadata.finding_rule_ids` | list[string] | Distinct stable rule IDs that fired, e.g. `WEBMCP-INJECTION-001` (registration events). Use with `{"contains": "..."}`. |
| `metadata.trust_state` | string | `trusted` \| `blocked` \| `null`, from local trust decisions (`varden web-shield trust`). |
| `metadata.enforcement_capable` | bool | Whether the calling integration reported it can actually enforce a block/approval/sanitisation. |
| `metadata.output_length` | int | Length of scanned tool output text, for size-based rules (output events). |
| `metadata.contains_user_generated_content` | bool | Output scan input flag (output events). |

Because these are plain `metadata.` paths, you can combine them with
operators exactly like any other Varden rule, e.g.:

```json
{
  "type": "webmcp.tool_invocation_requested",
  "metadata.risk_score": {"gte": 60},
  "metadata.mutates_state": true
}
```

## Example rules

Translating the brief's example policy ideas into Varden's actual schema:

```json
{
  "block": [
    {
      "name": "block-critical-webmcp-metadata",
      "type": "webmcp.tool_registered",
      "metadata.risk_band": "critical"
    }
  ],
  "require_approval": [
    {
      "name": "approve-new-payment-tools",
      "type": "webmcp.tool_invocation_requested",
      "metadata.mentions_payment": true,
      "metadata.first_seen": true
    }
  ],
  "monitor": [
    {
      "name": "monitor-readonly-same-origin-tools",
      "type": "webmcp.tool_registered",
      "metadata.top_origin": {"eq": "metadata.owner_origin"},
      "metadata.risk_score": {"lte": 19}
    }
  ]
}
```

(The last example is illustrative — Varden's rule matcher compares a field
against a literal value or operator spec, not against another field, so a
same-origin check in practice is expressed as a `domain` allowlist or handled
upstream; see `webmcp_block_untrusted_origin_invocation` in the shipped pack
for the supported pattern.)

## The shipped default pack

`policy-packs/webmcp-web-shield.json` is a safe default enforcement profile.
It is **not** applied automatically — importing it is how you opt in to Web
Shield enforcement (see "Rollout" below). It ships:

- `block`: critical-risk registrations, critical-risk metadata changes on a
  known identity, critical-risk output contamination, invocation on a
  locally-blocked origin, and detected extension/wrapper tamper (recorded as
  policy intent — see the honesty note on `achieved_enforcement` below).
- `require_approval`: payment-capable invocations, first-seen mutating-tool
  invocations, and high-risk-band registrations.
- `sanitise`: suspicious-band registrations, suspicious-band tool output.
- `warn`: guarded-band registrations, `modelContext` replacement, tool-surface
  churn, cross-origin data flow.
- `monitor`: catch-all retention of registrations, invocations, output scans
  and tamper signals so the dashboard/timeline stays complete even when no
  stronger rule fires.

Import it with the existing pack machinery (`varden.policy_packs`), or let
`varden web-shield demo` merge it into your working `policy.json`
automatically. Merging is additive: `merge_policy_pack(current, pack,
mode="merge")` only adds rules whose `name` isn't already present, so running
the demo against a policy file you've already customised won't clobber your
changes.

## Policy is authoritative — risk scoring is evidence

Every layer up to and including risk scoring (`varden/webshield/risk.py`)
produces *evidence*: findings, a 0–100 score, a band. None of it enforces
anything by itself. The only thing that turns evidence into an outcome is
`PolicyEngine.evaluate()`, called from `WebShieldStore._log_event` for every
`webmcp.*` event before it is persisted.

This matters concretely for **output scanning**: `scan_tool_output` computes
a risk band and a set of findings, but the returned `outcome` (`allow` /
`sanitise` / `truncate` / `quarantine` / `block`) is derived from the policy's
`requested_enforcement` for that event, not directly from the risk band. If
no policy rule matches — for example, an operator who has never imported the
Web Shield pack, so `/webshield/config` reports `"enabled": false` — the
policy decision is `allow` and the API never withholds output, regardless of
how severe the underlying scan findings are. This is covered by
`test_output_scan_never_blocks_when_no_webmcp_policy_rules_are_configured` in
`tests/test_webshield_api.py`, and is the concrete mechanism behind the
rollout guarantee in the next section.

`_log_event` additionally distinguishes:

- `policy_decision` — the raw bucket the rule matched (`block`, `warn`, …).
- `requested_enforcement` — the decision mapped into Web Shield's enforcement
  vocabulary.
- `achieved_enforcement` — what was *actually* possible. This can legitimately
  differ from `requested_enforcement`: an already-completed invocation can
  only be `observed_only`; a forensic-only event like
  `webmcp.extension_tamper_detected` is `unavailable` because by definition
  the thing it describes already happened; and a caller can report
  `enforcement_capable: false` (e.g. it captured an unwrapped reference before
  the wrapper installed) to make the store record `unavailable` instead of
  silently claiming success.
- `enforcement_limitation` — a human-readable reason when `achieved !=
  requested`.

## Rollout: existing users see no change

A fresh Varden install's `policy.json` has no `webmcp.*` rules, so every
`webmcp.*` event resolves to the engine's built-in default: `allow`, with
`policy_decision == "allow"`. `GET /webshield/config` reports `"enabled":
false` whenever the current policy has zero rules whose `type` starts with
`webmcp.`. Web Shield only starts producing warn/sanitise/require_approval/
block outcomes once you explicitly import a pack (or write your own rules) —
running `varden web-shield demo` is the one command that does this for you,
and it does so via the same additive merge described above, not by replacing
your file.
