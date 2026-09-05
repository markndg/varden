# Provenance & authority

Varden asks not only whether an agent *can* invoke a tool, but whether the
**causal chain** that led to the invocation is authorised to exercise that
tool's power.

## Core distinction

| Concept | Meaning |
|---------|---------|
| Tool possession | Process can call the API / binary |
| Delegated authority | This causal chain is permitted to exercise that class of power |

Untrusted data must never create or broaden a `Delegation`. Client-asserted
`trusted` / `user_intent` / `approved` claims are not authoritative.

## Untrusted influence sources

Treat as relevant provenance when they shape later actions:

* web pages and fetched content
* MCP tool results and (where applicable) tool metadata
* WebMCP registrations / descriptions
* issue and PR text
* repository files and downloaded artifacts
* shell / tool output
* external documents and emails

An agent deciding to act does **not** by itself mint user authority.

## Chains and Ghostjacking-style flows

A typical confused-deputy / Ghostjacking-style pattern:

1. Untrusted content enters (web, MCP A, WebMCP, issue text).
2. The agent already possesses privileged tools.
3. Influenced reasoning triggers a privileged action (secrets, shell, MCP B, exfil).

Authority-flow enrichment runs before PolicyEngine. Findings may include
delegation violations, untrusted→privileged flows, and cross-server influence.

## MCP A → MCP B

On the supported path, provenance from A survives via session provenance
(`trace_id`) into B's guard. Arbitrary hosts that neither use the gateway nor
record session provenance **lose** causality — report that as a gap, do not
pretend enforcement.

## Inspection commands

```bash
varden provenance evaluate [--json]
varden provenance demo
varden provenance trace <trace_id> [--db]
varden provenance explain <event_id> [--db]
varden provenance sources <trace_id> [--db]
varden authority violations [--db] [--limit N] [--json]
varden authority explain <event_id> [--db]
```

Use when:

* investigating a block / require_approval
* untrusted content likely influenced a privileged action
* cross-MCP causality may exist
* the user asks why Varden blocked something

## Approvals vs authority

Scoped approvals (`varden approvals …`) are operator-issued grants for a
specific blocked/require_approval action. They are not a substitute for forging
trusted user provenance. See also `docs/approvals.md` and
`docs/provenance-authority.md` in the Varden tree.

## Posture vs provenance

`varden posture` attests **enforcement-state** (what is currently routed /
enforced). It is not a replacement for provenance or authority-flow
investigation. A runtime can be `protected_with_gaps` and still need
`varden authority explain` / `varden provenance sources` after a suspicious
privileged action.
