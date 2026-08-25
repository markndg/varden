# Provenance-Aware Authority Flow

Varden doesn't only ask whether an agent is allowed to use a tool. It asks whether the information that caused the tool call was authorised to exercise that tool's power.

## Core idea

Untrusted information must not be able to acquire authority merely because an agent read it.

Three explicit concepts:

1. **Provenance** — where information originated
2. **Taint / trust** — how trustworthy that origin is
3. **Authority** — what actions an origin is allowed to cause

The critical distinction is between:

- **Capability possession** — the agent process can technically call tool X
- **Delegated authority** — *this causal chain* is authorised to exercise X

That is what turns Varden from an action firewall into a runtime information-flow / authority firewall for agents.

## Enforcement path

```text
source observation
  -> provenance capture (SDK / Web Shield / MCP metadata)
  -> causal propagation (contextvars + lineage)
  -> authority classification (deterministic)
  -> delegation check (monotonic; untrusted cannot broaden)
  -> Action metadata enrichment
  -> PolicyEngine.evaluate (existing ordered buckets)
  -> allow / warn / require_approval / block
  -> evidence (findings, attack path, explanation)
```

## Quick start

```bash
# Import the fail-closed pack in the Rules workspace, or:
# merge policy-packs/provenance-authority-defense.json

varden provenance evaluate
varden provenance demo
varden authority violations
varden provenance explain <event-id>
```

Dashboard: `/ui/authority`

## What is blocked by default

With `provenance-authority-defense` imported:

- untrusted → secret/credential read
- untrusted → privileged shell
- untrusted MCP → privileged MCP / confused deputy
- private/secret → public network egress
- unknown provenance → DELETE / ADMIN / PAYMENT
- WebMCP critical findings retained as taint into downstream actions

## Compatibility

Existing Varden behaviour remains. Missing provenance is represented as **unknown**, never silently trusted. Existing policies continue to load. `varden.protect()` keeps working.

See also:

- [Threat model](provenance-threat-model.md)
- [Policy](provenance-policy.md)
- [SDK](provenance-sdk.md)
- [MCP](provenance-mcp.md)
- [Limitations](provenance-limitations.md)
- [Evaluation](provenance-evaluation.md)
