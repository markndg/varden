# MCP gateway & routing

## Model

```text
Agent / MCP Host
       │
       ▼
Varden MCP Gateway  (optional but required for ENFORCED MCP)
       │
       ├── MCP Server A
       └── MCP Server B
```

Direct host → server connections (bypassing the gateway) are **not** enforced.
Coverage should report MCP as `NOT_ROUTED` until traffic is wrapped.

## Wrap config (non-destructive)

Preserve the original file. Write a new wrapped config:

```bash
varden mcp wrap /path/to/mcp.json --output /path/to/mcp.varden.json
# alias:
varden mcp patch-config /path/to/mcp.json --output /path/to/mcp.varden.json
```

Point the MCP host at the **wrapped** file. Review printed change list before
switching.

Each server entry becomes a gateway launcher roughly of the form:

```bash
python -m varden.runtime.mcp_gateway --server-id NAME --downstream-json '...'
```

Explain-only:

```bash
varden mcp gateway
```

## What the gateway does

* Privileged methods (`tools/call`, `resources/read`, `prompts/get`) are
  evaluated through Varden **before** forwarding downstream.
* Downstream results are treated as untrusted influence in the provenance chain.
* Fail-closed semantics apply when the control plane is required and unreachable
  under guarded/strict fail-closed posture.

## Cross-server causality

Untrusted results from server A can later influence a privileged call to
server B. Per-server gateway processes alone do **not** automatically share
memory. The supported continuity path is control-plane **session provenance**
keyed by `trace_id`, used by:

* Varden-aware host adapters (`VardenMcpHost`)
* gateway/SDK merge of session sources on `/sdk/guard`

Do not manually invent provenance in application code unless that is the
documented integration; prefer the supported host/session path.

## Approvals

Privileged MCP actions may return `require_approval`. Use:

```bash
varden approvals pending --json
varden approvals approve <approval_id>
varden approvals deny <approval_id>
```

Retry the **exact** operation with the server-issued token. Do not invent tokens.

## Verify MCP is genuinely routed

```bash
varden posture --json
varden coverage --json
```

When MCP is **applicable** (discovered config, required coverage, or gateway),
`NOT_ROUTED` makes posture `not_fully_routed` (not `protected`).

When MCP is **not applicable** (no discovered/required MCP), catalog
`NOT_ROUTED` must not force that posture result.

Expect MCP to leave `NOT_ROUTED` when the host uses the wrapped config and the
gateway is active. If posture/coverage still shows applicable `NOT_ROUTED`,
the host is likely still on the original config or traffic never hit the gateway.

Remediation (diagnostic only — `varden posture` does not mutate configs):

```bash
varden mcp wrap /path/to/mcp.json --output /path/to/mcp.varden.json
```

Also useful:

```bash
varden runtime readiness --json
varden runtime self-test
```
