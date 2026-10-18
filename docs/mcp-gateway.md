# MCP gateway

```text
Agent / MCP Host
       |
       v
Varden MCP Gateway
       |
       +---- MCP Server A
       |
       +---- MCP Server B
```

## Wrap an existing config (non-destructive)

```bash
varden mcp wrap mcp.json --output mcp.varden.json
```

Shows exactly what changed. Point your MCP host at the wrapped config.

Each server becomes:

```text
python -m varden.runtime.mcp_gateway --server-id NAME --downstream-json '...'
```

Privileged methods (`tools/call`, `resources/read`, `prompts/get`) are guarded
before forwarding. Downstream results are tainted into the gateway provenance
chain so cross-server confused-deputy flows retain upstream influence.

Discovery and lifecycle messages are forwarded without a policy decision:
`initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`,
`prompts/list`, and the `notifications/*` messages the gateway recognizes.
Every other well-formed method, including a method the gateway has not
classified, is sent to `/sdk/guard` as `mcp_call` before it is forwarded.
A missing or failed guard response is not forwarded. A malformed tool name,
resource URI, or prompt name is not forwarded even when a policy would allow
the call. Method matching is case-insensitive (`Tools/Call` is `tools/call`).

This is enforcement only for traffic that enters the gateway. A client that
connects to an MCP server directly is `NOT_ROUTED`. The gateway does not
attest that path as `ENFORCED`.
