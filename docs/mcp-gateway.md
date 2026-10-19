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

Discovery and lifecycle messages are forwarded without a policy decision.
The allowlist is exact, not a prefix: `initialize`, `ping`, `tools/list`,
`resources/list`, `resources/templates/list`, `prompts/list`, and these
notification names: `notifications/initialized`, `notifications/tools/list_changed`,
`notifications/resources/list_changed`, `notifications/prompts/list_changed`,
`notifications/progress`, `notifications/cancelled`, `notifications/message`.
Method matching is case-insensitive. `TOOLS/LIST` is `tools/list`. `TOOLS/CALL`
is `tools/call`.

That allowlist is disjoint from `tools/call`, `resources/read`, and `prompts/get`.
A discovery or notification message is one JSON-RPC method. Its `params` are
data for that method. A nested `params.method` of `tools/call` is not a second
operation and is not rewritten into a privileged call. Names that only look
similar, such as `notifications/tools/call`, are not on the allowlist and
require a guard decision before they are forwarded.

The gateway does not treat discovery forwarding as privileged execution, and it
does not attest a client that connects to an MCP server directly. That path
stays `NOT_ROUTED`.

Every other well-formed method, including a method the gateway has not
classified, is sent to `/sdk/guard` as `mcp_call` before it is forwarded.
A missing or failed guard response is not forwarded. A malformed tool name,
resource URI, or prompt name is not forwarded even when a policy would allow
the call.
