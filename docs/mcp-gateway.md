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
