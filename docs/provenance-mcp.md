# Provenance + MCP

- MCP tool definitions and results create provenance sources (`mcp_tool_definition` / `mcp_tool_response`).
- Servers cannot increase their own authority by advertising metadata.
- Cross-server flows (untrusted MCP → privileged MCP) raise `cross_server_authority_flow` / `confused_deputy`.
- Tool fingerprints are stored in `tool_fingerprints` for rug-pull / trust-drift detection (`GET /mcp/security/tools`).

An MCP host that does not expose causal context yields `provenance_complete=false`.
