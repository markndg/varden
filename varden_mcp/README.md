# Varden MCP server

The Varden MCP server exposes the Varden control plane as [Model Context Protocol](https://modelcontextprotocol.io/) tools so MCP-capable hosts (Claude Code, Cursor, and others) can query events, inspect and update policy, read alerts and dashboards, and call guard/log endpoints from an agentic workflow. It speaks MCP over stdio and uses synchronous HTTP to the Varden API.

## Install

```bash
pip install varden[mcp]
```

For a local checkout:

```bash
pip install -e ".[mcp]"
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VARDEN_BASE_URL` | `http://127.0.0.1:8000` | Base URL of the running Varden control plane |
| `VARDEN_API_KEY` | `admin-demo-key` | API key sent as `Authorization: Bearer <key>` |
| `VARDEN_TIMEOUT` | `10.0` | Per-request timeout in seconds (float) |
| `VARDEN_MCP_AGENT_NAME` | `mcp` | Default `agent_name` when missing or a generic placeholder (`unknown`, `unknown_agent`, etc.); MCP overrides these so the UI does not label rows as unknown. |

The control plane UI scopes the overview by **agent name**. If `agent_name` is missing on events, they are hidden whenever a specific agent is selected in the UI—even though alerts and `/events` still see them. Guard and log tools therefore set `agent_name` to `VARDEN_MCP_AGENT_NAME` when it would otherwise be empty. Clear the agent filter in the UI, or pick this name in the agent dropdown, to see MCP-originated rows.

## Claude Code quick start

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "varden": {
      "command": "varden-mcp",
      "env": {
        "VARDEN_BASE_URL": "http://127.0.0.1:8000",
        "VARDEN_API_KEY": "admin-demo-key"
      }
    }
  }
}
```

## Conformance testing (mcp-test)

Once `mcp-test` is published:

```bash
mcp-test conformance --command varden-mcp \
  --server-arg --env VARDEN_BASE_URL=http://127.0.0.1:8000
```

## Tools

1. **varden_health** — Check control plane connectivity and health/bootstrap info.
2. **varden_get_events** — List recent decision events with pagination (`limit`, `offset`).
3. **varden_get_alerts** — List active alerts.
4. **varden_get_dashboard** — Dashboard overview (KPIs, counts, classifier rates).
5. **varden_get_policy** — Fetch the active policy document.
6. **varden_validate_policy** — Validate a proposed policy without applying it.
7. **varden_put_policy** — Replace the active policy (validate first).
8. **varden_get_policy_versions** — Policy version history.
9. **varden_guard** — Submit an action for an allow/warn/block decision; the server calls `/sdk/guard` then `/sdk/log` so the event stream reflects the check without a separate log call. Returns JSON with `decision`, `action`, `event_id`, `guard_http_status`, and `log`.
10. **varden_log_event** — Log an outcome to the event store without going through guard (for example after a tool has actually run).

`varden_guard` performs **both** `POST /sdk/guard` and `POST /sdk/log` in one tool call. The guard endpoint already persists a decision event; the follow-up log adds a second row with `output_payload.source` set to `varden_mcp` (and the guard `event_id`) so MCP-initiated checks are easy to spot in the stream. If `/sdk/log` fails, the tool still returns the guard `decision` and includes `log.log_failed` with an error string.
11. **varden_get_workflows** — List configured workflows.
12. **varden_get_jobs** — List recent background jobs and status.

## Cursor / MCP Inspector

The **command** in MCP settings must start the **server process** (stdio JSON-RPC), not a tool name. Tools such as `varden_health` only exist *after* the server is running; if the host tries to `spawn varden_health`, the **command** field was set to a tool name by mistake.

Use one of these:

| Situation | Command | Args (if separate) |
|-----------|---------|-------------------|
| Installed package, same PATH as your terminal | `varden-mcp` | _(none)_ |
| GUI app (Cursor) cannot find `varden-mcp` | `python3` | `-m`, `varden_mcp.server` |
| From repo with venv activated | path to venv `python` | `-m`, `varden_mcp.server` |

Example for Cursor **MCP** config (merge into your `mcp.json` / MCP servers UI):

```json
{
  "mcpServers": {
    "varden": {
      "command": "python3",
      "args": ["-m", "varden_mcp.server"],
      "env": {
        "VARDEN_BASE_URL": "http://127.0.0.1:8000",
        "VARDEN_API_KEY": "admin-demo-key"
      }
    }
  }
}
```

If you use `varden-mcp` as the command, leave **args** empty.

## Development

Run the MCP Inspector (requires `mcp[cli]`). The file argument is the **Python module** that defines the server; do not put a tool name there.

```bash
mcp dev varden_mcp/server.py
```

After the Inspector connects, invoke tools (e.g. `varden_health`) from the tool list in the UI—not as the spawn command.
