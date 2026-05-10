# Varden Monitor — `shell.execute` action schema

Varden Monitor wraps arbitrary host processes. Each invocation uses the same SDK path as in-process guards: **`VardenGuard.guarded_action`** (which calls **`POST /sdk/guard`**) before `exec`, then **`record_result`** (which calls **`POST /sdk/log`**) after the child exits. This document is the stable contract for policy authors.

## Action shape

- **`type`**: always `tool_call` (matches existing policy engine and dashboard).
- **`tool`**: always `shell.execute` (legacy `host.exec` is deprecated; policy should target `shell.execute`).
- **`args`** (dict):
  - **`argv`**: list of strings, truncated per element and total length (redaction; do not rely on full secrets never appearing in argv).
  - **`argv_join`**: single string, shell-quoted join of argv, truncated (~8k) for `field:args.argv_join` rules.
  - **`cwd`**: current working directory string (truncated).
  - **`env_keys`**: sorted list of **environment variable names only** (no values), capped (~200). Use for policies like “`RAILWAY_TOKEN` present” only if you add a rule on `field:args.env_keys` with `contains` (stringified list) or extend the engine later.
- **`metadata`**:
  - **`execution_surface`**: `varden_monitor` for `varden-monitor` / `varden monitor run`, or `varden_session` when launched from `varden session` (override with `VARDEN_EXECUTION_SURFACE`).
  - **`app_name`**: default `varden-monitor` for the standalone CLI; `varden-session` for PATH shims.
  - **`tenant`**: mirror of tenant id for SDK-style metadata.
- **`agent_name`**: from `--agent` or `VARDEN_AGENT_NAME` (default `varden-monitor` or `varden-session` in shims).
- **`trace_id`**: from `--trace` or `VARDEN_TRACE_ID`, else falls back to `workflow_id` if set.
- **`workflow_id`**: from `--workflow` or `VARDEN_WORKFLOW_ID`.
- **`tenant_id`**: from `--tenant` or `VARDEN_TENANT_ID` (default `default`).

## Raw payload (`guard` / classifier input)

The `payload` object alongside `action` mirrors `argv` / `cwd` with tighter caps for server-side classification in deep scan mode.

## Intelligence

When `tool` is `shell.execute` (or legacy `host.exec`), [varden/intelligence.py](../varden/intelligence.py) adds a base `host_exec` risk reason and boosts score when `argv_join` matches high-risk substrings (e.g. `rm -rf`, `terraform destroy`, `curl `). Tune policy for precise blocks/warns.

## Policy examples

Match destructive argv:

```json
{
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "rm -rf" }
}
```

Match Railway CLI invocations:

```json
{
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "railway" }
}
```

Prefer combining with other signals (warn vs block) to limit false positives.

## Session environment

When using `varden session` or `varden monitor .`, the shell exports:

- **`VARDEN_SESSION_ORIG_PATH`**: `PATH` before shims were prepended (used to locate the real CLI).
- **`VARDEN_SESSION_SHIM_DIR`**: directory containing generated wrappers (removed on process exit).
- **`VARDEN_SESSION_PASSIVE`**: when set to `1`, shims **execute first** and only **`/sdk/log`** records the run (passive / visibility mode).
- **`VARDEN_EXECUTION_SURFACE`**: defaults to `varden_session` in session subshells; shims and passive logging include it in `metadata.execution_surface`.

## CLI

See [README.md](README.md) for `varden-monitor`, `varden session`, and `varden monitor .` usage and environment variables.
