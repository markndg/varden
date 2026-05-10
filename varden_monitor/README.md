# Varden Monitor

Apache-2.0 host CLI that runs **`POST /sdk/guard`** before and **`POST /sdk/log`** after a subprocess. Use it to put **Cursor terminals**, **task runners**, or **CI steps** on the same policy rail as in-process SDK usage—without modifying closed-source IDEs.

## Requirements

- Python 3.10+
- A running Varden control plane (same machine or URL)
- Credentials: `VARDEN_API_KEY` or `VARDEN_BEARER_TOKEN`, optional `VARDEN_BASE_URL` (default `http://127.0.0.1:8000`)

## Usage

```bash
varden-monitor run -- python -V
# or, from the platform CLI:
varden monitor run -- python -V
```

Place **`--`** before the command you want to execute.

### Options

| Flag / env | Meaning |
|------------|---------|
| `--base-url` / `VARDEN_BASE_URL` | Varden API base URL |
| `--api-key` / `VARDEN_API_KEY` | API key header |
| `--bearer` / `VARDEN_BEARER_TOKEN` | Bearer token |
| `--agent` / `VARDEN_AGENT_NAME` | `agent_name` on events (default `varden-monitor`) |
| `--trace` / `VARDEN_TRACE_ID` | Trace id |
| `--workflow` / `VARDEN_WORKFLOW_ID` | Workflow id |
| `--tenant` / `VARDEN_TENANT_ID` | Tenant (default `default`) |
| `--fail-mode open\|closed` / `VARDEN_MONITOR_FAIL_MODE` | `open`: if guard/log HTTP fails, still run command; `closed`: abort |
| `--timeout` / `VARDEN_MONITOR_TIMEOUT` | HTTP timeout seconds |
| `--stdout-cap` / `--stderr-cap` | Max chars of child output stored in log payload |

## `varden monitor .` (passive)

Shorthand for a **passive session**: same PATH shims as `varden session --passive .`, but the shims **run the real binary first** and **log** the outcome to Varden with an allow decision (visibility without blocking). Use when you want telemetry without enforcement.

```bash
varden monitor .
```

## `varden session` (PATH shims)

Starts a subshell (or runs one command) with a **temporary directory prepended to `PATH`**. That directory contains small wrappers for common CLIs (`railway`, `kubectl`, `terraform`, `docker`, `npm`, …). Each wrapper resolves the **real** binary using the original `PATH` (`VARDEN_SESSION_ORIG_PATH`), then runs **`python -m varden_monitor.shim_runner <name> …`**, which calls **`/sdk/guard`** before exec (unless `--passive`). If policy **blocks**, the real binary is never started.

```bash
varden session .
varden session . -- cursor .
varden session /path/to/repo -- terraform plan
varden session --passive .   # log-only shims
```

Also available as `varden-session` if installed from `pyproject` scripts.

## Cursor and other IDEs

Varden does **not** inject into proprietary editor binaries. Run **`varden session . -- cursor .`** from a normal terminal so Cursor inherits the protected `PATH`, or configure the IDE terminal profile to use a shell started via `varden session`. Anything not launched through that environment is outside this MVP.

## Action schema

See [SCHEMA.md](./SCHEMA.md) for the `shell.execute` payload contract used with `/sdk/guard`.
