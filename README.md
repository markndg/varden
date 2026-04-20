# Arbiter OSS

![Arbiter logo](sentinel/web/assets/sentinel-icon.png)

**Arbiter OSS is a self-hosted runtime firewall for AI agents.**
It sits between agent reasoning and action execution so teams can allow, warn, or block tool calls, HTTP requests, LLM calls, and workflow steps from infrastructure they run themselves.

This OSS edition is shaped for adoption:
- 5-minute local start
- one-line Python protection with `arbiter.protect()`
- fast mode by default for low overhead
- optional deep scan mode for slower, richer inspection
- production-style dashboard at `/`
- dedicated visual rules page at `/ui/rules`
- working demo agents that show a blocked action and a warned action
- end-to-end trace IDs and parent/child event linkage for agent decision chains
- trace and behaviour explainability APIs for graphing suspicious sequences
- self-hosted single-tenant control plane with policy management, events, alerts, workflows, jobs, and metrics

---

## Why Arbiter OSS exists

Most AI security products still focus on the chatbot threat model: prompt in, response out.
Arbiter protects the **agent runtime** instead:

- tool execution
- HTTP/API calls
- LLM provider calls
- data movement and inferred lineage
- workflow execution visibility

That makes it useful for teams building internal agents, copilots, orchestration layers, and mixed internal/external LLM systems.

---

## What you get in this OSS release

### Runtime enforcement
- policy engine with `allow`, `warn`, `block`, and `monitor` paths
- classifier-assisted decisions for secrets, PII, and internal data markers
- action logging for tool calls, HTTP calls, and LLM calls
- Python SDK with invisible runtime protection via `arbiter.protect()`
- optional `arbiter.trace_agent(...)`, `arbiter.tool(...)`, and tagging helpers for advanced use cases only

### Self-hosted control plane
- dashboard at `/`
- health/bootstrap endpoint at `/health`
- policy editing, validation, version history, and a dedicated visual rules page at `/ui/rules`
- events, alerts, workflows, jobs, and dashboard overview APIs
- single-tenant local auth for simple self-hosted evaluation

### Developer adoption features
- local SQLite-backed start for instant evaluation
- self-host docs and Docker Compose deployment
- demo agent scripts in `demos/`
- Rust and Java SDK starter clients for platform parity

---

## 5-minute quick start

### 1) Create a virtual environment and install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

### 2) Copy the demo policy

```bash
copy examples\policy.json policy.json
```

### 3) Start Arbiter

```bash
python -m sentinel.api --config examples/dev.env
```

### 4) Open the UI

- Dashboard: `http://127.0.0.1:8000/`
- Rules: `http://127.0.0.1:8000/ui/rules`
- Health/bootstrap: `http://127.0.0.1:8000/health`
- OpenAPI docs: `http://127.0.0.1:8000/docs`

For local dev, the bootstrap API key is:

```text
admin-demo-key
```

---

## First-run demo flow

### Fastest path

```bash
arbiter demo
```

That starts the local OSS stack, seeds one allowed, one warned, and one blocked trace, and opens the command center.


After the API is running, open a second terminal and run the demo agents.

### Demo 1: blocked subprocess

```bash
python demos/blocked_tool_agent.py
```

What it does:
- runs normal application code
- attempts a dangerous subprocess command containing `delete_database`
- Arbiter blocks it before execution
- a blocked event is written to the control plane

### Demo 2: warned outbound HTTP action

```bash
python demos/flagged_data_agent.py
```

What it does:
- sends an outbound HTTP request containing internal/secrets markers
- Arbiter classifies the payload automatically
- Arbiter warns, logs classifiers, and still records the event even if the remote call fails

### What you should see in the dashboard

After running the demos, the dashboard should show:
- a blocked event for `subprocess.run`
- a warned event for the outbound `httpx` request
- updated KPIs, flow panels, recent events, classifier hits, fast-path latency metrics, and trace summaries

---


## Official LangChain integration

Arbiter ships a first-class optional LangChain integration in `arbiter_langchain` (alias for `sentinel_langchain`) so teams can add policy enforcement and tracing to LangChain tools without rewriting their app architecture.

### Install

```bash
pip install -e .[langchain]
```

### Drop-in usage

```python
import arbiter
from arbiter_langchain import protect_tools

arbiter.protect_from_env(auto_instrument=False)
tools = protect_tools(tools, agent_name='support-agent')
```

### What you get

- pre-execution allow / warn / block checks on tool calls
- LangChain callback events for traces and chain visibility
- dashboard-linked traces, decisions, and rule hits
- support for wrapping tools directly or instrumenting an agent object

### LangChain demo set

Run these after Arbiter is up:

```bash
python demos/langchain/allow_warn_block_demo.py
python demos/langchain/sql_guard_demo.py
python demos/langchain/exfiltration_demo.py
```

The demos are designed to look good in the OSS dashboard:
- a clear allowed tool call
- a warned outbound data movement attempt
- a blocked dangerous SQL action

See also: `docs/langchain.md`

---

## Python: one-line protection

```python
import arbiter
import requests

arbiter.protect()

requests.post(
    "https://partner.example/api/report",
    json={"notes": "internal only customer data", "token": "abc123"},
    timeout=2,
)
```

### What `protect()` does

With zero extra developer instrumentation, Arbiter patches common Python runtime paths so actions are checked by the control plane:

- `requests`
- `httpx` sync and async clients
- `subprocess.run` and `subprocess.Popen`
- OpenAI Responses and Chat Completions, if installed
- Anthropic Messages, if installed
- future imports of those libraries after `protect()` is called

Arbiter sends pre-execution checks to:
- `POST /sdk/guard`

and outcome logging to:
- `POST /sdk/log`

### Environment-based configuration

```python
import arbiter

arbiter.protect_from_env()
```

Environment variables for local or self-hosted rollouts:

```text
SENTINEL_BASE_URL=http://127.0.0.1:8000
SENTINEL_API_KEY=admin-demo-key
SENTINEL_APP_NAME=my-app
SENTINEL_MODE=enforce
SENTINEL_AUTO_INSTRUMENT=true
SENTINEL_FAIL_MODE=open
SENTINEL_TIMEOUT=5.0
```

### Scan modes

Arbiter OSS defaults to **fast** mode to keep the policy path lightweight.

```text
SENTINEL_SCAN_MODE=fast
```

Fast mode:
- always enforces direct tool and field rules
- only runs classifier or risk enrichment when the active policy needs it
- records decision latency so teams can validate overhead

Deep mode:

```text
SENTINEL_SCAN_MODE=deep
```

Deep mode:
- always runs classifier + risk enrichment
- is slower but richer for investigations and tighter policies

Because scan depth is set on the control plane, developers cannot silently bypass it in application code.

---

## Policy model

The default OSS policy is in `examples/policy.json` and can be changed centrally from `/ui/rules`:

```json
{
  "block": [
    {"type": "tool_call", "tool": "delete_database"},
    {"type": "tool_call", "tool": "subprocess.run", "field:args.args": {"contains": "delete_database"}}
  ],
  "warn": [
    {"classifier:internal": true},
    {"classifier:secrets": true}
  ],
  "monitor": [],
  "allow": []
}
```

This gives a useful first-run story:
- dangerous destructive tools are blocked
- internal/secrets content is surfaced as a warn path

---

## Core API surface

### Runtime and dashboard
- `GET /health`
- `GET /dashboard/overview`
- `GET /events`
- `GET /alerts`
- `GET /workflows`
- `GET /jobs`
- `GET /policy`
- `PUT /policy`
- `POST /policy/validate`
- `GET /policy/versions`

### SDK ingestion
- `POST /sdk/guard`
- `POST /sdk/log`
- aliases under `/v1/actions/...`

### Demo endpoint
- `POST /demo/tool`

---


## Dashboard frontend

The dashboard has been rebuilt as a typed React + TypeScript application and compiled into static assets served by the FastAPI control plane.

Frontend source lives in `frontend/` and can be worked on independently:

- `cd frontend && npm install`
- `npm run dev` for local UI development
- `npm run build` to emit production assets into `sentinel/web/app`

The backend continues to serve the UI at `/ui` and `/ui/rules`, so deployment and existing routes stay unchanged.

## Self-hosting

Arbiter OSS is designed so teams can run it themselves.

Use:
- `deploy/docker-compose.yml`
- `deploy/self_hosting.md`
- `deploy/operations.md`

Notes:
- local/dev defaults use SQLite for fast adoption
- production self-hosting should disable dev bootstrap auth and set a strong signing secret
- the dashboard auto-loads the bootstrap API key from `/health` in local dev mode
- this OSS release is intentionally single-tenant and does not include enterprise governance APIs

---

## Included demos and examples

- `demos/blocked_tool_agent.py`
- `demos/flagged_data_agent.py`
- `demos/README.md`

These are intended to be the shortest path from clone to “I can see Arbiter doing useful work.”

---



## LangChain integration

Arbiter includes a drop-in `arbiter_langchain` (alias for `sentinel_langchain`) integration package for protecting LangChain tool execution without relying on fragile monkey patching. The recommended model is:

- wrap tools with `protect_tools(...)` for allow / warn / block enforcement
- attach `ArbiterCallbackHandler(...)` for chain, tool, and LLM trace events
- or use `create_protected_agent(...)` to get both in one step

```python
import arbiter
from arbiter_langchain import create_protected_agent

arbiter.protect_from_env(auto_instrument=False, app_name="langchain-app")
protected = create_protected_agent(tools=my_tools, agent_name="research-agent")
agent = initialize_agent(
    tools=protected["tools"],
    llm=llm,
    callbacks=protected["callbacks"],
)
```

A lightweight demo lives at `demos/langchain_integration_demo.py`.

## Language SDKs

This repository also includes starter SDKs for:
- `sdks/rust`
- `sdks/java`

Python is the most complete runtime-integrated path in this OSS release.


## License

Arbiter OSS is licensed under **AGPL-3.0-or-later**. That means anyone who modifies and runs Arbiter for users over a network must make the corresponding source code for those modifications available to those users.

This is the strongest widely adopted **open-source** option if you want to discourage companies from taking the code, modifying it, and quietly running it as a closed hosted service.

Important: no OSI-approved open-source license prevents people from copying or modifying code entirely. If you eventually want stronger commercial restrictions than AGPL permits, the usual path is **dual licensing**: keep OSS under AGPL and offer separate commercial terms for customers who do not want AGPL obligations.

## Repository hygiene

This repository includes:
- `LICENSE` with the full AGPL-3.0-or-later text
- `AUTHORS` listing project authorship
- `NOTICE` for copyright and branding notice
- `.gitignore` for Python, Node, and local runtime state
- `.gitattributes` for line endings and generated frontend assets
- `CODEOWNERS`, `CONTRIBUTING.md`, and `SECURITY.md` to support a clean OSS workflow



## New in this OSS cut

- `trace_id` propagation across SDK-guarded actions
- parent-child event linkage for replayable decision chains
- `/traces/{trace_id}` API for graph-ready execution traces
- behavioural enrichment in the intelligence layer, including suspicious multi-step sequence scoring
- policy template for warning on suspicious sequences

## Included OSS policy packs

Arbiter now ships with an out-of-the-box database safety pack for agent-written SQL. The default policy blocks destructive database operations and warns on suspect SQL patterns such as schema enumeration, broad reads from sensitive tables, `SELECT *`, and missing `LIMIT` clauses on reads.

Included SQL protections:
- block destructive SQL such as `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, dangerous privilege changes, unbounded `DELETE` / `UPDATE`, and multi-statement SQL
- warn on schema enumeration via `information_schema`, `pg_catalog`, `sqlite_master`, `SHOW TABLES`, and similar patterns
- warn on broad reads from sensitive tables, `SELECT *`, `UNION SELECT`, and read queries without a `LIMIT`
- monitor common SQL execution tools including `sql.query`, `db.query`, `postgres.query`, `mysql.query`, `sqlite.query`, `psycopg.execute`, `cursor.execute`, and `sqlalchemy.execute`

The policy templates `block_dangerous_database_operations` and `warn_suspect_sql_operations` are available from the policy API and are also reflected in the default `policy.json`.
