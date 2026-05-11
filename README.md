# Varden

<img src="varden/web/assets/varden-icon.png" alt="Varden logo" width="128" />

**Project links:** [Source](https://github.com/markndg/varden) · [Issues](https://github.com/markndg/varden/issues) · [Security](https://github.com/markndg/varden/security)

**Varden is a self-hosted runtime firewall for AI agents.**
It sits between agent reasoning and action execution so teams can allow, warn, or block tool calls, HTTP requests, LLM calls, and workflow steps from infrastructure they run themselves.

Key Features:
- 5-minute local start
- one-line Python protection with `varden.protect()`
- deep scan mode by default for full classifier and risk enrichment (optional **fast** scan mode for lower overhead when policy allows)
- production-style dashboard at `/`
- dedicated visual rules page at `/ui/rules`
- working demo agents that show a blocked action and a warned action
- end-to-end trace IDs and parent/child event linkage for agent decision chains
- trace and behaviour explainability APIs for graphing suspicious sequences
- self-hosted single-tenant control plane with policy management, events, alerts, workflows, jobs, and metrics

---

## Why Varden exists

Most AI security products still focus on the chatbot threat model: prompt in, response out.
Varden protects the **agent runtime** instead:

- tool execution
- HTTP/API calls
- LLM provider calls
- data movement and inferred lineage
- workflow execution visibility

That makes it useful for teams building internal agents, copilots, orchestration layers, and mixed internal/external LLM systems.

---

## What you get in this release

### Runtime enforcement
- policy engine with `allow`, `warn`, `block`, and `monitor` paths
- useful set of starter policy packs
- classifier-assisted decisions for secrets, PII, and internal data markers
- action logging for tool calls, HTTP calls, and LLM calls
- Python SDK with invisible runtime protection via `varden.protect()`
- optional `varden.trace_agent(...)`, `varden.tool(...)`, and tagging helpers for advanced use cases only

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

Clone this repository and install in editable mode (**not on PyPI yet**—`pip install varden` will follow). The distribution name will be **`varden`**; import paths are `varden`, `varden_sdk`, `varden_langchain`, and `varden_monitor`.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

### 2) Create a starter `policy.json`

The control plane loads **`policy.json`** at the project root (`VARDEN_POLICY_FILE`). It must be a single JSON document with four top-level lists: `block`, `warn`, `monitor`, and `allow` (see [Policy model](#policy-model)).

Bootstrap a full baseline from the bundled pack (recommended):

```bash
python -c "import json, pathlib; p=pathlib.Path('policy-packs/baseline-operational-safety.json'); pathlib.Path('policy.json').write_text(json.dumps(json.loads(p.read_text(encoding='utf-8'))['template'], indent=2) + '\n', encoding='utf-8')"
```

PowerShell:

```powershell
python -c "import json, pathlib; p=pathlib.Path('policy-packs/baseline-operational-safety.json'); pathlib.Path('policy.json').write_text(json.dumps(json.loads(p.read_text(encoding='utf-8'))['template'], indent=2) + chr(10), encoding='utf-8')"
```

### 3) Start Varden

```bash
python -m varden.api --config examples/dev.env
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

## `varden session`: guard cloud and ops CLIs from your shell

After `pip install -e .`, the **`varden session`** command starts an interactive shell (or a one-shot command) with a temporary **`PATH` prefix** so selected binaries are **resolved through Varden** instead of calling the real tools directly. Each shim forwards to the real executable on your original `PATH`, sends a **shell-execute** action to the control plane (`VARDEN_BASE_URL`), and either **enforces** policy before run or, in passive mode, **runs first and logs** the outcome.

**When to use it:** wrap everyday operator workflows—Kubernetes, Terraform, cloud CLIs, Docker, package managers, Git, database clients, and common deploy targets—so decisions and traces land in the same dashboard as Python `varden.protect()` traffic.

**Shimmed commands** (first on `PATH` inside the session): `railway`, `supabase`, `vercel`, `fly`, `render`, `kubectl`, `terraform`, `aws`, `gcloud`, `az`, `psql`, `mysql`, `git`, `npm`, `pip`, `pip3`, `docker`, `docker-compose`, `cursor`.

**Examples**

```bash
# Start a subshell in the current directory (enforcing: guard → exec → log)
export VARDEN_BASE_URL=http://127.0.0.1:8000
export VARDEN_API_KEY=admin-demo-key
varden session

# Same, but log-only (no guard before exec; still posts telemetry)
varden session --passive

# Session rooted in another directory
varden session ~/src/my-infra

# One-shot: run a single guarded command, then exit
varden session -- kubectl get pods -A

# Open the current folder in Cursor; the `cursor` CLI goes through the shim (this launch is guarded and logged).
# Child processes inside the IDE may not inherit the session PATH unless Cursor forwards it (use an interactive `varden session` shell for full coverage).
varden session . -- cursor .
```


**Behaviour notes**

- **Enforcing (default):** each shim uses the same guard → execute → log pipeline as `varden monitor`; blocks surface as a failed invocation with policy context in the control plane.
- **`--passive`:** the real command always runs; Varden records an allowed decision with execution metadata afterward (useful for gradual rollout or inventory).
- The session sets **`VARDEN_AGENT_NAME=varden-session`**, **`VARDEN_EXECUTION_SURFACE=varden_session`**, and a **`VARDEN_TRACE_ID`** if one is not already set. Shims honour **`VARDEN_MONITOR_*`** (timeout, caps, fail mode) alongside the usual **`VARDEN_BASE_URL`** / **`VARDEN_API_KEY`** (or bearer token) variables.
- On macOS, if `cursor` is not on your normal `PATH`, the shim tries known paths under `Cursor.app`.

Exit the subshell to tear down the temporary shim directory.

---

## First-run demo flow

### Fastest path

```bash
python -m varden.cli demo
```

That starts the local stack, seeds one allowed, one warned, and one blocked trace, and opens the command center.

If you installed the package and have the console script on your `PATH`, this equivalent command also works:

```bash
varden demo
```


After the API is running, open a second terminal and run the demo agents.

### Demo 1: blocked subprocess

```bash
python demos/blocked_tool_agent.py
```

What it does:
- runs normal application code
- attempts a dangerous subprocess command containing `delete_database`
- Varden blocks it before execution
- a blocked event is written to the control plane

### Demo 2: warned outbound HTTP action

```bash
python demos/flagged_data_agent.py
```

What it does:
- sends an outbound HTTP request containing internal/secrets markers
- Varden classifies the payload automatically
- Varden warns, logs classifiers, and still records the event even if the remote call fails

### What you should see in the dashboard

After running the demos, the dashboard should show:
- a blocked event for `subprocess.run`
- a warned event for the outbound `httpx` request
- updated KPIs, flow panels, recent events, classifier hits, fast-path latency metrics, and trace summaries

---


## LangChain integration

Varden ships a first-class optional LangChain integration in `varden_langchain` so teams can add policy enforcement and tracing to LangChain tools without rewriting their app architecture.

### Install

```bash
pip install -e .[langchain]
```

### Drop-in usage

```python
import varden
from varden_langchain import protect_tools

varden.protect_from_env(auto_instrument=False)
tools = protect_tools(tools, agent_name='support-agent')
```

Optional: combine callbacks and wrapped tools in one step:

```python
import varden
from varden_langchain import create_protected_agent

varden.protect_from_env(auto_instrument=False, app_name="langchain-app")
protected = create_protected_agent(tools=my_tools, agent_name="research-agent")
agent = initialize_agent(
    tools=protected["tools"],
    llm=llm,
    callbacks=protected["callbacks"],
)
```

### What you get

- pre-execution allow / warn / block checks on tool calls
- LangChain callback events for traces and chain visibility
- dashboard-linked traces, decisions, and rule hits
- support for wrapping tools directly or instrumenting an agent object

### LangChain demo set

Run these after Varden is up:

```bash
python demos/langchain/allow_warn_block_demo.py
python demos/langchain/sql_guard_demo.py
python demos/langchain/exfiltration_demo.py
```

The demos are designed to look good on the dashboard:
- a clear allowed tool call
- a warned outbound data movement attempt
- a blocked dangerous SQL action

See also: `docs/langchain.md`

---

## Python: one-line protection

```python
import varden
import requests

varden.protect()

requests.post(
    "https://partner.example/api/report",
    json={"notes": "internal only customer data", "token": "abc123"},
    timeout=2,
)
```

### What `protect()` does

With zero extra developer instrumentation, Varden patches common Python runtime paths so actions are checked by the control plane:

- `requests`
- `httpx` sync and async clients
- `subprocess.run` and `subprocess.Popen`
- OpenAI Responses and Chat Completions, if installed
- Anthropic Messages, if installed
- future imports of those libraries after `protect()` is called

Varden sends pre-execution checks to:
- `POST /sdk/guard`

and outcome logging to:
- `POST /sdk/log`

### Environment-based configuration

```python
import varden

varden.protect_from_env()
```

Environment variables for local or self-hosted rollouts:

```text
VARDEN_BASE_URL=http://127.0.0.1:8000
VARDEN_API_KEY=admin-demo-key
VARDEN_APP_NAME=my-app
VARDEN_MODE=enforce
VARDEN_AUTO_INSTRUMENT=true
VARDEN_FAIL_MODE=open
VARDEN_TIMEOUT=5.0
```

### Scan modes

Varden defaults to **deep** mode to keep the policy path fully enforced. Toggle between the two within app.

```text
VARDEN_SCAN_MODE=fast
```

Fast mode:
- always enforces direct tool and field rules
- only runs classifier or risk enrichment when the active policy needs it
- records decision latency so teams can validate overhead

Deep mode:

```text
VARDEN_SCAN_MODE=deep
```

Deep mode:
- always runs classifier + risk enrichment
- is slower but richer for investigations and tighter policies

Because scan depth is set on the control plane, developers cannot silently bypass it in application code.

---

## Policy model

Policies are a single JSON document saved as **`policy.json`** (or the path in **`VARDEN_POLICY_FILE`**). The runtime expects **four arrays** at the top level:

| Key | Role |
|-----|------|
| `block` | Deny the action before it runs when a rule matches. |
| `warn` | Allow but flag; downstream intelligence may raise risk. |
| `monitor` | Observed and logged; use for broad coverage of tool or channel types. |
| `allow` | Optional explicit **allow** decisions with a matched rule (only evaluated if nothing matched in `block`, `warn`, or `monitor`). |

**How matching works:** the engine walks the buckets in order **`block` → `warn` → `monitor` → `allow`**. For each bucket it scans rules **in list order** and returns as soon as **one rule matches** the normalized action; that bucket sets the outcome (`block`, `warn`, `monitor`, or `allow`). If **no** rule matches in **any** bucket, the action is **allowed** by default. Optional per-rule metadata such as `name`, `title`, `description`, `priority`, and `reason` is carried for the UI and audit output; **`enabled: false` skips a rule.**

**What a rule looks like:** each rule is a JSON object whose **predicate keys** are compared to fields on the action, for example:

- **Action type and tool:** `type` (e.g. `tool_call`, `http_request`, `llm_call`), `tool`, `url`, `domain`, `method`
- **Arguments and payload:** `field:args.args`, `field:args.kwargs` with operators such as `{ "contains": "substring" }`, `{ "in": ["a", "b"] }`, `{ "gte": 60 }`, `{ "exists": true }`, `startswith`, `endswith`, `eq`, `lte`
- **Classifiers and risk:** `classifier:secrets`, `classifier:internal`, `min_risk_score`, `field:risk_score`, and other classifier or metadata keys the guard populates
- **Nested metadata:** keys starting with `metadata.` for behaviour or enrichment features

**Where to start:** import or merge the `template` section from files in **`policy-packs/`** (see `policy-packs/README.md`), use **`GET /policy/templates`** for SQL-oriented starter fragments, or author rules in the visual editor at **`/ui/rules`**, which reads and writes the same four-list document.

**Minimal example** (illustrative only; real policies are usually larger):

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

The dashboard has been designed to be feature rich, built using React + typescript.

Frontend source lives in `frontend/` and can be worked on independently:

- `cd frontend && npm install`
- `npm run dev` for local UI development
- `npm run build` to emit production assets into `varden/web/app`

The backend continues to serve the UI at `/ui` and `/ui/rules`, so deployment and existing routes stay unchanged.

## Self-hosting

Varden is designed so teams and/or developers can run it themselves.

Use:
- `deploy/docker-compose.yml`
- `deploy/self_hosting.md`
- `deploy/operations.md`

Notes:
- local/dev defaults use SQLite for fast adoption
- production self-hosting should disable dev bootstrap auth and set a strong signing secret
- the dashboard auto-loads the bootstrap API key from `/health` in local dev mode
- this distribution is intentionally **single-tenant**; multi-tenant enterprise governance APIs are not part of the default product surface

---

## Included demos and examples

- `demos/blocked_tool_agent.py`
- `demos/flagged_data_agent.py`
- `demos/README.md`

These are intended to be the shortest path from clone to “I can see Varden doing useful work.”

---

## Language SDKs

This repository also includes starter SDKs for:
- `sdks/rust`
- `sdks/java`

Python is the most complete runtime-integrated path in this repository.


## License

Varden uses a split license model:
- **Core platform and dashboard** are licensed under **AGPL-3.0-or-later**.
- **SDKs** in `sdks/python`, `sdks/java`, and `sdks/rust` are licensed under **Apache-2.0**.

For AGPL-covered components, anyone who modifies and runs Varden for users over a network must make the corresponding source code for those modifications available to those users.

This is a strong **copyleft** option if you want to discourage companies from taking the code, modifying it, and quietly running it as a closed hosted service.

Important: no OSI-approved license prevents people from copying or modifying code entirely. If you eventually want stronger commercial restrictions than AGPL permits, the usual path is **dual licensing**: keep the AGPL-licensed tree available under AGPL and offer separate commercial terms for customers who do not want AGPL obligations.

## Repository hygiene

This repository includes:
- `LICENSE` with the full AGPL-3.0-or-later text
- `AUTHORS` listing project authorship
- `NOTICE` for copyright and branding notice
- `.gitignore` for Python, Node, JVM build artifacts (`*.class`, `sdks/java/target/`), and local runtime state
- `.gitattributes` for line endings and generated frontend assets
- `CODEOWNERS`, `CONTRIBUTING.md`, and `SECURITY.md` to support a clean contribution workflow
