# Sentinel OSS demos

These demos are intentionally shaped to prove that the developer experience is:

import sentinel
sentinel.protect()

That is the only Sentinel setup in the demo files.

## Blocked demo

```bash
python demos/blocked_tool_agent.py
```

What it proves:
- you do **not** need `@sentinel.tool`
- you do **not** need to pass config into `protect()` for local OSS use
- one-line protection intercepts a dangerous subprocess
- Sentinel blocks the action before execution and records the event

## Warned demo

```bash
python demos/flagged_data_agent.py
```

What it proves:
- you do **not** need explicit tagged data helpers
- you do **not** need to pass config into `protect()` for local OSS use
- one-line protection intercepts an outbound HTTP request
- sensitive markers in the payload are classified and surfaced as a warn path

Before running the demos, start the Sentinel control plane locally. After running them, open the dashboard at `/` and the dedicated rules page at `/ui/rules`.


## Allowed demo

```bash
python demos/allowed_safe_agent.py
```

What it proves:
- one-line protection does not get in the way of ordinary safe agent work
- Sentinel records the event, trace, and allow decision
- the command center can now show blocked, warned, and allowed flows side by side


## LangChain demos

Official LangChain integration demos live in `demos/langchain/`:
- `allow_warn_block_demo.py`
- `sql_guard_demo.py`
- `exfiltration_demo.py`

These are intended to be the fastest way for OSS users to see Sentinel protecting a framework they already know.
