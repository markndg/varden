# Arbiter LangChain integration

Arbiter ships an optional LangChain integration in `arbiter_langchain` (alias for `sentinel_langchain`).

It is designed to feel drop-in:

```python
from arbiter_langchain import protect_tools

tools = protect_tools(tools, agent_name='research-agent')
```

## What it does

- wraps LangChain-style tools before they execute
- sends pre-execution policy checks to Arbiter
- records outcomes for traces and decision drilldown
- adds callback events so chain and tool activity can be visualised in the dashboard

## Main APIs

### `protect_tools(...)`
Wrap an existing list of tools.

### `protect_agent(...)`
Instrument an agent object that already has a `tools` attribute.

### `create_protected_agent(...)`
Return a ready-to-wire bundle with:
- protected tools
- callback handlers
- workflow id metadata

## Example

```python
import arbiter
from arbiter_langchain import create_protected_agent

arbiter.protect_from_env(auto_instrument=False)

bundle = create_protected_agent(
    tools=tools,
    agent_name='support-agent',
)

protected_tools = bundle['tools']
callbacks = bundle['callbacks']
workflow_id = bundle['workflow_id']
```

## Demos

See:
- `demos/langchain/allow_warn_block_demo.py`
- `demos/langchain/sql_guard_demo.py`
- `demos/langchain/exfiltration_demo.py`

These are intended to give users walkthrough of:
- allowed execution
- warned external data movement
- blocked dangerous SQL
