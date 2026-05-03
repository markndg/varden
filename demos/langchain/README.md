# Varden × LangChain demos

These demos show the `varden_langchain` integration with minimal setup:

```python
import varden
varden.protect(...)
```

Then the only LangChain-specific step is wrapping tools with `protect_tools(...)`.

## Install

```bash
pip install -e .[langchain]
```

## Start Varden

```bash
python -m varden.api --config examples/dev.env
```

## Run a demo

### 1. Full allow / warn / block walkthrough

```bash
python -m demos.langchain.allow_warn_block_demo
```

### 2. Dangerous SQL guard pack demo

```bash
python -m demos.langchain.sql_guard_demo
```

### 3. External data exfiltration warning demo

```bash
python -m demos.langchain.exfiltration_demo
```

Each demo emits Varden events and traces so you can inspect the flow in the dashboard.

