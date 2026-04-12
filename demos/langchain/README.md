# Arbiter × LangChain demos

These demos show the `arbiter_langchain` (alias for `sentinel_langchain`) integration in a way that is easy to run and easy to understand.

## Install

```bash
pip install -e .[langchain]
```

## Start Arbiter

```bash
python -m sentinel.api --config examples/dev.env
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

Each demo emits Arbiter events and traces so you can inspect the flow in the dashboard.
