# Sentinel × LangChain demos

These demos show the official `sentinel_langchain` integration in a way that is easy to run and easy to understand.

## Install

```bash
pip install -e .[langchain]
```

## Start Sentinel

```bash
python -m sentinel.api --config examples/dev.env
```

## Run a demo

### 1. Full allow / warn / block walkthrough

```bash
python demos/langchain/allow_warn_block_demo.py
```

### 2. Dangerous SQL guard pack demo

```bash
python demos/langchain/sql_guard_demo.py
```

### 3. External data exfiltration warning demo

```bash
python demos/langchain/exfiltration_demo.py
```

Each demo emits Sentinel events and traces so you can inspect the flow in the dashboard.
