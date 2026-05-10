# Varden Python SDK

This directory contains the Apache-2.0 licensed Python SDK implementation and
its standalone packaging metadata.

Primary import surface:

```python
import varden
varden.protect()
```

Local package install from this directory:

```bash
pip install .
```

Editable install for development:

```bash
pip install -e .
```

After publish, users can install directly with:

```bash
pip install varden
```

From the **monorepo** root install (`pip install -e .`) also exposes **`varden-monitor`** and **`varden-session`**, plus `varden monitor` / `varden session` on the platform CLI. See [varden_monitor/README.md](../../varden_monitor/README.md) for PATH-shim sessions and passive `varden monitor .`.
