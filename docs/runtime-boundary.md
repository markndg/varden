# Runtime boundary

Varden's **enforced runtime boundary** is the point at which a side-effecting
operation must receive a Varden decision **before** execution.

```text
capture → provenance → authority/delegation → policy → decision → side effect → evidence
```

Adapters (HTTP, subprocess, filesystem, MCP gateway, tools) classify differently
but all feed the **same** PolicyEngine via `POST /sdk/guard`.

## One-line protection

```python
import varden

varden.protect()
```

Default: `mode=guarded`, `fail_mode=closed`, automatic supported interceptors,
provenance propagation, authority enforcement, and coverage attestation.

Strict:

```python
varden.protect(mode="strict", require_coverage=["http", "subprocess", "mcp"])
```

## Modes

See [runtime-modes.md](runtime-modes.md).

## Coverage

See [runtime-coverage.md](runtime-coverage.md).

## MCP gateway

See [mcp-gateway.md](mcp-gateway.md).

## Approvals

See [approvals.md](approvals.md).

## Limitations

See [runtime-limitations.md](runtime-limitations.md).

**This is a runtime enforcement boundary, not an OS syscall sandbox.**
