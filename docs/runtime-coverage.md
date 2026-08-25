# Runtime coverage

Coverage is based on **active instrumentation**, not marketing claims.

Statuses:

* `ENFORCED`
* `PARTIAL`
* `OBSERVATIONAL`
* `UNCOVERED`
* `UNSUPPORTED`
* `NOT_ROUTED` (MCP until gateway-wrapped)

```bash
varden coverage
varden runtime status
```

```http
GET /runtime/coverage
```

There is **no vanity protection percentage** unless a denominator is explicitly defined.

Strict readiness is `READY` / `NOT READY` with a list of missing required surfaces.
