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
varden coverage --json
varden runtime status
varden runtime readiness --json
```

```http
GET /runtime/coverage
```

There is **no vanity protection percentage** unless a denominator is explicitly defined.

A verified `varden session` contract does not change subprocess coverage to
`ENFORCED`. The shim is one layer. The child holds the verification key, so
same-user replacement of that key, the contract, or the control-plane URL, and
direct execution of the real binary, remain outside it.

Strict readiness is `READY` / `NOT READY` with a list of missing required surfaces.
