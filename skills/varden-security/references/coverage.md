# Coverage states & attestation

Varden coverage is **active instrumentation attestation**, not a marketing score.
There is no vanity protection percentage.

## Three related concepts

```text
coverage  = what execution surfaces Varden can currently observe/enforce
readiness = whether configured runtime requirements are satisfied
posture   = Varden's authoritative interpretation of the current enforcement state
```

| Question | Answered by |
|----------|-------------|
| Could Varden reliably determine and report its state? | Attestation validity (`verification.attestation`) |
| Are required / discovered surfaces satisfied? | Readiness |
| What does that mean for overall protection? | **`varden posture`** |

These are not the same. Do **not** treat "coverage command succeeded" as
`PROTECTED`. Prefer:

```bash
varden posture --json
```

Supporting detail:

```bash
varden coverage --json
varden runtime readiness --json
varden runtime status
varden runtime self-test
```

HTTP equivalents (control plane):

* `GET /runtime/posture`
* `GET /runtime/coverage`
* `GET /runtime/readiness`
* `GET /runtime/status`

Parse JSON. Do not invent states from log prose.

## Posture result vocabulary

Stable lowercase JSON values:

| Result | Meaning |
|--------|---------|
| `protected` | Enforcing runtime ready; all **applicable** surfaces ENFORCED |
| `protected_with_gaps` | Enforcing runtime active; applicable incomplete coverage remains |
| `not_fully_routed` | Applicable surface is `NOT_ROUTED` (often MCP) |
| `not_ready` | Readiness contract failed for non-routing reasons |
| `not_protected` | No meaningful active enforcing boundary |

`PARTIAL` ≠ `PROTECTED`. An applicable `PARTIAL` / `UNCOVERED` /
`UNSUPPORTED` / `OBSERVATIONAL` / `NOT_ROUTED` surface prevents `protected`.

### Applicability

Surfaces may be catalogued but **not applicable** to the current runtime
(e.g. MCP with no discovered config and not required). Non-applicable
`NOT_ROUTED` must not force `not_fully_routed`.

MCP becomes applicable when:

* MCP config is discovered, or
* `require_coverage` includes `mcp`, or
* the gateway marks MCP `ENFORCED`

### Precedence (simplified)

```text
NOT_PROTECTED → NOT_READY → NOT_FULLY_ROUTED → PROTECTED_WITH_GAPS → PROTECTED
```

Routing-only readiness failures (applicable `NOT_ROUTED`) map to
`not_fully_routed` rather than generic `not_ready`.

## Status vocabulary (per surface)

| Status | Operational meaning |
|--------|---------------------|
| `ENFORCED` | Known calls through that specific supported surface are pre-execution guarded under active instrumentation |
| `PARTIAL` | Some paths through the surface can bypass enforcement |
| `OBSERVATIONAL` | Varden receives events but cannot prevent execution |
| `UNCOVERED` | Known execution path is not intercepted |
| `UNSUPPORTED` | Surface is known but not automatically instrumented |
| `NOT_ROUTED` | A routable enforcement mechanism exists but traffic is not currently using it |

Category rollups may show `ENFORCED VIA GATEWAY` for MCP when the gateway path
is active. Treat that as gateway-enforced, not as proof that direct MCP
connections are covered.

Strict readiness (`varden runtime readiness --json`) reports:

* `READY`
* `READY WITH EXCEPTIONS` (operator passed `allow_uncovered`)
* `NOT READY`

## Required coverage contract

```python
varden.protect(mode="strict", require_coverage=["http", "subprocess", "mcp"])
```

Explicitly required surfaces strongly influence readiness and posture. If a
required surface is unavailable or not routed, posture cannot be `protected`.

## Evidence required before claiming enforcement

A surface may be called enforced **only if** Varden attestation says so after
setup (coverage verify / self-test). Insufficient evidence:

* package installed
* skill present
* control plane process running
* dashboard reachable
* `import varden` succeeded
* MCP config file exists (without gateway routing)

## Common causes of PARTIAL

* Saved pre-`protect()` function references (e.g. `from subprocess import Popen`)
* Filesystem: Python APIs only; native extensions / other processes outside hooks
* HTTP: some clients enforced, others uncovered → network category PARTIAL
* Tool dispatch: only wrapped/registered tools are strongly guarded

## Common causes of NOT_ROUTED

* MCP servers configured but host still uses direct stdio/command without
  `varden mcp wrap`
* Gateway available but agent pointed at the original config

## Common causes of UNCOVERED / UNSUPPORTED

* Raw TCP/UDP sockets
* aiohttp / direct urllib3 (unless separately instrumented)
* Child-process network after an allowed spawn
* Framework callback-only paths (often OBSERVATIONAL)

## Modes and fail semantics

Product modes for `varden.protect()` / session:

* `observe` — non-blocking observation (fail-open by default)
* `guarded` — enforcing (default); fail-closed by default
* `strict` — enforcing + readiness gate; fail-closed; cannot use fail-open

Fail-closed: control-plane unreachable → privileged side effects blocked.
Fail-open: outage may allow side effects with warning — never present as normal
guarded posture.

Strict must not report ready when discovered relevant surfaces (e.g. MCP config
present) remain `NOT_ROUTED` unless explicitly accepted via `allow_uncovered`.

## "Installed" ≠ "enforced"

Always close the loop with `varden posture --json` after any install or routing
change.
