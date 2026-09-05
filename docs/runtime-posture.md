# Runtime security posture

```text
coverage  = what execution surfaces Varden can currently observe/enforce
readiness = whether configured runtime requirements are satisfied
posture   = Varden's authoritative interpretation of the current enforcement state
```

**Don't ask your agent whether it's secure. Ask Varden to prove what is enforced.**

## Purpose

`varden posture` is a side-effect-free attestation command. It observes
authoritative coverage + readiness state and emits a stable overall result.
It does **not** install hooks, wrap MCP configs, grant approvals, or repair gaps.

```bash
varden posture
varden posture --json
```

Control plane: `GET /runtime/posture`

## Result vocabulary

JSON uses stable lowercase values:

| Result | When |
|--------|------|
| `protected` | Enforcing runtime is ready; every **applicable** surface is ENFORCED |
| `protected_with_gaps` | Enforcing runtime is active; applicable incomplete coverage remains |
| `not_fully_routed` | An applicable surface is `NOT_ROUTED` (commonly MCP) |
| `not_ready` | Readiness failed for non-routing reasons |
| `not_protected` | No meaningful active enforcing boundary (including observe mode) |

### Precedence

```text
NOT_PROTECTED
    ↓
NOT_READY          (non-routing readiness failures)
    ↓
NOT_FULLY_ROUTED   (applicable NOT_ROUTED / routing-only readiness failures)
    ↓
PROTECTED_WITH_GAPS
    ↓
PROTECTED
```

## Applicability

Posture must not treat catalogued-but-irrelevant surfaces as material gaps.

MCP is applicable only when discovered, required via `require_coverage`, or
gateway-enforced. A default catalog `NOT_ROUTED` with `applicable=false` does
**not** force `not_fully_routed`.

Network extras (raw sockets, aiohttp, urllib3) become applicable once HTTP
instrumentation is active.

## Verification vs posture

Human output separates:

```text
Verification
  Attestation: VALID
  Readiness: READY
  Self-test: NOT_RUN

Result
  PROTECTED WITH GAPS
```

Attestation validity answers whether Varden could determine state. Posture
answers what that state means. Default posture does not run self-test
(`NOT_RUN`).

## JSON schema (`schema_version: "1"`)

```json
{
  "schema_version": "1",
  "result": "not_fully_routed",
  "runtime": {
    "active": true,
    "mode": "guarded",
    "fail_mode": "closed",
    "readiness": "not_ready"
  },
  "verification": {
    "attestation": "valid",
    "readiness": "not_ready",
    "self_test": "not_run"
  },
  "surfaces": {
    "network": {"state": "partial"},
    "subprocess": {"state": "enforced"},
    "filesystem": {"state": "partial"},
    "mcp": {"state": "not_routed"}
  },
  "gaps": [
    {
      "surface": "mcp",
      "state": "not_routed",
      "severity": "high",
      "reason": "MCP traffic is not routed through Varden",
      "remediation_available": true,
      "remediation": "Route MCP through the Varden gateway using `varden mcp wrap`."
    }
  ]
}
```

Additive evolution preferred. No ANSI, secrets, or credential dumps.

## Structured gaps

Gaps derive from applicable coverage surfaces. Fields populated only when
reliable: `surface`, `component`, `state`, `severity`, `reason`,
`remediation_available`, `remediation`, optional `accepted_exception`.

## CI usage

```bash
varden posture --json
```

Exit status is currently success even when gaps exist (matches coverage CLI
conventions). Consumers should assert on `result` in JSON.

## Agent usage

Agents must call `varden posture --json` and report `result` without upgrading
it. See `skills/varden-security/SKILL.md` and `docs/runtime-boundary.md`.
