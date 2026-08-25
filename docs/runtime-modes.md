# Runtime modes

| Mode | Side effects | Control-plane outage | Coverage gaps |
|------|--------------|----------------------|---------------|
| `observe` | Not prevented | May continue (fail open) | Reported |
| `guarded` (default; alias `enforce`) | Prevented on supported interceptors | Fail closed | Reported; not claimed complete |
| `strict` | Prevented; refuses missing required coverage | Fail closed only | Startup fails if required coverage absent |

Do not equate `guarded` with complete coverage.

## Enforcement vocabulary

* **Observational** — Varden sees the event after/beside execution.
* **Intercepted** — Varden sees the action before execution.
* **Enforced** — Varden can prevent execution based on policy.
* **Strict** — Varden refuses sensitive operation when required enforcement coverage is absent.
