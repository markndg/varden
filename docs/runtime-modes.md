# Runtime modes

| Mode | Side effects | Control-plane outage | Coverage gaps |
|------|--------------|----------------------|---------------|
| `observe` | Not prevented | May continue (fail open) | Reported |
| `guarded` (default; alias `enforce`) | Prevented on supported interceptors | Fail closed by default. `fail_mode=open` is explicit and only applies when the control plane returns no deny decision | Reported; not claimed complete |
| `strict` | Prevented; refuses missing required coverage | Fail closed only | Startup fails if required coverage absent |

Do not equate `guarded` with complete coverage.

A deny decision in the guard body is not an outage. `block`, `blocked`, `require_approval` and `approval_required` on `decision.action` or `decision.effective_action` stop the protected call on any HTTP status. One FastAPI `detail` wrapper is recognized. Nested JSON on the action is not a policy decision. `fail_mode=open` applies when the body has no decision slot.

## Enforcement vocabulary

* **Observational** — Varden sees the event after/beside execution.
* **Intercepted** — Varden sees the action before execution.
* **Enforced** — Varden can prevent execution based on policy.
* **Strict** — Varden refuses sensitive operation when required enforcement coverage is absent.
