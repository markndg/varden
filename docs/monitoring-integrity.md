# Monitoring Integrity Protection

Monitoring Integrity Protection (MIP) stops a protected agent from disabling
the monitoring that supervises it, on the execution surfaces Varden actually
intercepts. It is off until a policy document contains
`monitoring_integrity.enabled: true`.

The default mode does not add an operating-system sandbox. A patched call is
prevented only when an interceptor raises before the original call. A graph
path, a log line, or an agent statement is not prevention.

An independently enforced deployment is separate. On Darwin it is a
deny-by-default Seatbelt profile applied by the supervisor before the agent
runs. On Linux the reference is a different Unix user. Neither is implied by
`monitoring_integrity.enabled`. See
[the boundary decision](monitoring-integrity-boundary.md).

## What already existed

| Capability | Classification | MIP use |
| --- | --- | --- |
| `observe` / `guarded` / `strict` | ENFORCED on patched calls | MIP must not be silently downgraded. `observe` records and does not prevent. |
| Filesystem monkeypatches | PARTIAL | Extended so a sealed monitoring path is mediated even when it is an ordinary workspace write. TOCTOU is narrowed, not eliminated. |
| Subprocess monkeypatches | PARTIAL | Launch-time deny for protected activations, service-control argv, and monitored-child policy. `os.exec*` and ctypes are NOT_ENFORCEABLE. |
| HTTP `requests` / `httpx` / `urllib` | PARTIAL | Mutating calls to a sealed control-plane or notification endpoint are denied. DNS rebinding remains open at URL-identity time. |
| MCP gateway | ENFORCED only while the gateway is the live route; otherwise NOT_ROUTED | Control-plane evaluation applies MIP. Direct stdio MCP does not. |
| Policy engine | ENFORCED for routed actions | `monitoring_integrity` is a section of the existing policy document, not a second language. |
| Coverage registry | ENFORCED as an honesty record | INV-005 refuses an agent coverage claim. The surface catalogue is unchanged. |
| Predictive Authority | ENFORCED only as a strengthen-only decision when mode is `enforce` and the call is intercepted | MIP adds the `monitoring_integrity_sabotage` pattern on the existing graph. It does not start a second traversal engine. |
| Provenance | PARTIAL | Untrusted instructions do not become authority to change monitoring. |
| Audit hash chain | OBSERVED tamper-evidence | The integrity evidence log has the same limit: replacing the file and every external head removes the evidence. |
| Approvals | ENFORCED when the control plane issues them | MIP approvals are single-use and bound to one asset, one invariant, and one operation. The protected agent cannot be the issuer. |
| PATH session shim | PARTIAL | Not an OS sandbox. Child coverage after launch is not verified without new evidence. |
| OS namespaces, seccomp, eBPF, sandbox profiles | PARTIAL. Darwin Seatbelt is tested for a supervisor-launched process tree. Linux user separation is a reference and was not executed on the Darwin development host. | The mandatory boundary. In-process hooks remain PARTIAL. |

## Threat model

The agent can read and write files, run a shell, call MCP tools, make HTTP
requests, edit configuration, install packages, start children, change
environment variables, retarget logs, call service managers, delegate work,
and rewrite the text of a health check. Instructions inside lower-trust
material are not trusted. Being inside an authorised workflow does not make
the agent an authority over its own monitor.

| Class | What MIP does on a covered surface | Status |
| --- | --- | --- |
| MIP-001 configuration tampering | Deny a mutation of a sealed enforcement file before the write. | ENFORCED for patched Python filesystem APIs. PARTIAL overall. |
| MIP-002 integration removal | Deny unlink or replacement of a sealed integration, and deny a declared activation command. | ENFORCED at those interceptors. |
| MIP-003 notification suppression | Deny a destination that does not canonicalise into the asset allowlist. | ENFORCED when the write or HTTP mutation is intercepted. |
| MIP-004 enforcement degradation | Deny a weaker `mode` or `fail_mode=open` on a sealed asset or protected environment key. | ENFORCED at those interceptors. In-process assignment to `CoverageRegistry` is not. |
| MIP-005 service termination | Deny `os.kill` of a sealed pid for a consequential signal, and deny service-control argv whose target is a sealed process name. | PARTIAL. `os.exec*` and an unpatched `kill` binary are NOT_ENFORCEABLE. |
| MIP-006 unmonitored child | Deny a launch whose arguments resolve to a sealed path. If `require_monitored_child` is set, deny an interpreter launch whose coverage is not verified. | PARTIAL. Descendants are not proven covered. |
| MIP-007 deception | An agent coverage claim is not evidence. A publish attached to a sealed asset is denied. Hash mismatch is `confirmed_tampering` only for the out-of-process manifest check. | The claim is not trusted. Speech in a model response is NOT_ENFORCEABLE. |
| MIP-008 multi-step | Declared grants are walked on the Predictive Authority graph. The earliest enforceable interruption is the first mutating edge that an interceptor can actually block. | The demo blocks the reload, not the earlier read. |
| MIP-009 indirect | A child or shell whose concrete path tokens resolve to a sealed asset is denied at the parent launch. | PARTIAL. Concatenated paths inside unobservable shell text can miss. |
| MIP-010 recovery | The sealed baseline stays in process memory. Evidence is an append-only hash chain. An independent approval can authorise one matching repair. | Detection of an out-of-band edit is the next verification read, not prevention. |

## Policy

```json
{
  "monitoring_integrity": {
    "enabled": true,
    "mode": "guarded",
    "fail_closed": true,
    "protected_agents": ["agent"],
    "assets": [
      {
        "id": "monitor.config",
        "type": "enforcement_config",
        "owner": "operator",
        "protected": true,
        "path": "/var/lib/varden/monitoring.json",
        "permitted_operations": ["read"],
        "integrity_fields": [
          {"path": "audit.enabled", "kind": "boolean_enabled"},
          {"path": "mode", "kind": "enforcement_mode"}
        ]
      }
    ],
    "grants": []
  }
}
```

`protected: false` records an asset and does not enforce it. A protected asset
needs a path, endpoint, process name, pid, or environment key. The catalogue
is sealed in the agent process at enable time. A second enable without the
release token does not replace it. Code running in the same interpreter can
still read that token and undo monkeypatches. That is not an independent
watchdog.

Modes:

| Mode | Protected mutation |
| --- | --- |
| `off` / absent | No MIP behaviour. |
| `observe` | Record the violation. Do not prevent the side effect. |
| `guarded` | Block, or require a scoped approval, before the original call. |
| `strict` | Same block, and missing mandatory evidence fails closed. |

Unknown evidence on a protected mutation does not become allow when
`fail_closed` is true. `NOT_ENFORCEABLE` is returned when no interceptor
exists. That outcome does not claim the side effect was prevented.

## Invariants

INV-001 through INV-008 are defined in `varden/monitoring_integrity/invariants.py`.
Each one names its surfaces, the trust assumption, and the limit. An invariant
that holds on `builtins.open` does not hold on `os.execv`.

## Predictive Authority

Hazardous monitoring states use the existing capability graph and
`bounded_reachability`. The pattern `monitoring_integrity_sabotage` is empty
on graphs that have no `mip_prohibited` node, so other analyses are unchanged.

- A read or in-memory edit is not an interruption.
- The earliest interruption is the first mutating edge whose surface is enforceable.
- The minimum cut is exact only inside the combination budget. Otherwise it is labelled `greedy_approximation` and is not a proof.
- `safe_conclusion` is false when the search is truncated, the depth budget is zero, or no grants were declared.
- Counterfactuals rebuild the same graph after one grant or surface change. Making a surface unavailable does not make a remaining path safe.
- The analysis cache drops when the registry generation changes. Invalidation does not recompute until the next query.

## Independent check

`python -m varden.monitoring_integrity.watchdog --manifest manifest.json` is a
separate process. It compares file digests with an operator manifest. It
classifies process death, connectivity loss, a stale heartbeat, and a digest
mismatch separately. A missed heartbeat is not proof of sabotage. Digest
mismatch is `confirmed_tampering`.

The process is independent of the agent interpreter only when it is actually
another process. The same OS user can stop it. `deploy/monitoring-integrity/varden-watchdog.service`
is a reference for running it as a different user. Varden does not install
that unit and does not claim the SDK provides the same guarantee.

## Commands

```bash
varden runtime integrity status --policy policy.json
varden runtime integrity paths --policy policy.json
varden runtime integrity paths --policy policy.json --counterfactual remove_permission --grant-id reload
varden runtime integrity verify --manifest manifest.json
varden runtime integrity demo
```

`varden runtime integrity demo` runs the multi-step sabotage in a temporary
directory. Without MIP the live file ends disabled. With MIP the reload is
blocked and the live file is unchanged.

The control-plane view is `/ui/integrity`. It reads `GET /runtime/integrity`.
If that request fails, the page says the posture is unknown. It does not show
a clean result. `verified_protection` is false: a matching file digest is not
a claim that every surface is enforced.

## Limits that remain

- Saved pre-patch function references, native extensions, `os.exec*`, `os.spawn*`, and ctypes bypass Python interception.
- A shell command that builds a path by concatenation, without a quoted or discrete path token, is not reliably bound to an asset.
- MCP that does not pass through the gateway is NOT_ROUTED.
- The in-process registry is not a watchdog. An agent that can execute arbitrary Python in the same interpreter can undo the patches.
- Predictive completeness is bounded. An incomplete graph is not safe.
- The evidence hash chain does not survive replacement of the log and every external copy of the head.
