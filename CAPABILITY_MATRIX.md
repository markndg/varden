# Varden capability matrix

Audit date: 2026-11-05. This file describes the tree the security gauntlet is built on, plus capabilities that exist only on other branches. A passing test is not treated as a completed enforcement proof.

## Tree under test

| Item | Value |
|---|---|
| Demonstration branch | `feature/security-gauntlet` |
| Base | `main` `63d3703f82e916f8b579bb9ff0f9b60c3273eebf` |
| Package version on that commit | 1.1.0 |
| Released remote | `origin/main` is the same commit |
| Unmerged monitoring-integrity work | `feature/monitoring-integrity` `8fcf94a` (one commit ahead of `main`). Not included in this branch. |

## Released on this branch (v1.1.0)

| Capability | Implementation | Tests on main | Platforms | Verification status |
|---|---|---|---|---|
| Policy engine (block, require_approval, sanitise, warn, monitor, allow) | `varden/policy.py`, `POST /sdk/guard` | `tests/test_policy_engine_hardening.py` and the security pass-2 suites | Host-independent Python | Implemented. A block is a pre-execution decision. It prevents a side effect only when the caller does not run the tool after a denying response. |
| Python SDK guard | `varden_sdk/sdk.py` `VardenGuard.guarded_action`, `protect()` | SDK and runtime tests | CPython on Linux, macOS, Windows where the process is instrumented | Implemented for patched Python calls. Saved references, native code, and a process that never calls the SDK are outside it. |
| Provenance and trust downgrade | `varden/provenance/`, client `observe_provenance` | `tests/provenance/` | Host-independent | Implemented. A client cannot mint `trusted` or `delegated`. That is not file or network isolation. |
| Predictive Authority | `varden/predictive_authority/` | `tests/predictive_authority/` | Host-independent | Implemented and **off by default**. Enforce mode can strengthen a decision. It is bounded reachability, not a forecast that an agent will take an action. |
| MCP gateway and inventory | `varden/runtime/mcp_gateway.py`, `varden/mcp_inventory.py` | MCP conformance and runtime tests | Where the gateway is the live route | Gateway enforcement applies to calls that use the gateway. A direct MCP connection is not covered. |
| Audit hash chain | `docs/audit-integrity.md` | `tests/security/pass2/test_p2_audit_integrity.py` | Host-independent | Tamper-evident, not tamper-proof. Replacing the whole store is outside the chain. |
| Web Shield | `varden/webshield/` | Web Shield tests | Browser extension is Chromium MV3 | Separate product surface. Not the agent OS boundary. |
| Coverage attestation | `varden/runtime/coverage.py` | runtime coverage tests | All | Filesystem and subprocess default to **PARTIAL**. `ENFORCED` is not the default for those surfaces. |
| Runtime posture | `docs/runtime-posture.md` | runtime tests | All | Reports what was probed. An enabled flag is not an OS sandbox. |

## Known limits of the released runtime

From `docs/runtime-limitations.md`, which this branch still contains:

- Python monkeypatches miss saved pre-patch references, native extensions, raw sockets, aiohttp, direct urllib3, gRPC, and websockets.
- Filesystem coverage is PARTIAL. OS-global isolation is not guaranteed.
- `varden session` PATH wrappers are not a complete boundary. The same user can skip the shim.
- OS sandboxes (namespaces, seccomp, eBPF, macOS sandbox, Windows job objects) are **not claimed** by the released runtime document.

## Unmerged: monitoring integrity (not in this branch)

Branch `feature/monitoring-integrity` at `8fcf94a`. The security gauntlet does not import or copy that code.

| Capability | Where it lives | What was actually executed before this audit | Status in the gauntlet |
|---|---|---|---|
| In-process monitoring-integrity hooks | `varden/monitoring_integrity/` on that branch | Unit tests on the branch, including a known shell-concatenation bypass that still succeeds against hooks alone | Unavailable here. Do not describe it as released. |
| macOS Seatbelt supervisor | `varden run --protected`, `macos_seatbelt_experimental` | Demonstrated on Darwin 27.2 arm64 for a supervisor-launched tree. Experimental. Same-user processes outside the profile are not covered. Named `sandbox-exec -n` profiles were not usable (exit 137). | **Unsupported in this checkout.** |
| Linux bubblewrap / POSIX users | adapter and `deploy/monitoring-integrity/` | Not executed. Workflow files exist and had not been run. | **Unverified.** |
| Windows restricted token and job object | `platforms.py` on that branch | Not executed. A job object is not a filesystem sandbox. | **Unverified.** |
| Other Unix | no enforcing adapter | n/a | **Unsupported.** |

## After the readiness pass

Branch `feature/security-gauntlet-readiness`, based on `feature/security-gauntlet` `66e38c6`. The monitoring-integrity commit is still not merged. The gauntlet can launch that checkout's Seatbelt adapter only when `VARDEN_INTEGRITY_ROOT` points at it. Without that variable the OS leg is `UNSUPPORTED` and no sandbox command is started.

| Host | What this suite will claim |
|---|---|
| macOS, integrity root unset | SDK and Predictive Authority only. OS leg `UNSUPPORTED`. |
| macOS, integrity root set to `feature/monitoring-integrity`, contained hash unchanged | Contained process `VERIFIED_PREVENTED` for `macos_seatbelt_experimental`. Overall stays `UNSUPPORTED` when a same-user write outside the profile completes. |
| Linux | OS leg `UNSUPPORTED`. Bubblewrap is unverified. The suite does not pretend a probe ran. |
| Windows | OS leg `UNSUPPORTED`. The restricted token is unverified. The suite does not pretend a probe ran. |

On Darwin 27.2 arm64, with the integrity worktree at `8fcf94a`, one contained `open` under `sandbox-exec -f` left the protected file hash unchanged (`dc70b8c6ac967c4c883f6ad2355596510a0bd5df4fdf5e91ca3a0edfff240f98`) and returned exit code 1. The same user then wrote a file outside that process. That outside write completed. This is not a release of the supervisor.

## What the gauntlet is allowed to claim

| Scenario | Control that may produce a verdict | OS enforcement |
|---|---|---|
| Prompt injection | Released `/sdk/guard` policy, then an independent check that a local sink file did not change. The allowed summary and the prevented export stay separate from the baseline. | Not claimed |
| Predictive Authority | Released engine, enabled explicitly for the run. The graph on the page is the live registry after those guard calls. | Not claimed. A hazardous path is reachability, not a confirmed future act |
| Mandatory enforcement | SDK leg can be prevented. An unguarded write is expected to succeed. A Seatbelt result is recorded only after `VARDEN_INTEGRITY_ROOT` runs the other checkout's adapter and the protected hash is unchanged. | Overall stays `UNSUPPORTED` unless that contained probe is the claim and no outside write completed. A same-user outside write keeps the overall result from being universal prevention. |
| Evidence export | The record of a real run, including the three scoped verdicts | Cannot upgrade the run's verdict |
| Coverage gap | Direct write outside the SDK | Must not report prevention |
