# Security release-candidate review

Starting commit: `ab87cda57be91a45ce4ccaeea023cd3b0ada7f6b`  
Remediation commit: `bf4561d01cddeff2568f5181b3039a525e2bcc3d`  
Base: `origin/main` `63d3703f82e916f8b579bb9ff0f9b60c3273eebf`  
Branch: `feature/security-gauntlet-readiness`  
Not merged, tagged, pushed, or released.

Recommendation: **CONDITIONAL**

The branch is safe to merge with the claims in `docs/supervisor-trust-boundary.md`. It is not a cross-platform mandatory-enforcement release. Windows was not executed. Linux isolated authority remains the single-host result in `MIP-007-REPORT.md` and was not re-executed in this review.

## Scope

Reviewed the diff from `origin/main` through the supervisor, isolated-authority provisioner, Seatbelt and bubblewrap adapters, attestation sealing, `varden run --protected`, and the gauntlet reports. Traced `varden run --protected` and `varden run --protected --authority isolated` from `varden/cli.py` into `run_argv`, `begin_isolated_launch`, `Supervisor.launch`, the platform adapter, and HMAC sealing.

## Findings

| Severity | Location | Finding | Exploitability | Disposition |
|---|---|---|---|---|
| HIGH | `varden/monitoring_integrity/supervisor.py:215` | The pre-launch write and key probes used to store their result in the workspace. That directory is writable by the agent. A process with the agent's identity could replace a successful read or write note with `PermissionError` and, when it could also restore the protected bytes, make a failed boundary look denied. | Practical against the fail-closed check. It does not create a second user. It hides a boundary that is already not holding. | Fixed. The supervisor reads the probe process stdout (`supervisor.py:651`). A workspace file is not a denial. |
| HIGH | `varden/monitoring_integrity/supervisor.py:612` | Every protected attestation set `seatbelt_family` to `macos_seatbelt` and copied the Seatbelt limitation text, including a TCP allowlist. A Linux bubblewrap record would have claimed Seatbelt behaviour that the mount does not provide. | A false enforcement claim in a signed record. Not a privilege escalation. | Fixed. Seatbelt fields and the TCP sentence are emitted only when the mechanism is Seatbelt. Linux text says network egress is not isolated. |
| HIGH | `varden/monitoring_integrity/supervisor.py:667` | `claim()` always used the Seatbelt scope string. A verified Linux process would have been described as a Seatbelt profile. | False claim on the Predictive Authority boundary object. Network stays out of `covers`, so it was not upgraded to verified. | Fixed. Non-Seatbelt claims say they are not a Seatbelt profile and not a network boundary. `os_isolation` is true only for Seatbelt or bubblewrap filesystem covers. |
| HIGH | `varden/monitoring_integrity/authority.py:304` | `provision()` interpolated `SUDO_USER` into `/etc/sudoers.d/varden-authority`. A newline in that value would have been another sudoers rule. `visudo -cf` checks syntax, not intent. | Requires control of the root provision process environment. The agent user cannot set it. | Fixed. The operator must be one account name and must not be `varden-agent` or `varden-supervisor`. |
| MEDIUM | `varden/monitoring_integrity/authority.py:314` | Subordinate uid ranges were appended at fixed offsets without an overlap check. An overlapping range lets another user map the same host ids inside a user namespace. | Depends on the host's existing `/etc/subuid` map. Not demonstrated here. | Fixed. Provision refuses an overlapping range. |
| MEDIUM | `varden/monitoring_integrity/authority.py:273` | In isolated mode the policy file can select the protected path. A symlink or a mode the agent can write would let that identity choose the asset that is probed. | Requires the operator to point `--policy` at an agent-writable path and to omit `--protected-path`. | Fixed. Isolated mode reads a regular file with `O_NOFOLLOW`, owned by the supervisor uid, not group- or world-writable, and not inside the workspace. |
| LOW | `varden/monitoring_integrity/authority.py:169` | The re-exec passes the operator environment to `sudo`. The installed sudoers rule does not grant `SETENV`, and `supervisor-exec` sets `VARDEN_AUTHORITY_REEXEC` itself. | A host sudoers policy with `env_reset` disabled would carry the operator environment into the supervisor process. The signing key is not in that environment. | Left as residual. |
| LOW | `CAPABILITY_MATRIX.md` historical section | An older section still says the supervisor is not in this branch. | A reader who stops there would miss the later MIP record. It does not mark Windows or Linux as verified. | A pointer was added above that section. The static `platform_matrix()` cells are unchanged. |

No critical authority-boundary bypass remained after these fixes. The following were reviewed and not treated as new vulnerabilities:

- Isolated launch does not fall back to developer mode. A failed re-exec or a non-supervisor uid with `VARDEN_AUTHORITY_REEXEC=1` returns failure (`authority.py` `begin_isolated_launch`).
- The agent sudoers rule can run only `agent-exec`. The agent is not granted the supervisor command.
- Signing keys are created with `O_EXCL|O_NOFOLLOW` and are not passed on argv, the environment, or an inherited descriptor that the probe stdout reports.
- `verify()` rejects a bad MAC, a non-supervisor origin, and an `execution_id` that does not match the directory. A missing key is not regenerated.
- Developer mode still shares a uid. A same-user process can read `authority.key` and recompute an HMAC. That is the documented model, not a silent isolated-mode claim.
- The hard-link count check still happens before launch. A same-user link created after the check is outside developer mode. Isolated mode relies on ownership, not the link count.
- Bubblewrap does not unshare the network. macOS Seatbelt remains experimental and process-scoped. Windows restricted tokens and job objects are not a filesystem boundary and were not executed.

## Platform claims

| Platform | Claim that the tree supports |
|---|---|
| macOS developer mode | Experimental Seatbelt for the launched tree. Same-user processes outside the profile are not covered. Network is a localhost TCP allowlist, not a firewall. |
| Linux developer mode | Bubblewrap mounts when a user namespace can be created. Otherwise the command is not started. Network is not isolated. Static matrix cell stays `unverified`. |
| Linux isolated authority | Two users, supervisor-owned state. Not implied by installing bubblewrap. Not available on macOS or Windows. An administrator and the supervisor uid are outside the claim. |
| Windows | Unverified. No isolated-authority implementation. |
| Evidence | HMAC gives consistency and, in isolated mode, authenticity against the agent uid. It does not give durability against the supervisor uid or root. |

Gauntlet HTML, JSON, and the evidence step use the same authority status from `diagnose()`. On this Mac that status is `unsupported`. `verified_by_probe` in `varden supervisor status` stays false. A launch result uses that field only for "the protected bytes did not change."

## Tests

On this Mac, after the fixes:

- Full Python suite: 1385 passed, 9 skipped.
- Skips: `test_linux_agent_identity_cannot_touch_supervisor_state` because this host is not Linux. The skip reason says it is not a security verification. Eight further skips are missing `openai` or `anthropic` modules in `tests/security/pass2/test_p3_review_remediation.py`.
- The Seatbelt gauntlet ran. It was not skipped.
- Ruff passed on the touched monitoring modules and tests.
- Gauntlet frontend unit tests: 2 passed. Production build succeeded.
- Playwright buyer smoke ran inside the full suite and passed.

The Linux agent-identity attacks from MIP-007 were not repeated in this review.

## Residual risk

- Root and `varden-supervisor` can read the signing key and delete records.
- Developer mode does not resist an unsupervised process of the same user.
- Linux isolated mode still needs a permitted user namespace. The default AppArmor restriction on the previously used kernel refuses the mount and the launch fails closed.
- Bubblewrap does not contain network egress.
- Windows has no executed filesystem boundary.
- Provision writes a sudoers rule. The rule is narrow, and it is still a root-authored privilege boundary.
