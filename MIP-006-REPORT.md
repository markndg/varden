# MIP-006 report

Starting commit: `c6b18245c4aca2d39347357da4c1016bae9602fc`  
Branch: `feature/security-gauntlet-readiness`  
Not merged, tagged, pushed, or released.

Recommendation: **CONDITIONAL**

macOS Seatbelt and Linux Bubblewrap denied protected filesystem operations for a process launched by `varden run --protected`. Windows was not executed and stays **UNSUPPORTED**. Linux network isolation was not established. An unsupervised same-user process can still read the signing key and rewrite evidence. That is not a host-wide guarantee.

## Findings

| Kind | Item | Evidence | What changed |
|---|---|---|---|
| Confirmed gap | A hard link in the writable workspace is the protected inode. Seatbelt allowed the write. The file became `disabled`. | Darwin probe before the fix. Return code of the agent was 0. Supervisor then marked the launch failed because the hash changed. | Launch is refused when the protected file or the key has `st_nlink != 1`. Re-run: command not started, hash unchanged. |
| Confirmed gap | A hard link of `authority.key` into the workspace was readable inside Seatbelt (`READ 32`). | Direct `sandbox-exec` read. | The key is checked at launch. A same-user process that links it after the check is still outside the claim. |
| Confirmed gap | Linux Bubblewrap returned `OSError` errno 30 and left the file unchanged, but the probe recorded only `OSError`. The supervisor treated that as "not a denial" and did not start the command. | Privileged container, bubblewrap 0.12, content unchanged. | The probe now records `OSError:30`. A later unprivileged run launched and denied the write. |
| Architectural limit | `DISABLE_MAX_PRIVILEGE` keeps the user's SID. A job object does not change file DACLs. | Source of `CreateRestrictedToken`. No Windows process was observed. | No new Windows identity was added. Protected launch still refuses to start unless the pre-launch write is denied. |
| Architectural limit | HMAC evidence is not tamper-proof if the attacker can read the on-disk key. | Same-user owns the `0700` state directory. | Documented. No privileged supervisor service was added. |
| Architectural limit | Linux bubblewrap does not unshare the network. | `1.1.1.1:443` connected from inside the launched process. | Not claimed as network enforcement. |
| Host limit | This Colima kernel blocks unprivileged user namespaces while `kernel.apparmor_restrict_unprivileged_userns=1`. | `bwrap: setting up uid map: Permission denied`. After the sysctl was set back to 1, the command was not started. | Fail closed. The sysctl was restored to 1 after the test. |
| Unverified | Windows filesystem, AppContainer, restricted SIDs, and a dedicated Windows user. | No Windows host. The platform workflows are not on the default branch, so GitHub-hosted dispatch was not available without a merge. | Left **UNSUPPORTED**. |
| Harness | A zero exit with an unchanged hash and no denial record was inconclusive. A caught denial that exits 0 is now a denial only when `denial_observed` is set. | Classifier tests. | The production writer exits 0, records `denied`, and is `OS_DENIED` only with an unchanged hash. |
| Documentation | The static `platform_matrix()` and `GAUNTLET_MATRIX` still say Linux and Windows are unverified or not executed. | `test_linux_and_windows_rows_are_not_executed_from_this_tree` | Left that way. A checkout is not a live verdict. This report is the execution record. |

## macOS

Host: Darwin 27.2.0, macOS 27.2 build 26B123, arm64, `sandbox-exec` present.  
Entry: `python -m varden.cli run --protected --json`.  
Adapter: `macos_seatbelt_experimental`.  
Protected bytes for the monitoring file match before and after each denied launch. The file body is the same as MIP-005, sha256 `771c439896b71b03c692d7fe3bfa87ffc97fd2ab1b3bcf0a10fe259d83240bc7`.

| Case | Result | Command exit |
|---|---|---|
| Direct, child, policy, symlink, environment, supervisor-key read | OS_DENIED | 0, attempt note `denied` |
| TCP connect to `1.1.1.1:443` and `127.0.0.1:9` | OS_DENIED | separate from the filesystem result |
| Pre-existing hard link | FAIL_CLOSED, not started | hash unchanged |
| Protected path inside the workspace | FAIL_CLOSED, not started | |
| Same-user process outside the launch | Write completed | |
| Rewritten attestation origin | Rejected | |

Seatbelt stays experimental. It is not host-wide. Descendant writes used the child script and were denied. The production spawn uses `close_fds=True`. A writable descriptor is not passed into the agent. A descriptor planted by another same-user process was not part of this claim.

## Linux

Host: Linux `6.8.0-100-generic` aarch64, Colima VM, user `mark` uid 501, bubblewrap 0.9.0, Python 3.12.3.  
`kernel.apparmor_restrict_unprivileged_userns` was set to `0` for the successful run and restored to `1` afterwards. `unprivileged_userns_clone` was `1`. `uidmap` was installed so `newuidmap` exists. With the AppArmor restriction left at `1`, bubblewrap printed `setting up uid map: Permission denied` and the supervisor did not start the command.

With namespaces permitted, `tests/monitoring_integrity/test_mip005.py`, `test_platforms.py`, and `test_supervisor.py` passed: 16 passed.

| Case | Result | Command exit |
|---|---|---|
| Direct, child, policy, symlink, environment, supervisor-key read | OS_DENIED | 0, note `denied`, hashes equal |
| Pre-existing hard link | FAIL_CLOSED | hashes equal |
| Containment path inside the workspace | FAIL_CLOSED | not started |
| Same-user write | Completed outside the launch | |
| Attestation origin rewritten | Rejected | |
| TCP `1.1.1.1:443` | NOT_PREVENTED (`1.1.1.1:open`) | protected hash unchanged |
| TCP `127.0.0.1:9` | Connection refused, which is not a sandbox denial | |

A nested Docker container running as root also saw errno 30 on the read-only mount. An unprivileged user inside that container could not map uids. The VM user, with namespaces permitted, is the result used for the filesystem claim.

## Windows

No Windows host was available. `CreateRestrictedToken` is called with `DISABLE_MAX_PRIVILEGE` and empty SID-disable lists, so the user identity remains. That is not filesystem isolation. The smallest defensible next step is a dedicated low-privilege identity and an explicit DACL that denies that identity the protected files and the state directory, with the launch refused until a Windows probe shows the hash unchanged. It was not implemented here, because it could not be executed. The current code still refuses the launch when the pre-launch write is not denied.

## CI

`.github/workflows/mip-linux-boundary.yml`, `mip-macos-boundary.yml`, and `mip-windows-boundary.yml` are `workflow_dispatch` workflows. They are not on `origin/main` (`63d3703`). GitHub will not dispatch a workflow that exists only on this branch without merging it to the default branch. Merging was out of scope. Those workflow files were not executed. A green workflow is not claimed.

The Linux result above is a real kernel, not a platform-name mock. It is one VM configuration, not every Ubuntu runner.

## Gauntlet

The mandatory scenario still separates SDK enforcement, the supervised process, and the unsupervised same-user write. Overall stays `UNSUPPORTED` while the same-user write completes. The scenario now also runs `varden run --protected` and stores `production_entry` on the record. The HTML assessment and the JSON export both list those case outcomes. An unsupported platform is not turned into a prevented verdict. The security engine's decisions were not changed.

## Performance

One hundred launches each. Unsandboxed is `/usr/bin/true`. Protected is `Supervisor.launch` of `/usr/bin/true`, including both probes and attestation sealing. Linux samples were taken while user namespaces were permitted. Windows was not benchmarked.

| Host | Unsandboxed median / p95 / p99 | Protected median / p95 / p99 |
|---|---|---|
| macOS 27.2 arm64, this session, after the hard-link check | 1.437 / 2.895 / 5.414 ms | 51.335 / 53.327 / 61.633 ms |
| Linux 6.8.0-100-generic aarch64 | 0.114 / 0.157 / 0.173 ms | 20.559 / 21.172 / 21.491 ms |

## Tests

- Ruff on `varden/monitoring_integrity`, `demos/security-gauntlet`, `tests/monitoring_integrity/test_mip005.py`, and `tests/security_gauntlet/test_runner.py`: passed. A repo-wide ruff invocation still reports existing demo-script findings that are outside this change.
- Full Python suite before the last assertion correction: 1375 passed, 8 skipped, 1 failed. The failure was the mandatory-scenario test looking for the HTML sentence inside the JSON document. The assertion now reads the JSON fields. That test then passed.
- Frontend `npm test`: 2 passed. `npm run build`: succeeded.
- Playwright drove the built page. The mandatory scenario's evidence step shows the production-entry lines from the same record, including `direct_write: OS_DENIED`, `hardlink_write: FAIL_CLOSED`, and overall `UNSUPPORTED`. The prompt-injection buyer smoke passed in the full suite.
- Linux VM, with user namespaces permitted: `test_mip005.py`, `test_platforms.py`, and `test_supervisor.py`: 16 passed. With the AppArmor restriction restored, a protected launch did not start.

## Residual risk

- Seatbelt through `sandbox-exec -f` is experimental.
- Same-user processes can read the key and forge an HMAC after the launch check.
- Linux filesystem denial requires a host that allows unprivileged user namespaces. The default AppArmor setting on this VM does not.
- Linux network egress is open inside the bubblewrap mount.
- Windows filesystem denial is unsupported.
- The static matrix in source is not a substitute for re-running the production entry.
