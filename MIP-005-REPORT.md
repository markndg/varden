# MIP-005 report

Starting commit: `4103d263ca0eedb500f002dcd06d6dc7051a493a`  
Branch: `feature/security-gauntlet-readiness`  
Host used for execution: Darwin 27.2.0, macOS 27.2 build 26B123, arm64 (Apple T8142), `sandbox-exec` present.  
Docker and Colima were not running. They were not started. No Windows host was available.

Recommendation: **NO-GO** for a cross-platform verified mandatory-enforcement claim.

macOS Seatbelt denial was observed for a supervisor-launched tree. Linux bubblewrap was not executed. Windows filesystem denial was not executed. An unsupervised same-user process wrote the protected file.

## Guarantee

The mandatory subject is the agent started by `varden run --protected`, plus descendants that remain inside that launch's OS boundary. The supervisor's signing key, attestation, and protected files are outside that subject's write and read allows when the profile is in force. The guarantee is not host-wide. Detail is in `docs/supervisor-trust-boundary.md`.

If the adapter, the layout, or the pre-launch probe cannot establish containment, the command is not started.

## Platform matrix

| Platform | Adapter | This session | Filesystem denial | Same-user outside the launch | Network |
|---|---|---|---|---|---|
| macOS 27.2 arm64 | `macos_seatbelt_experimental` via `varden run --protected` | Executed | OS denial observed for the launched tree | Write completed. Not prevented | Not given a verified result |
| Linux | `linux_bubblewrap_unverified` | Not executed. No Linux kernel on this host | **UNSUPPORTED** | Not tested | **UNSUPPORTED** |
| Windows | `windows_restricted_token_unverified` | Not executed. No Windows host | **UNSUPPORTED**. A job object and `DISABLE_MAX_PRIVILEGE` are not treated as filesystem isolation | Not tested | **UNSUPPORTED** |

The Linux workflow's separate-user DAC job is a different mechanism from bubblewrap. A workflow file was not run, so it is not evidence.

## Production entry results

Entry point: `python -m varden.cli run --protected --json`.  
Protected monitoring hash before and after each denied case: `771c439896b71b03c692d7fe3bfa87ffc97fd2ab1b3bcf0a10fe259d83240bc7`.  
Policy file hash for the policy case: `f72d617150b27016cdbecc8954756c3c786ccfac425b7129d18254be819cd5b7`.

The agent caught `OSError` and exited 0. The exit code is not the proof. The proof is that the attempt note is `denied` and the hash did not change.

| Case | Capability | Outcome | Command exit |
|---|---|---|---|
| direct_write | filesystem | OS_DENIED | 0 |
| child_write | descendant | OS_DENIED | 0 |
| policy_write | policy | OS_DENIED | 0 |
| symlink_write | filesystem | OS_DENIED | 0 |
| env_write | filesystem | OS_DENIED | 0 |
| read_supervisor_key | supervisor state | OS_DENIED | 0 |
| unsupervised_same_user | same user, not launched | OBSERVED_OUTSIDE_BOUNDARY | not a supervised process |
| containment_unavailable | protected path inside the workspace | FAIL_CLOSED, command not started | n/a |
| tampered_attestation | evidence MAC | REJECTED | n/a |

Mechanism recorded on the launched cases: `macos_seatbelt_experimental`.

## Supervisor authority

The launched tree could not read `authority.key`. Changing `origin` in `attestation.json` made `verify` reject the record. The key file remains readable by an unsupervised process of the same uid, because that process owns the `0700` state directory. Python permission checks are not the boundary for that process. No second OS principal was introduced.

## Performance

100 samples on this Mac. Unsandboxed is `/usr/bin/true`. Protected is `Supervisor.launch` of `/usr/bin/true`, including both pre-launch probes, the wait, and attestation sealing. Internal phases were not timed separately, because that would be a different path from the production launch. Every protected sample left the protected hash unchanged.

| Path | Median | p95 | p99 |
|---|---|---|---|
| Unsandboxed `/usr/bin/true` | 1.332 ms | 1.477 ms | 1.625 ms |
| Protected launch | 51.114 ms | 52.415 ms | 53.000 ms |

Linux and Windows were not benchmarked.

## Tests in this session

- `tests/monitoring_integrity/test_mip005.py`: 2 passed
- `tests/monitoring_integrity/test_platforms.py`, `test_supervisor.py`, and `tests/security_gauntlet/test_runner.py`: 33 passed
- Ruff passed on the touched Python
- CI workflows were edited and not executed. A green badge does not exist for this commit. Skipped and unrun jobs are not verification

## Residual risk

- Seatbelt through `sandbox-exec -f` is experimental.
- Same-user processes outside the launch are not contained and can forge an attestation if they read the on-disk key.
- Linux user namespaces, bubblewrap mounts, symlinks, and hard links were not observed.
- Windows ACLs, AppContainer, and a restricted token were not observed.
- Network egress was not given a verified result in this run.
