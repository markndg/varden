# MIP-007 report

Starting commit: `9109842593990cf364685eafe8b1e101bb97de38`  
Branch: `feature/security-gauntlet-readiness`  
Not merged, tagged, pushed, or released.

Recommendation: **CONDITIONAL**

Linux isolated authority was executed with two OS identities. The agent user, including a process that was not in the supervised tree, could not read the signing key or write supervisor state. macOS isolated authority is unsupported. Windows isolated authority was not implemented. Evidence is authenticated in isolated mode and is not durable against the supervisor identity or an administrator.

## Initial findings

| Kind | What was true at `9109842` | What enforces it |
|---|---|---|
| Process-scoped denial | Seatbelt on macOS, and bubblewrap on Linux when user namespaces work, stop the launched tree from writing the protected path | OS, after a pre-launch probe |
| Same-user gap | Mode `0700` and `0600` do not create a second principal. The owner can read `authority.key` and recompute the HMAC | Not OS isolation |
| Hard-link check | A second directory entry refuses the launch. A same-user process can still create a link after the check | Application check. On Linux, a different uid is stopped by DAC and `fs.protected_hardlinks`, which the check does not replace |
| Evidence | Canonical JSON plus HMAC detects modification when the key is secret. It does not stop deletion or rollback by whoever can write the state directory | Application check |
| Windows | Restricted token and a job object were not a filesystem boundary and were not executed | Unsupported |

## Authority architecture

Developer mode remains `varden run --protected`. Isolated mode is the single extra switch, `varden run --protected --authority isolated`.

Isolated mode is a Linux user split, not a standing privileged daemon.

- `varden-supervisor` owns `/var/lib/varden/authority` mode `0700`: keys, the interpreter path, and execution records.
- `varden-agent` runs the command. The supervisor identity starts that command through a root-owned helper, `agent-exec`, allowed by a sudoers rule that does not let the agent become the supervisor.
- `varden supervisor provision` runs as root once, writes the sudoers rule, and installs the helpers. It does not start a service.
- `varden supervisor status` reports `available`, `configured`, `failed`, or `unsupported`. Configured is not a probe. A launch sets `verified_by_probe` only when it ran and the protected hash did not change.
- An isolated request never falls back to developer mode. A missing key for an existing execution is not regenerated. `--state-dir` is rejected in isolated mode.

The attacker who is root, or who is `varden-supervisor`, is outside the claim. HMAC does not make records append-only.

## Linux results

Host: Linux `6.8.0-100-generic` aarch64, Colima, operator uid 501 (`mark`). Bubblewrap 0.9.0. `kernel.apparmor_restrict_unprivileged_userns` was set to `0` for the runs and restored to `1`.

`tests/monitoring_integrity/test_authority.py`: 4 passed. The attack process was `sudo -n -u varden-agent`. `id -u` matched `varden-agent`. That is the agent identity, not root.

| Attempt from `varden-agent` | Result |
|---|---|
| List `/var/lib/varden/authority` | Non-zero exit, permission denied |
| Read `authority.key` after a real launch | Non-zero exit |
| Write `forged.json` into the authority directory | Non-zero exit, file absent |
| `ln` the protected file into the workspace | Non-zero exit, link absent |
| `sudo -n -u varden-supervisor -- true` | Non-zero exit |
| `varden run --protected --authority isolated` writing the protected file | Launched, `authority_model` `isolated`, `verified_by_probe` true, command exit 0, note began with an OS error, protected sha256 unchanged, no `authority.key` descriptor in `/proc/self/fd` |

Developer-mode Linux regressions on the same host, with namespaces permitted: `test_mip005.py`, `test_platforms.py`, and `test_supervisor.py`, 16 passed.

## Evidence

| Property | Isolated mode | Developer mode |
|---|---|---|
| Consistency | Canonical JSON. `verify` rejects a record whose `execution_id` does not match the directory, and a record whose MAC does not match | Same checks. The key is readable by the same user |
| Authenticity | The MAC key is mode `0600` and owned by `varden-supervisor`. The agent user could not read it and could not write a replacement record | The same user can read the key and produce a new MAC |
| Durability | Not claimed. The supervisor user and root can delete or replace files. There is no remote trust anchor | Not claimed |

## macOS and Windows

macOS developer-mode Seatbelt is unchanged and still experimental. Isolated authority is `unsupported`. A launchd helper and a second macOS user were not added.

Windows stays unverified. No restricted-token change is treated as supervisor isolation. The design to test on a Windows host is a dedicated service account plus a DACL, with launch refused until that identity's probe fails the write.

## Gauntlet

The mandatory scenario still separates the SDK, the supervised process, and the unsupervised same-user write. It now also records `authority` from `varden supervisor status`. On this Mac the HTML line is `Isolated supervisor authority: unsupported`. That is not folded into a prevented verdict. The production entry remains developer mode.

## Performance

One hundred samples. Developer protected time is `Supervisor.launch` of `/usr/bin/true`, including both probes and sealing. Isolated time is the production command `varden run --protected --authority isolated` of `/usr/bin/true`, including the sudo transition, both probes, bubblewrap, and sealing. The sudo column is `sudo -n -u varden-supervisor -- true` and is only the identity switch.

| Path | Median | p95 | p99 |
|---|---|---|---|
| Linux unsandboxed `/usr/bin/true` | 0.115 ms | 0.164 ms | 0.190 ms |
| Linux developer protected launch | 20.786 ms | 22.512 ms | 24.828 ms |
| Linux sudo to the supervisor identity | 1.574 ms | 2.127 ms | 2.206 ms |
| Linux isolated protected launch | 138.029 ms | 165.770 ms | 175.045 ms |

The last isolated sample reported `authority_model` `isolated`, `verified_by_probe` true, and command exit 0.

## Tests

On this Mac, the full Python suite was `1381 passed, 8 skipped`. That includes the supervisor tests, the security tests, the gauntlet tests, and the Playwright buyer smoke. Frontend unit tests were 2 passed. The production frontend build succeeded. Ruff passed on the monitoring, CLI, authority test, and gauntlet trees. On Linux, the identity tests were 4 passed and the developer-mode supervisor tests were 16 passed. The GitHub workflow files were not dispatched. They are not on the default branch, and this change was not pushed.

## Reproduce

On the Linux host, from this repository, with sudo:

```bash
sudo python -m varden.cli supervisor provision
python -m varden.cli supervisor status
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
python -m pytest -q tests/monitoring_integrity/test_authority.py
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
```

`status` must say `configured` before the pytest module will run the agent-identity attacks. On a host where it is not configured, those attacks are not counted as a pass. With the AppArmor restriction left at `1`, bubblewrap cannot map uids and an isolated launch must not be described as verified.

## Residual risk

- Root and `varden-supervisor` can read the key and delete records.
- Isolated mode requires a host that allows the agent user's user namespace. This VM's default AppArmor setting does not.
- Bubblewrap still does not contain network egress.
- Developer mode on every platform still shares the user account.
- macOS and Windows do not have isolated authority.
- Provision installs a sudoers rule. It is limited to the two helper commands. It is still a root-authored privilege boundary and should be reviewed on each host.
