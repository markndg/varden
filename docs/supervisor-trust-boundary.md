# Supervisor trust boundary

The protected subject is a process the Varden supervisor launches, and the descendants that stay inside that process's containment. The supervisor does not claim the host, the user account, or a privileged administrator.

## Subjects

| Subject | Inside the containment claim |
|---|---|
| Supervised agent | Yes, when `varden run --protected` launches it after the pre-launch probe |
| Descendant of that agent | Yes, only where the OS boundary applies to the process tree. On macOS that is the Seatbelt profile |
| Unsupervised same-user process | No. The same uid can read supervisor files it owns and can write a protected path the profile does not cover |
| Trusted supervisor process | The supervisor is the launcher. It is not sandboxed by the profile it applies to the agent |
| Privileged host administrator | No. Root, or a Windows administrator, is outside this boundary |

## What the agent may touch

On a probed macOS launch the profile allows writes under the workspace and under `/private/var/folders` and `/dev`. It does not allow a write allow-rule for the protected path or a read of the supervisor state directory.

The supervised agent therefore cannot, through that profile:

- modify the protected monitoring file or a protected policy file kept outside the workspace
- read `authority.key` under the supervisor state directory
- rewrite the sealed attestation and have `verify` accept it, because the MAC no longer matches and the agent cannot read the key

An unsupervised process running as the same user can. The state directory is mode `0700` and owned by that user. Mode bits do not create a second principal. That process can read the signing key, recompute a MAC, and write the protected file. Those actions are outside the claim. HMAC evidence is not independently tamper-proof against a process that can read `authority.key`.

The profile and the Linux mounts name paths. A second hard link is the same inode. On macOS, a hard link placed in the workspace before launch let a Seatbelt process change the protected file and read a hardlinked key. `link` from inside the profile to the protected file was denied. The supervisor now refuses to start when the protected file, or the key at the moment of launch, has more than one directory entry. A same-user process that creates the link after that check is still outside the claim.

## Linux

Bubblewrap was executed on Linux `6.8.0-100-generic` aarch64 (Colima). With user namespaces permitted, `varden run --protected` denied protected writes, symlink writes, child writes, environment writes, and reads of the supervisor key. The protected hash did not change. A pre-existing hard link refused the launch. A public TCP connect to `1.1.1.1:443` succeeded, so network isolation is not a result of the filesystem mount. When AppArmor's `kernel.apparmor_restrict_unprivileged_userns` was `1`, bubblewrap could not map uids and the command was not started.

## When containment cannot be established

`varden run --protected` refuses to start the command when:

- the host adapter cannot be prepared
- the protected path sits inside a writable prefix, including the workspace
- the pre-launch write probe changes the protected bytes or does not report a denial
- the pre-launch probe can read the supervisor key

The result is a failed launch, not a verified denial of a command that never started. Observation mode is a separate explicit opt-in and is not OS enforcement.

## What is not claimed

Host-wide protection and protection of unsupervised same-user processes are not claims of this boundary. Windows filesystem denial was not executed. `DISABLE_MAX_PRIVILEGE` and a Windows job object are not a filesystem boundary. A non-zero exit code is not, by itself, an OS denial. An agent that catches the denial and exits 0 is still a denial when the attempt recorded the error and the protected hash is unchanged.
