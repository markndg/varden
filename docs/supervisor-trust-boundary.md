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

An unsupervised process running as the same user can. The state directory is mode `0700` and owned by that user. Mode bits do not create a second principal. That process can read the signing key, recompute a MAC, and write the protected file. Those actions are outside the claim.

## When containment cannot be established

`varden run --protected` refuses to start the command when:

- the host adapter cannot be prepared
- the protected path sits inside a writable prefix, including the workspace
- the pre-launch write probe changes the protected bytes or does not report a denial
- the pre-launch probe can read the supervisor key

The result is a failed launch, not a verified denial of a command that never started. Observation mode is a separate explicit opt-in and is not OS enforcement.

## What is not claimed

Host-wide protection, protection of unsupervised same-user processes, Linux bubblewrap, and Windows filesystem denial are not claims of this boundary. `DISABLE_MAX_PRIVILEGE` and a Windows job object are not a filesystem boundary. A non-zero exit code is not, by itself, an OS denial.
