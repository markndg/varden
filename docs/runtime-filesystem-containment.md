# Filesystem containment

Varden evaluates filesystem policy against the **effective target**, not merely
the caller-supplied path string.

## What is strengthened

* Lexical traversal (`../`, nested `..`, repeated separators)
* Symlink escapes (file/dir links, nested/relative links, create-under-linked-parent)
* Path-component containment (rejects `/workspace-safe` as inside `/workspace`)
* Non-existent targets: nearest existing parent is resolved; prospective child
  is evaluated from that parent
* Rename/replace: **source and destination** are classified independently
* Re-check of the effective target immediately before the underlying operation
  (narrows — does not eliminate — check/use gaps)
* `os.open`, `os.link`, and `os.symlink`, including keyword arguments
  (`os.remove(path=...)`, `os.rename(src=..., dst=...)`)
* Relative `dir_fd` calls are joined to the directory descriptor's path on
  macOS (`F_GETPATH`) and Linux (`/proc/self/fd`) before classification.
  An unresolvable relative descriptor is refused while enforcement is on.
  Absolute paths ignore `dir_fd`, matching the kernel. This is still path
  identity, not an `openat2` containment guarantee.

API unchanged:

```python
import varden
varden.protect()
```

## What PARTIAL means

Varden canonicalises and evaluates intercepted filesystem targets, including
traversal and symlink indirection, before policy evaluation, and re-resolves
immediately before the patched operation proceeds.

However, Python-level interception cannot guarantee that the filesystem object
remains unchanged between security evaluation and the underlying operation in
every race scenario, nor can it guarantee mediation of filesystem access paths
outside the patched/runtime-covered surfaces (native code, child processes,
raw file descriptors, and calls that never enter the patched Python functions).

Coverage therefore remains explicitly attested as **PARTIAL**.

## Resolution statuses

* `resolution_success`
* `resolution_partial` (non-existent leaf; parent resolved)
* `resolution_failed`

Under guarded/strict **fail-closed**, ambiguous security-sensitive resolution
does not silently ALLOW.

## Residual TOCTOU

A parent directory that is a normal in-workspace path at check time can be
replaced with a symlink to an outside path before use. Varden's pre-use
re-check detects many such mutations; concurrent races at the kernel boundary
and unpatched APIs remain out of scope. Relative `dir_fd` paths are resolved
to a directory path before classification on macOS and Linux. That is not
`openat2` `RESOLVE_BENEATH` containment, and a directory renamed after the
descriptor path is read can still disagree with the kernel.

A path-scoped passthrough applies only to the thread or task that entered
the original syscall, and only until that syscall returns. Another task does
not inherit it.

`O_NOFOLLOW` is applied when the checked final component was not a symlink.
A symlink swapped in after that check is not followed. Replacing a regular
file's inode, pre-existing hard links, raw descriptors, and native code
remain outside this boundary.

See also `docs/runtime-limitations.md`.
