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
* Descriptor-relative `dir_fd` calls are classified from the path string.
  A benign relative name against an untracked directory descriptor is not
  contained. Blanket denial of `dir_fd` would stop the process from deleting
  its own temporary files (`shutil.rmtree`), so that form stays PARTIAL.

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
and unpatched APIs remain out of scope. Descriptor-relative (`openat`)
hardening is future work, not claimed here.

See also `docs/runtime-limitations.md`.
