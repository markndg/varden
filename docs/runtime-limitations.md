# Runtime limitations

Be candid:

* Python monkeypatching cannot intercept **saved pre-patch function references**.
* Native extensions may bypass Python interception.
* External child processes may perform syscalls outside Python hooks.
* Raw sockets, aiohttp, direct urllib3, gRPC, and websockets may be **uncovered**.
* Filesystem coverage is **PARTIAL**: Python APIs only; OS-global isolation is
  **NOT GUARANTEED**.
* Filesystem policy uses **canonical / symlink-aware effective targets** and a
  pre-use re-check, but Python-level interception cannot eliminate all
  **TOCTOU** races between check and use, nor mediate unpatched APIs.
* PATH wrappers in `varden session` are one layer — not a complete security boundary.
* OS sandbox backends (namespaces, seccomp, eBPF, macOS sandbox, Windows job
  objects) are **not** claimed by this milestone.
* Audit hash chaining provides **tamper evidence**, not confidentiality, and
  cannot alone prove against an attacker replacing or truncating the entire
  audit store and any trusted chain head without an external checkpoint.
* Do not describe the audit chain as “tamper-proof”.

Coverage attestation exists specifically so these gaps are visible.
