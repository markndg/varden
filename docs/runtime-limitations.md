# Runtime limitations

Be candid:

* Python monkeypatching cannot intercept **saved pre-patch function references**.
* Native extensions may bypass Python interception.
* External child processes may perform syscalls outside Python hooks.
* Raw sockets, aiohttp, direct urllib3, gRPC, and websockets may be **uncovered**.
* Filesystem coverage is **PARTIAL**: Python APIs only; OS-global isolation is
  **NOT GUARANTEED**.
* PATH wrappers in `varden session` are one layer — not a complete security boundary.
* OS sandbox backends (namespaces, seccomp, eBPF, macOS sandbox, Windows job
  objects) are **not** claimed by this milestone.

Coverage attestation exists specifically so these gaps are visible.
