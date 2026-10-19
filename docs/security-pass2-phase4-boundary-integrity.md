# Security Hardening Pass 2 — Phase 4

Security boundary integrity, destination binding, and adversarial resilience.

Branch: `security/pass2-phase4-boundary-integrity`

Starting point: latest `main` after the Phase 3 squash merge `security: Phase 3 enforcement integrity hardening (#76)`.

Baseline SHA:

`d3ad9affffb2734f450fbae9e0b52945756af6bf`

Final SHA: the tip of this branch after these commits. `git rev-parse HEAD` on the branch is authoritative. This report is part of a commit, so the hash cannot be written inside it.

No pull request was opened. Nothing was merged, tagged, published, or released. This report is not a security approval. Independent review is required before merge.

The pre-change full suite was not re-run in this session. The Phase 3 report recorded 1189 passed and 7 Playwright setup errors on the same browser tests. The counts below are the post-change runs.

## 1. Threat model and trust boundaries

Varden is an in-process runtime firewall. It mediates Python calls that enter the functions it patched, asks the control plane for a decision, and refuses the call when that decision is a deny or when a local boundary it owns cannot be satisfied. It is not a sandbox.

**Enforceable inside a cooperative process.** `protect()` installs wrappers for `requests` `Session.request` and `Session.send`, `httpx` `Client.send` and `AsyncClient.send`, `urllib.request.urlopen`, the patched filesystem calls, subprocess entry points (`Popen`, `run`, `call`, `check_*`, `os.system`, `os.popen`, asyncio subprocess), and the OpenAI and Anthropic transport methods when those classes exist. MCP client traffic is enforced when it goes through the gateway or host. A locked guarded or strict contract refuses a delivered deny and does not treat `fail_mode=open` as permission to ignore that deny.

**Detectable, not preventable, once the call has left the wrapper.** Replacing `Session.send` after `Session.request` is still the wrapper is detected and the request fails closed. Replacing the entry point the agent actually calls is visible on the next `verify()`, readiness check, or attestation, which downgrades that surface from `ENFORCED`. The call that already went through the replaced function is not stopped. A copied asyncio context does not inherit a filesystem passthrough, but a same-thread nested call of an already authorized path still does, by design, for the duration of that syscall.

**What an agent in this process can mutate.** Any Python attribute: `builtins.open`, `os.*`, `subprocess.Popen`, `requests.Session.send`, `httpx.Client.send`, the async wrappers, `socket.getaddrinfo`, the coverage registry's method table, saved originals in `varden_sdk.sdk._ORIGINALS`, and a foreign wrapper another library installed. Ordinary writes to `CoverageRegistry._mode` and `_fail_mode` do not change a locked contract. Ordinary assignment to `guard.product_mode` and `guard.fail_mode` raises. A caller who can replace the registry object, the checker callables, or `_sealed_contract` is outside that protection.

**What requires an OS, container, or network boundary.** Raw sockets, `ctypes` or libc `connect`, native extensions, `os.exec*` and `os.spawn*`, other processes, aiohttp, direct urllib3, a saved pre-patch function, an HTTP proxy that resolves the target itself, pre-existing hard links, `os.read` and `os.write` on an already-open descriptor, and a true filesystem jail (`openat2` `RESOLVE_BENEATH`, mount namespace, container). Varden does not claim those.

**What is claimed `ENFORCED` after this phase, and only while the live probe passes.** `http.requests`, `http.httpx`, `http.urllib`, `subprocess`, and the LLM transports when their SDK classes import. Each probe requires the wrapper identity. The HTTP probes also require the `socket.getaddrinfo` pin hook. Filesystem stays `PARTIAL`. `http.aiohttp` stays `UNSUPPORTED`. `http.raw_sockets` and `http.urllib3` stay `UNCOVERED`. The legacy tree `sdks/python` does not implement these probes and must not be described as Phase 4 enforcement. The packaged SDK is the repository-root `varden_sdk`.

## 2. Attack inventory

| Attack | Result |
|---|---|
| Public DNS answer, then a later lookup of loopback, RFC1918, or link-local | Prevented on direct `requests`, `httpx` sync, `httpx` async, and `urllib.request.urlopen`. The connect uses the authorized address set. |
| Mixed public and non-public answers | Prevented for a direct hop when policy blocks the non-public category. Zero connections in the gauntlet. |
| IPv6 loopback and unique-local answers | Prevented before connect when policy blocks those categories. |
| Redirect onto a newly resolved private or loopback name | Prevented. The redirect hop is authorized on its own and pinned. The forbidden address receives no connection. |
| DNS change after authorization, including a pooled socket to the old address | Prevented for the tested urllib3 and httpx pools. The mismatched peer is dropped. The next connect uses the new pin. |
| Explicit or environment HTTP proxy | Detected and labeled `status=proxy`, `socket_bound=false`. Not prevented at the target. The proxy resolves the target. |
| Custom `HTTPAdapter` or `httpx` transport | Detected and labeled `status=unbound`, `socket_bound=false`. Not pinned. |
| Failure to resolve, or a malformed answer, on a direct hop | Prevented. `VardenBlockedError`, zero connections, including under `fail_mode=open`. |
| HTTPS after a pin | The URL host is still the TLS server name. A certificate for that name verifies. A certificate mismatch names the hostname, not the pinned IP. |
| Replace `Session.send` | Detected. `http.requests` leaves `ENFORCED`. A later `Session.request` fails closed. Readiness fails when `http.requests` is required. |
| Foreign wrapper left by another library | Detected. `reconcile_runtime()` does not override it. The surface does not stay `ENFORCED`. |
| Saved original, then `reconcile_runtime()` | Restored to the Varden wrapper. |
| Mutate locked mode or fail mode | The sealed contract is unchanged. Attribute assignment raises. |
| Repeated `protect()` with a weaker mode | Refused. The installed wrapper stays. |
| Concurrent checker flip during readiness | Readiness is not ready. The surface is not left `ENFORCED`. |
| Relative `dir_fd` aimed at a secret | Prevented on macOS by joining `F_GETPATH` and classifying the result. |
| Unresolvable relative `dir_fd` | Prevented while enforcing. The call is refused before the syscall. |
| Symlink swapped onto the final component after the check | Prevented for mediated `os.open` and `builtins.open` via `O_NOFOLLOW` when the check did not already see a symlink. |
| Pre-existing hard link under a benign name | Not prevented. Filesystem stays `PARTIAL`. |
| Async or thread copy of a passthrough context | Does not inherit the bypass. |
| `os.read` of an already-open descriptor, native code | Unsupported. Named in the filesystem limitations. |

## 3. Confirmed vulnerabilities

These were true on the Phase 3 tip. The gauntlet reproduces the boundary; the fixes are in this branch.

**V-DNS-01. Authorization and connect did not share a destination.** Phase 3 resolved enough to record `dns_rebinding=open` and to classify a literal IP. The HTTP client then called `getaddrinfo` again, or reused a pooled socket, and could connect to a different address. A redirect was re-authorized as a URL, then resolved again by the client. Preflight DNS was not a rebinding control.

**V-DNS-02. Proxy and custom transports were not distinguished from a direct connect.** A policy decision on the target URL could be read as a decision on the TCP peer. For a proxy, the TCP peer is the proxy.

**V-TAMP-01. A replaced wrapper could remain attested `ENFORCED`.** Coverage `mark(ENFORCED)` and a later status read did not require the live function to still be the wrapper. `strict_readiness()` did not verify before reporting ready.

**V-TAMP-02. Locked-contract fields could be reassigned on the registry object.** Enforcement reads now go through the sealed snapshot taken at lock. Ordinary `_mode` and `_fail_mode` writes do not change it. Replacing the registry or the snapshot object still does.

**V-FS-01. Relative `dir_fd` was classified by the relative name only.** `os.open("notes.txt", dir_fd=secret_dir_fd)` did not see the directory. Phase 3 documented this and kept filesystem `PARTIAL`.

**V-FS-02. A filesystem passthrough token was visible to any task that copied the context.** A nested call during the original syscall could run unauthorized if it shared that context.

**V-FS-03. A final-component symlink could replace a regular file after classification and be followed.** The re-check narrowed the window. It did not pin the file type into the syscall.

## 4. Reproductions and side-effect evidence

`tests/security/pass2/test_p4_boundary_integrity.py` uses a deterministic resolver, a `socket.socket.connect` log, and local listeners. Policy decisions and connected addresses are asserted separately. For every blocked destination, the forbidden address is absent from the connect log and the listener's accept list is empty.

Before this branch, the same shape of test fails open at the socket: authorize `rebind.test` as `203.0.113.10` (or `1.1.1.1`), then the client's second lookup returns `127.0.0.1`, and `connect` is attempted to loopback. After this branch, `connect` is attempted only to the authorized address. The loopback listener accepts nothing.

The redirect test returns a `302` to `evil.rebind` from the authorized listener. The second hop's resolver answer is loopback. No second connect is logged.

The pool test completes one request to `127.0.0.1`, changes the authorized set to a documentation address, and issues a second request. The first server does not see the second path. The connect log's later address is the new pin.

The HTTPS test serves a certificate whose SAN is `pinned.test` on `127.0.0.1`. The request URL host stays `pinned.test`. Verification succeeds. An earlier failed certificate, before the SAN was correct, reported `not valid for 'pinned.test'`, which is the hostname and not the pinned IP.

The tamper tests replace `Session.send` with the saved original. `strict_readiness()` is false when `http.requests` is required. `surface.evidence["operational"]` is false. `attestation()["tamper_events"]` is non-empty. `session.get` raises `VardenBlockedError` and does not create the sentinel file.

The symlink test replaces the final component inside the saved `os.open`, after classification. The open raises `OSError` and the secret is not read.

The hard-link test is the negative result. A benign name for an `id_rsa` inode is read. Filesystem status remains `PARTIAL`.

These fixtures do not prove production OS containment. They prove the Python connect and open paths under test.

## 5. Root causes

- HTTP clients resolve and pool independently of the URL that policy saw. Pinning has to be at `getaddrinfo` and at pool reuse, not at a preflight lookup.
- `httpx` async resolves through `anyio` in an executor. A context variable does not reach that executor. The pin table is process-global and keyed by host. Conflicting pins for one host fail the lookup instead of choosing one.
- Proxy and custom transports do not connect to the URL host. Treating them as pinned would be a false guarantee.
- Coverage status was a stored label. Nothing compared it to the function object on the way out of `strict_readiness()`.
- `dir_fd` was not part of the path passed to `classify_path`.
- The passthrough context variable was the authorization itself, so a copied context carried it.
- `open` did not pass a flag that makes the kernel reject a new symlink.

## 6. Remediations

**Destination binding** (`varden/destination_binding.py`). For a direct default transport, resolve once, attach `metadata.destination_binding`, and install a `socket.getaddrinfo` hook that answers only the authorized addresses for that host until the send returns. The URL host is not rewritten, so TLS SNI and certificate verification stay on the hostname. Pooled urllib3 and httpx connections whose peer is not in the set are closed before send. Proxies are `status=proxy` and `socket_bound=false`. Custom adapters and transports are `status=unbound` and are not resolved, so a `MockTransport` or a capturing adapter stays offline. An unresolved or malformed direct hop raises `VardenBlockedError` while enforcement is on. Observe does not raise. `fail_mode=open` does not waive this. It is not a control-plane transport failure.

**Identity.** `dns_rebinding` on the canonical URL stays `open` for hostnames and `not_applicable` for literals. The pin is a separate `connection_binding` status. Resolved address categories are recomputed. A client label of `public` on `10.1.2.3` does not stick. A hostname's `destination_category` is elevated, never lowered, from those addresses. A literal IP is not lowered by a claimed address list. There is still no default deny of every private address. A policy that allows the elevated category still connects to that address.

**One guarded action per hop.** Resolution and the proxy label ride on the existing HTTP action. They do not add a second budget charge.

**Tamper.** `verify()` downgrades `ENFORCED` to `UNCOVERED` when a sealed checker fails, records a tamper event (capped at 50), and sets `evidence.operational` false. `strict_readiness()` and `attestation()` call `verify()` first. HTTP checkers include the resolution hook. `Session.request` fails closed if `Session.send` is no longer the installed wrapper. `reconcile_runtime()` restores a wrapper only when the current function is the saved original. A foreign function is reported and left in place. The getaddrinfo hook is not installed over a foreign hook. After the first successful verification, later checks do not rewrite evidence on every call. The checker still runs. That cost is about 3 microseconds and is the fail-closed probe for a required surface.

**Filesystem.** Relative `dir_fd` is joined to the descriptor path on macOS (`fcntl.F_GETPATH`) and, in code, on Linux (`/proc/self/fd`). An unresolvable relative descriptor is refused while enforcing, before policy. Absolute paths ignore `dir_fd`. Allowed calls still use the original `dir_fd` form, so `shutil.rmtree` of a temporary directory still works. `O_NOFOLLOW` is added on `os.open`, and as a `builtins.open` opener, when the check did not already see a symlink and the caller did not supply an opener. The passthrough is a token keyed by thread or asyncio task and is removed when the syscall returns.

**Standalone SDK.** `sdks/python` is unchanged in behavior. A comment states that destination binding, attestation, and directory-descriptor resolution are not in that tree. Its deny and transport fail-open tests still apply.

## 7. DNS connection-binding verdict

**Direct default transports: bound, with connection evidence.** `requests` using `HTTPAdapter`, `httpx` sync `HTTPTransport` over `ConnectionPool`, `httpx` async `AsyncHTTPTransport` over `AsyncConnectionPool`, and `urllib.request.urlopen` pin `socket.getaddrinfo` to the authorization-time address set and scrub a mismatched pooled peer. The gauntlet records the connected address.

**Not bound, and not claimed as bound.** Explicit proxies, environment proxies, custom adapters, custom transports, aiohttp, direct urllib3, raw sockets, a saved pre-patch client, and any resolver that does not call `socket.getaddrinfo`. Proxy hops report `socket_bound=false` and `status=proxy`. Custom hops report `status=unbound`. The local resolver is not required to see a proxied target, and a proxy hop is not failed closed for that reason.

**Not solved at the URL-identity layer.** `canonicalize_destination` still reports `dns_rebinding=open` for a hostname. A passing preflight check is not this control. The control is the pin plus the pool scrub, and only for the transports above.

Python 3.13's `ipaddress` treats the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` as private. Category elevation follows that. Tests that need a globally routed label use `1.1.1.1` and refuse the connect in-process.

## 8. Filesystem containment verdict

Filesystem coverage remains **`PARTIAL`**.

Prevented on the patched calls, on the platform tested: a relative `dir_fd` whose directory path can be read and whose joined path is denied; a relative `dir_fd` whose path cannot be read, while enforcing; a final-component symlink introduced after a non-symlink check, via `O_NOFOLLOW`; a passthrough inherited by another thread or task.

Not prevented: inode replacement of a regular file between the re-check and the syscall; a parent directory replaced after the re-check; a hard link that already exists under another name; a directory renamed after `F_GETPATH` or `readlink`; `os.read` and `os.write`; a caller-supplied `opener`; native code; another process. `openat2` is not used. A Linux-only flag is not described as cross-platform containment.

## 9. Runtime tamper-resistance verdict

Three cases:

1. **Accidental interference.** Another library's wrapper is detected. Reconciliation does not remove it. The surface loses `ENFORCED`. An operator can see `tamper_events` and `evidence.operational=false`.
2. **Agent-accessible configuration.** Locked mode and fail mode survive ordinary field writes. `protect()` with a different mode raises and leaves the wrapper installed. A required surface that fails its probe fails readiness.
3. **Privileged in-process attacker.** Not contained. Code that calls a saved original, patches the checker, replaces `CoverageRegistry`, or connects through libc does not pass through these wrappers. Monkeypatching cannot prevent that. Isolate untrusted code in another process or a container.

Varden will not leave a known critical interceptor attested `ENFORCED` after `verify()`, readiness, or attestation. It will not stop the already-replaced call.

## 10. Coverage attestation verdict

Public statuses are unchanged: `ENFORCED`, `PARTIAL`, `OBSERVATIONAL`, `UNCOVERED`, `UNSUPPORTED`, `NOT_ROUTED`.

Evidence on each surface, when `verify()` has run, carries `configured`, `installed`, `verified`, and `operational`. Those are inspection fields, not new public states. `ENFORCED` after a failed checker is removed. A failed self-test makes `strict_readiness()["ready"]` false when that surface is required. An unknown required name is missing and not ready. JSON attestation remains a dictionary with `tamper_events` and is valid JSON. Unknown coverage is not treated as protected: `missing_required` fails a name that is not an enforced, active, verified surface.

`mark(ENFORCED)` without a checker, before the contract is locked, still records verified. Existing unit tests depend on that. Production `protect()` locks the contract and installs checkers. A locked HTTP surface cannot stay `ENFORCED` without the hook and both wrappers.

## 11. Platform support matrix

Tested: macOS Darwin 25.6.0, CPython 3.13.13, arm64. Libraries in this environment: urllib3 2.7.0, requests 2.34.2, httpx 0.28.1, httpcore 1.0.9.

| Boundary | macOS (tested) | Linux (not run) | Windows (not run) |
|---|---|---|---|
| `getaddrinfo` pin | exercised | same Python hook, not run | same Python hook, not run |
| `dir_fd` path | `F_GETPATH`, exercised | `/proc/self/fd` is implemented, not run | no `dir_fd`; relative form would be refused if reached, not run |
| `O_NOFOLLOW` | exercised | present on Linux, not run | not present; the flag is applied only when `os.O_NOFOLLOW` exists |
| `openat2` | not implemented | not implemented | not applicable |

Do not read this as Linux or Windows coverage.

## 12. Performance measurements

Script: `tests/security/pass2/bench_p4_boundary.py`. One process, stubbed control plane, local HTTP server, 19 October 2026. There is no Phase 3 microbenchmark, so these are absolute costs. The new per-call integrity probe is the `coverage verify` row.

| Operation | Median | p95 | n |
|---|---:|---:|---:|
| `open` unpatched | 8.2 µs | 11.1 µs | 200 |
| `open` patched | 513.5 µs | 615.8 µs | 200 |
| `requests` GET, literal, unpatched | 315.0 µs | 370.7 µs | 50 |
| `requests` GET, literal, patched | 519.3 µs | 611.6 µs | 40 |
| `requests` GET, pinned hostname | 496.9 µs | 694.3 µs | 40 |
| `guarded_action` (stub allow) | 14.4 µs | 18.8 µs | 200 |
| coverage `verify()` | 2.9 µs | 3.0 µs | 200 |
| `getaddrinfo` with hook, no pin | 17.5 µs | 21.5 µs | 100 |
| `getaddrinfo` after unpatch | 16.8 µs | 19.4 µs | 100 |
| `protect` + `unpatch` | 36.0 ms | 36.9 ms | 5 |
| second `protect` refused | 35.6 ms | 36.7 ms | 20 |

The pin does not add a measurable hop beyond the existing HTTP wrapper on this machine (pinned hostname median is within the literal patched spread). The idle hook adds well under a microsecond to an unpinned lookup. `verify()` is about 3 microseconds because the steady state is a pointer compare. Patched `open` is dominated by classification and the guarded action, which Phase 3 already did. A real control-plane round trip remains the large term. Activation constructs a guard and installs wrappers once. A weaker second `protect()` raises before it replaces wrappers. The ~36 ms on that refusal is guard construction, not a second install.

No extra policy call and no second budget charge were added for resolution, proxy labeling, or the integrity probe.

## 13. Remaining bypasses

Ranked by severity for an agent that can run Python in the guarded process.

1. **High. Privileged in-process tampering.** Saved originals, libc connect, a replaced checker, a replaced registry. Detection applies only to the known wrappers, and only on a later probe. Operational requirement: do not run untrusted code in the Varden process.
2. **High. Proxy DNS.** The TCP peer is the proxy. The proxy's resolution of the target is not pinned. Operational requirement: a proxy must enforce destination policy itself, or not be used for guarded egress.
3. **High. Unbound HTTP stacks.** Custom transports, custom adapters, aiohttp, direct urllib3, raw sockets. They are labeled or left `UNCOVERED` / `UNSUPPORTED`. They are not blocked merely for being unbound, because that would reject test doubles and legitimate custom clients. An agent that can choose its HTTP stack can leave the pin.
4. **High. Filesystem outside the patched calls.** Hard links, raw descriptors, native code, inode races. `PARTIAL` is the claim. Operational requirement: OS or container isolation for secrets that must not be reachable under another name.
5. **Medium. Stale directory-descriptor path.** `F_GETPATH` and `/proc/self/fd` can disagree with the kernel after a rename. This is not `RESOLVE_BENEATH`.
6. **Medium. Platforms not executed.** Linux descriptor resolution and Windows refusal of relative `dir_fd` are implemented to fail closed or to resolve, and were not run.
7. **Medium. Pool scrub follows current urllib3 and httpcore object shapes.** A future version that reuses a socket without `getaddrinfo` and without a visible peer could skip the scrub. The pin still covers a fresh lookup.
8. **Low. Concurrent pins of one host with different address sets fail the lookup (`EAI_FAIL`).** That is fail-closed. It can turn a race into a failed request rather than a crossed destination.
9. **Low. Legacy `sdks/python`.** No pin, no attestation, no `dir_fd` resolution. It still refuses a delivered deny. It is not the packaged SDK.

## 14. Breaking changes

- A direct hop that does not resolve, or whose DNS answer has no usable address, raises `VardenBlockedError` under guarded and strict, including `fail_mode=open`. Observe still proceeds. Control-plane fail-open for `transport_failure` and `service_failure_with_allow` is unchanged.
- A relative `dir_fd` that cannot be named is refused while enforcing. On macOS a resolvable `dir_fd` is classified as the joined path, so a secret directory is denied even when the relative name is benign. `shutil.rmtree` of an ordinary temporary directory still works.
- `O_NOFOLLOW` can make a mediated open fail when a symlink appears after the check. An open of a symlink that classification already saw does not get the flag.
- `Session.request` raises `VardenBlockedError` (`interceptor_tamper`) if `Session.send` is no longer the installed wrapper.
- `protect()` is otherwise the same call.

## 15. Final test results

Machine: macOS Darwin 25.6.0, CPython 3.13.13. Ruff 0.17.1 on the modified Python files: all checks passed.

| Command | Result |
|---|---|
| `python -m compileall -q varden varden_sdk varden_langchain sdks/python` | exit 0 |
| `python -m pytest -q tests/security/pass2/` | 390 passed, 32 warnings, 29.45s |
| `python -m pytest -q tests/security/test_guard_response_enforcement.py` | 36 passed, 15 warnings, 1.40s |
| `python -m pytest -q tests/test_clean_wheel_smoke.py` | 4 passed, 4.87s |
| `python -m pytest -q --tb=line -p no:cacheprovider` | 1219 passed, 49 warnings, 7 errors, 206.68s |
| `tests/security/gauntlet tests/runtime tests/test_mcp_server.py tests/test_mcp_inventory.py` | 176 passed, 2 warnings, 79.52s |
| `tests/browser/test_ui_smoke.py` with `PLAYWRIGHT_BROWSERS_PATH` set to the installed cache | 8 passed, 2.49s |

The 7 errors in the full command are `tests/browser/test_ui_smoke.py` setup failures: Playwright looked for Chromium under the sandbox browser cache and did not find it. No frontend code changed. The same file passed 8 tests when pointed at the installed Playwright cache. The warnings are the existing `fail_mode=open` user warning.

Phase 2 and Phase 3 assertions that hostname `dns_rebinding` stays `open` still pass. Provider create-block tests in the pass 2 suite passed as part of the 390. No regression test was removed or weakened. `test_allow_decision_does_not_connect_to_a_rejected_destination` now supplies a deterministic resolver so the first hop is a real authorization; the rejected redirect still performs no second send.

## 16. Security readiness recommendation

Ready for independent security review. Not approved for merge.

The review should focus on: the `getaddrinfo` pin and pool scrub against the installed urllib3 and httpcore versions; the decision that proxies and custom transports are explicitly unbound rather than blocked; the filesystem `PARTIAL` claim, including hard links and the absence of `openat2`; and the statement that a privileged in-process attacker is out of scope. A documented limitation is not a closed boundary.
