# Security Hardening Pass 2 — Phase 3

Enforcement completeness, side-effect prevention, and coverage integrity.

Branch: `security/pass2-phase3-enforcement-integrity`

Baseline SHA (latest `main` at start, working tree clean, Phase 1 and Phase 2 already merged):

`4c96aafd5b66e35a5a9f7601527a11fb73918016`

Final SHA: the tip of this branch after the Phase 3 commit. `git rev-parse HEAD` on the branch is authoritative. This report is part of that commit, so the hash cannot be written inside it.

The waiting Threat Intelligence / UI alignment branch was not merged. Nothing was tagged, published, or released. No pull request was opened.

## Invariant

For an applicable, enforced operation, a definitive block prevents the protected side effect. Tests in `tests/security/pass2/test_p3_enforcement_integrity.py` use temporary files, local HTTP servers, and a fake MCP stdin. Returned decisions alone are not the evidence.

## A. Enforcement coverage matrix

| Surface | Entry point | Interceptor | Actual execution boundary | Verified prevention | Coverage state | Residual risk |
|---|---|---|---|---|---|---|
| SDK `protect()` / tool call | `VardenGuard.guarded_action` | tool wrapper | original function runs only after a non-deny decision, or after a real control-plane outage when `fail_mode=open` and the mode is not strict | decision matrix writes a sentinel file only on the executing rows | enforced for wrapped tools | `@tool` is a no-op with no active guard; `atexit` restores patches at process exit |
| HTTP `requests` | `Session.request`, `Session.send` | both methods; depth counter so `request` does not authorize twice when it calls `send` | connect happens after authorization; redirects re-authorized; cross-host hop drops `Authorization`, `Cookie`, `Proxy-Authorization`, per-call auth/cookies, and session auth | blocked `get` and `send` leave the local server with zero hits under `fail_mode=open`; allowed request connects; redirect to a blocked host does not connect | ENFORCED only while both wrappers are installed; unwrapping `send` downgrades to UNCOVERED | DNS rebinding open; saved pre-patch references; direct urllib3; proxy CONNECT target is the request URL |
| HTTP `httpx` | `Client.send`, `AsyncClient.send` | both | same authorize-before-connect and redirect re-auth; cross-origin credential drop | probe requires both sync and async send | ENFORCED only when both are wrapped | same DNS residual; custom transports |
| HTTP urllib | `urllib.request.urlopen` | existing patch | patched urlopen only | existing suite | UNCOVERED until patched; catalog does not claim raw handlers | lower-level handlers |
| HTTP aiohttp / raw sockets / urllib3 | none | none | not intercepted | not claimed | UNSUPPORTED or UNCOVERED | direct use bypasses Varden |
| Filesystem | `builtins.open`, `Path.open`, `os.open`, `os.remove`/`unlink`/`rename`/`replace`/`link`/`symlink` | keyword and positional | syscall runs after classification and a pre-use re-check | keyword remove/rename, `os.open`, `Path.touch`, `os.link`, and `dir_fd` plus a secret basename do not create or destroy the sentinel | PARTIAL, and the runtime mark stays PARTIAL | TOCTOU to the kernel; benign `dir_fd`; pre-existing hard links; raw fds; `os.read`/`os.write`; native code; benign workspace paths may not consult policy |
| Subprocess | `Popen`, `run`, `call`, `check_call`, `check_output`, `os.system`, `os.popen`, `asyncio.create_subprocess_exec`/`shell` | extended wrappers reinstall if restored to the saved original | child starts only after authorization | blocked forms, including `shell=True` and asyncio, create no sentinel file; allow does; `require_approval` does not start | ENFORCED for those Python hooks | `os.exec*`, `os.spawn*`, ctypes, saved references, native forks; not an OS sandbox |
| MCP gateway | `McpGatewaySession.exchange` | exact method classification | privileged methods write stdin only after `response_authorizes_execution` | blocked `tools/call`, `resources/read`, `prompts/get` write nothing; missing decision does not forward; malformed JSON-RPC is `-32600` | enforced for gateway-routed client requests | discovery still forwards when the control plane is down; direct stdio is NOT_ROUTED; server-initiated MCP is outside this proxy |
| MCP host | `VardenMcpHost.call_tool` | same decision helpers | in-process handler runs only after a recognized non-deny decision | HTTP 200 `require_approval` does not call the handler; allow calls it once | same trust boundary as the gateway | host has no fail-open; a delivered deny does not execute, including in observe |
| LangChain | `invoke` / `ainvoke` / `_run` / `_arun` | depth counter so invoke does not double-authorize `_run` | tool body runs only if the guard does not block | existing integration tests plus the shared decision path | PARTIAL; callbacks stay observational | callbacks swallow `VardenBlockedError` and do not stop a tool that already started |
| LLM transports | OpenAI / Anthropic sync and async `create` | patched when the class exists | request body leaves only after the guard | coverage is ENFORCED only when every known sync and async create is wrapped | PARTIAL when an async class is missing; UNCOVERED when the SDK is absent | cognition is never covered; openai/anthropic are not installed in the development venv, so the async class paths were not executed here |
| Standalone `sdks/python` | `VardenClient.guard` then `guarded_action` | local decision helpers mirroring the root deny set | original tool runs only when no deny was delivered | HTTP 200 `require_approval` with `fail_mode=open` writes nothing; `ConnectionError` with `fail_mode=open` still runs | legacy tree, version 1.0.3 so it does not outrank the root package | not the packaged wheel; root `varden_sdk` is canonical |

## B. Findings register

### F-FS-01 — keyword filesystem calls skipped mediation

- Severity: high. Exploitability: any caller using `os.remove(path=...)` or `os.rename(src=..., dst=...)`.
- Affected code: `varden_sdk/patches.py` path extraction (positional only).
- Root cause: wrappers read `args[0]` and ignored keywords, so the original function ran with no policy check.
- Remediation: `_call_path` reads the positional slot or the keyword name.
- Regression: `test_keyword_remove_and_rename_produce_no_side_effect`.

### F-FS-02 — `os.open` and `Path.touch` were not mediated

- Severity: high. A secret file could be opened or created by file descriptor without `builtins.open`.
- Root cause: `os.open` was not patched. `Path.touch` uses `os.open`.
- Remediation: patch `os.open` (positional and keyword). `O_RDONLY` is `0` on macOS and is not treated as a missing flag.
- Regression: `test_os_open_and_path_touch_do_not_open_or_create_secrets`.

### F-FS-03 — `os.link` / `os.symlink` created a second name for a secret

- Severity: high for links created after interception. Realpath of the new name is not the secret path, so a destination-only check missed it.
- Remediation: patch both calls and classify both ends. Policy sees the source classification.
- Regression: `test_hard_link_of_secret_is_not_created`.
- Residual: a hard link created before interception still has a benign realpath. Coverage stays PARTIAL.

### F-FS-04 — descriptor-relative paths are not contained

- Severity: high if claimed as full containment; treated as a documented PARTIAL residual.
- A blanket denial of every `dir_fd` call was implemented and removed. `shutil.rmtree` unlinks with `dir_fd`, and denying those calls stops the process from deleting its own temporary files.
- Current behaviour: classify the path string, so `os.open("id_rsa", O_RDONLY, dir_fd=fd)` is still a secrets operation. A benign relative name against an untracked directory descriptor is not contained.
- Regression: `test_dir_fd_secret_name_is_not_opened`. Documentation: `docs/runtime-filesystem-containment.md`.

### F-MCP-01 — gateway treated HTTP 200 with no decision as allow

- Severity: high. A control plane that answered without `decision.action` still had its JSON-RPC written to the downstream stdin.
- Affected code: `varden/runtime/mcp_gateway.py` `McpGatewaySession.guard`.
- Remediation: after `guard_response_blocks` and `raise_for_status`, require `response_authorizes_execution`. Otherwise return blocked with reason `missing_guard_decision` and do not forward. HTTP errors with no decision still raise, and `exchange` returns JSON-RPC `-32001` without forwarding.
- Regression: `test_mcp_missing_decision_does_not_forward`, `test_blocked_mcp_methods_never_reach_downstream`.

### F-MCP-02 — host adapter treated only HTTP 403 as a block

- Severity: high. HTTP 200 `require_approval` ran the in-process handler.
- Affected code: `varden/runtime/mcp_host.py` `call_tool`.
- Remediation: same helpers. A deny or a missing decision returns `McpToolResult(blocked=True)` and does not call the handler. An HTTP error with no deny body calls `raise_for_status`. The host has no fail-open: a delivered deny does not execute.
- Regression: `test_mcp_host_http_200_deny_does_not_call_handler`, `test_mcp_host_allow_calls_handler_once`.

### F-SDK-01 — standalone tree fail-open and a lossy deny parser

- Severity: high for anyone installing `sdks/python` instead of the root package.
- Root cause: that tree defaulted `fail_mode` to `open`, and treated only HTTP 403 and `action == "block"` as a deny. `require_approval` executed. Version `3.0.0` could outrank the canonical `1.0.3` package.
- Remediation: default `fail_mode` is `closed` on `VardenGuard` and `protect_from_env`. Local helpers mirror the root deny set (`block`, `blocked`, `require_approval`, `approval_required`, `unsupported`) and ambiguous decisions. A delivered deny raises before fail-open. Version lowered to `1.0.3`. The root package remains the one `pip install` builds from the repository root.
- Regression: `test_standalone_sdk_deny_under_fail_open_writes_nothing`, `test_standalone_sdk_transport_failure_still_fail_opens_when_asked`.

### F-HTTP-01 — `Session.send` was uncovered while `http.requests` could be ENFORCED

- Severity: high. `Session.send(prepared)` connected with no authorization.
- Remediation: wrap `send` with the same authorize-before-connect and redirect re-auth path. A depth counter keeps `Session.request` from authorizing the same hop twice. The coverage probe requires both wrappers.
- Regression: `test_blocked_http_never_connects_under_fail_open`, `test_unwrapping_session_send_downgrades_requests_coverage`.

### F-HTTP-02 — cross-host redirects forwarded credentials

- Severity: medium. Only `Authorization` was stripped.
- Remediation: also drop `Cookie` and `Proxy-Authorization`, per-call `auth` and `cookies`, and `session.auth` for that hop. httpx drops the same headers on a cross-origin `next_request`.
- Regression: `test_allowed_http_connects_and_cross_host_redirect_drops_credentials` (local listeners on `127.0.0.1` and `::1`; this host cannot bind `127.0.0.2`).

### F-HTTP-03 — DNS rebinding remains open

- Severity: residual, carried forward from Phase 2. Not closed.
- A pre-connect `getaddrinfo` can differ from the address `connect()` uses. No supported client pins the verified address through to the socket.
- `Destination.dns_rebinding` stays `open` for hostnames and `not_applicable` for literal IPs.
- Regression lock: `test_dns_rebinding_remains_an_open_residual`.

### F-SUB-01 — extended subprocess wrappers and shell metadata

- Severity: medium. Restoring `subprocess.call` to the saved original left it unpatched, and `shell` / `cwd` / `executable` were not part of the policy payload.
- Remediation: reinstall when the attribute is the saved original. Payload keeps those fields, redacts environment values, and marks `shell=True` elevated.
- Regression: `test_blocked_subprocess_forms_create_no_child_file`, `test_subprocess_coverage_names_unpatched_exec`.

### F-LLM-01 — transport coverage could be marked ENFORCED without an async probe

- Severity: medium (coverage honesty). A missing async create method no longer produces a silent ENFORCED mark. Missing async is PARTIAL. If nothing is patched, the catalog stays UNCOVERED.
- Executed after the review remediation against openai 1.109.1 and anthropic 0.125.0. See section G.

### F-LC-01 — LangChain enforcement ignored the locked mode, and `_run` was unwrapped

- Severity: medium. `_maybe_block` now uses the locked enforcing flag. `_run` and `_arun` are wrapped. A depth counter prevents invoke from authorizing the same call twice (Phase 1 budget).
- Callbacks remain observational on purpose.

## C. Decision matrix

`classify_guard_response` is the shared contract for a completed HTTP body. Transport failure is not a response class. Fail-open applies only to `transport_failure` and to `service_failure_with_allow` (a non-success status whose body is an authoritative allow). An empty or malformed success body, and an HTTP error with no decision, do not execute in guarded or strict mode.

| Mode | fail_mode | Classification | Side effect |
|---|---|---|---|
| observe | open or closed | any, including explicit block | executes (observe does not prevent) |
| guarded or strict | closed | `authoritative_allow` on a 2xx | executes |
| guarded or strict | open or closed | `authoritative_deny`, `approval_required`, `invalid_decision`, `no_decision`, `service_failure` | no side effect |
| guarded | open | `service_failure_with_allow` (for example HTTP 503 whose decision is allow) | executes |
| guarded | closed | `service_failure_with_allow` | no side effect |
| guarded | open | `transport_failure` (connection refused, reset, timeout before a response) | executes |
| guarded | closed | `transport_failure` | no side effect |
| guarded | open | unexpected client exception that is not transport | no side effect |
| strict | open | construction | `ValueError`; strict refuses fail-open |

The MCP gateway and host do not implement fail-open. Only `authoritative_allow` forwards or runs the handler. A 5xx allow does not.

`response_authorizes_execution` is true only for a recognized non-deny action (`allow`, `warn`, `warned`, `monitor`, `sanitise`) with no deny in another recognized slot.

## D. Implementation summary

Changed:

- `varden/runtime/guard_response.py` — `response_authorizes_execution`.
- `varden/runtime/mcp_gateway.py`, `varden/runtime/mcp_host.py` — missing or non-authorizing decisions do not forward or run the handler.
- `varden_sdk/patches.py` — keyword paths, `os.open`, `os.link`, `os.symlink`, subprocess reinstall and metadata, filesystem mark stays PARTIAL with the real limitations.
- `varden_sdk/sdk.py` — `Session.send`, redirect credential stripping, httpx cross-origin header drop, requests/httpx/subprocess coverage probes, LLM async gap.
- `varden_langchain/integration.py` — locked enforcing flag, `_run` / `_arun`, depth counter.
- `varden/runtime/coverage.py` — catalog limitations for `Session.send` and `os.exec*` / `os.spawn*` / ctypes.
- `sdks/python/varden_sdk/sdk.py`, `sdks/python/pyproject.toml` — deny-before-fail-open, default `fail_mode=closed`, version `1.0.3`.
- `docs/runtime-filesystem-containment.md` — patched set and the `dir_fd` residual.
- `tests/security/pass2/test_p3_enforcement_integrity.py` — side-effect gauntlet.
- `tests/test_clean_wheel_smoke.py` — installed-wheel keyword `os.remove` smoke.

Compatibility: public `protect()` signature is unchanged. The standalone tree's default fail mode changed from open to closed, matching the root package. Explicit `fail_mode="open"` still executes on a genuine transport failure. Filesystem coverage was not promoted to ENFORCED. Phase 1 transactional budgets are preserved by the HTTP and LangChain depth counters. Phase 2 canonical identity and exact MCP method classification are unchanged.

## E. Evidence

Commands actually run on this branch (do not treat a row as passed unless it appears here):

- Baseline, before code changes: `.venv/bin/python -m pytest tests/security tests/runtime tests/test_sdk.py tests/test_security_regressions.py tests/test_hardening_fixes.py tests/test_hardening_audit_fs.py -q --tb=line -p no:cacheprovider` — 489 passed.
- Phase 3 file plus related regressions: `.venv/bin/python -m pytest tests/security/pass2/test_p3_enforcement_integrity.py tests/security/test_guard_response_enforcement.py tests/runtime/test_filesystem_containment.py tests/runtime/test_mcp_gateway.py tests/security/pass2/test_p2_decision_correctness.py tests/runtime/test_hardening_invariants.py tests/test_langchain_integration.py -q --tb=line -p no:cacheprovider` — 150 passed.
- The two HTTP redirect tests bind `127.0.0.1` and `::1`. `127.0.0.2` cannot be bound on this Mac (`EADDRNOTAVAIL`).

- Phase 3 gauntlet collected 49 tests. They are included in the full suite result below.
- Full suite before the review remediation: `.venv/bin/python -m pytest -q --tb=line -p no:cacheprovider` — 1096 passed, 1 skipped, 31 warnings, 194.56s.
- Full suite after the review remediation: the same command — **1146 passed, 1 skipped, 49 warnings, 197.29s**. The skip is `tests/browser/test_ui_smoke.py` because `playwright` is not installed (`pytest tests/browser/test_ui_smoke.py -rs`).
- Clean wheel after the remediation: `.venv/bin/python -m pytest tests/test_clean_wheel_smoke.py tests/browser/test_ui_smoke.py -q -rs` — 4 passed, 1 skipped, 4.04s. The enforcement smoke installs the root wheel into a fresh venv with `PYTHONPATH` empty and checks that keyword `os.remove` of `id_rsa` does not delete the file after a delivered block.
- Compile: `.venv/bin/python -m compileall -q varden varden_sdk varden_langchain sdks/python` — exit 0.
- Compile: `.venv/bin/python -m compileall -q` on the changed modules — exit 0.
- Ruff: the new gauntlet file is clean. `ruff check` on the pre-existing modules still reports historical `BLE001` / import-order findings that this pass did not introduce and did not mass-rewrite. There is no ruff configuration or ruff job in `.github/`.

Platform: macOS, CPython 3.13.13. CI Linux can bind extra loopback addresses this host cannot; the tests no longer require `127.0.0.2`. Provider tests ran against openai 1.109.1, anthropic 0.125.0, and langchain-core 1.6.12. `.github/workflows/ci.yml` job `provider integrations` installs `.[test,providers]` and runs those tests so a missing SDK is not silent in CI.

## G. Independent review remediation

Reviewed commit: `8d4d5156e0f9c9ea737bd54b72d15620bc9783c7`.

### Control-plane responses

Root cause: `VardenClient.guard` turned a completed response with no usable decision into `KeyError` or `HTTPStatusError`. `guarded_action` treated every exception as an outage, so guarded/fail-open executed.

Change: `classify_guard_response` distinguishes authoritative allow, authoritative deny, approval required, invalid decision, no decision, service failure, and service failure with an allow. Fail-open runs only for `is_transport_failure` (no HTTP response: connect, reset, timeout) and for the documented 5xx-with-allow case. Empty HTTP 200, malformed JSON, HTTP 401/404/429/500/502/503 without a decision, and unexpected client exceptions do not execute. The standalone tree classifies the same fixture set. The gateway and host stay fail-closed and forward only `authoritative_allow`.

### Nested interception

Root cause: filesystem and LangChain used a depth counter around the whole operation, including policy evaluation and user code. `Session.send` skipped authorization for every nested send while `Session.request` was in progress.

Change: filesystem passthrough is a set of path identities installed only around the original syscall, after the guard returns. A callback or `__fspath__` that opens a different path is enforced. LangChain skips a second charge only for `_run` / `_arun` of the tool whose `invoke` already guarded; a nested tool is a new decision. `Session.send` skips only when the URL is the hop just authorized. httpx rebuilds a redirect request without reading an unread body, so a cross-origin hop still reauthorizes and drops `Authorization` and `Cookie`.

A task created during the original syscall can inherit the same-path passthrough. A different path in that task is still enforced. That residual is named on the filesystem coverage limitations. Coverage stays PARTIAL. TOCTOU, `dir_fd`, pre-existing hard links, raw descriptors, native code, `os.exec*` / `os.spawn*` / ctypes, and DNS rebinding are unchanged.

### Provider verification

openai 1.109.1 and anthropic 0.125.0 expose the sync and async `create` methods the patch targets. A block does not call the installed fake `create`. An allow calls it once. Unwrapping async OpenAI `create` downgrades `llm.openai_transport` from ENFORCED to UNCOVERED. Removing `AsyncCompletions` before patch leaves the surface PARTIAL. No paid API call was made.

Regression file: `tests/security/pass2/test_p3_review_remediation.py`.

No frontend files changed, so the frontend build and browser pass were not run.

## F. Residual risk

Fixed and verified:

- Keyword filesystem mediation, `os.open` / `Path.touch`, `os.link` of a secret after interception.
- Gateway and host do not treat a missing or denying decision as permission to run.
- Explicit deny and `require_approval` do not execute under `fail_mode=open` on the root SDK, the MCP paths, and the standalone SDK.
- `Session.send` is part of requests coverage. Cross-host redirects drop the listed credential headers.
- Standalone default fail mode is closed, and its version no longer outranks the root package.

Mitigated, not eliminated:

- Filesystem TOCTOU between the pre-syscall re-check and the kernel operation.
- DNS rebinding / DNS-to-connect identity for hostnames.

Partially enforced:

- Filesystem. Includes `dir_fd` with a benign relative name, hard links created before interception, raw descriptors, and paths that never enter a patched function.
- Subprocess. Python hooks only.
- LangChain callbacks (observational).
- LLM transports when an async class cannot be patched.

Unsupported or not routed:

- `os.exec*`, `os.spawn*`, ctypes process creation.
- aiohttp, raw sockets, direct urllib3.
- Direct MCP stdio outside the gateway.
- Server-initiated or bidirectional MCP (sampling and other server-to-client requests). The gateway authorizes client requests it forwards; it is not a reverse proxy for server-initiated calls.
- Native extensions and saved pre-patch references.

Deferred:

- Connection-time IP pinning. A practical pin has to be the address the socket actually connects to. A pre-connect resolve does not prove that, so it was not claimed.
- Descriptor-relative (`openat` / `O_PATH`) containment. Not implemented; coverage stays PARTIAL.
- UI redesign. No frontend change was required to stop the backend from over-claiming. Coverage APIs already expose status and limitations.

## Merge readiness

No known P0 bypass remains on the declared supported paths that these tests execute. Explicit blocks prevent the sentinel side effect on those paths. Fail-open does not override a delivered denial. MCP privileged methods are not forwarded without authorization. Coverage claims for filesystem stay PARTIAL, and requests coverage drops when `Session.send` is unwrapped. DNS rebinding and filesystem TOCTOU are still open and are labeled as such.

The review findings in section G are remediated on the paths those tests execute. DNS rebinding, filesystem TOCTOU, and the same-path passthrough inherited by a task created during the syscall remain open and labeled. This branch was not merged. Another independent review is required before merge.
