# Varden Web Shield — Architecture Note

Status: Phases 1–3 implemented and tested (174 automated tests, all passing). Phase 4 (browser
extension) and Phase 5 (JS SDK) implemented as functional code with meaningfully lighter test
coverage than the Python core (no headless-browser integration harness for the extension; the SDK
has Node-based unit tests against a stubbed `fetch`, not a real browser). Phase 6 (cross-origin
flow reporting, lifecycle anomalies, tamper-detection signal) is implemented for the single-hop
case; deep multi-hop chain reconstruction across many tools/origins is not. See
`docs/web-shield-limitations.md` and the final delivery report for the honest breakdown.

## 1. Why this design

Varden already has a working shape for "discover untrusted third-party tool metadata, normalise
it, evaluate it against policy, store evidence, show it on the dashboard": **`varden/mcp_inventory.py`**
(MCP server/tool discovery) and **`varden/rules/token_budget.py`** + **`varden/token_budget.py`**
(a typed policy rule with its own enforcement store). Web Shield reuses both shapes rather than
inventing new ones:

| Existing abstraction | Reused as |
|---|---|
| `Action` / `Decision` / `EventRecord` (`varden/models.py`) | WebMCP activity is still persisted through `EventRecord`; no parallel event table for the *event log* itself. |
| `PolicyEngine.evaluate()` / rule buckets | Web Shield adds two genuinely new buckets, `require_approval` and `sanitise`, alongside the existing `block/warn/monitor/allow` (`varden/policy.py::MODES`, `varden/policy_packs.py::RULE_BUCKETS`). WebMCP conditions are **not** a separate typed rule class — they are ordinary rules with `"type": "webmcp.tool_registered"` etc. plus dot-notation predicates like `"metadata.risk_band": "critical"`, resolved by a small extension to `PolicyEngine._get_field` that understands `metadata.*` keys. This reuses the existing generic rule-matching machinery rather than adding a parallel typed-rule system. |
| `McpInventoryStore` scan/inventory/gap pattern | `varden/webshield/store.py::WebShieldStore` follows the same `ingest → inventory query → risk analysis` shape, but for browser-supplied tool registrations instead of local MCP config files. |
| `varden/redaction.py` | Reused directly for event payload redaction; extended with `redact_webmcp_value()` (recursively redacts values under sensitive keys) and `redact_webmcp_output()` (caps + lightly redacts plaintext tool output) — see `varden/redaction.py`. |
| `require()` / rate limiter / idempotency (`varden/app_factory.py`) | All new routes use `require(x_api_key, authorization, role, scope="ingest"/"read"/"write")` exactly like existing routes; extension traffic uses the `ingest` scope like `/sdk/log`. |
| DB migration convention (`varden/db.py::_apply_migrations`) | New tables added as schema version 5, following the exact `if N not in versions: executescript(...)` pattern. |
| Dashboard page-switch pattern (`frontend/src/main.tsx`) | New `WebShieldPage` added as a sibling to `OverviewPage`/`RulesPage`, not a second app. |
| CLI nested subparsers (`varden budget status`) | `varden web-shield <cmd>` follows the same `add_subparsers` nesting. |

**Genuinely new abstractions** (nothing existing covers these):

- `WebMCPToolDefinition` — canonical, versioned, cross-draft tool representation (§5 of the brief).
- A **layered classifier engine** (`varden/webshield/engine.py` + `layers/*.py`) — Varden's existing
  `ClassifierEngine` is a flat boolean-flag classifier tuned for HTTP/SQL/tool-call payloads; WebMCP
  metadata needs structural, Unicode, instruction-pattern, capability-consistency, lifecycle,
  provenance and output-contamination analysis with **explainable, field-scoped findings** — a
  different shape entirely.
- A **versioned risk scoring profile** (`varden/webshield/risk.py`) — Varden's existing risk score is an
  additive heuristic embedded in `DecisionIntelligence.enrich`; Web Shield needs a scoring model
  that is centralised, versioned, and returns a driver breakdown (bounded contribution per category,
  not naive summation) that can be evaluated for precision/recall.
- **Lifecycle/identity state** (`varden/webshield/layers/lifecycle.py` for the classifier, plus
  `WebShieldStore._existing_tool_names` / `_recent_registration_count` / `_prior_violation_count`
  for the queries that feed it) — per-origin, per-tool-identity history (first seen, metadata hash
  history, churn) — nothing in Varden currently tracks identity over time for anything other than
  `token_budgets` spend rows.
- **Browser extension** and **JS SDK** — no browser-facing code exists in the repository today.

## 2. Browser → Varden data flow

```
Website JS                Extension (page world)        Extension (isolated world)      Varden API
-----------                ----------------------        --------------------------      ----------
document.modelContext  →   wrapped registerTool()   →    postMessage (signed,       →    POST /webshield/registrations
  .registerTool(def)       captures def + stack           per-frame channel id)           (static + lifecycle scan,
                            trace, origin, frame id                                        policy eval, persisted event)

agent invokes tool      →   wrapped invoke path      →    postMessage              →     POST /webshield/invocations
  (where observable)         (best-effort; see limits)                                     (invocation-time re-check,
                                                                                             approval gate if required)

tool returns result     →   wrapped result handler   →    postMessage              →     POST /webshield/outputs
                                                                                             (Layer 7 output scan)
```

The **JS SDK** (`sdks/js/web-shield`, published as `@varden/web-shield`) provides the same wrapping
logic for sites that want to call Varden directly, without depending on the extension being
installed. The extension and the SDK talk to the exact same `/webshield/*` API and JSON wire
format, but do **not** share a compiled rule pack: the extension's local fallback scanner
(`extension/src/fallback-rules.js`) is a small, independently-maintained JS reimplementation of a
handful of the server's highest-value patterns, not a build artifact of the Python engine. This is
a known drift risk, called out explicitly in `docs/web-shield-limitations.md` rather than papered
over with an unbuilt "shared rule pack" abstraction.

## 3. Registration-time vs invocation-time vs output-time controls

| Phase | What Varden can actually control | Enforcement ceiling |
|---|---|---|
| **Registration-time** | The tool definition object handed to `registerTool`/`provideContext`. Varden can classify it before the page's own registration call resolves (synchronous wrapper), and can rewrite the definition object in place for **sanitise**, or throw/no-op for **block**, *if* the page called through the wrapped method. | Full control **only** if the page uses the wrapped `modelContext` methods (via extension page-world script or SDK). If a compatible privileged browser API existed, this would be equivalent to a capability broker; today it does not, so this is best-effort instrumentation, not a sandbox. |
| **Invocation-time** | Only observable where the *agent integration* itself calls through Varden (SDK-integrated agent runtime) or where the extension can see the invocation call before it reaches the tool's handler. Browsers do not expose a generic "intercept any function call" primitive; Varden Web Shield can only see invocations that go through code paths it has wrapped. | Partial. `require_approval` can genuinely pause invocation **only when the calling integration awaits Varden's decision** (SDK path, or an agent runtime that calls the extension's exposed API). If the agent calls the *original* unwrapped function directly (e.g. it captured a reference before instrumentation installed), Varden cannot stop it — this is disclosed as an "unavailable enforcement" state, never silently ignored. |
| **Output-time** | The tool's return value, if it flows back through the wrapped invocation path. | Same ceiling as invocation-time: enforceable when the agent integration or extension mediates the call, best-effort otherwise. |

This ceiling is the reason the data model (§8 of the brief, implemented in `varden/webshield/models.py::EnforcementOutcome`)
distinguishes **policy decision**, **requested enforcement**, **achieved enforcement**, and
**enforcement limitations** as four separate fields rather than collapsing them into one status.

## 4. Browser limitations (stated plainly)

- There is **no standard privileged browser API** for intercepting WebMCP tool registration or
  invocation as of this writing. The extension's page-world script installs as early as
  `document_start` + a `MutationObserver`/property-descriptor trap allows, but a page that defines
  `modelContext` before the content script's `world: "MAIN"` script runs, or that captures a
  reference to the original method before wrapping, can bypass observation entirely. This is
  detected where possible (`webmcp.extension_tamper_detected`) but cannot be prevented.
- WebMCP itself is an active, multi-draft proposal. Varden Web Shield targets the commonly
  implemented surface (`document.modelContext.registerTool/provideContext/unregisterTool`,
  and the earlier `navigator.modelContext` naming) and preserves unknown fields in an
  `extension_metadata` bag rather than assuming a single frozen schema (§5 below).
  See `docs/web-shield-limitations.md` for the full, explicit list.
- Manifest V3 extensions cannot execute arbitrary remote code (Chrome Web Store policy and CSP);
  the fallback ruleset is bundled, not fetched.
- Detection is **scanning + policy**, not sandboxing. Web Shield reduces and evidences risk; it
  does not guarantee an LLM will not be manipulated by content it never should have trusted in the
  first place, and it does not replace least-privilege credential design.

## 5. Supported WebMCP API variants

`varden/webshield/models.py::ApiSurface` enumerates:

- `document.model_context` — current mainstream draft (`document.modelContext.registerTool`)
- `navigator.model_context` — earlier/alternate draft (`navigator.modelContext.registerTool`)
- `declarative` — `<script type="application/modelcontext+json">`-style declarative definitions,
  where observable
- `imperative_unknown` — any object shape matching the imperative `{name, description, inputSchema,
  execute}` contract but not attributable to a known global (defensive default; still fully
  scanned, tagged for provenance uncertainty)

Every stored tool carries `schema_version` (canonical-model version, currently `"1"`) and
`api_surface` (one of the above) so that behaviour never depends on assuming a single frozen
upstream spec.

## 6. Threat model

See `docs/web-shield-threat-model.md` for the full structured model. Summary of the seven
categories, all covered by at least one classifier layer and at least one corpus case:

1. Tool framing (instructions hidden in name/title/description/schema/examples/annotations)
2. Tool hijacking / lifecycle manipulation
3. Cross-tool manipulation
4. Cross-origin data flow
5. Capability mismatch
6. Output contamination
7. Resource/DoS abuse

## 7. Implementation phases (status)

| Phase | Scope | Status |
|---|---|---|
| 1 | Canonical model, static scanner (layers 1–4), risk engine, CLI `scan`/`explain`, corpus, `evaluate` | **Done, tested** |
| 2 | Event taxonomy, DB migration, stores, API endpoints, policy predicates, approval model | **Done, tested** |
| 3 | Attack lab (20 cases), dashboard (overview/inventory/detail), `web-shield demo` | **Done, tested**. Dashboard is a new page in the existing React SPA, not a second app. |
| 4 | Browser extension (MV3) | **Functional** (page-world wrapping via native `world: "MAIN"` content script + authenticated `MessageChannel` bridge, badge, popup, options, local fallback, offline queue). **No automated browser tests** — no headless-Chrome/Playwright harness was set up in this environment; verified by manual code review only. This is the single biggest test-coverage gap in the whole feature — see limitations doc. |
| 5 | JS SDK (`@varden/web-shield`) | **Done**, Node-based unit tests (`node:test` + stubbed `fetch`), no real-browser tests. |
| 6 | Cross-origin flow reporting, lifecycle anomaly detection, tamper-detection events | **Single-hop implemented and tested** (`POST /webshield/cross-origin`, lifecycle churn/near-duplicate/late-session detection, `webmcp.extension_tamper_detected`). Multi-hop chain reconstruction (e.g. automatically inferring A→B→C across independently-reported hops) is **not implemented**. |

## 8. Non-goals / explicitly deferred

- No global reputation network (local-only trust, by design — §6 "Layer 6" of the brief).
- No claim of blocking 100% of prompt injection; see `docs/web-shield-limitations.md`.
- No change to default enforcement for existing Varden users: Web Shield events are always scanned
  and recorded, but no `block`/`warn`/`require_approval`/`sanitise` action is taken unless an
  operator imports the `webmcp-web-shield` policy pack (`POST /policy/import-pack`, the Web Shield
  dashboard banner, or automatically as part of `varden web-shield demo`). `GET /webshield/config`
  reports `enabled: false` until that pack (or an equivalent hand-written rule) is present.
