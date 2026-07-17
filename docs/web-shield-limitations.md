# Web Shield limitations

Varden Web Shield is **runtime governance and tool-surface security for
browser agents** — not a guarantee that no malicious WebMCP tool can ever
reach or fool an agent. This document lists what it does not do, as
plainly as we know how to state it, so that claims elsewhere in the docs
and README stay defensible.

## Draft API and browser support

WebMCP (`document.modelContext` / `navigator.modelContext`) is an
in-progress, evolving proposal, not a finished, universally-implemented
browser standard. Concretely:

- The canonical `WebMCPToolDefinition` model is versioned
  (`schema_version`) precisely because the underlying draft is expected to
  change; unknown/draft-specific fields are preserved in an extension map
  rather than dropped, but new *required* semantics in a future draft may
  need code changes, not just data changes.
- The extension's page-world script wraps whatever `registerTool` etc.
  already exists, or installs a minimal stand-in if nothing does yet
  (`instrument()` in `extension/src/page-world.js`) — this lets the demo/
  attack-lab work even without a real browser-side WebMCP implementation,
  but it means the extension cannot validate that its assumptions about a
  *real* implementation's calling conventions are still correct once one
  ships broadly.
- Only Chromium-family MV3 (`minimum_chrome_version: "116"`) is targeted.
  There is no Firefox/Safari build, and no MV2 fallback.

## Extension injection timing

`document_start` is the earliest a content script can run — this is
already the strictest timing Chrome offers, but it is not "before the
page exists." A page's own inline `<script>` in `<head>`, if it runs before
the content script's `document_start` callback executes (implementation
detail of script execution ordering that Web Shield does not control),
could in principle call a native `registerTool` before instrumentation is
installed. This is a genuine, unfixable-by-this-project browser limitation,
not a bug. `guardProperty`'s replacement detection
(`webmcp.context_replaced`) is a partial, *forensic* mitigation for the
related case of the object being swapped out *after* installation — it
detects the swap, it does not prevent whatever the swap enabled.

## Unobservable browser-internal agent behaviour

Web Shield observes what a page exposes to `document.modelContext`/
`navigator.modelContext` and reports to the Varden API from there. It has
no visibility into:

- an agent's internal reasoning about which tool to call or why;
- a browser-agent implementation that consumes page content through some
  mechanism other than the observed DOM property (e.g. a future non-DOM
  tool-exposure surface, or a native browser feature with no content-script
  hook at all);
- tool calls that happen entirely inside a backend/agent host process that
  never touches the observed page, unless that host process is itself
  integrated via the JavaScript SDK.

## Extension enforcement is currently observe-only

This is the most important enforcement-specific limitation and is
repeated from `docs/web-shield-extension.md` because it materially affects
what you should expect from a fresh install: the bundled browser extension
**observes and reports** WebMCP activity; it does not currently withhold a
registration from the page based on the server's decision the way the
JavaScript SDK's `mode: "enforce"` does for an explicit
`shield.registerTool(...)` call. If you need real browser-side blocking
today, integrate the SDK directly into the site/agent-host code rather than
relying on the extension alone. The `achieved_enforcement` field on every
Web Shield event exists specifically so this distinction is visible in the
data rather than papered over — an extension-observed `block` decision is
recorded honestly, not claimed as achieved.

Separately, even the SDK's own `install()` convenience wrapper (zero-code-
change instrumentation) cannot withhold a registration either, because it
must return synchronously from the wrapped call while the server round-trip
is still async — see `docs/web-shield-sdk.md`. Only an explicit, awaited
`shield.registerTool(modelContext, tool)` call can actually gate on the
server's decision.

Tamper/context-replacement detection
(`webmcp.context_replaced`, `webmcp.extension_tamper_detected`) is, by
construction, always forensic: Varden can only observe that a replacement
happened after it happened, so `achieved_enforcement` for these events is
always `unavailable`, never a real block — see `_log_event`'s `retroactive`
handling in `varden/webshield/store.py`.

## No LLM safety guarantee

Detecting and blocking/sanitising a malicious tool registration or output
reduces the *attack surface* an LLM-driven agent is exposed to. It does not
and cannot guarantee that an agent will behave safely given whatever content
does pass through — an agent could still be manipulated by content Web
Shield judged low-risk, or by reasoning failures unrelated to any external
tool at all. Web Shield is a tool-surface security control, not an AI safety
system.

## Scanning vs. policy vs. sandboxing — three different things

- **Scanning** (the layered classifier engine) produces *evidence*: findings
  and a risk score. It never itself blocks anything.
- **Policy** (Varden's existing `PolicyEngine`) is what turns evidence into
  an action (allow/warn/sanitise/require_approval/block). No policy rule =
  no enforcement, regardless of how severe the underlying finding is — see
  the policy-authoritative guarantee in `docs/web-shield-policy.md`, and the
  concrete regression test
  (`test_output_scan_never_blocks_when_no_webmcp_policy_rules_are_configured`)
  that verifies this for output scanning specifically.
- **Sandboxing** — actually preventing a tool from doing something
  regardless of what any classifier concluded — is not something Web Shield
  implements at all. It has no mechanism to constrain what a real,
  unblocked tool invocation can do once it executes; it can only decide
  whether to allow that invocation to proceed, pause it for approval, or
  (where the integration is capable of it) refuse it.

## False positives and false negatives

Per `docs/web-shield-evaluation.md`, the bundled corpus currently measures
precision 0.944 / recall 1.000 on 23 cases — real numbers from a small,
hand-authored, non-adversarially-optimized corpus, not a claim about
real-world traffic. In particular:

- **False positives are expected and, by design, not always "bugs."**
  `benign-honest-destructive-tool` scores in the `guarded` band precisely
  because "correctly declared as destructive" is still worth surfacing —
  the default policy pack routes this to `require_approval`, not `block`,
  so the practical cost of this kind of false positive is a pause for human
  confirmation, not an outright refusal.
- **Pattern-based detection cannot catch novel phrasing outside its pattern
  families.** Layer 3 (`layers/patterns.py`) is regex-based, written to
  catch paraphrases within known semantic categories (instruction-hierarchy
  override, secrecy demand, forced tool selection, etc.), not a general
  language model — an attacker who avoids every known category's phrasing
  entirely, or who fragments an attack across fields in a way none of the
  Unicode/pattern checks span, can evade detection. This is a structural
  property of deterministic pattern matching, not something the 23-case
  corpus's 1.000 recall can rule out for inputs outside that corpus.
- **Output scanning inherits the same pattern-based limits** as
  registration scanning (Layer 7 reuses Layer 2/3's checks), plus an
  additional one: it can only scan text it is given. If an integration never
  calls `scanOutput`/`POST /webshield/outputs` for a given tool result, that
  result is not scanned at all — Web Shield cannot intercept output that
  never passes through an integrated call site.

## What "174+ tests passing" does and does not mean

The Python core (`varden/webshield/`) has comprehensive unit, property/fuzz
(Hypothesis), and API test coverage — this is real, and running `pytest`
in a clean checkout demonstrates it. The browser extension and JavaScript
SDK have meaningfully lighter coverage:

- The extension has **no automated browser-integration test harness** (no
  Playwright/Puppeteer suite) in this repository — no automated coverage of
  multi-frame registration, spoofed-message rejection, extension reload
  behaviour, or achieved-vs-unavailable enforcement *from the extension's
  own code path* (as opposed to the server-side logic, which the API tests
  do cover directly).
- The JS SDK's tests (`sdks/js/web-shield/test/sdk.test.js`) run against a
  stubbed `fetch` under Node's built-in test runner — they verify the SDK's
  request-building, response-handling, and event-emission logic, not
  behaviour in a real browser DOM or against a real WebMCP implementation.

Both gaps are called out here rather than hidden behind an aggregate test
count, and are listed as required-before-release work in the final delivery
report.

## Positioning

Consistent with the above: Varden Web Shield is described throughout this
project's documentation as **"runtime governance and tool-surface security
for browser agents,"** never as something that "stops all prompt injection"
or is an "industry first." Treat any documentation or marketing copy that
makes a stronger claim than this document supports as a bug to be filed.
