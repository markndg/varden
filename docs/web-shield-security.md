# Web Shield security

This document covers the security posture of Web Shield itself: message
authenticity in the browser, API hardening, and the localhost threat model.
For the threats Web Shield *detects*, see `docs/web-shield-threat-model.md`.
For data handling, see `docs/web-shield-privacy.md`.

## Page-to-extension message authenticity

**Trust boundary statement:** the isolated extension context validates a
per-frame protocol and derives trusted browser context from Chrome APIs.
Events originating in the page MAIN world remain untrusted observations
because the host page controls that execution environment. The real chain of
trust is `isolated content script -> extension service worker -> Varden
server` — never the page-world script. See
`docs/web-shield-hardening-review.md` #2 for the full audit and rationale;
this section summarises the current design and its honest limits.

The single biggest spoofing risk in a browser extension like this is a
malicious page pretending to be the extension's own instrumentation — e.g.
sending a fake event claiming a benign `tool_registered` event to mask a
real malicious registration, or flooding fabricated events to pollute the
dashboard. Web Shield's page-world/isolated-world split
(`docs/web-shield-extension.md`) raises the bar against this, but does not
and cannot make the page-world sensor itself tamper-proof:

1. `content-isolated.js` generates a random per-frame nonce and creates a
   `MessageChannel`, transferring one port to the page world via
   `window.postMessage(msg, window.location.origin, [channel.port2])`. This
   initial broadcast carries **no secret** — it only announces that a port
   exists. The **target origin** argument (`window.location.origin`, not
   `"*"`) means the browser itself refuses to deliver this message if the
   page's origin has changed by the time it's delivered.
2. The page-world script must first send a `handshake` message *through*
   that exact port before the isolated side will reveal the nonce (as a
   `handshake_ack`). Every subsequent event must carry that nonce plus a
   strictly increasing sequence number, a supported protocol version, and a
   recognised event kind; `extension/src/protocol.js` (unit-tested in
   `extension/test/protocol.test.js`) enforces all of this and rejects
   (without crashing) missing/wrong/replayed nonces, decreasing or repeated
   sequence numbers, unknown event kinds, oversized payloads, and events
   sent before the handshake completes. Rejected events are logged locally
   as a diagnostic and never relayed to the Varden server as real telemetry.
3. In practice, no page script has had the opportunity to register a
   competing `window` `'message'` listener before this handshake happens,
   because both content scripts are injected at MV3's `document_start`,
   before any page script runs. **This is a timing/ordering property of the
   browser's injection guarantees, not a cryptographic authentication
   mechanism** — do not describe it as "authenticated" or "unforgeable" in
   any documentation, and do not assume it survives every edge case (e.g. a
   page that was already partially loaded before the extension was
   installed, or unusual extension-reload timing).
4. `content-isolated.js` never trusts anything the page told it about origin
   or frame identity — `ownerOrigin`, `topOrigin`, and `isThirdPartyFrame`
   are computed from the isolated world's own `window.location`/`window.top`.
   `background.js` goes one step further and treats Chrome's own
   `sender.tab.id` / `sender.frameId` (from `chrome.runtime.onMessage`) as
   the authoritative tab/frame identity sent to the server, not anything a
   content script or page claims about itself.
5. `background.js` only accepts messages whose `message.source ===
   'varden-webshield-content'` from its own content script's
   `chrome.runtime.sendMessage` call — this is a `sender.id`-scoped channel;
   an arbitrary page cannot call `chrome.runtime.sendMessage` targeting
   another extension's background listener at all (that's a browser
   platform guarantee, not something Web Shield has to implement).

What this does **not** protect against, and never claims to:

- A page can still register a genuinely malicious tool with genuinely
  malicious content — that's the threat this whole system exists to
  *detect*, not something message-channel hardening prevents.
- A sufficiently determined page script can inspect or replace the wrapped
  `registerTool`/etc. functions, retain and call the pre-wrap original
  directly, install a `Proxy` in front of `document.modelContext`, or race
  the extension's own setup. `page-world.js`'s accessor guards
  (`wrapMethod`/`guardProperty`) report the loss of sensor integrity as
  `wrapper_tamper_detected` / `context_replaced` tamper evidence when they
  can detect it — this is forensic, not preventive, and a page can still act
  in ways the extension never observes at all. Treat every page-world event
  as `observed_untrusted`, distinct from a confirmed absence of activity.
- It cannot protect against a *browser-level* compromise (a malicious or
  compromised extension with broader permissions could interfere with any
  other extension); that is outside any content script's threat model.

## Protecting the local Varden API from browser-based requests

The Varden server the extension/SDK talks to is typically `127.0.0.1` or
`localhost`. Two distinct risks apply here:

1. **An arbitrary website tricking a visitor's browser into calling the
   local Varden API** (the classic "localhost DNS rebinding" / drive-by
   cross-site request class of attack). Mitigations already present in
   Varden and reused as-is by Web Shield:
   - Every write endpoint requires an API key (`require(..., scope=
     "ingest")` for `/webshield/registrations`, `/webshield/lifecycle`,
     `/webshield/invocations`, `/webshield/outputs`, `/webshield/cross-origin`)
     — a same-origin `fetch()` from an arbitrary website has no way to know
     or supply that key. The one automatic-discovery path
     (`ensureApiKey`/`apiKey()` reading `bootstrap_api_key` from `/health`)
     is a **development convenience** intended for the demo/attack-lab flow
     on a machine you already control, not a production credential exchange
     — see the honest caveat in `docs/web-shield-privacy.md`.
   - Rate limiting via the existing `RateLimiter`/`ingest` bucket
     (`varden/app_factory.py`) applies to Web Shield's ingest endpoints
     exactly like every other Varden ingest route.
2. **A malicious extension or script on the same machine hitting the local
   API directly.** Nothing about "localhost" implies trust between
   processes on the same machine — this is a known, documented limitation
   of any local-first tool. Varden's existing auth (`require()`, API keys) is
   the boundary here, same as for every other Varden endpoint; Web Shield
   introduces no new bypass and no new trust assumption.

## API hardening applied to every `/webshield/*` write endpoint

All of the following are the *existing* Varden API conventions
(`varden/app_factory.py`), reused unmodified rather than reimplemented:

- **Authentication**: `require(x_api_key, authorization, role, scope=
  "ingest")` on every ingest route; returns 401/403 on missing or
  insufficient credentials.
- **Payload limits**: `_check_payload_size()` rejects any request body over
  200,000 bytes with `413 Payload Too Large`, before any parsing/scanning
  work is done on it — this bounds the resource cost of a single malicious
  or malformed request regardless of how expensive scanning it would be.
- **Rate limiting**: the `ingest` scope's bucket
  (`config.ingest_rate_limit_per_minute`, burst multiplier 2.0) applies
  uniformly; see `test_rate_limiting_applies_to_ingest_scope` in
  `tests/test_webshield_api.py`.
- **Replay protection**: every mutating endpoint accepts an optional
  `Idempotency-Key` header. The cache identity is a composite of
  tenant/principal (from the caller's own authenticated identity, never a
  browser-supplied field), HTTP method, canonical route, and the caller's
  key — never the raw key alone (`varden/idempotency.py`,
  `docs/web-shield-hardening-review.md` #3). A byte-stable hash of the
  canonical (key-order-independent) request body is stored alongside the
  cached response: an exact repeat (same scope, key, and body) replays the
  original response instead of re-executing; the same key reused with a
  *different* body returns `409 Conflict` with the stable error code
  `IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST` rather than silently
  returning a mismatched cached result. Records expire after a bounded,
  configurable TTL. This is the same mechanism used elsewhere in Varden
  (e.g. `PUT /policy`).
- **Schema validation**: `_require_str()` and explicit type/field checks
  reject malformed payloads (missing `session_id`, non-string identity keys,
  etc.) with `400 Bad Request` rather than raising an unhandled exception.
- **No cross-session data access from browser-supplied IDs**: session,
  tab and frame identifiers are opaque strings scoped by the *tenant*
  derived from the caller's own API key (`require()`'s returned `record
  ["tenant_id"]`), never trusted as an authorization boundary by themselves.
  Varden OSS is single-tenant per deployment, so "cross-tenant isolation" in
  the strict SaaS sense doesn't apply; what's tested instead
  (`test_registration_ignores_browser_supplied_tenant_id_and_cannot_forge_it`)
  is that a browser-supplied `tenant_id` field in the request body is simply
  ignored — the server always uses the tenant resolved from the caller's own
  authenticated identity, so a page cannot inject data under a different
  tenant it doesn't control by forging a request field.
- **Untrusted-input treatment**: every field taken from the browser
  (tool name/description/schema, output text, origins) flows entirely
  through the same structural/Unicode/pattern classifiers before touching
  policy or storage; nothing from the browser is trusted, evaluated as code,
  or reflected back without going through redaction (`docs/web-shield-privacy.md`).

## Content Security Policy and code loading

- `extension/manifest.json`'s `content_security_policy.extension_pages` is
  `"script-src 'self'; object-src 'none'"` — the popup and options pages
  load no remote or inline script.
- No part of Web Shield (extension, SDK, or server) ever fetches and
  executes remote code. Regexes and rule tables are compiled once from
  static, checked-in source (`varden/webshield/layers/*.py`,
  `extension/src/fallback-rules.js`); there is no remote rule-download
  mechanism to poison.
- Extension `permissions` are limited to `storage`, `activeTab`, `scripting`;
  `host_permissions` are limited to `127.0.0.1`/`localhost` — the extension
  cannot make network requests to an arbitrary remote host unless you
  deliberately reconfigure the endpoint in Options.

## Non-goals (explicitly out of scope)

- Web Shield is not a sandbox. It cannot stop a browser agent from executing
  a tool call that was never routed through it in the first place (no
  Web Shield integration at all in that agent's page/host).
- It does not attempt browser exploit mitigation, supply-chain verification
  of the extension's own dependencies (there are none — zero runtime
  dependencies in both the extension and the SDK), or protection against a
  fully compromised OS/browser.
- See `docs/web-shield-limitations.md` for the complete, unhedged list.
