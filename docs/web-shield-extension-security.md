# Web Shield browser extension: permissions, CSP, and local API threat model

This document is the permission-by-permission justification requested by
the pre-release hardening pass (`docs/web-shield-hardening-review.md` #11).
It complements, and does not replace, `docs/web-shield-extension.md`
(architecture) and `docs/web-shield-security.md` (message authenticity and
API hardening).

## Manifest V3 permission table

`extension/manifest.json` requests exactly this permission set — nothing
broader:

| Permission | Why it is needed | What it does *not* grant |
|---|---|---|
| `storage` | `chrome.storage.local` holds the configured server endpoint, Observe/Enforce mode, and the capped offline event queue (`MAX_QUEUE_SIZE = 200`, see `docs/web-shield-extension.md` "Local fallback"); `chrome.storage.session` holds one per-tab session ID. | No access to cookies, history, bookmarks, or any other browser data store. |
| `activeTab` | Lets the popup (`src/popup.js`) show state for the tab the user is currently looking at without a broad, always-on host permission. | Does **not** grant scripting/network access to that tab beyond what the static `content_scripts` and `host_permissions` entries already grant; it is a UI-scoped grant, not used to elevate the content-script injection surface. |
| `scripting` | Declares the capability MV3 requires for the manifest's static `content_scripts` entries (page-world and isolated-world injection) to run. The extension does **not** call `chrome.scripting.executeScript` dynamically/programmatically anywhere in this codebase. | No ability to inject arbitrary code into arbitrary tabs at runtime outside the two declared, fixed content scripts. |
| `host_permissions`: `http(s)://127.0.0.1/*`, `http(s)://localhost/*` | The **only** hosts `background.js` is allowed to `fetch()` — this is what makes "the extension can only ever talk to a local Varden server" an enforced browser-level guarantee, not just a convention. | Does **not** grant network access to any remote/production host. A user who deliberately points Options at a non-local endpoint is outside this guarantee (see "Non-local endpoints" below) — the manifest permission itself still only covers localhost; a non-local fetch from a MV3 extension requires a matching host permission the user would have to add themselves, which this manifest does not declare. |

Explicitly **absent** (each of these was considered and rejected as
unnecessary for this extension's function):

* `tabs` — full tab-list/URL access. Not needed; `activeTab` + `sender.tab.id`
  (from `chrome.runtime.onMessage`, Chrome-provided) cover everything the
  extension actually uses.
* `webNavigation`, `webRequest`, `declarativeNetRequest` — no network
  interception of page traffic; Web Shield only observes WebMCP API calls,
  never raw network requests.
* `cookies`, `history`, `bookmarks`, `downloads`, `clipboardRead` — no
  business need; none are requested.
* `<all_urls>` in `host_permissions` or `permissions` — deliberately not
  requested. The static `content_scripts` `matches: ["<all_urls>"]` entries
  govern **where the two fixed content scripts run** (this has to be broad,
  since Web Shield cannot know in advance which site will call WebMCP APIs),
  but that is a different, narrower grant than `host_permissions`, which
  governs what the **background service worker** can `fetch()` — and that
  remains localhost-only.
* `externally_connectable` — absent from the manifest, so no other
  extension or web page can open a `chrome.runtime.connect`/`sendMessage`
  channel to this extension's background service worker at all.
* `web_accessible_resources` — absent; no extension-bundled resource (HTML,
  JS, images) is exposed to page-world code via a `chrome-extension://` URL.

## Content Security Policy

```json
"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'" }
```

* `script-src 'self'` — the popup and options pages (the only
  `extension_pages`) load no remote or inline script; every script is a
  file shipped in the extension package. There is no `'unsafe-eval'` or
  `'unsafe-inline'` anywhere in this policy.
* `object-src 'none'` — no `<object>`/`<embed>`/plugin content.
* No part of Web Shield (extension, server, or SDK) ever fetches and
  executes remote code. Detection logic (`varden/webshield/layers/*.py`,
  `extension/src/fallback-rules.js`) is compiled once from static,
  checked-in source; there is no remote rule-download mechanism to poison
  or man-in-the-middle.

## No remote executable code, no page-controlled privileged calls

* The background service worker (`src/background.js`) is the only place
  that ever makes a network request, and the URL it fetches is always
  `<configured endpoint>/webshield/...` — a fixed, extension-configured
  base URL (`chrome.storage.local`), never a URL supplied by page content
  or by a content-script message field. A hostile page cannot get the
  extension to fetch an arbitrary attacker-chosen URL.
* Content scripts never forward a page-supplied field directly into a
  privileged Chrome API call without going through validation first: every
  event from the page-world script is validated by
  `extension/src/protocol.js` (`docs/web-shield-hardening-review.md` #2)
  before `content-isolated.js` relays anything to the background worker,
  and the background worker itself only ever accepts messages tagged
  `message.source === 'varden-webshield-content'` from its own content
  script (`sender.id`-scoped by the browser platform itself).

## Server endpoint configuration and non-local endpoints

* Default configuration (`src/options.js` default) points at
  `http://127.0.0.1:8000` — no user action is required to get a fully local
  setup.
* A user *can* reconfigure the endpoint in Options to a non-local host, but
  the manifest's `host_permissions` do not cover that host, so MV3 will
  block the background worker's `fetch()` to it. **This is intentional**:
  Web Shield OSS's threat model and this manifest are both scoped to a
  local server. Pointing at a remote endpoint is unsupported without also
  re-packaging the extension with different `host_permissions` — this
  document does not claim any TLS/authentication posture for a
  hypothetical non-local deployment, because the shipped manifest does not
  enable one.
* If you do fork/rebuild the extension with a remote `host_permissions`
  entry, that endpoint **must** be HTTPS with a valid certificate; nothing
  in this codebase implements certificate pinning or additional transport
  authentication beyond what the browser's own TLS stack provides.

## Local API threat model (summary — full detail in `docs/web-shield-security.md`)

* Every Web Shield ingest endpoint requires an API key
  (`require(..., scope="ingest")`); a same-origin `fetch()` from an
  arbitrary website has no way to discover or supply that key in normal
  operation.
* The one automatic-discovery path (`bootstrap_api_key` on `GET /health`)
  is an explicit **development convenience** for the local demo/attack-lab
  flow, not a production credential-exchange mechanism — see
  `docs/web-shield-privacy.md`.
* No CORS middleware is installed on the Varden server. This is a
  deliberate default, not an oversight: without an
  `Access-Control-Allow-Origin` response, a browser will not let a
  cross-origin page's script *read* a response, and — because every
  credentialed write requires a custom header (`x-api-key` or
  `Authorization`) or a non-simple `Content-Type`
  (`application/json`) — the browser's CORS preflight (`OPTIONS`) fails
  before the actual mutating request is even sent, since this server does
  not answer preflights with an allow-origin header. A hostile page
  therefore cannot complete a cross-origin registration/lifecycle/output
  POST against a local Varden server purely via `fetch()`, independent of
  whether it also knows a valid API key.
* "Runs on localhost" is never treated as an authentication boundary on its
  own anywhere in this codebase or its documentation — see
  `docs/web-shield-security.md` "Protecting the local Varden API from
  browser-based requests" for the full localhost-DNS-rebinding and
  same-machine-process discussion. All authorization decisions go through
  the same `require()` API-key/role check used by every other Varden
  endpoint.

## Known gaps

* There is no automated CSP/permission regression test (e.g. a script that
  parses `manifest.json` in CI and fails the build if a new permission is
  added without a corresponding entry in this document). This is a
  process gap, not a code vulnerability — tracked here rather than silently
  ignored.
* Extension→server capability negotiation (an old extension talking to a
  hardened server getting an explicit "incompatible" response rather than
  silently misbehaving) is not yet implemented — see
  `docs/web-shield-hardening-review.md` #15/backward compatibility.
