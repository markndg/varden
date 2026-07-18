// Varden Web Shield — page-world instrumentation.
//
// Runs in the page's own JS realm (MV3 "MAIN" world) at document_start, so
// it installs before any page script has a chance to run. This script is
// NOT the trust boundary — the host page fully controls this execution
// context and can inspect, replace, race, or bypass anything here. Every
// event this script produces is an `observed_untrusted` sensor reading, and
// the isolated content script (src/content-isolated.js) — not this file —
// is what actually validates and authenticates the channel. See
// docs/web-shield-hardening-review.md #2 for the full threat model.
//
// It never invents browser capabilities that don't exist: it only wraps a
// `registerTool`/`unregisterTool`/`provideContext`/`clearContext` method
// that is already present on `document.modelContext` / `navigator.modelContext`.
// If no such object/method exists, this script does nothing to that surface
// — it does NOT create a stand-in implementation, because doing so would
// make a page believe a WebMCP agent runtime is present when it is not
// (docs/web-shield-hardening-review.md #4).
(function () {
  'use strict';
  const NS = '__vardenWebShieldPageWorld';
  if (window[NS]) return;
  window[NS] = true;

  const PROTOCOL_VERSION = 1;

  let port = null;
  let ackedNonce = null;
  let sequence = 0;
  const pending = [];

  function sendRaw(kind, detail) {
    port.postMessage({ kind, detail, protocol_version: PROTOCOL_VERSION, nonce: ackedNonce, sequence: sequence++ });
  }

  function send(kind, detail) {
    if (!port || ackedNonce === null) {
      pending.push({ kind, detail });
      return;
    }
    sendRaw(kind, detail);
  }

  function flush() {
    while (port && ackedNonce !== null && pending.length) {
      const next = pending.shift();
      sendRaw(next.kind, next.detail);
    }
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (port) return; // A port was already accepted; ignore any further init broadcasts.
    if (event.data && event.data.type === 'varden-webshield-init' && event.ports && event.ports[0]) {
      port = event.ports[0];
      port.onmessage = (ackEvent) => {
        const msg = ackEvent.data;
        if (msg && msg.kind === 'handshake_ack' && ackedNonce === null && typeof msg.nonce === 'string') {
          ackedNonce = msg.nonce;
          flush();
        }
      };
      // Prove we hold this exact port before the isolated side will ever
      // reveal the nonce to us.
      port.postMessage({ kind: 'handshake' });
    }
  });

  function safeSnapshot(value) {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (e) {
      try { return { name: value && value.name, description: String((value && value.description) || '') }; } catch (e2) { return {}; }
    }
  }

  function wrapMethod(target, methodName, onCall, apiSurface) {
    const existing = target[methodName];
    if (typeof existing !== 'function' || existing.__vardenWrapped) return;
    const original = existing.bind(target);
    const wrapped = function (...args) {
      try { onCall(...args); } catch (e) { /* never let observation break the page */ }
      return original(...args);
    };
    wrapped.__vardenWrapped = true;

    // Guard the *method* itself (not just its parent object) as an accessor
    // property, so a page that replaces `target[methodName]` directly —
    // without ever touching the parent object — is still detected and
    // reported as tamper evidence rather than silently and permanently
    // defeating observation with no trace at all. This still cannot stop a
    // determined page from doing so; it only makes the loss of sensor
    // integrity visible.
    let current = wrapped;
    try {
      Object.defineProperty(target, methodName, {
        configurable: true,
        enumerable: true,
        get() { return current; },
        set(value) {
          send('wrapper_tamper_detected', { api_surface: apiSurface, method: methodName });
          current = value; // Never fight the page for control of its own object.
        },
      });
    } catch (e) {
      // Non-configurable method: best effort only, cannot detect later
      // replacement. This is a genuine browser/page limitation.
      target[methodName] = wrapped;
    }
  }

  function instrument(target, apiSurface) {
    if (!target || typeof target !== 'object') return;
    // Only wrap methods that genuinely exist. Never fabricate a
    // `registerTool` (or any other) stand-in when the browser/agent has not
    // actually provided one — see docs/web-shield-hardening-review.md #4.
    wrapMethod(target, 'registerTool', (toolDef) => send('tool_registered', { api_surface: apiSurface, tool: safeSnapshot(toolDef) }), apiSurface);
    wrapMethod(target, 'unregisterTool', (name) => send('tool_unregistered', { api_surface: apiSurface, name: safeSnapshot(name) }), apiSurface);
    wrapMethod(target, 'provideContext', () => send('provide_context', { api_surface: apiSurface }), apiSurface);
    wrapMethod(target, 'clearContext', () => send('clear_context', { api_surface: apiSurface }), apiSurface);
  }

  function guardProperty(root, propertyName, apiSurface) {
    let current = root[propertyName];
    let installedOnce = current !== undefined;
    if (current) instrument(current, apiSurface);
    try {
      Object.defineProperty(root, propertyName, {
        configurable: true,
        enumerable: true,
        get() { return current; },
        set(value) {
          if (installedOnce) send('context_replaced', { api_surface: apiSurface });
          installedOnce = true;
          current = value;
          instrument(current, apiSurface);
        },
      });
    } catch (e) {
      // Some pages may define modelContext as non-configurable before we
      // run; we can still observe the current value once, but cannot detect
      // later replacement. This is a genuine browser limitation.
    }
  }

  guardProperty(document, 'modelContext', 'document_model_context');
  guardProperty(navigator, 'modelContext', 'navigator_model_context');
})();
