// Varden Web Shield — page-world instrumentation.
//
// Runs in the page's own JS realm (MV3 "MAIN" world) at document_start, so
// it installs before any page script has a chance to run. It never invents
// browser capabilities it doesn't have: it wraps whatever `registerTool`
// method already exists on `document.modelContext` / `navigator.modelContext`
// (or defines a minimal stand-in if the browser/agent has not provided one
// yet), and it reports what it observes to the isolated content script over
// a `MessageChannel` port. That port is transferred via `postMessage` with a
// structured-clone `MessagePort` — once transferred, no other script on the
// page (and no other extension) can observe or forge messages on it, which
// is what makes this an "authenticated" channel rather than a spoofable
// `window.postMessage` broadcast.
(function () {
  'use strict';
  const NS = '__vardenWebShieldPageWorld';
  if (window[NS]) return;
  window[NS] = true;

  let port = null;
  const pending = [];

  function flush() {
    while (port && pending.length) port.postMessage(pending.shift());
  }

  function send(kind, detail) {
    const message = { kind, detail, ts: Date.now() };
    if (port) port.postMessage(message);
    else pending.push(message);
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data && event.data.type === 'varden-webshield-init' && event.ports && event.ports[0]) {
      port = event.ports[0];
      flush();
    }
  });

  function safeSnapshot(value) {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (e) {
      try { return { name: value && value.name, description: String((value && value.description) || '') }; } catch (e2) { return {}; }
    }
  }

  function wrapMethod(target, methodName, onCall) {
    const existing = target[methodName];
    if (typeof existing !== 'function' || existing.__vardenWrapped) return;
    const original = existing.bind(target);
    const wrapped = function (...args) {
      try { onCall(...args); } catch (e) { /* never let observation break the page */ }
      return original(...args);
    };
    wrapped.__vardenWrapped = true;
    try { target[methodName] = wrapped; } catch (e) { /* non-configurable method; cannot wrap */ }
  }

  function instrument(target, apiSurface) {
    if (!target || typeof target !== 'object') return;
    if (typeof target.registerTool !== 'function') {
      // No native/agent-provided implementation yet: install a minimal
      // stand-in so pages can still register tools and Web Shield can still
      // observe them, without pretending to be a full WebMCP agent runtime.
      target.registerTool = function () {};
    }
    wrapMethod(target, 'registerTool', (toolDef) => send('tool_registered', { api_surface: apiSurface, tool: safeSnapshot(toolDef) }));
    wrapMethod(target, 'unregisterTool', (name) => send('tool_unregistered', { api_surface: apiSurface, name: safeSnapshot(name) }));
    wrapMethod(target, 'provideContext', () => send('provide_context', { api_surface: apiSurface }));
    wrapMethod(target, 'clearContext', () => send('clear_context', { api_surface: apiSurface }));
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
