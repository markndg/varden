// Varden Web Shield — isolated-world relay.
//
// Runs alongside src/page-world.js in the same frame, in the extension's
// ISOLATED JS world. The page cannot execute code in this world directly,
// which is what makes this script (not page-world.js) the trust boundary:
// the real chain of trust is
//
//   isolated content script -> extension service worker -> Varden server
//
// page-world.js runs in the page's own MAIN-world execution context, which
// the host page fully controls. This file therefore treats *everything* it
// receives from page-world.js as an untrusted, unauthenticated observation —
// see docs/web-shield-hardening-review.md #2 — and:
//
//   * generates its own per-frame nonce (never exposed on the page-visible
//     ``window.postMessage`` broadcast — only revealed over the private
//     MessagePort, after the page side proves it received that exact port
//     by initiating the handshake through it);
//   * requires a strictly increasing per-frame sequence number;
//   * requires a supported protocol version and a known event kind;
//   * enforces a payload size limit;
//   * derives frame/tab/origin metadata itself (from this ISOLATED world's
//     own ``window``), never trusting anything the page-world message claims
//     about its own identity.
//
// It does NOT and cannot make the MAIN-world observation itself tamper-
// proof: a sufficiently determined page script can still replace wrapped
// functions, call the retained original directly, or otherwise act outside
// what page-world.js can see. Loss of sensor integrity is reported (see
// 'wrapper_tamper_detected' / 'context_replaced') as tamper evidence, not
// hidden — but "reported" is not the same as "prevented".
(function () {
  'use strict';

  var protocol = self.VardenWebShieldProtocol;
  var PROTOCOL_VERSION = protocol.PROTOCOL_VERSION;

  function randomNonce() {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      var bytes = crypto.getRandomValues(new Uint8Array(16));
      var hex = '';
      for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
      return hex;
    }
    // Only reachable if the extension is somehow running in a context
    // without WebCrypto, which should not happen for a Chromium MV3
    // extension; kept as a defensive (not security-bearing) fallback.
    return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
  }

  var nonce = randomNonce();
  var state = protocol.createChannelState(nonce);
  var channel = new MessageChannel();

  // Frame-scoped correlation id generated *here* (extension isolated world),
  // used only to help correlate this channel's own diagnostics/events with
  // each other. It is NOT the trust boundary for frame identity: the
  // background service worker uses Chrome's own ``sender.frameId`` /
  // ``sender.tab.id`` as the authoritative identifiers (see background.js),
  // never anything a message claims about itself.
  var localFrameCorrelationId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);

  var topOrigin;
  var isThirdPartyFrame = false;
  try {
    topOrigin = window.top.location.origin;
    isThirdPartyFrame = window.top !== window && topOrigin !== window.location.origin;
  } catch (e) {
    // Cross-origin top frame: we cannot read its origin at all, which is
    // itself a strong third-party-frame signal.
    topOrigin = undefined;
    isThirdPartyFrame = true;
  }

  function relay(kind, detail) {
    try {
      chrome.runtime.sendMessage({
        source: 'varden-webshield-content',
        frameId: localFrameCorrelationId,
        ownerOrigin: window.location.origin,
        topOrigin: topOrigin || window.location.origin,
        isThirdPartyFrame: isThirdPartyFrame,
        scriptSourceOrigin: window.location.origin,
        event: { kind: kind, detail: detail, ts: Date.now(), observed_trust: 'observed_untrusted' },
      });
    } catch (e) {
      // "Extension context invalidated" happens on reload/update; the page
      // keeps working normally, we just stop reporting until next load.
    }
  }

  channel.port1.onmessage = function (event) {
    var msg = event.data;

    if (msg && msg.kind === 'handshake') {
      var handshakeResult = protocol.validateHandshake(state, msg);
      if (!handshakeResult.ok) {
        relay('protocol_diagnostic', { reason: handshakeResult.reason });
        return;
      }
      protocol.completeHandshake(state);
      // The nonce is revealed here, over the already-private port, only
      // after the page side has proven it holds this exact port by sending
      // the handshake request through it — never on the page-visible
      // ``window.postMessage`` broadcast used to set the port up.
      channel.port1.postMessage({ kind: 'handshake_ack', nonce: nonce, protocol_version: PROTOCOL_VERSION });
      return;
    }

    var result = protocol.validateEvent(state, msg);
    if (!result.ok) {
      relay('protocol_diagnostic', { reason: result.reason, kind: msg && msg.kind });
      return;
    }
    relay(msg.kind, msg.detail);
  };

  // The only page-visible broadcast in this whole handshake: an
  // announcement that a port is available, carrying no secret. Anyone
  // listening on ``window`` for 'message' at this instant could observe
  // that this happened and could grab the port reference, but MV3 injects
  // both this script and page-world.js at document_start, before any page
  // script has run, so in practice no page script has had the opportunity
  // to register a competing listener yet. This is a timing property of the
  // browser's injection order, not a cryptographic guarantee — see
  // docs/web-shield-hardening-review.md #2 for the full limitation.
  window.postMessage({ type: 'varden-webshield-init' }, window.location.origin, [channel.port2]);
})();
