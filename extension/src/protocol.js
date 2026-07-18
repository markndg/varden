// Varden Web Shield — page-world <-> isolated-world protocol.
//
// Pure validation logic for the per-frame channel between the untrusted
// MAIN-world instrumentation (page-world.js) and the trusted ISOLATED-world
// relay (content-isolated.js). Kept dependency-free (no `chrome.*`, no DOM)
// so it can run unmodified as a classic content-script global AND under
// plain Node for unit tests (see extension/test/protocol.test.js).
//
// Security model (docs/web-shield-hardening-review.md #2): the page MAIN
// world is untrusted — a hostile page can inspect, replace, or race
// page-world.js's wrappers, and can send arbitrary structured-clone-able
// objects through the MessagePort once it holds a reference to it. This
// module is the enforcement point that makes the ISOLATED world reject
// anything that does not look like a well-formed, freshly-sequenced event
// from *this* channel's own handshake — it does not, and cannot, make the
// MAIN-world observation itself tamper-proof.
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VardenWebShieldProtocol = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PROTOCOL_VERSION = 1;
  var MAX_PAYLOAD_BYTES = 32 * 1024;
  var MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;

  // Events the ISOLATED world will ever relay to the background service
  // worker. Anything else is rejected as "unknown_event_type" — an allowlist,
  // not a denylist, so a newly-invented event kind fails closed.
  var ALLOWED_EVENT_KINDS = [
    'tool_registered',
    'tool_unregistered',
    'provide_context',
    'clear_context',
    'context_replaced',
    'wrapper_tamper_detected',
  ];

  function createChannelState(nonce) {
    return { nonce: nonce, handshakeComplete: false, lastSequence: -1 };
  }

  function isPlainMessage(msg) {
    return !!msg && typeof msg === 'object';
  }

  function validateHandshake(state, msg) {
    if (!isPlainMessage(msg) || msg.kind !== 'handshake') {
      return { ok: false, reason: 'not_handshake' };
    }
    if (state.handshakeComplete) {
      return { ok: false, reason: 'duplicate_handshake' };
    }
    return { ok: true };
  }

  function completeHandshake(state) {
    state.handshakeComplete = true;
  }

  // Validate one page-world -> isolated-world event envelope against the
  // channel's current state. Never throws: a hostile page can pass a Proxy
  // or getter-laden object as ``msg``/``msg.detail`` designed to throw on
  // property access, and validation must fail closed rather than crash the
  // extension's message handler.
  function validateEvent(state, msg, options) {
    options = options || {};
    var maxPayloadBytes = options.maxPayloadBytes || MAX_PAYLOAD_BYTES;
    var protocolVersion = options.protocolVersion || PROTOCOL_VERSION;
    try {
      if (!isPlainMessage(msg)) {
        return { ok: false, reason: 'malformed_message' };
      }
      if (!state.handshakeComplete) {
        return { ok: false, reason: 'event_before_handshake' };
      }
      if (msg.protocol_version !== protocolVersion) {
        return { ok: false, reason: 'unsupported_protocol_version' };
      }
      if (msg.nonce !== state.nonce) {
        return { ok: false, reason: 'nonce_mismatch' };
      }
      var sequence = msg.sequence;
      if (
        typeof sequence !== 'number' ||
        !isFinite(sequence) ||
        Math.floor(sequence) !== sequence ||
        sequence < 0 ||
        sequence > MAX_SEQUENCE ||
        sequence <= state.lastSequence
      ) {
        return { ok: false, reason: 'sequence_rejected' };
      }
      if (!msg.kind || ALLOWED_EVENT_KINDS.indexOf(msg.kind) === -1) {
        return { ok: false, reason: 'unknown_event_type' };
      }
      var size;
      try {
        size = JSON.stringify(msg.detail === undefined ? null : msg.detail).length;
      } catch (serializeError) {
        // Cyclic objects survive structured-clone transport (unlike JSON)
        // but must not be allowed to reach persistence/serialisation later.
        return { ok: false, reason: 'unserializable_payload' };
      }
      if (size > maxPayloadBytes) {
        return { ok: false, reason: 'payload_too_large' };
      }
      state.lastSequence = sequence;
      return { ok: true };
    } catch (unexpectedError) {
      // e.g. msg was a Proxy/getter that throws on property access.
      return { ok: false, reason: 'validation_error' };
    }
  }

  return {
    PROTOCOL_VERSION: PROTOCOL_VERSION,
    MAX_PAYLOAD_BYTES: MAX_PAYLOAD_BYTES,
    ALLOWED_EVENT_KINDS: ALLOWED_EVENT_KINDS,
    createChannelState: createChannelState,
    validateHandshake: validateHandshake,
    completeHandshake: completeHandshake,
    validateEvent: validateEvent,
  };
});
