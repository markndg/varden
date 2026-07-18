'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  PROTOCOL_VERSION,
  createChannelState,
  validateHandshake,
  completeHandshake,
  validateEvent,
} = require('../src/protocol.js');

function handshakenState(nonce) {
  const state = createChannelState(nonce || 'nonce-a');
  completeHandshake(state);
  return state;
}

function event(overrides) {
  return Object.assign(
    { kind: 'tool_registered', detail: { tool: { name: 't' } }, protocol_version: PROTOCOL_VERSION, nonce: 'nonce-a', sequence: 0 },
    overrides,
  );
}

// --- handshake -------------------------------------------------------------

test('handshake: accepts a well-formed handshake message', () => {
  const state = createChannelState('nonce-a');
  const result = validateHandshake(state, { kind: 'handshake' });
  assert.equal(result.ok, true);
});

test('handshake: rejects a duplicate handshake', () => {
  const state = createChannelState('nonce-a');
  completeHandshake(state);
  const result = validateHandshake(state, { kind: 'handshake' });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'duplicate_handshake');
});

test('handshake: rejects a non-handshake message', () => {
  const state = createChannelState('nonce-a');
  const result = validateHandshake(state, { kind: 'tool_registered' });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'not_handshake');
});

// --- events: nonce -----------------------------------------------------------

test('event: rejects an event with no nonce', () => {
  const state = handshakenState('nonce-a');
  const result = validateEvent(state, event({ nonce: undefined }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'nonce_mismatch');
});

test('event: rejects the wrong nonce', () => {
  const state = handshakenState('nonce-a');
  const result = validateEvent(state, event({ nonce: 'wrong-nonce' }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'nonce_mismatch');
});

test('event: rejects a nonce reused from another frame/channel', () => {
  // Simulates a hostile page that observed frame A's nonce (e.g. via a
  // shared worker, or by compromising frame A) and replays it against
  // frame B's independently-generated channel state.
  const frameAState = handshakenState('nonce-frame-a');
  const frameBState = handshakenState('nonce-frame-b');
  const stolenEnvelope = event({ nonce: frameAState.nonce, sequence: 0 });
  const result = validateEvent(frameBState, stolenEnvelope);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'nonce_mismatch');
});

// --- events: sequence --------------------------------------------------------

test('event: accepts increasing sequence numbers', () => {
  const state = handshakenState();
  assert.equal(validateEvent(state, event({ sequence: 0 })).ok, true);
  assert.equal(validateEvent(state, event({ sequence: 1 })).ok, true);
  assert.equal(validateEvent(state, event({ sequence: 5 })).ok, true);
});

test('event: rejects a duplicate sequence number', () => {
  const state = handshakenState();
  assert.equal(validateEvent(state, event({ sequence: 0 })).ok, true);
  const result = validateEvent(state, event({ sequence: 0 }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'sequence_rejected');
});

test('event: rejects a decreasing sequence number', () => {
  const state = handshakenState();
  assert.equal(validateEvent(state, event({ sequence: 5 })).ok, true);
  const result = validateEvent(state, event({ sequence: 2 }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'sequence_rejected');
});

test('event: rejects a non-integer or negative sequence number', () => {
  const state = handshakenState();
  assert.equal(validateEvent(state, event({ sequence: 1.5 })).ok, false);
  assert.equal(validateEvent(state, event({ sequence: -1 })).ok, false);
  assert.equal(validateEvent(state, event({ sequence: 'zero' })).ok, false);
  assert.equal(validateEvent(state, event({ sequence: Infinity })).ok, false);
});

// --- events: schema / protocol / handshake gating ----------------------------

test('event: rejects an event before handshake completion', () => {
  const state = createChannelState('nonce-a');
  const result = validateEvent(state, event());
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'event_before_handshake');
});

test('event: rejects an unsupported protocol version', () => {
  const state = handshakenState();
  const result = validateEvent(state, event({ protocol_version: 999 }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unsupported_protocol_version');
});

test('event: rejects an unknown event type', () => {
  const state = handshakenState();
  const result = validateEvent(state, event({ kind: 'delete_all_user_data' }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unknown_event_type');
});

test('event: rejects a malformed (non-object) message', () => {
  const state = handshakenState();
  assert.equal(validateEvent(state, null).ok, false);
  assert.equal(validateEvent(state, 'a string').ok, false);
  assert.equal(validateEvent(state, 42).ok, false);
  assert.equal(validateEvent(state, undefined).ok, false);
});

// --- events: payload limits and hostile payloads -----------------------------

test('event: rejects a payload exceeding the size limit', () => {
  const state = handshakenState();
  const giant = { blob: 'x'.repeat(64 * 1024) };
  const result = validateEvent(state, event({ detail: giant }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'payload_too_large');
});

test('event: accepts a payload within the size limit', () => {
  const state = handshakenState();
  const result = validateEvent(state, event({ detail: { small: 'ok' } }));
  assert.equal(result.ok, true);
});

test('event: rejects a cyclic detail object instead of crashing', () => {
  const state = handshakenState();
  const cyclic = {};
  cyclic.self = cyclic;
  const result = validateEvent(state, event({ detail: cyclic }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unserializable_payload');
});

test('event: a getter that throws on property access fails closed, does not throw', () => {
  const state = handshakenState();
  const hostile = {};
  Object.defineProperty(hostile, 'kind', { get() { throw new Error('gotcha'); } });
  assert.doesNotThrow(() => {
    const result = validateEvent(state, hostile);
    assert.equal(result.ok, false);
  });
});

test('event: a Proxy that throws on every trap fails closed, does not throw', () => {
  const state = handshakenState();
  const hostile = new Proxy(
    {},
    {
      get() { throw new Error('proxy trap'); },
      has() { throw new Error('proxy trap'); },
    },
  );
  assert.doesNotThrow(() => {
    const result = validateEvent(state, hostile);
    assert.equal(result.ok, false);
  });
});

// --- multi-frame isolation ----------------------------------------------------

test('two independent frame channels never share sequence or nonce state', () => {
  const frameA = handshakenState('nonce-a');
  const frameB = handshakenState('nonce-b');
  assert.equal(validateEvent(frameA, event({ nonce: 'nonce-a', sequence: 0 })).ok, true);
  // Frame B must start its own sequence from scratch and use its own nonce;
  // frame A having consumed sequence 0 must not affect frame B at all.
  assert.equal(validateEvent(frameB, event({ nonce: 'nonce-b', sequence: 0 })).ok, true);
  // Frame B cannot submit using frame A's channel state ("one frame cannot
  // submit through another frame's state").
  assert.equal(validateEvent(frameA, event({ nonce: 'nonce-b', sequence: 1 })).ok, false);
});

test('reconnecting a channel (fresh state) invalidates the old sequence/nonce', () => {
  const before = handshakenState('nonce-old');
  assert.equal(validateEvent(before, event({ nonce: 'nonce-old', sequence: 0 })).ok, true);

  // A reconnect (e.g. after navigation, or extension reload) creates a brand
  // new channel state with a brand new nonce; the old envelope must not
  // validate against it.
  const after = handshakenState('nonce-new');
  const replayed = validateEvent(after, event({ nonce: 'nonce-old', sequence: 1 }));
  assert.equal(replayed.ok, false);
  assert.equal(replayed.reason, 'nonce_mismatch');
});
