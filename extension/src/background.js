// Varden Web Shield — background service worker.
//
// Owns configuration, the connection to the local/configured Varden server,
// the offline fallback path, the per-tab badge, and the (capped, redacted)
// offline event queue. Content scripts never talk to Varden directly; they
// only relay observations here, so this file is the single place that
// decides "connected" vs "local protection" and the single place that ever
// makes a network request.

import { localFallbackScan } from './fallback-rules.js';

const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const DEFAULT_ENDPOINT = 'http://127.0.0.1:8000';
const MAX_QUEUE_SIZE = 200;

const tabState = new Map(); // tabId -> { band, connected, protectionMode, toolCount, origin }

async function getConfig() {
  const stored = await chrome.storage.local.get(['endpoint', 'mode', 'apiKey']);
  return {
    endpoint: stored.endpoint || DEFAULT_ENDPOINT,
    mode: stored.mode || 'observe',
    apiKey: stored.apiKey || '',
  };
}

async function ensureApiKey(config) {
  if (config.apiKey) return config.apiKey;
  try {
    const res = await fetch(`${config.endpoint}/health`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return '';
    const health = await res.json();
    if (health.bootstrap_api_key) {
      await chrome.storage.local.set({ apiKey: health.bootstrap_api_key });
      return health.bootstrap_api_key;
    }
  } catch (e) { /* server unreachable */ }
  return '';
}

/** Capability negotiation with a hardened server (docs/web-shield-hardening-review.md #15).
 * An older extension connecting to a newer server gets an explicit
 * compatibility result rather than silently operating incorrectly. */
async function checkServerCompatibility(config, apiKey) {
  if (!apiKey) return { compatible: true, checked: false };
  try {
    const res = await fetch(`${config.endpoint}/webshield/extension/health`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({
        session_id: `ext-compat-${EXTENSION_VERSION}`,
        extension_version: EXTENSION_VERSION,
        connected: true,
        protection_mode: 'connected',
      }),
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return { compatible: true, checked: false };
    const body = await res.json();
    return {
      compatible: body.compatible !== false,
      checked: true,
      reason: body.compatibility && body.compatibility.reason,
      protocol: body.compatibility && body.compatibility.protocol,
    };
  } catch (e) {
    return { compatible: true, checked: false };
  }
}

async function getSessionId(tabId) {
  const key = `session:${tabId}`;
  const stored = await chrome.storage.session.get(key);
  if (stored[key]) return stored[key];
  const sessionId = `ext-${tabId}-${Date.now().toString(36)}`;
  await chrome.storage.session.set({ [key]: sessionId });
  return sessionId;
}

async function queueOffline(entry) {
  const { queue = [] } = await chrome.storage.local.get('queue');
  queue.push({ ...entry, queued_at: Date.now() });
  while (queue.length > MAX_QUEUE_SIZE) queue.shift();
  await chrome.storage.local.set({ queue });
}

async function flushQueue(config, apiKey) {
  const { queue = [] } = await chrome.storage.local.get('queue');
  if (!queue.length) return;
  const remaining = [];
  for (const entry of queue) {
    const ok = await postToVarden(config, apiKey, entry.path, entry.body).catch(() => false);
    if (ok === false) remaining.push(entry);
  }
  await chrome.storage.local.set({ queue: remaining });
}

async function postToVarden(config, apiKey, path, body) {
  const res = await fetch(`${config.endpoint}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(4000),
  });
  if (res.status >= 500) throw new Error(`server error ${res.status}`);
  return res.json().catch(() => ({}));
}

function bandTone(band) {
  if (band === 'critical') return { color: '#ff6b7a', text: '!' };
  if (band === 'high') return { color: '#ff9a4d', text: '!' };
  if (band === 'suspicious' || band === 'guarded') return { color: '#ffbf5a', text: '\u2022' };
  return { color: '#4ce0b5', text: '\u2713' };
}

async function updateBadge(tabId) {
  const state = tabState.get(tabId) || {};
  if (!state.connected) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#8a8fa3' });
    await chrome.action.setBadgeText({ tabId, text: '?' });
    await chrome.action.setTitle({ tabId, title: 'Varden Web Shield: local protection only (server unreachable)' });
    return;
  }
  const tone = bandTone(state.band || 'low');
  await chrome.action.setBadgeBackgroundColor({ tabId, color: tone.color });
  await chrome.action.setBadgeText({ tabId, text: state.toolCount ? String(state.toolCount) : '' });
  await chrome.action.setTitle({
    tabId,
    title: `Varden Web Shield: ${state.toolCount || 0} tool(s), highest risk: ${state.band || 'low'}`,
  });
}

async function handleToolRegistered(tabId, message, frameId) {
  const config = await getConfig();
  const apiKey = await ensureApiKey(config);
  const sessionId = await getSessionId(tabId);
  const tool = message.event.detail.tool || {};
  const body = {
    session_id: sessionId,
    owner_origin: message.ownerOrigin,
    top_origin: message.topOrigin,
    api_surface: message.event.detail.api_surface || 'document_model_context',
    tool,
    is_third_party_frame: message.isThirdPartyFrame,
    script_source_origin: message.scriptSourceOrigin,
    // Chrome-provided sender.frameId is authoritative; the content script's
    // own correlation id (message.frameId) is kept only as a secondary,
    // non-trusted diagnostic tag — never used for identity/isolation
    // decisions server-side. See docs/web-shield-hardening-review.md #2/#6.
    frame_id: String(frameId),
    frame_correlation_id: message.frameId,
    tab_id: String(tabId),
    extension_version: EXTENSION_VERSION,
  };

  let band = 'low';
  let connected = true;
  try {
    if (!apiKey) throw new Error('no api key available yet');
    const result = await postToVarden(config, apiKey, '/webshield/registrations', body);
    const detail = result.detail || result;
    band = (detail.scan && detail.scan.risk && detail.scan.risk.band) || (detail.event && detail.event.action && detail.event.action.metadata && detail.event.action.metadata.risk_band) || 'low';
  } catch (e) {
    connected = false;
    const fallback = localFallbackScan(tool);
    band = fallback.band;
    await queueOffline({ path: '/webshield/registrations', body });
  }

  const state = tabState.get(tabId) || { toolCount: 0, band: 'low' };
  state.toolCount = (state.toolCount || 0) + 1;
  state.connected = connected;
  state.protectionMode = connected ? 'connected' : 'local_fallback';
  state.band = rankBand(band) > rankBand(state.band) ? band : state.band;
  state.origin = message.ownerOrigin;
  tabState.set(tabId, state);
  await updateBadge(tabId);
}

function rankBand(band) {
  return { low: 0, guarded: 1, suspicious: 2, high: 3, critical: 4 }[band] || 0;
}

async function handleContextReplaced(tabId, message, frameId) {
  const config = await getConfig();
  const apiKey = await ensureApiKey(config);
  const sessionId = await getSessionId(tabId);
  const body = {
    session_id: sessionId,
    event: 'extension_tamper_detected',
    top_origin: message.topOrigin,
    frame_id: String(frameId),
    details: { api_surface: message.event.detail.api_surface },
  };
  try {
    if (apiKey) await postToVarden(config, apiKey, '/webshield/lifecycle', body);
  } catch (e) {
    await queueOffline({ path: '/webshield/lifecycle', body });
  }
  const state = tabState.get(tabId) || { toolCount: 0 };
  state.band = 'critical';
  tabState.set(tabId, state);
  await updateBadge(tabId);
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.source !== 'varden-webshield-content') return;
  const tabId = sender.tab ? sender.tab.id : undefined;
  if (tabId === undefined) return;
  // Chrome-provided sender metadata is authoritative; a content script (let
  // alone the page) cannot forge which tab/frame it is actually running in.
  // See docs/web-shield-hardening-review.md #2.
  const frameId = typeof sender.frameId === 'number' ? sender.frameId : undefined;
  const kind = message.event && message.event.kind;
  if (kind === 'tool_registered') {
    handleToolRegistered(tabId, message, frameId);
  } else if (kind === 'context_replaced' || kind === 'wrapper_tamper_detected') {
    handleContextReplaced(tabId, message, frameId);
  } else if (kind === 'protocol_diagnostic') {
    // Rejected-envelope diagnostics from content-isolated.js's protocol
    // validation (bad nonce, replayed sequence, oversized payload, etc.).
    // Never forwarded to Varden as a tool/lifecycle event; logged locally
    // only, so a flood of malformed page-world traffic cannot itself become
    // an ingestion vector.
    console.debug('[varden-webshield] rejected page-world event', message.event && message.event.detail);
  }
  // tool_unregistered / provide_context / clear_context are accepted for
  // future lifecycle correlation but do not change the badge today.
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

// ---- popup / options plumbing -------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.source) return undefined;
  if (message.source === 'varden-webshield-popup-query') {
    (async () => {
      const state = tabState.get(message.tabId) || { toolCount: 0, band: 'low', connected: false, protectionMode: 'unknown' };
      const config = await getConfig();
      const { queue = [] } = await chrome.storage.local.get('queue');
      sendResponse({ state, config, queuedEvents: queue.length });
    })();
    return true;
  }
  if (message.source === 'varden-webshield-options-get') {
    getConfig().then(sendResponse);
    return true;
  }
  if (message.source === 'varden-webshield-options-set') {
    chrome.storage.local.set(message.config).then(() => sendResponse({ ok: true }));
    return true;
  }
  return undefined;
});

chrome.alarms.create('varden-webshield-health', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'varden-webshield-health') return;
  const config = await getConfig();
  const apiKey = await ensureApiKey(config);
  if (!apiKey) return;
  const compat = await checkServerCompatibility(config, apiKey);
  if (compat.checked && !compat.compatible) {
    console.warn('[varden-webshield] incompatible with server:', compat.reason);
    await chrome.storage.local.set({ serverCompatibility: compat });
    return; // Do not flush queued events to a server we are incompatible with.
  }
  await chrome.storage.local.set({ serverCompatibility: compat });
  await flushQueue(config, apiKey);
});
