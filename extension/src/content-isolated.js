// Varden Web Shield — isolated-world relay.
//
// Runs alongside src/page-world.js in the same frame but in the extension's
// isolated JS world, which the page cannot see or tamper with. Its only job
// is to hand the page-world script an authenticated MessageChannel port and
// relay whatever it reports to the background service worker, tagged with
// this frame's own origin/top-origin/third-party status (which the page
// cannot spoof, since those come from the isolated world's own `window`,
// not from anything the page told us).
(function () {
  'use strict';
  const channel = new MessageChannel();
  window.postMessage({ type: 'varden-webshield-init' }, window.location.origin, [channel.port2]);

  const frameId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  let topOrigin;
  let isThirdPartyFrame = false;
  try {
    topOrigin = window.top.location.origin;
    isThirdPartyFrame = window.top !== window && topOrigin !== window.location.origin;
  } catch (e) {
    // Cross-origin top frame: we cannot read its origin at all, which is
    // itself a strong third-party-frame signal.
    topOrigin = undefined;
    isThirdPartyFrame = true;
  }

  channel.port1.onmessage = (event) => {
    try {
      chrome.runtime.sendMessage({
        source: 'varden-webshield-content',
        frameId,
        ownerOrigin: window.location.origin,
        topOrigin: topOrigin || window.location.origin,
        isThirdPartyFrame,
        scriptSourceOrigin: window.location.origin,
        event: event.data,
      });
    } catch (e) {
      // "Extension context invalidated" happens on reload/update; the page
      // keeps working normally, we just stop reporting until next load.
    }
  };
})();
