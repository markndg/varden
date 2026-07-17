(async function () {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const origin = tab && tab.url ? new URL(tab.url).origin : '—';
  document.getElementById('origin').textContent = origin;

  chrome.runtime.sendMessage({ source: 'varden-webshield-popup-query', tabId: tab && tab.id }, (response) => {
    if (!response) return;
    const { state, config, queuedEvents } = response;
    document.getElementById('tool-count').textContent = String(state.toolCount || 0);
    document.getElementById('risk-band').textContent = state.band || 'low';
    document.getElementById('protection-mode').textContent = state.connected ? `connected (${config.mode})` : 'local protection (server unreachable)';
    document.getElementById('queued').textContent = String(queuedEvents || 0);

    const pill = document.getElementById('conn-pill');
    if (!state.toolCount) {
      pill.className = 'pill pill--pending';
      pill.textContent = 'no tools seen yet';
    } else if (!state.connected) {
      pill.className = 'pill pill--warn';
      pill.textContent = 'local protection';
    } else if (state.band === 'critical' || state.band === 'high') {
      pill.className = 'pill pill--danger';
      pill.textContent = 'high risk found';
    } else if (state.band === 'suspicious' || state.band === 'guarded') {
      pill.className = 'pill pill--warn';
      pill.textContent = 'warnings';
    } else {
      pill.className = 'pill pill--ok';
      pill.textContent = 'protected';
    }

    document.getElementById('open-dashboard').href = `${config.endpoint}/ui/web-shield`;
  });
})();
