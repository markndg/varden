(function () {
  const endpointInput = document.getElementById('endpoint');
  const modeSelect = document.getElementById('mode');
  const savedLabel = document.getElementById('saved');

  chrome.runtime.sendMessage({ source: 'varden-webshield-options-get' }, (config) => {
    endpointInput.value = (config && config.endpoint) || 'http://127.0.0.1:8000';
    modeSelect.value = (config && config.mode) || 'observe';
  });

  document.getElementById('save').addEventListener('click', () => {
    const endpoint = endpointInput.value.trim().replace(/\/$/, '') || 'http://127.0.0.1:8000';
    const mode = modeSelect.value;
    chrome.runtime.sendMessage({ source: 'varden-webshield-options-set', config: { endpoint, mode, apiKey: '' } }, () => {
      savedLabel.textContent = 'Saved.';
      setTimeout(() => { savedLabel.textContent = ''; }, 2000);
    });
  });
})();
