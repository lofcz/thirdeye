'use strict';

const statusEl = document.getElementById('status');
const captureBtn = document.getElementById('capture');
const spawnBtn = document.getElementById('spawn');
const spawnElevatedBtn = document.getElementById('spawn-elevated');

function setStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.classList.toggle('error', Boolean(isError));
}

let pending = 0;
let done = 0;
let warmMessage = null;

function refreshStatus() {
  if (pending > 0) {
    setStatus(`Capturing... (${done} saved, ${pending} queued)`, false);
    return;
  }
  if (warmMessage) {
    setStatus(warmMessage.text, warmMessage.error);
  }
}

window.thirdeyeDemo.onWarmStatus((payload) => {
  if (!payload) return;
  warmMessage = {
    text: payload.message || payload.state,
    error: payload.state === 'error',
  };
  refreshStatus();
});

window.thirdeyeDemo.getWarmStatus().then((s) => {
  if (s && s.state === 'warming') {
    warmMessage = { text: 'Warming elevated capture worker…', error: false };
    refreshStatus();
  } else if (s && s.state === 'ready') {
    warmMessage = { text: 'Elevated worker ready', error: false };
    refreshStatus();
  }
});

captureBtn.addEventListener('click', async () => {
  pending += 1;
  refreshStatus();
  try {
    const result = await window.thirdeyeDemo.capture();
    if (result.ok) {
      done += 1;
      setStatus(`Saved: ${result.filePath} (${result.ms != null ? result.ms.toFixed(0) + 'ms' : 'ok'})`, false);
    } else {
      setStatus(`Capture failed: ${result.error}`, true);
    }
  } catch (err) {
    setStatus(`Capture failed: ${err}`, true);
  } finally {
    pending -= 1;
    refreshStatus();
  }
});

spawnBtn.addEventListener('click', async () => {
  spawnBtn.disabled = true;
  try {
    await window.thirdeyeDemo.spawnInvisible();
    setStatus('Invisible app launched (protected window).', false);
  } catch (err) {
    setStatus(`Failed to launch: ${err}`, true);
  } finally {
    spawnBtn.disabled = false;
  }
});

spawnElevatedBtn.addEventListener('click', async () => {
  spawnElevatedBtn.disabled = true;
  try {
    await window.thirdeyeDemo.spawnInvisibleElevated();
    setStatus('Elevated invisible app launched (protected window, admin).', false);
  } catch (err) {
    setStatus(`Failed to launch elevated app: ${err.message || err}`, true);
  } finally {
    spawnElevatedBtn.disabled = false;
  }
});
