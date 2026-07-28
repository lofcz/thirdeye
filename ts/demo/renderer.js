'use strict';

const statusEl = document.getElementById('status');
const captureBtn = document.getElementById('capture');
const spawnBtn = document.getElementById('spawn');

function setStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.classList.toggle('error', Boolean(isError));
}

let pending = 0;
let done = 0;

function refreshStatus() {
  if (pending > 0) {
    setStatus(`Capturing... (${done} saved, ${pending} queued)`, false);
  }
}

captureBtn.addEventListener('click', async () => {
  pending += 1;
  refreshStatus();
  try {
    const result = await window.thirdeyeDemo.capture();
    if (result.ok) {
      done += 1;
      setStatus(`Saved: ${result.filePath}`, false);
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
