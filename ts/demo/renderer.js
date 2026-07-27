'use strict';

const statusEl = document.getElementById('status');
const captureBtn = document.getElementById('capture');
const spawnBtn = document.getElementById('spawn');

function setStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.classList.toggle('error', Boolean(isError));
}

captureBtn.addEventListener('click', async () => {
  captureBtn.disabled = true;
  setStatus('Capturing...', false);
  try {
    const result = await window.thirdeyeDemo.capture();
    if (result.ok) {
      setStatus(`Saved: ${result.filePath}`, false);
    } else {
      setStatus(`Capture failed: ${result.error}`, true);
    }
  } catch (err) {
    setStatus(`Capture failed: ${err}`, true);
  } finally {
    captureBtn.disabled = false;
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
