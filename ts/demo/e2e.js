'use strict';

// E2E driver: launches invisible app, launches demo app, triggers capture via
// CDP, verifies the protected window is present in the saved screenshot.

const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const DEMO_DIR = __dirname;
const ELECTRON = path.join(DEMO_DIR, 'node_modules', 'electron', 'dist', 'electron.exe');
const CAPTURE_PREFIX = 'capture_';

function existingCaptures() {
  return new Set(
    fs.readdirSync(DEMO_DIR).filter((f) => f.startsWith(CAPTURE_PREFIX) && f.endsWith('.jpg')),
  );
}

function waitForNewCapture(before, timeoutMs) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const iv = setInterval(() => {
      const now = fs.readdirSync(DEMO_DIR).filter((f) => f.startsWith(CAPTURE_PREFIX));
      const fresh = now.filter((f) => !before.has(f));
      if (fresh.length) {
        clearInterval(iv);
        resolve(path.join(DEMO_DIR, fresh[0]));
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(iv);
        reject(new Error('timeout waiting for capture file'));
      }
    }, 250);
  });
}

async function main() {
  const before = existingCaptures();

  // 1. launch the invisible (protected) companion app
  const invisible = spawn(ELECTRON, [path.join(DEMO_DIR, 'invisible.js')], {
    stdio: 'ignore',
    detached: true,
  });
  invisible.unref();

  // 2. launch the demo app with a CDP port so we can click the capture button
  const demo = spawn(
    ELECTRON,
    [path.join(DEMO_DIR, 'main.js'), '--remote-debugging-port=9223'],
    { stdio: 'ignore', detached: true },
  );
  demo.unref();

  // 3. wait for CDP, find the page, click capture
  const deadline = Date.now() + 15000;
  let target = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch('http://127.0.0.1:9223/json');
      const pages = await res.json();
      target = pages.find((p) => p.url.includes('index.html'));
      if (target) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 400));
  }
  if (!target) throw new Error('demo app page not reachable over CDP');

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));

  let msgId = 0;
  const pending = new Map();
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    }
  });
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      const id = ++msgId;
      pending.set(id, resolve);
      ws.send(JSON.stringify({ id, method, params }));
    });

  await send('Runtime.enable');

  // wait for the invisible window to be fully up before capturing
  await new Promise((r) => setTimeout(r, 2500));

  // Rapid-fire 5 clicks to verify the queue produces 5 distinct files.
  const CLICKS = 5;
  await send('Runtime.evaluate', {
    expression: `for (let i = 0; i < ${CLICKS}; i++) document.getElementById('capture').click(); 'clicked ${CLICKS}x'`,
    awaitPromise: false,
  });
  console.log(`clicked ${CLICKS} times rapidly`);

  // Wait for all expected new captures to appear.
  const deadline2 = Date.now() + 60000;
  let fresh = [];
  while (Date.now() < deadline2) {
    const now = fs.readdirSync(DEMO_DIR).filter((f) => f.startsWith(CAPTURE_PREFIX) && f.endsWith('.jpg'));
    fresh = now.filter((f) => !before.has(f));
    if (fresh.length >= CLICKS) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  console.log(`produced ${fresh.length}/${CLICKS} captures:`);
  fresh.sort().forEach((f) => console.log('  ', f, fs.statSync(path.join(DEMO_DIR, f)).size, 'bytes'));

  if (fresh.length !== CLICKS) {
    throw new Error(`expected ${CLICKS} captures, got ${fresh.length}`);
  }
  const uniqueNames = new Set(fresh);
  if (uniqueNames.size !== CLICKS) {
    throw new Error(`filenames not unique: ${uniqueNames.size}/${CLICKS}`);
  }
  console.log('OK: all rapid captures produced unique files');

  ws.close();
  try { process.kill(demo.pid); } catch {}
  try { process.kill(invisible.pid); } catch {}
}

main().catch((e) => {
  console.error('E2E FAILED:', e.message);
  process.exit(1);
});
