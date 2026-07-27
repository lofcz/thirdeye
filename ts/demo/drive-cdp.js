'use strict';

// Drives the running Electron demo over CDP (ws endpoint on 127.0.0.1:9222).
// 1. clicks "Launch invisible app"
// 2. clicks "Capture screenshot"
// 3. prints the status line text

async function getJson(url) {
  const res = await fetch(url);
  return res.json();
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let id = 0;
    const pending = new Map();

    ws.onopen = () => resolve(api);
    ws.onerror = (e) => reject(new Error('ws error'));
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve: r, reject: rj } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rj(new Error(JSON.stringify(msg.error)));
        else r(msg.result);
      }
    };

    function send(method, params) {
      return new Promise((r, rj) => {
        const mid = ++id;
        pending.set(mid, { resolve: r, reject: rj });
        ws.send(JSON.stringify({ id: mid, method, params }));
      });
    }

    const api = {
      send,
      async evaluate(expression) {
        const res = await send('Runtime.evaluate', {
          expression,
          awaitPromise: true,
          returnByValue: true,
        });
        if (res.exceptionDetails) {
          throw new Error('evaluate exception: ' + JSON.stringify(res.exceptionDetails));
        }
        return res.result.value;
      },
      close: () => ws.close(),
    };
  });
}

(async () => {
  const targets = await getJson('http://127.0.0.1:9222/json');
  const page = targets.find((t) => t.type === 'page' && t.url.includes('index.html'));
  if (!page) throw new Error('demo page not found: ' + JSON.stringify(targets));

  const cdp = await connect(page.webSocketDebuggerUrl);

  const hasBridge = await cdp.evaluate('!!window.thirdeyeDemo');
  console.log('bridge exposed:', hasBridge);

  // Launch the invisible app
  await cdp.evaluate(`document.getElementById('spawn').click()`);
  await new Promise((r) => setTimeout(r, 2500));
  console.log('after spawn status:', await cdp.evaluate(`document.getElementById('status').textContent`));

  // Capture screenshot
  await cdp.evaluate(`document.getElementById('capture').click()`);
  await new Promise((r) => setTimeout(r, 2500));
  const status = await cdp.evaluate(`document.getElementById('status').textContent`);
  console.log('after capture status:', status);

  cdp.close();
  process.exit(0);
})().catch((e) => {
  console.error('FAILED:', e.message);
  process.exit(1);
});
