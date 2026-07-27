'use strict';

// Companion app: shows a window flagged with WDA_EXCLUDEFROMCAPTURE via
// Electron's win.setContentProtection(true). Conventional screenshots
// (PrintScreen, Snipping Tool, BitBlt) will not see it; thirdeye will.

const { app, BrowserWindow } = require('electron');

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 260,
    x: 80,
    y: 80,
    resizable: false,
    autoHideMenuBar: true,
    title: 'You should not see this window in screenshots',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // Sets WDA_EXCLUDEFROMCAPTURE on the window (Windows).
  win.setContentProtection(true);

  win.loadURL(
    'data:text/html;charset=utf-8,' +
      encodeURIComponent(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body {
      margin: 0;
      height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: #1d1024;
      color: #f3d9ff;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    h1 { font-size: 16px; margin: 0; }
    p { font-size: 12px; color: #b98ad1; margin: 0; text-align: center; line-height: 1.6; }
  </style>
</head>
<body>
  <h1>Invisible window (WDA_EXCLUDEFROMCAPTURE)</h1>
  <p>
    Standard screenshots cannot see this window.<br />
    Capture with the ThirdEye demo app to reveal it.
  </p>
</body>
</html>`),
  );
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});
