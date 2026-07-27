'use strict';

const { app, BrowserWindow, ipcMain, screen } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const { ThirdEyeSession, ThirdeyeFormat } = require('@lofcz/thirdeye');

// Capture must see real screen pixels, not a DPI-virtualized view. Opt out of
// per-monitor DPI scaling for this process so the GDI capture coordinates line
// up with the physical desktop at any scale factor.
app.commandLine.appendSwitch('high-dpi-support', '1');
app.commandLine.appendSwitch('force-device-scale-factor', '1');

let mainWindow = null;
let invisibleProcess = null;
let session = null;

function getSession() {
  if (!session) {
    session = new ThirdEyeSession();
  }
  return session;
}

function launchInvisibleApp() {
  if (invisibleProcess) {
    return;
  }

  invisibleProcess = spawn(
    process.execPath,
    [path.join(__dirname, 'invisible.js')],
    {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined },
      stdio: 'ignore',
      detached: false,
    },
  );

  invisibleProcess.on('exit', () => {
    invisibleProcess = null;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 520,
    height: 420,
    resizable: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile('index.html');
}

app.whenReady().then(() => {
  ipcMain.handle('capture', () => {
    const stamp = new Date()
      .toISOString()
      .replace(/[:.]/g, '-')
      .replace('T', '_')
      .slice(0, 19);
    const filePath = path.join(app.getAppPath(), `capture_${stamp}.jpg`);

    try {
      const s = getSession();
      s.captureToFile(filePath, {
        format: ThirdeyeFormat.Jpeg,
        quality: 90,
        bypassProtection: true,
      });
      console.log('[capture diag]', s.lastError());
      return { ok: true, filePath };
    } catch (err) {
      return { ok: false, error: String(err && err.message ? err.message : err) };
    }
  });

  ipcMain.handle('spawn-invisible', () => {
    launchInvisibleApp();
    return true;
  });

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('will-quit', () => {
  if (invisibleProcess) {
    try {
      invisibleProcess.kill();
    } catch {
      /* already gone */
    }
    invisibleProcess = null;
  }
  if (session) {
    session.close();
    session = null;
  }
});
