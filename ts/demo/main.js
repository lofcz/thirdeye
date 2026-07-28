'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const {
  ThirdEyeSession,
  ThirdeyeFormat,
  ThirdeyeMode,
  prepareAsync,
  clean,
  state,
} = require('@lofcz/thirdeye');
const koffi = require('koffi');

function launchElevated(exePath, args, cwd) {
  const shell32 = koffi.load('shell32.dll');

  const SHELLEXECUTEINFOW = koffi.struct('SHELLEXECUTEINFOW', {
    cbSize: 'uint32',
    fMask: 'uint32',
    hwnd: 'void *',
    lpVerb: 'str16',
    lpFile: 'str16',
    lpParameters: 'str16',
    lpDirectory: 'str16',
    nShow: 'int',
    hInstApp: 'void *',
    lpIDList: 'void *',
    lpClass: 'str16',
    hkeyClass: 'void *',
    dwHotKey: 'uint32',
    hIconOrMonitor: 'void *',
    hProcess: 'void *',
  });

  const ShellExecuteExW = shell32.func(
    'bool __stdcall ShellExecuteExW(_Inout_ SHELLEXECUTEINFOW *pExecInfo)',
  );
  const GetLastError = koffi.load('kernel32.dll').func('uint32 __stdcall GetLastError()');

  const info = {
    cbSize: koffi.sizeof(SHELLEXECUTEINFOW),
    fMask: 0,
    hwnd: null,
    lpVerb: 'runas',
    lpFile: exePath,
    lpParameters: args,
    lpDirectory: cwd,
    nShow: 1,
    hInstApp: null,
    lpIDList: null,
    lpClass: null,
    hkeyClass: null,
    dwHotKey: 0,
    hIconOrMonitor: null,
    hProcess: null,
  };

  const ok = ShellExecuteExW(info);
  if (!ok) {
    const err = GetLastError();
    if (err === 1223) throw new Error('Elevation cancelled (UAC declined by user).');
    throw new Error(`ShellExecuteExW failed, GetLastError=${err}`);
  }
  return true;
}

app.commandLine.appendSwitch('high-dpi-support', '1');
app.commandLine.appendSwitch('force-device-scale-factor', '1');

let mainWindow = null;
let invisibleProcess = null;
let session = null;
let preparePromise = null;
let prepareReady = false;

function sendWarmStatus(payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('warm-status', payload);
  }
}

function startPrepare() {
  if (preparePromise) return preparePromise;
  sendWarmStatus({ state: 'warming', message: 'Preparing capture helper…' });
  const t0 = performance.now();
  preparePromise = prepareAsync({ elevate: true })
    .then((ok) => {
      prepareReady = !!ok;
      const ms = performance.now() - t0;
      const st = state();
      console.log(`[prepare] ${ok ? 'ok' : 'FAIL'} in ${ms.toFixed(0)}ms mode=${st.mode} pid=${st.pid}`);
      sendWarmStatus({
        state: ok ? 'ready' : 'error',
        message: ok
          ? `Ready (mode ${st.mode}, pid ${st.pid}, ${ms.toFixed(0)}ms)`
          : 'Prepare failed',
        ms,
        pid: st.pid,
        mode: st.mode,
      });
      return ok;
    })
    .catch((err) => {
      prepareReady = false;
      console.error('[prepare] error', err);
      sendWarmStatus({
        state: 'error',
        message: `Prepare failed: ${err.message || err}`,
      });
      throw err;
    });
  return preparePromise;
}

function getSession() {
  if (!session) session = new ThirdEyeSession();
  return session;
}

function launchInvisibleApp() {
  if (invisibleProcess) return;
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
  mainWindow.webContents.on('did-finish-load', () => {
    if (prepareReady) {
      const st = state();
      sendWarmStatus({ state: 'ready', message: `Ready (pid ${st.pid})`, pid: st.pid });
    } else if (preparePromise) {
      sendWarmStatus({ state: 'warming', message: 'Preparing capture helper…' });
    }
  });
}

app.whenReady().then(() => {
  startPrepare();

  let captureQueue = Promise.resolve();
  let captureCounter = 0;

  const runCapture = async () => {
    captureCounter += 1;
    const stamp = new Date()
      .toISOString()
      .replace(/[:.]/g, '-')
      .replace('T', '_')
      .slice(0, 23);
    const filePath = path.join(app.getAppPath(), `capture_${stamp}_${captureCounter}.jpg`);

    try {
      await startPrepare();
      const s = getSession();
      const t0 = performance.now();
      await s.captureToFileAsync(filePath, {
        format: ThirdeyeFormat.Jpeg,
        quality: 90,
        inclusive: true,
      });
      const ms = performance.now() - t0;
      console.log(`[capture] ${ms.toFixed(1)}ms -> ${filePath}`);
      return { ok: true, filePath, ms };
    } catch (err) {
      return { ok: false, error: String(err && err.message ? err.message : err) };
    }
  };

  ipcMain.handle('capture', () => {
    const result = captureQueue.then(runCapture, runCapture);
    captureQueue = result.catch(() => {});
    return result;
  });

  ipcMain.handle('spawn-invisible', () => {
    launchInvisibleApp();
    return true;
  });

  ipcMain.handle('spawn-invisible-elevated', () => {
    launchElevated(
      process.execPath,
      `"${path.join(__dirname, 'invisible.js')}"`,
      __dirname,
    );
    return true;
  });

  ipcMain.handle('warm-status', () => ({
    state: prepareReady ? 'ready' : preparePromise ? 'warming' : 'idle',
    ...state(),
  }));

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('will-quit', () => {
  if (invisibleProcess) {
    try { invisibleProcess.kill(); } catch { /* ignore */ }
    invisibleProcess = null;
  }
  try { clean(); } catch { /* ignore */ }
  if (session) {
    session.close();
    session = null;
  }
});
