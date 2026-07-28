'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('thirdeyeDemo', {
  capture: () => ipcRenderer.invoke('capture'),
  spawnInvisible: () => ipcRenderer.invoke('spawn-invisible'),
  spawnInvisibleElevated: () => ipcRenderer.invoke('spawn-invisible-elevated'),
  getWarmStatus: () => ipcRenderer.invoke('warm-status'),
  onWarmStatus: (cb) => {
    const handler = (_event, payload) => cb(payload);
    ipcRenderer.on('warm-status', handler);
    return () => ipcRenderer.removeListener('warm-status', handler);
  },
});
