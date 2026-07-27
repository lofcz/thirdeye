'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('thirdeyeDemo', {
  capture: () => ipcRenderer.invoke('capture'),
  spawnInvisible: () => ipcRenderer.invoke('spawn-invisible'),
});
