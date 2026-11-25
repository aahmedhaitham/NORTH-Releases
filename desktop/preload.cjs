const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('north', {
  connect: (address) => ipcRenderer.invoke('north:connect', address),
});
