const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nodexDesktop', Object.freeze({
  getBootstrapStatus: () => ipcRenderer.invoke('nodex:bootstrap-status'),
  retryBootstrap: () => ipcRenderer.invoke('nodex:retry-bootstrap'),
  openDataFolder: () => ipcRenderer.invoke('nodex:open-data-folder'),
}));
