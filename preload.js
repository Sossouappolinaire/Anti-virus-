const { contextBridge, ipcRenderer } = require('electron');
const call = (c) => (...a) => ipcRenderer.invoke(c, ...a);
contextBridge.exposeInMainWorld('api', {
  getPath: call('path:get'),
  pickFolder: call('dialog:folder'),
  scanStart: call('scan:start'),
  scanCancel: call('scan:cancel'),
  scanPause: call('scan:pause'),
  quarantine: call('file:quarantine'),
  deleteFiles: call('file:delete'),
  showItem: call('file:show'),
  quarList: call('quar:list'),
  quarRestore: call('quar:restore'),
  quarDelete: call('quar:delete'),
  quarDeleteAll: call('quar:deleteAll'),
  perfScan: call('perf:scan'),
  tempClean: call('temp:clean'),
  cfgGet: call('cfg:get'),
  cfgSet: call('cfg:set'),
  onProgress: (cb) => ipcRenderer.on('scan:progress', (_, d) => cb(d)),
  onVT: (cb) => ipcRenderer.on('vt:update', (_, d) => cb(d)),
});
