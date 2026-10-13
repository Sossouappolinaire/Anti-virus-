const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');

let win;
let cancel = false;
let paused = false;
const waitPause = async () => { while (paused && !cancel) await new Promise((r) => setTimeout(r, 200)); };
const SIGNATURES = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'hashes.json'), 'utf8')).hashes || {}; }
  catch { return {}; }
})();

const QDIR = () => path.join(app.getPath('userData'), 'quarantine');
const CFG = () => path.join(app.getPath('userData'), 'config.json');
const loadCfg = () => { try { return JSON.parse(fs.readFileSync(CFG(), 'utf8')); } catch { return {}; } };

function createWindow() {
  win = new BrowserWindow({
    width: 1100, height: 760, minWidth: 900, minHeight: 600,
    title: 'Antivirus Sossou Sa Mont Sion',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.removeMenu();
  win.loadFile('index.html');
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());

/* ---------- Outils ---------- */
const SKIP = new Set(['$recycle.bin', 'system volume information', 'winsxs', 'installer', 'softwaredistribution', 'assembly', 'servicing', 'node_modules']);

async function walk(dir, cb) {
  if (cancel) return;
  let entries;
  try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (cancel) return;
    await waitPause();
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (SKIP.has(e.name.toLowerCase()) || p.startsWith(QDIR())) continue;
      await walk(p, cb);
    } else if (e.isFile()) await cb(p);
  }
}

function hashFile(p) {
  return new Promise((resolve) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(p);
    s.on('data', (d) => h.update(d));
    s.on('error', () => resolve(null));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

async function dirSize(dir) {
  let total = 0;
  await walk(dir, async (p) => { try { total += (await fsp.stat(p)).size; } catch {} });
  return total;
}

const run = (cmd, args) => new Promise((resolve) =>
  execFile(cmd, args, { windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err, out) => resolve(err ? '' : out)));
const psJson = async (script) => {
  const out = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script + ' | ConvertTo-Json -Compress']);
  try { const j = JSON.parse(out); return Array.isArray(j) ? j : j ? [j] : []; } catch { return []; }
};

/* ---------- Analyse ---------- */
const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|mp3|mp4)\.(exe|scr|bat|cmd|com|pif|vbs|js|ps1|msi)$/i;
const EXEC_EXT = /\.(exe|scr|dll|com|pif|msi)$/i;
const SCRIPT_EXT = /\.(bat|cmd|vbs|ps1)$/i;
const DAY = 86400000;

ipcMain.handle('path:get', (_, name) => {
  if (name === 'disk') return (process.env.SystemDrive || 'C:') + '\\';
  try { return app.getPath(name); } catch { return null; }
});
ipcMain.handle('dialog:folder', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});
ipcMain.handle('scan:cancel', () => { cancel = true; paused = false; });
ipcMain.handle('scan:pause', () => { paused = !paused; return paused; });

ipcMain.handle('scan:start', async (_, folder) => {
  cancel = false; paused = false;
  const t0 = Date.now();
  const send = (d) => win.webContents.send('scan:progress', { ...d, elapsed: Math.round((Date.now() - t0) / 1000), threats: threats.size });
  let lastSend = 0;
  const tick = (d) => { if (Date.now() - lastSend > 150) { lastSend = Date.now(); send(d); } };
  const files = [], large = [], threats = new Map();
  const addThreat = (p, level, reason, type = 'suspect') => {
    const old = threats.get(p);
    if (old) { if (type === 'virus') Object.assign(old, { level, reason, type }); return; }
    threats.set(p, { path: p, level, reason, type });
  };
  const rank = { faible: 1, moyen: 2, 'élevé': 3 };

  // Phase 1 : parcours + détection de fichiers suspects
  await walk(folder, async (p) => {
    let st; try { st = await fsp.stat(p); } catch { return; }
    files.push({ p, size: st.size, mtime: st.mtimeMs });
    if (st.size > 500 * 1024 * 1024) large.push({ path: p, size: st.size });
    const low = p.toLowerCase();
    const inTemp = low.includes('\\temp\\') || low.includes('\\appdata\\local\\temp');
    const inSys = low.includes('\\windows\\system32\\') || low.includes('\\windows\\syswow64\\');
    if (DOUBLE_EXT.test(p)) addThreat(p, 'élevé', 'Double extension (fichier déguisé)');
    else if (EXEC_EXT.test(p) && inTemp) addThreat(p, 'moyen', 'Exécutable dans un dossier temporaire');
    else if (SCRIPT_EXT.test(p)) addThreat(p, inTemp ? 'moyen' : 'faible', 'Script (.bat, .cmd, .vbs, .ps1)');
    else if (EXEC_EXT.test(p) && inSys && Date.now() - st.mtimeMs < 2 * DAY) addThreat(p, 'faible', 'Fichier système très récent');
    tick({ phase: 'Recherche des fichiers…', scanned: files.length, current: p });
  });

  // Phase 2 : empreintes SHA-256 (virus connus + doublons)
  const bySize = new Map();
  for (const f of files) bySize.set(f.size, (bySize.get(f.size) || 0) + 1);
  const toHash = files.filter((f) => f.size >= 1024 && (f.size <= 100 * 1024 * 1024 || bySize.get(f.size) > 1));
  const byHash = new Map();
  const totalBytes = toHash.reduce((a, f) => a + f.size, 0) || 1;
  let done = 0, doneBytes = 0;
  const t1 = Date.now();
  for (const f of toHash) {
    await waitPause();
    if (cancel) break;
    const h = await hashFile(f.p);
    done++; doneBytes += f.size;
    if (h) {
      f.hash = h;
      if (SIGNATURES[h]) addThreat(f.p, 'élevé', 'Virus connu : ' + SIGNATURES[h], 'virus');
      const lp = f.p.toLowerCase();
      if (!lp.includes('\\windows\\') && !lp.includes('\\program files')) {
        if (!byHash.has(h)) byHash.set(h, []);
        byHash.get(h).push({ path: f.p, mtime: f.mtime, size: f.size });
      }
    }
    tick({ phase: 'Vérification des fichiers…', scanned: files.length, current: f.p, done: doneBytes, total: totalBytes, eta: Math.round(((Date.now() - t1) / Math.max(doneBytes, 1)) * (totalBytes - doneBytes) / 1000) });
  }
  const dups = [...byHash.values()].filter((g) => g.length > 1)
    .map((g) => ({ size: g[0].size, wasted: g[0].size * (g.length - 1), files: g.sort((a, b) => a.mtime - b.mtime) }))
    .sort((a, b) => b.wasted - a.wasted).slice(0, 300);

  const list = [...threats.values()].sort((a, b) => rank[b.level] - rank[a.level]);
  large.sort((a, b) => b.size - a.size);
  const result = { scanned: files.length, duration: Math.round((Date.now() - t0) / 1000), cancelled: cancel, threats: list, dups, large: large.slice(0, 25) };
  vtCheck(list.filter((t) => t.type === 'suspect' && t.level !== 'faible').slice(0, 20));
  return result;
});

// Vérification VirusTotal (facultative, 4 requêtes/minute max)
async function vtCheck(list) {
  const key = loadCfg().vtKey;
  if (!key) return;
  for (const t of list) {
    if (cancel) break;
    const h = await hashFile(t.path);
    if (!h) continue;
    try {
      const r = await fetch('https://www.virustotal.com/api/v3/files/' + h, { headers: { 'x-apikey': key } });
      if (r.ok) {
        const s = (await r.json()).data.attributes.last_analysis_stats;
        win.webContents.send('vt:update', { path: t.path, malicious: s.malicious, total: Object.values(s).reduce((a, b) => a + b, 0) });
      } else if (r.status === 404) win.webContents.send('vt:update', { path: t.path, unknown: true });
    } catch {}
    await new Promise((r) => setTimeout(r, 16000));
  }
}

/* ---------- Actions sur les fichiers ---------- */
async function moveFile(src, dest) {
  try { await fsp.rename(src, dest); } catch { await fsp.copyFile(src, dest); await fsp.unlink(src); }
}

ipcMain.handle('file:quarantine', async (_, p) => {
  try {
    await fsp.mkdir(QDIR(), { recursive: true });
    const id = crypto.randomUUID();
    await moveFile(p, path.join(QDIR(), id + '.quar'));
    await fsp.writeFile(path.join(QDIR(), id + '.json'), JSON.stringify({ id, origin: p, name: path.basename(p), date: new Date().toISOString() }));
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('file:delete', async (_, paths) => {
  const r = await dialog.showMessageBox(win, {
    type: 'warning', buttons: ['Annuler', 'Supprimer'], defaultId: 0, cancelId: 0,
    title: 'Confirmer la suppression',
    message: paths.length === 1 ? 'Supprimer définitivement ce fichier ?' : `Supprimer définitivement ${paths.length} fichiers ?`,
    detail: paths.slice(0, 8).join('\n') + (paths.length > 8 ? '\n…' : '') + '\n\nCette action est irréversible.',
  });
  if (r.response !== 1) return { cancelled: true, deleted: [], failed: [] };
  const deleted = [], failed = [];
  for (const p of paths) { try { await fsp.unlink(p); deleted.push(p); } catch { failed.push(p); } }
  return { deleted, failed };
});

ipcMain.handle('file:show', (_, p) => shell.showItemInFolder(p));

/* ---------- Quarantaine ---------- */
ipcMain.handle('quar:list', async () => {
  try {
    const names = (await fsp.readdir(QDIR())).filter((n) => n.endsWith('.json'));
    const out = [];
    for (const n of names) { try { out.push(JSON.parse(await fsp.readFile(path.join(QDIR(), n), 'utf8'))); } catch {} }
    return out.sort((a, b) => b.date.localeCompare(a.date));
  } catch { return []; }
});

ipcMain.handle('quar:restore', async (_, id) => {
  try {
    const meta = JSON.parse(await fsp.readFile(path.join(QDIR(), id + '.json'), 'utf8'));
    let dest = meta.origin;
    if (fs.existsSync(dest)) dest = dest + '.restauré';
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await moveFile(path.join(QDIR(), id + '.quar'), dest);
    await fsp.unlink(path.join(QDIR(), id + '.json'));
    return { ok: true, dest };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('quar:delete', async (_, id) => {
  const r = await dialog.showMessageBox(win, { type: 'warning', buttons: ['Annuler', 'Supprimer'], defaultId: 0, cancelId: 0, title: 'Confirmer', message: 'Supprimer définitivement ce fichier en quarantaine ?' });
  if (r.response !== 1) return { cancelled: true };
  try { await fsp.unlink(path.join(QDIR(), id + '.quar')); await fsp.unlink(path.join(QDIR(), id + '.json')); return { ok: true }; }
  catch (e) { return { ok: false, error: e.message }; }
});

/* ---------- Ralentissements ---------- */
const tempDirs = () => [os.tmpdir(), path.join(process.env.SystemRoot || 'C:\\Windows', 'Temp')];

ipcMain.handle('perf:scan', async () => {
  const [procs, startup] = await Promise.all([
    psJson('Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Name,Id,@{n="mb";e={[int]($_.WorkingSet64/1MB)}},@{n="cpu";e={[int]$_.CPU}}'),
    psJson('Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location'),
  ]);
  let temp = 0;
  for (const d of tempDirs()) temp += await dirSize(d);
  return { procs, startup, temp, ramTotal: os.totalmem(), ramFree: os.freemem() };
});

ipcMain.handle('temp:clean', async () => {
  const before = await Promise.all(tempDirs().map(dirSize));
  const r = await dialog.showMessageBox(win, { type: 'question', buttons: ['Annuler', 'Nettoyer'], defaultId: 0, cancelId: 0, title: 'Fichiers temporaires', message: 'Supprimer les fichiers temporaires ?', detail: 'Les fichiers utilisés par un programme en cours sont ignorés.' });
  if (r.response !== 1) return { cancelled: true };
  for (const d of tempDirs()) {
    let items = []; try { items = await fsp.readdir(d); } catch {}
    for (const i of items) { try { await fsp.rm(path.join(d, i), { recursive: true, force: true }); } catch {} }
  }
  const after = await Promise.all(tempDirs().map(dirSize));
  const sum = (a) => a.reduce((x, y) => x + y, 0);
  return { freed: Math.max(0, sum(before) - sum(after)), temp: sum(after) };
});

/* ---------- Réglages ---------- */
ipcMain.handle('cfg:get', () => loadCfg());
ipcMain.handle('cfg:set', async (_, cfg) => {
  await fsp.mkdir(app.getPath('userData'), { recursive: true });
  await fsp.writeFile(CFG(), JSON.stringify({ ...loadCfg(), ...cfg }));
  return true;
});

ipcMain.handle('quar:deleteAll', async () => {
  const r = await dialog.showMessageBox(win, { type: 'warning', buttons: ['Annuler', 'Tout supprimer'], defaultId: 0, cancelId: 0, title: 'Confirmer', message: 'Supprimer définitivement tous les fichiers en quarantaine ?', detail: 'Cette action est irréversible.' });
  if (r.response !== 1) return { cancelled: true };
  let count = 0;
  try { for (const f of await fsp.readdir(QDIR())) { try { await fsp.unlink(path.join(QDIR(), f)); if (f.endsWith('.quar')) count++; } catch {} } } catch {}
  return { ok: true, count };
});
