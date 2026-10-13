const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (b) => b >= 1e9 ? (b / 1e9).toFixed(2) + ' Go' : b >= 1e6 ? (b / 1e6).toFixed(1) + ' Mo' : b >= 1e3 ? Math.round(b / 1e3) + ' Ko' : b + ' o';
const dur = (s) => s >= 3600 ? Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min' : s >= 60 ? Math.floor(s / 60) + ' min ' + (s % 60) + ' s' : s + ' s';
const pl = (n, a, b) => n + ' ' + (n > 1 ? b : a);
const btn = (act, p, label, cls = 'gray') => `<button class="btn sm ${cls}" data-act="${act}" data-p="${esc(p)}">${label}</button>`;
const bulk = (act, label, cls) => `<button class="btn ${cls}" data-act="${act}">${label}</button>`;
const LV = { 'élevé': 'red', moyen: 'orange', faible: 'gray' };
let R = { threats: [], dups: [], large: [], scanned: 0 };
let paused = false, qcount = 0;

const setBadge = (s, n) => { const e = $(s); e.textContent = n; e.hidden = !n; };
const badges = () => { setBadge('#b-scan', R.threats.length); setBadge('#b-dups', R.dups.length); setBadge('#b-quar', qcount); };

document.querySelectorAll('nav button').forEach((b) => b.onclick = () => {
  document.querySelectorAll('nav button, section').forEach((e) => e.classList.remove('on'));
  b.classList.add('on');
  $('#tab-' + b.dataset.tab).classList.add('on');
  if (b.dataset.tab === 'quar') loadQuar();
});

/* ---------- Analyse ---------- */
function setBusy(on) {
  document.querySelectorAll('[data-scan], #pick').forEach((b) => b.disabled = on);
  $('#ctrl').hidden = !on;
}
async function startScan(folder) {
  if (!folder) return;
  paused = false;
  $('#pauseBtn').textContent = 'Pause'; $('#pauseBtn').className = 'btn blue';
  setBusy(true);
  $('#progress').hidden = false;
  $('#bar').classList.add('indet'); $('#bar').classList.remove('paused');
  $('#pct').textContent = '…'; $('#t-eta').textContent = '…';
  $('#heroTitle').textContent = 'Analyse en cours';
  $('#heroSub').textContent = folder;
  $('#threats').innerHTML = '';
  R = await api.scanStart(folder);
  setBusy(false);
  $('#bar').classList.remove('indet', 'paused');
  $('#fill').style.width = '100%';
  $('#pct').textContent = R.cancelled ? 'Arrêtée' : '100 %';
  $('#phase').textContent = R.cancelled ? 'Analyse arrêtée' : 'Analyse terminée';
  $('#cur').textContent = '';
  $('#t-files').textContent = R.scanned.toLocaleString('fr-FR');
  $('#t-thr').textContent = R.threats.length;
  $('#t-dur').textContent = dur(R.duration);
  $('#t-eta').textContent = '–';
  $('#heroTitle').textContent = R.threats.length ? pl(R.threats.length, 'menace trouvée', 'menaces trouvées') : 'Aucune menace trouvée';
  renderThreats(); renderDups();
}
document.querySelectorAll('[data-scan]').forEach((b) => b.onclick = async () => startScan(await api.getPath(b.dataset.scan)));
$('#pick').onclick = async () => startScan(await api.pickFolder());
$('#stopBtn').onclick = () => api.scanCancel();
$('#pauseBtn').onclick = async () => {
  paused = await api.scanPause();
  $('#pauseBtn').textContent = paused ? 'Reprendre' : 'Pause';
  $('#pauseBtn').className = 'btn ' + (paused ? 'green' : 'blue');
  $('#bar').classList.toggle('paused', paused);
  if (paused) $('#phase').textContent = 'En pause';
};
api.onProgress((p) => {
  if (!paused) $('#phase').textContent = p.phase;
  $('#cur').textContent = p.current || '';
  $('#t-files').textContent = p.scanned.toLocaleString('fr-FR');
  $('#t-thr').textContent = p.threats;
  $('#t-dur').textContent = dur(p.elapsed);
  if (p.total) {
    const pct = Math.min(99, Math.round((p.done / p.total) * 100));
    $('#bar').classList.remove('indet');
    $('#fill').style.width = pct + '%';
    $('#pct').textContent = pct + ' %';
    $('#t-eta').textContent = p.eta != null ? dur(p.eta) : '…';
  }
});
api.onVT((u) => {
  const t = R.threats.find((x) => x.path === u.path);
  if (!t) return;
  if (u.unknown) t.vt = 'VirusTotal : fichier inconnu';
  else { t.vt = `VirusTotal : ${u.malicious}/${u.total} détections`; if (u.malicious >= 3) t.level = 'élevé'; else if (u.malicious === 0) t.level = 'faible'; }
  renderThreats();
});

function renderThreats() {
  badges();
  const el = $('#threats');
  if (!R.threats.length) { el.innerHTML = R.scanned ? '<div class="card empty">Aucune menace détectée. Le dossier est propre.</div>' : ''; return; }
  const n = (l) => R.threats.filter((t) => t.level === l).length;
  el.innerHTML = `<div class="card"><div class="head"><h3>Menaces détectées</h3>
    ${['élevé', 'moyen', 'faible'].filter(n).map((l) => `<span class="chip ${LV[l]}">${n(l)} ${l}</span>`).join('')}<span class="sp"></span>
    ${bulk('qall', 'Tout mettre en quarantaine', 'orange')}${bulk('dall', 'Tout supprimer', 'red')}${bulk('iall', 'Tout ignorer', 'gray')}</div>` +
    R.threats.map((t) => `<div class="row"><div class="lv ${LV[t.level]}"></div><div class="grow">
      <div><span class="chip ${LV[t.level]}">${t.level}</span> <b>${esc(t.reason)}</b>${t.vt ? ' · ' + esc(t.vt) : ''}</div>
      <div class="path">${esc(t.path)}</div>
      <div class="acts">${btn('ignore', t.path, 'Ignorer')}${btn('quar', t.path, 'Mettre en quarantaine', 'orange')}${btn('del', t.path, 'Supprimer', 'red')}${btn('show', t.path, 'Ouvrir le dossier', 'teal')}</div></div></div>`).join('') + '</div>';
}

/* ---------- Doublons ---------- */
function renderDups() {
  badges();
  const el = $('#dups');
  if (!R.dups.length) { el.innerHTML = '<div class="card empty">Aucun doublon pour le moment. Lance une analyse depuis l’onglet Analyse.</div>'; return; }
  const total = R.dups.reduce((a, g) => a + g.wasted, 0);
  el.innerHTML = `<div class="card"><div class="head"><h3>${pl(R.dups.length, 'groupe de doublons', 'groupes de doublons')}</h3><span class="mute">${fmt(total)} récupérables. Le fichier le plus ancien est conservé.</span><span class="sp"></span>${bulk('dupclean', 'Supprimer toutes les copies', 'red')}</div></div>` +
    R.dups.map((g, i) => `<div class="card"><div class="head"><b>${fmt(g.size)} × ${g.files.length}</b><span class="mute">${fmt(g.wasted)} récupérables</span><span class="sp"></span>${btn('dupall', i, 'Supprimer les copies', 'red')}</div>` +
      g.files.map((f, k) => `<div class="row"><div class="grow path">${esc(f.path)}</div><div class="acts" style="margin:0">${k === 0 ? '<span class="keep">Conservé</span>' : btn('quar', f.path, 'Quarantaine', 'orange') + btn('del', f.path, 'Supprimer', 'red')}${btn('show', f.path, 'Ouvrir', 'teal')}</div></div>`).join('') + '</div>').join('');
}

/* ---------- Ralentissements ---------- */
$('#perfBtn').onclick = async () => {
  $('#perfBtn').disabled = true; $('#perf').innerHTML = '<div class="card empty">Analyse en cours…</div>';
  const d = await api.perfScan();
  $('#perfBtn').disabled = false;
  renderPerf(d);
};
function renderPerf(d) {
  const used = d.ramTotal - d.ramFree, pct = Math.round((used / d.ramTotal) * 100);
  const tips = [];
  if (pct > 85) tips.push('La mémoire est presque pleine : ferme les programmes les plus gourmands ci-dessous.');
  if (d.startup.length > 8) tips.push(`${d.startup.length} programmes se lancent au démarrage : désactive ceux dont tu n’as pas besoin dans le Gestionnaire des tâches, onglet Démarrage.`);
  if (d.temp > 1e9) tips.push('Les fichiers temporaires dépassent 1 Go : un nettoyage libère de la place.');
  if (R.large.length) tips.push(`${R.large.length} fichiers de plus de 500 Mo trouvés lors de la dernière analyse.`);
  $('#perf').innerHTML =
    `<div class="card"><h3>${tips.length ? 'À faire' : 'Rien d’anormal détecté'}</h3>${tips.length ? '<ul>' + tips.map((t) => `<li>${esc(t)}</li>`).join('') + '</ul>' : ''}</div>` +
    `<div class="card"><b>Mémoire utilisée : ${pct} %</b> <span class="mute">(${fmt(used)} sur ${fmt(d.ramTotal)})</span><div class="meter"><i style="width:${pct}%;background:${pct > 85 ? 'var(--red)' : pct > 70 ? 'var(--orange)' : 'var(--green)'}"></i></div></div>` +
    `<div class="card"><h3>Programmes les plus gourmands en mémoire</h3><table><tr><th>Programme</th><th>Mémoire</th><th>Temps processeur cumulé</th></tr>` +
    d.procs.map((p) => `<tr><td>${esc(p.Name || p.name)}</td><td>${p.mb} Mo</td><td>${p.cpu} s</td></tr>`).join('') + '</table></div>' +
    `<div class="card"><h3>Programmes au démarrage (${d.startup.length})</h3><table>` +
    d.startup.map((s) => `<tr><td>${esc(s.Name)}</td><td class="path">${esc(s.Command || '')}</td></tr>`).join('') + '</table></div>' +
    `<div class="card"><div class="head"><h3>Fichiers temporaires</h3><b id="tmpSize">${fmt(d.temp)}</b><span class="sp"></span><button class="btn orange" data-act="tmp">Nettoyer</button></div></div>` +
    `<div class="card"><h3>Très gros fichiers</h3>` +
    (R.large.length ? R.large.map((f) => `<div class="row"><b>${fmt(f.size)}</b><div class="grow path">${esc(f.path)}</div><div class="acts" style="margin:0">${btn('show', f.path, 'Ouvrir', 'teal')}${btn('del', f.path, 'Supprimer', 'red')}</div></div>`).join('')
      : '<p class="mute">Aucun. Lance une analyse d’un dossier ou du disque pour les repérer.</p>') + '</div>';
}

/* ---------- Quarantaine ---------- */
async function loadQuar() {
  const list = await api.quarList();
  qcount = list.length; badges();
  $('#quar').innerHTML = list.length ? `<div class="card"><div class="head"><h3>${pl(list.length, 'fichier en quarantaine', 'fichiers en quarantaine')}</h3><span class="sp"></span>${bulk('qrestall', 'Tout restaurer', 'green')}${bulk('qdelall', 'Tout supprimer', 'red')}</div>` +
    list.map((q) => `<div class="row"><div class="grow"><b>${esc(q.name)}</b><div class="path">${esc(q.origin)}</div><div class="mute" style="font-size:12px">${esc(new Date(q.date).toLocaleString('fr-FR'))}</div></div>
      <div class="acts" style="margin:0">${btn('restore', q.id, 'Restaurer', 'green')}${btn('qdel', q.id, 'Supprimer', 'red')}</div></div>`).join('') + '</div>'
    : '<div class="card empty">La quarantaine est vide.</div>';
}

/* ---------- Actions ---------- */
function drop(paths) {
  R.threats = R.threats.filter((t) => !paths.includes(t.path));
  R.large = R.large.filter((t) => !paths.includes(t.path));
  R.dups = R.dups.map((g) => ({ ...g, files: g.files.filter((f) => !paths.includes(f.path)) })).filter((g) => g.files.length > 1);
  renderThreats(); renderDups();
}
document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-act]');
  if (!b || b.disabled) return;
  const p = b.dataset.p, act = b.dataset.act;
  if (act === 'ignore') drop([p]);
  else if (act === 'show') api.showItem(p);
  else if (act === 'quar') { const r = await api.quarantine(p); if (r.ok) { qcount++; drop([p]); } else alert('Échec : ' + r.error); }
  else if (act === 'del') { const r = await api.deleteFiles([p]); if (r.deleted.length) drop(r.deleted); else if (r.failed.length) alert('Suppression impossible (fichier utilisé ou accès refusé).'); }
  else if (act === 'iall') { R.threats = []; renderThreats(); }
  else if (act === 'qall') {
    b.disabled = true; const ok = [];
    for (const t of [...R.threats]) { const r = await api.quarantine(t.path); if (r.ok) ok.push(t.path); }
    qcount += ok.length; drop(ok);
    if (R.threats.length) alert(pl(R.threats.length, 'fichier n’a pas pu être déplacé', 'fichiers n’ont pas pu être déplacés') + '.');
  }
  else if (act === 'dall') { const r = await api.deleteFiles(R.threats.map((t) => t.path)); if (r.deleted.length) drop(r.deleted); if (r.failed.length) alert(r.failed.length + ' fichier(s) non supprimé(s).'); }
  else if (act === 'dupclean') { const r = await api.deleteFiles(R.dups.flatMap((g) => g.files.slice(1).map((f) => f.path))); if (r.deleted.length) drop(r.deleted); if (r.failed.length) alert(r.failed.length + ' fichier(s) non supprimé(s).'); }
  else if (act === 'dupall') { const g = R.dups[+p]; const r = await api.deleteFiles(g.files.slice(1).map((f) => f.path)); if (r.deleted.length) drop(r.deleted); if (r.failed.length) alert(r.failed.length + ' fichier(s) non supprimé(s).'); }
  else if (act === 'restore') { const r = await api.quarRestore(p); if (!r.ok) alert('Échec : ' + r.error); loadQuar(); }
  else if (act === 'qdel') { await api.quarDelete(p); loadQuar(); }
  else if (act === 'qrestall') { b.disabled = true; for (const q of await api.quarList()) await api.quarRestore(q.id); loadQuar(); }
  else if (act === 'qdelall') { await api.quarDeleteAll(); loadQuar(); }
  else if (act === 'tmp') { const r = await api.tempClean(); if (!r.cancelled) { $('#tmpSize').textContent = fmt(r.temp); alert(fmt(r.freed) + ' libérés.'); } }
});

/* ---------- Réglages ---------- */
api.cfgGet().then((c) => { if (c.vtKey) $('#vtKey').value = c.vtKey; });
api.quarList().then((l) => { qcount = l.length; badges(); });
$('#saveKey').onclick = async () => { await api.cfgSet({ vtKey: $('#vtKey').value.trim() }); $('#saved').textContent = 'Enregistrée'; };
