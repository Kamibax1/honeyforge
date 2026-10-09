/* HoneyForge dashboard — логика UI (FR-C1..C5, FR-C7, лента realtime).
 * Все запросы идут через nginx-фронт под маскированным путём /assets/ (MASK-2),
 * поэтому на стенде http://localhost:8080 достаточно открыть index.html. */
'use strict';

const API = '/assets';                 // reverse-proxy -> Control API
const WS_PATH = '/static/rt';          // WebSocket-лента realtime-слоя
const TOKEN_KEY = 'hf_token';
const FEED_KEY = 'hf_feed_key';

let token = localStorage.getItem(TOKEN_KEY) || '';
let profilesCache = [];
let honeypotsCache = [];
let currentProfId = null;
let ws = null;
let evSeenIds = new Set();

/* ---------------- helpers ---------------- */
const $ = (id) => document.getElementById(id);

function toast(msg, ok = true) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (ok ? '' : ' bad');
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.className = 'toast'), 3500);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtTs(v) {
  if (!v) return '—';
  let d = typeof v === 'number' ? new Date(v * 1000) : new Date(String(v));
  if (isNaN(d)) return String(v);
  return d.toLocaleString('ru-RU', { hour12: false });
}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.json);
  }
  const r = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (r.status === 401 && token) {
    logout();
    throw new Error('Сессия истекла — войдите заново');
  }
  if (!r.ok) {
    let detail = '';
    try {
      const j = await r.json();
      detail = Array.isArray(j.detail)
        ? j.detail.map((d) => (d.msg || d.loc || []).join(': ')).join('; ')
        : String(j.detail || j.message || ('HTTP ' + r.status));
    } catch (_) { detail = await r.text().catch(() => '') || ('HTTP ' + r.status); }
    throw new Error(detail || ('HTTP ' + r.status));
  }
  if (r.status === 204) return null;
  const ct = r.headers.get('content-type') || '';
  return ct.includes('json') ? r.json() : r.text();
}

function jval(el, fallback) {
  try {
    const v = JSON.parse(el.value || 'null');
    return v === null || v === undefined || el.value.trim() === '' ? fallback : v;
  } catch (_) { return undefined; } // сигнал об ошибке парсинга
}

/* ---------------- auth (FR-C5) ---------------- */
async function doLogin(ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
  const errEl = $('lgErr');
  errEl.textContent = '';
  const u = $('lgUser').value.trim(), p = $('lgPass').value;
  if (!u || !p) { errEl.textContent = 'Введите логин и пароль'; return; }
  try {
    const body = new URLSearchParams({ username: u, password: p, grant_type: 'password' });
    const r = await fetch(API + '/auth/login', { method: 'POST', body });
    if (!r.ok) {
      let m = 'Неверный логин или пароль';
      try {
        const j = await r.json();
        if (typeof j.detail === 'string') m = j.detail;
      } catch (_) {}
      throw new Error(m);
    }
    const j = await r.json();
    token = j.access_token;
    localStorage.setItem(TOKEN_KEY, token);
    $('whoami').textContent = `${j.login} (${j.role})`;
    enterApp();
    toast('Вход выполнен');
  } catch (e) {
    errEl.textContent = e.message || 'Ошибка входа';
  }
  return false;
}

function logout() {
  token = '';
  localStorage.removeItem(TOKEN_KEY);
  if (ws) { try { ws.close(); } catch (_) {} ws = null; }
  setWsDot(false);
  $('shell').classList.add('hidden');
  $('loginView').classList.remove('hidden');
  $('whoami').textContent = '';
  closeNav();
}

function setWsDot(on) {
  $('wsdot').className = 'dot ' + (on ? 'on' : 'off');
  const lb = $('wsLabel');
  if (lb) lb.textContent = on ? 'realtime: online' : 'realtime: офлайн';
}

/* ---------------- mobile nav ---------------- */
function openNav() {
  $('sidebar').classList.add('open');
  $('navScrim').classList.add('show');
}
function closeNav() {
  $('sidebar').classList.remove('open');
  $('navScrim').classList.remove('show');
}

/* ---------------- app bootstrap ---------------- */
async function enterApp() {
  $('loginView').classList.add('hidden');
  $('shell').classList.remove('hidden');
  connectWS();
  try {
    await Promise.all([loadProfiles(), loadHoneypots()]);
    await Promise.all([refreshEvents(), loadAlerts(), loadTokens(), loadStats()]);
    try { $('auRows').innerHTML = (await renderAuditRows()) || ''; } catch (_) {}
  } catch (e) {
    toast(e.message, false);
    if (String(e.message).includes('401') || String(e.message).includes('истекла')) logout();
  }
}

/* ---------------- fleet (FR-C2) ---------------- */
const ST_LABEL = { online: 'онлайн', offline: 'офлайн', pending: 'ожидает' };

async function loadHoneypots() {
  honeypotsCache = await api('/honeypots');
  const rows = honeypotsCache.map((h) => `
    <tr>
      <td class="hp-name">${esc(h.name)}</td>
      <td class="mono">${esc(h.host_addr || '—')}</td>
      <td>${esc(h.profile_name || 'не задан')}</td>
      <td><span class="lvl ${esc(h.level || '')}">${esc(h.level || '—')}</span></td>
      <td><span class="st ${esc(h.status)}"><i></i>${esc(ST_LABEL[h.status] || h.status)}</span></td>
      <td class="mono">${fmtTs(h.last_seen)}</td>
      <td class="actions">
        <button class="btn icon ok" data-cmd="start" data-id="${h.id}" title="Запустить ловушку">▶</button>
        <button class="btn icon stop" data-cmd="stop" data-id="${h.id}" title="Остановить ловушку">■</button>
        <button class="btn icon dl" data-cmd="bundle" data-id="${h.id}" data-name="${esc(h.name)}" title="Скачать deploy-bundle (docker)">📦</button>
      </td>
    </tr>`).join('');
  $('hpRows').innerHTML = rows || '<tr><td colspan="7" class="hint empty">нет ловушек — зарегистрируйте новую ниже 👇</td></tr>';
  const sel = $('fTrap');
  const cur = sel.value;
  sel.innerHTML = '<option value="">все ловушки</option>' +
    honeypotsCache.map((h) => `<option value="${h.id}">${esc(h.name)}</option>`).join('');
  sel.value = cur;
}

async function addHoneypot() {
  const name = $('hpName').value.trim();
  if (!name) { toast('Укажите имя ловушки', false); return; }
  const pid = $('hpProfile').value ? parseInt($('hpProfile').value, 10) : null;
  try {
    const res = await api('/honeypots', { method: 'POST', json: { name, profile_id: pid } });
    $('hpName').value = '';
    await loadHoneypots();
    await loadStats();
    const secret = res.agent_secret || '(скрыт)';
    showBundleHint(res.uuid, secret);
  } catch (e) { toast(e.message, false); }
}

function showBundleHint(uuid, secret) {
  const w = window.open('', '_blank');
  if (!w) { toast('Ловушка зарегистрирована. Секреты: uuid=' + uuid, false); return; }
  w.document.write(`<pre style="font:13px/1.5 monospace;padding:20px">
Ловушка зарегистрирована (секреты показаны один раз — сохраните их):

HF_NODE_UUID=${uuid}
HF_NODE_SECRET=${secret}

Далее: вкладка «Парк ловушек» → кнопка 📦 deploy сгенерирует
docker-compose-бандл для хоста ловушки.</pre>`);
}

async function hpCommand(id, cmd) {
  try {
    if (cmd === 'bundle') { downloadBundle(id); return; }
    await api('/honeypots/' + id, { method: 'PATCH', json: { desired_state: cmd } });
    toast('Команда «' + cmd + '» поставлена в очередь агенту');
    await loadHoneypots();
  } catch (e) { toast(e.message, false); }
}

async function downloadBundle(id) {
  try {
    const files = await api('/honeypots/' + id + '/deploy-bundle');
    const w = window.open('', '_blank');
    const parts = Object.entries(files).map(([fn, content]) =>
      `<h3>${esc(fn)}</h3><pre>${esc(typeof content === 'string' ? content : JSON.stringify(content, null, 2))}</pre>`);
    if (w) {
      w.document.write('<body style="font:13px monospace">' +
        '<p>Сохраните файлы рядом (deploy-bundle, FR-C6):</p>' + parts.join('') + '</body>');
    } else {
      const blob = new Blob([JSON.stringify(files, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'deploy-bundle.json'; a.click();
    }
  } catch (e) { toast(e.message, false); }
}

/* ---------------- profiles (FR-C1) ---------------- */
async function loadProfiles() {
  profilesCache = await api('/profiles');
  const pc = $('profCount');
  if (pc) pc.textContent = profilesCache.length;
  $('profList').innerHTML = profilesCache.map((p) =>
    `<li data-pid="${p.id}" class="${p.id === currentProfId ? 'sel' : ''}">
       <div class="prof-row"><b>${esc(p.name)}</b><span class="lvl ${esc(p.level)}">${esc(p.level)}</span></div>
       <div class="hint">${esc(p.description || '')} · v${p.version}</div></li>`).join('') ||
    '<li class="hint empty">профилей нет — создайте первый</li>';
  const sel = $('hpProfile');
  const cur = sel.value;
  sel.innerHTML = '<option value="">без профиля</option>' +
    profilesCache.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  sel.value = cur;
}

function fillProfileEditor(p) {
  currentProfId = p.id;
  $('pfName').value = p.name;
  $('pfDesc').value = p.description || '';
  $('pfLevel').value = p.level;
  $('pfServices').value = JSON.stringify(p.services || [], null, 1);
  $('pfCreds').value = JSON.stringify(p.credentials || [], null, 1);
  $('pfTokens').value = JSON.stringify(p.honeytokens || [], null, 1);
  const m = p.masking || {};
  $('pfCover').value = m.cover_path || '';
  $('pfInterval').value = m.beacon_interval_sec ?? 45;
  $('pfJitter').value = m.beacon_jitter_pct ?? 35;
  $('pfProc').value = m.process_name || '';
  document.querySelectorAll('#profList li').forEach((li) =>
    li.classList.toggle('sel', parseInt(li.dataset.pid, 10) === p.id));
}

function blankProfile() {
  currentProfId = null;
  $('pfName').value = ''; $('pfDesc').value = ''; $('pfLevel').value = 'medium';
  $('pfServices').value = '[{"proto":"tcp","port":22,"kind":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1"}]';
  $('pfCreds').value = '[{"username":"admin","password":"P@ssw0rd123","note":"bait"}]';
  $('pfTokens').value = '[{"kind":"ssh_key","label":"deploy-backup"}]';
  $('pfCover').value = '/static/js/analytics.js';
  $('pfInterval').value = 45; $('pfJitter').value = 35;
  $('pfProc').value = 'kworker/0:2-events_unbound';
  $('pfMsg').textContent = '';
}

function collectProfile() {
  const services = jval($('pfServices'), []);
  const creds = jval($('pfCreds'), []);
  const tokens = jval($('pfTokens'), []);
  if (services === undefined || creds === undefined || tokens === undefined) {
    throw new Error('Некорректный JSON в полях services/creds/honeytokens');
  }
  return {
    name: $('pfName').value.trim(),
    description: $('pfDesc').value.trim(),
    level: $('pfLevel').value,
    services, credentials: creds, honeytokens: tokens,
    masking: {
      cover_path: $('pfCover').value.trim() || '/static/js/analytics.js',
      beacon_interval_sec: parseInt($('pfInterval').value, 10) || 45,
      beacon_jitter_pct: parseInt($('pfJitter').value, 10) || 35,
      process_name: $('pfProc').value.trim() || 'kworker/0:2-events_unbound',
    },
  };
}

async function saveProfile() {
  try {
    const body = collectProfile();
    if (currentProfId) {
      await api('/profiles/' + currentProfId, { method: 'PUT', json: body });
      $('pfMsg').textContent = 'Профиль обновлён';
    } else {
      const p = await api('/profiles', { method: 'POST', json: body });
      currentProfId = p.id;
      $('pfMsg').textContent = 'Профиль создан (id=' + p.id + ')';
    }
    toast('Профиль сохранён');
    await loadProfiles();
  } catch (e) { $('pfMsg').textContent = ''; toast(e.message, false); }
}

async function deleteProfile() {
  if (!currentProfId) { toast('Сначала выберите профиль', false); return; }
  if (!confirm('Удалить профиль?')) return;
  try {
    await api('/profiles/' + currentProfId, { method: 'DELETE' });
    blankProfile();
    await loadProfiles();
    toast('Профиль удалён');
  } catch (e) { toast(e.message, false); }
}

/* ---------------- events feed (FR-C4) ---------------- */
async function refreshEvents() {
  const q = new URLSearchParams({ limit: '200' });
  if ($('fTrap').value) q.set('honeypot_id', $('fTrap').value);
  if ($('fType').value) q.set('etype', $('fType').value);
  if ($('fSrc').value.trim()) q.set('src_ip', $('fSrc').value.trim());
  const rows = await api('/events?' + q.toString());
  evSeenIds.clear();
  $('evRows').innerHTML = rows.map(eventRow).join('') ||
    '<tr><td colspan="7" class="hint empty">событий пока нет — атакуйте ловушку (nmap / ssh / http)</td></tr>';
}

const ET_LABEL = {
  connect: 'connect', auth: 'auth', command: 'command', request: 'request',
  scan: 'scan', honeytoken: 'honeytoken', session: 'session', file: 'file',
};

function eventRow(e) {
  const payload = e.payload || {};
  const creds = payload.username ? `${payload.username}/${payload.password || ''}` : '';
  let pl = payload.command || payload.request || payload.banner_request || payload.note || '';
  if (!pl && payload.bytes !== undefined) pl = `${payload.bytes} bytes`;
  return `<tr data-evid="${esc(e.id ?? '')}" class="evrow">
    <td class="mono">${fmtTs(e.ts_received)}</td>
    <td>${esc(e.honeypot_name || e.honeypot_id || '')}</td>
    <td><span class="tag ${esc(e.etype)}">${esc(ET_LABEL[e.etype] || e.etype)}</span></td>
    <td class="mono">${esc(e.src_ip)}</td>
    <td class="mono">${esc(e.dst_port ?? '')}</td>
    <td class="mono">${esc(creds)}</td>
    <td class="mono ell" title="${esc(pl)}">${esc(pl)}</td></tr>`;
}

/* ---------------- alerts / honeytokens (FR-C7, FR-A6) ---------------- */
async function loadAlerts() {
  const rows = await api('/alerts');
  $('alRows').innerHTML = rows.map((a) => `<tr>
    <td class="mono">${fmtTs(a.created_at)}</td>
    <td>${esc(a.rule)}</td>
    <td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td>
    <td class="mono">${esc(a.src_ip || '')}</td>
    <td>${esc(a.detail || '')}</td></tr>`).join('') ||
    '<tr><td colspan="5" class="hint">алертов нет</td></tr>';
}

async function loadTokens() {
  const rows = await api('/honeytokens');
  $('htRows').innerHTML = rows.map((t) => `<tr>
    <td>${esc(t.label)}</td><td>${esc(t.kind)}</td>
    <td>${t.triggered ? '🔥 ДА' : 'нет'}</td>
    <td class="mono">${fmtTs(t.triggered_at)}</td>
    <td class="mono">${esc(t.triggered_by_ip || '')}</td></tr>`).join('') ||
    '<tr><td colspan="5" class="hint">honeytokens не заведены</td></tr>';
}

/* ---------------- stats & audit ---------------- */
async function loadStats() {
  try {
    const s = await api('/stats');
    $('stTotal').textContent = s.honeypots_total;
    $('stOnline').textContent = s.honeypots_online;
    $('stEvents').textContent = s.events_last_24h;
    $('stAlerts').textContent = s.alerts_open;
  } catch (_) {}
}

async function renderAuditRows() {
  try {
    const rows = await api('/audit?limit=100');
    return rows.map((a) => `<tr>
      <td class="mono">${fmtTs(a.ts)}</td><td>${esc(a.actor)}</td>
      <td>${esc(a.action)}</td><td>${esc(a.object || '')}</td>
      <td class="mono ell">${esc(JSON.stringify(a.meta || {}))}</td></tr>`).join('');
  } catch (_) {
    return '<tr><td colspan="5" class="hint">аудит доступен роли admin</td></tr>';
  }
}

async function exportIocs(fmt) {
  try {
    const r = await fetch(`${API}/export/iocs?fmt=${fmt}&days=7`, {
      headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'ioc.' + fmt;
    a.click();
    toast('Экспорт IoC (' + fmt + ') скачан');
  } catch (e) { toast('Экспорт: ' + e.message, false); }
}

/* ---------------- realtime WebSocket ---------------- */
let wsRetry = 4000;

function askFeedKey() {
  const k = window.prompt('Ключ доступа к realtime-ленте (RT_FEED_KEY):',
                          localStorage.getItem(FEED_KEY) || '');
  if (k) localStorage.setItem(FEED_KEY, k);
  return k || '';
}

function connectWS() {
  if (ws) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  let key = localStorage.getItem(FEED_KEY) || '';
  if (!key) key = askFeedKey();
  const url = `${proto}://${location.host}${WS_PATH}?k=${encodeURIComponent(key)}`;
  try { ws = new WebSocket(url); } catch (_) { return; }
  ws.onopen = () => { setWsDot(true); wsRetry = 4000; };
  ws.onclose = (e) => {
    setWsDot(false);
    ws = null;
    // 1008 policy violation — неверный ключ ленты: спросим заново
    if (e.code === 1008) {
      localStorage.removeItem(FEED_KEY);
      if (askFeedKey()) connectWS();
      return;
    }
    setTimeout(connectWS, wsRetry);
    wsRetry = Math.min(wsRetry * 2, 30000);
  };
  ws.onerror = () => { if (ws) ws.close(); };
  ws.onmessage = (m) => {
    let d; try { d = JSON.parse(m.data); } catch (_) { return; }
    if (d.type === 'hello') return;
    if (d.type === 'event') {
      if (d.id && evSeenIds.has(d.id)) return;
      if (d.id) evSeenIds.add(d.id);
      const tr = document.createElement('tr');
      tr.className = 'evrow new';
      tr.innerHTML = `<td class="mono">${fmtTs(d.ts)}</td>
        <td>${esc(d.trap || '')}</td>
        <td><span class="tag ${esc(d.etype || d.type)}">${esc(d.etype || '?')}</span></td>
        <td class="mono">${esc(d.src_ip || '')}</td>
        <td class="mono">${esc(d.dst_port ?? '')}</td>
        <td class="mono">${d.payload && d.payload.username ? esc(d.payload.username + '/' + (d.payload.password || '')) : ''}</td>
        <td class="mono ell">${esc((d.payload && (d.payload.command || d.payload.request)) || '')}</td>`;
      const tb = $('evRows');
      if (tb.querySelector('.hint')) tb.innerHTML = '';
      tb.prepend(tr);
      while (tb.children.length > 300) tb.removeChild(tb.lastChild);
      bumpCounter('stEvents');
    } else if (d.type === 'honeytoken_trigger') {
      toast('🔥 Honeytoken сработал: ' + (d.labels || []).join(', '), false);
      loadTokens(); loadAlerts();
    } else if (d.type === 'alert') {
      toast('⚠ Алерт: ' + (d.rule || ''), false);
      loadAlerts(); loadStats();
    } else if (d.type === 'status') {
      loadHoneypots();
    } else if (d.type === 'config') {
      loadProfiles();
    }
  };
}

function bumpCounter(id) {
  const el = $(id);
  el.textContent = (parseInt(el.textContent, 10) || 0) + 1;
}

/* ---------------- tabs ---------------- */
const TAB_TITLES = {
  fleet: 'Парк ловушек',
  profiles: 'Конструктор профилей',
  feed: 'Лента событий',
  alerts: 'Алерты / Honeytokens',
  audit: 'Аудит / Экспорт IoC',
};

function switchTab(name) {
  document.querySelectorAll('.side-nav button').forEach((b) =>
    b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab').forEach((s) =>
    s.classList.toggle('hidden', s.id !== 'tab-' + name));
  const pt = $('pageTitle');
  if (pt) pt.textContent = TAB_TITLES[name] || 'HoneyForge';
  closeNav();
  if (name === 'feed') refreshEvents().catch((e) => toast(e.message, false));
  if (name === 'alerts') { loadAlerts(); loadTokens(); }
  if (name === 'audit') renderAuditRows().then((h) => { $('auRows').innerHTML = h; });
  if (name === 'fleet') { loadHoneypots(); loadStats(); }
}

/* ---------------- wiring ---------------- */
document.addEventListener('DOMContentLoaded', () => {
  // вход и по клику, и по Enter: клик по submit-кнопке в браузере порождает
  // submit на форме, поэтому handler ставится один раз и идемпотентно
  let loginBound = false;
  const bindLogin = (e) => {
    if (!loginBound) { loginBound = true; $('loginForm').addEventListener('submit', doLogin); }
    doLogin(e);
  };
  $('btnLogin').addEventListener('click', bindLogin);
  $('btnLogout').addEventListener('click', logout);

  document.querySelectorAll('.side-nav button').forEach((b) =>
    b.addEventListener('click', () => switchTab(b.dataset.tab)));

  // мобильное меню
  const burger = $('burger');
  if (burger) burger.addEventListener('click', () =>
    $('sidebar').classList.contains('open') ? closeNav() : openNav());
  const scrim = $('navScrim');
  if (scrim) scrim.addEventListener('click', closeNav);

  const btnRefreshAll = $('btnRefreshAll');
  if (btnRefreshAll) btnRefreshAll.addEventListener('click', () => {
    Promise.all([loadProfiles(), loadHoneypots(), loadStats()])
      .then(() => { refreshEvents(); loadAlerts(); loadTokens(); })
      .catch((e) => toast(e.message, false));
    toast('Данные обновлены');
  });

  $('btnAddHp').addEventListener('click', addHoneypot);
  $('hpRows').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-cmd]');
    if (btn) hpCommand(parseInt(btn.dataset.id, 10), btn.dataset.cmd);
  });

  $('profList').addEventListener('click', (e) => {
    const li = e.target.closest('li[data-pid]');
    if (!li) return;
    const p = profilesCache.find((x) => x.id === parseInt(li.dataset.pid, 10));
    if (p) fillProfileEditor(p);
  });
  $('btnNewProf').addEventListener('click', blankProfile);
  $('btnSaveProf').addEventListener('click', saveProfile);
  $('btnDelProf').addEventListener('click', deleteProfile);

  $('btnRefreshEv').addEventListener('click', () => refreshEvents().catch((e) => toast(e.message, false)));
  ['fTrap', 'fType'].forEach((id) => $(id).addEventListener('change', () => refreshEvents().catch(() => {})));
  $('fSrc').addEventListener('keydown', (e) => { if (e.key === 'Enter') refreshEvents().catch(() => {}); });

  $('btnExpCsv').addEventListener('click', () => exportIocs('csv'));
  $('btnExpStix').addEventListener('click', () => exportIocs('stix'));

  blankProfile();

  if (token) {
    // проверяем токен через /auth/me; при ошибке остаёмся на экране входа
    api('/auth/me').then((me) => {
      $('whoami').textContent = `${me.login} (${me.role})`;
      enterApp();
    }).catch(() => logout());
  }
});
