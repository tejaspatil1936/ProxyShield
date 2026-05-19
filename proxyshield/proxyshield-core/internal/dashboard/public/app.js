'use strict';

const MAX_EVENTS      = 100;
const STATS_INTERVAL  = 2000;
const RECONNECT_DELAY = 3000;
const SPARK_POINTS    = 60;   // 60 seconds of history

let events    = [];
let paused    = false;
let es        = null;
let rpsHistory = Array(SPARK_POINTS).fill(0);
let sparkPeak = 0;

// ── Helpers ──────────────────────────────────────────────────────────────────

const el = id => document.getElementById(id);

// When the dashboard is token-protected, the operator opens it as
// /dashboard?token=SECRET. Carry that token to the data endpoints (EventSource
// can't set headers, so it goes in the query string).
const AUTH_TOKEN = new URLSearchParams(location.search).get('token') || '';
function withToken(path) {
  if (!AUTH_TOKEN) return path;
  return path + (path.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(AUTH_TOKEN);
}

function formatTime(ts) {
  return new Date(ts || Date.now()).toLocaleTimeString('en-US', {
    hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function formatLatency(ms) {
  if (ms == null) return '';
  return ms < 1 ? ms.toFixed(2) + 'ms' : ms.toFixed(1) + 'ms';
}

function formatUptime(s) {
  if (s < 60)   return Math.floor(s) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (Math.floor(s) % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

// ── Connection status ─────────────────────────────────────────────────────────

function setStatus(connected) {
  const dot  = el('status-dot');
  const text = el('status-text');
  dot.className  = 'conn-dot ' + (connected ? 'connected' : 'disconnected');
  text.textContent = connected ? 'Live' : 'Reconnecting…';
}

// ── Threat tag rendering ──────────────────────────────────────────────────────

const tagClass = {
  SQL_INJECTION: 'ttag-sql',
  XSS:           'ttag-xss',
  BRUTE_FORCE:   'ttag-brute',
  HONEYPOT_TRAP: 'ttag-honeypot',
  HIGH_ENTROPY:  'ttag-entropy',
  BLACKLISTED_IP:'ttag-blacklist',
  BANNED_IP:     'ttag-banned',
  RATE_LIMITED:  'ttag-ratelimit',
};

function threatTag(tag) {
  if (!tag) return '';
  const cls = tagClass[tag] || 'ttag-ratelimit';
  const label = tag.replace(/_/g, ' ');
  return `<span class="ttag ${cls}">${label}</span>`;
}

function statusPill(name) {
  if (name === 'request:forwarded') return '<span class="pill pill-fwd">FORWARDED</span>';
  if (name === 'request:blocked')   return '<span class="pill pill-blocked">BLOCKED</span>';
  if (name === 'ip:banned')         return '<span class="pill pill-banned">IP BANNED</span>';
  if (name === 'config:reloaded')   return '<span class="pill pill-reload">CONFIG</span>';
  if (name === 'rate-limit:warning')return '<span class="pill pill-throttle">THROTTLED</span>';
  return '<span class="pill pill-received">RECEIVED</span>';
}

// ── Event feed ────────────────────────────────────────────────────────────────

function addEvent(evt) {
  if (paused) return;
  events.unshift(evt);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  el('feed-count').textContent = events.length + ' events';
  renderFeed();
}

function renderFeed() {
  const tbody = el('event-feed');
  tbody.innerHTML = events.map(evt => {
    const d = evt.data || {};
    return `<tr>
      <td class="cell-time">${formatTime(evt.timestamp)}</td>
      <td>${statusPill(evt.name)}</td>
      <td class="cell-ip">${d.ip || '—'}</td>
      <td class="cell-path">${d.path || '—'}</td>
      <td>${threatTag(d.threatTag || '')}</td>
      <td class="cell-lat">${d.latency_ms != null ? formatLatency(d.latency_ms) : ''}</td>
    </tr>`;
  }).join('');
}

function clearFeed() {
  events = [];
  el('feed-count').textContent = '0 events';
  renderFeed();
}

// ── Stats + threat bars ───────────────────────────────────────────────────────

const THREAT_KEYS = [
  'SQL_INJECTION','XSS','BRUTE_FORCE','HONEYPOT_TRAP','HIGH_ENTROPY','BLACKLISTED_IP','RATE_LIMITED'
];

function updateStats(s) {
  el('stat-rps').textContent       = s.requestsPerSecond.toFixed(1);
  el('stat-forwarded').textContent = s.totalForwarded.toLocaleString();
  el('stat-blocked').textContent   = s.totalBlocked.toLocaleString();
  el('stat-bans').textContent      = s.activeBans.toLocaleString();
  el('stat-uptime').textContent    = formatUptime(s.uptimeSeconds);

  const byType = s.blockedByType || {};
  const total  = THREAT_KEYS.reduce((acc, k) => acc + (byType[k] || 0), 0);
  const max    = Math.max(...THREAT_KEYS.map(k => byType[k] || 0), 1);

  el('total-threats-badge').textContent = total.toLocaleString() + ' total';

  THREAT_KEYS.forEach(k => {
    const numEl = el('threat-' + k);
    const barEl = el('bar-' + k);
    const count = byType[k] || 0;
    if (numEl) numEl.textContent = count.toLocaleString();
    if (barEl) barEl.style.width = ((count / max) * 100).toFixed(1) + '%';
  });

  // Sparkline history
  rpsHistory.push(s.requestsPerSecond);
  if (rpsHistory.length > SPARK_POINTS) rpsHistory.shift();
  drawSparkline(s.requestsPerSecond);
}

async function fetchStats() {
  try {
    const res = await fetch(withToken('/stats'));
    if (res.ok) updateStats(await res.json());
  } catch (_) {}
}

// ── Sparkline canvas ──────────────────────────────────────────────────────────

function drawSparkline(currentRPS) {
  const canvas = el('rps-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W   = canvas.offsetWidth  || 320;
  const H   = canvas.offsetHeight || 100;
  canvas.width  = W;
  canvas.height = H;

  const data = rpsHistory;
  const peak = Math.max(...data, 0.1);
  if (currentRPS > sparkPeak) sparkPeak = currentRPS;

  el('spark-peak').textContent = sparkPeak.toFixed(1);
  el('spark-avg').textContent  = (data.reduce((a,b) => a+b, 0) / data.length).toFixed(1);

  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = '#e8eaf0';
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 3; i++) {
    const y = Math.round((i / 3) * (H - 8)) + 4;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  if (data.length < 2) return;

  const pad  = 4;
  const step = (W - pad * 2) / (data.length - 1);

  // Gradient fill
  const grad = ctx.createLinearGradient(0, pad, 0, H - pad);
  grad.addColorStop(0, 'rgba(79,110,247,.18)');
  grad.addColorStop(1, 'rgba(79,110,247,0)');

  ctx.beginPath();
  data.forEach((v, i) => {
    const x = pad + i * step;
    const y = H - pad - ((v / peak) * (H - pad * 2));
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo(pad + (data.length - 1) * step, H - pad);
  ctx.lineTo(pad, H - pad);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = pad + i * step;
    const y = H - pad - ((v / peak) * (H - pad * 2));
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#4f6ef7';
  ctx.lineWidth   = 2;
  ctx.lineJoin    = 'round';
  ctx.stroke();

  // Dot at current value
  const lastX = pad + (data.length - 1) * step;
  const lastY = H - pad - ((data[data.length - 1] / peak) * (H - pad * 2));
  ctx.beginPath();
  ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
  ctx.fillStyle = '#4f6ef7';
  ctx.fill();
  ctx.strokeStyle = '#fff';
  ctx.lineWidth   = 2;
  ctx.stroke();
}

// ── SSE connection ────────────────────────────────────────────────────────────

function connect() {
  if (es) { try { es.close(); } catch(_) {} }
  es = new EventSource(withToken('/events'));
  es.onopen  = () => setStatus(true);
  es.onerror = () => { setStatus(false); es.close(); setTimeout(connect, RECONNECT_DELAY); };

  const names = [
    'request:received',
    'request:forwarded',
    'request:blocked',
    'ip:banned',
    'config:reloaded',
    'rate-limit:warning',
  ];

  names.forEach(name => {
    es.addEventListener(name, e => {
      let data = {};
      try { data = JSON.parse(e.data); } catch(_) {}
      addEvent({ name, data, timestamp: new Date().toISOString() });
    });
  });
}

// ── Pause toggle ──────────────────────────────────────────────────────────────

el('pause-chk').addEventListener('change', e => { paused = e.target.checked; });

// ── Init ──────────────────────────────────────────────────────────────────────

connect();
fetchStats();
setInterval(fetchStats, STATS_INTERVAL);
window.addEventListener('resize', () => drawSparkline(rpsHistory[rpsHistory.length - 1] || 0));
