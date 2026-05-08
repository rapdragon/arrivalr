import os
import json
import time
import logging
import secrets
import threading
import urllib.request
import urllib.parse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

STATE_FILE = Path(os.environ.get('STATE_FILE', '/data/seen.json'))
HISTORY_FILE = Path('/data/history.json')
SETTINGS_FILE = Path('/data/settings.json')
WEB_PORT = int(os.environ.get('WEB_PORT', 7070))
SESSION_TTL = 86400  # 24 hours

ENV_DEFAULTS = {
    'radarr_url':             os.environ.get('RADARR_URL', '').rstrip('/'),
    'radarr_api_key':         os.environ.get('RADARR_API_KEY', ''),
    'sonarr_url':             os.environ.get('SONARR_URL', '').rstrip('/'),
    'sonarr_api_key':         os.environ.get('SONARR_API_KEY', ''),
    'pushover_token':         os.environ.get('PUSHOVER_TOKEN', ''),
    'pushover_user':          os.environ.get('PUSHOVER_USER', ''),
    'poll_interval':          int(os.environ.get('POLL_INTERVAL', 300)),
    'history_retention_days': int(os.environ.get('HISTORY_RETENTION_DAYS', 30)),
    'admin_password':         os.environ.get('ADMIN_PASSWORD', ''),
    'viewer_password':        os.environ.get('VIEWER_PASSWORD', ''),
}

_sessions = {}
_sessions_lock = threading.Lock()


def get_settings():
    if SETTINGS_FILE.exists():
        saved = json.loads(SETTINGS_FILE.read_text())
        merged = {**ENV_DEFAULTS, **{k: v for k, v in saved.items() if v not in (None, '')}}
        merged['poll_interval'] = int(merged['poll_interval'])
        merged['history_retention_days'] = int(merged['history_retention_days'])
        return merged
    return dict(ENV_DEFAULTS)


def save_settings(data):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    allowed = set(ENV_DEFAULTS.keys())
    clean = {k: v for k, v in data.items() if k in allowed}
    SETTINGS_FILE.write_text(json.dumps(clean, indent=2))


def create_session(role):
    token = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[token] = {'role': role, 'expires': time.time() + SESSION_TTL}
    return token


def get_session_role(cookie_header):
    if not cookie_header:
        return None
    for part in cookie_header.split(';'):
        name, _, val = part.strip().partition('=')
        if name.strip() == 'arrivalr_session':
            with _sessions_lock:
                s = _sessions.get(val.strip())
                if s and s['expires'] > time.time():
                    return s['role']
    return None


def invalidate_session(cookie_header):
    if not cookie_header:
        return
    for part in cookie_header.split(';'):
        name, _, val = part.strip().partition('=')
        if name.strip() == 'arrivalr_session':
            with _sessions_lock:
                _sessions.pop(val.strip(), None)


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Arrivalr — Sign In</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f0f0f; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 40px; width: 100%; max-width: 360px; display: flex; flex-direction: column; gap: 28px; }
  .logo { text-align: center; }
  .logo h1 { font-size: 1.7rem; font-weight: 700; color: #fff; display: flex; align-items: center; justify-content: center; gap: 10px; }
  .badge { background: #e50914; color: #fff; font-size: 0.68rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.5px; }
  .logo p { color: #555; font-size: 0.82rem; margin-top: 8px; }
  .form { display: flex; flex-direction: column; gap: 16px; }
  .field { display: flex; flex-direction: column; gap: 6px; }
  .field label { font-size: 0.82rem; color: #aaa; }
  .field input { background: #252525; border: 1px solid #333; color: #e0e0e0; padding: 11px 14px; border-radius: 6px; font-size: 0.9rem; width: 100%; transition: border-color 0.15s; }
  .field input:focus { outline: none; border-color: #555; }
  .btn { background: #e50914; border: none; color: #fff; padding: 12px; border-radius: 6px; cursor: pointer; font-size: 0.9rem; font-weight: 600; transition: background 0.15s; width: 100%; }
  .btn:hover { background: #c40812; }
  .error { background: #2e1a1a; border: 1px solid #5a2020; color: #e74c3c; padding: 11px 14px; border-radius: 6px; font-size: 0.82rem; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>Arrivalr <span class="badge">LIVE</span></h1>
    <p>Media Monitor</p>
  </div>
  __ERROR__
  <form method="post" action="/login" class="form">
    <div class="field">
      <label>Username</label>
      <input type="text" name="username" placeholder="admin or viewer" autofocus autocomplete="username">
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password">
    </div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div>
</body>
</html>"""


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Arrivalr</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f0f0f; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; }
  header { background: #1a1a2e; border-bottom: 1px solid #2a2a4a; padding: 20px 32px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.4rem; font-weight: 600; color: #fff; }
  header .subtitle { font-size: 0.85rem; color: #888; margin-top: 2px; }
  .badge { background: #e50914; color: #fff; font-size: 0.7rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.5px; }
  .header-actions { display: flex; align-items: center; gap: 10px; }
  .role-pill { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.5px; padding: 4px 10px; border-radius: 10px; text-transform: uppercase; }
  .role-pill.admin { background: #1a1a3e; color: #7b8cde; }
  .role-pill.viewer { background: #1a2e1a; color: #7bde8c; }
  .gear-btn { background: none; border: 1px solid #333; color: #888; width: 36px; height: 36px; border-radius: 8px; cursor: pointer; font-size: 1.1rem; display: flex; align-items: center; justify-content: center; transition: all 0.15s; }
  .gear-btn:hover { border-color: #666; color: #fff; }
  .logout-btn { color: #555; font-size: 0.82rem; text-decoration: none; padding: 7px 12px; border: 1px solid #2a2a2a; border-radius: 6px; transition: all 0.15s; white-space: nowrap; }
  .logout-btn:hover { color: #ddd; border-color: #555; }
  .controls { padding: 20px 32px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .filter-btn { background: #1e1e1e; border: 1px solid #333; color: #aaa; padding: 7px 16px; border-radius: 20px; cursor: pointer; font-size: 0.85rem; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { background: #e50914; border-color: #e50914; color: #fff; }
  .count { margin-left: auto; font-size: 0.85rem; color: #666; }
  .grid { padding: 0 32px 32px; display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
  .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 10px; padding: 18px; display: flex; flex-direction: column; gap: 10px; transition: border-color 0.15s; }
  .card:hover { border-color: #444; }
  .card-header { display: flex; align-items: flex-start; gap: 12px; }
  .type-icon { width: 38px; height: 38px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; flex-shrink: 0; }
  .type-icon.movie { background: #1a1a3e; }
  .type-icon.series { background: #1a2e1a; }
  .type-icon.episode { background: #2e1a2e; }
  .card-title { font-size: 1rem; font-weight: 600; color: #fff; line-height: 1.3; }
  .card-year { font-size: 0.8rem; color: #888; margin-top: 2px; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .tag { background: #252525; color: #aaa; font-size: 0.75rem; padding: 3px 9px; border-radius: 4px; }
  .tag.folder { background: #1a1a2e; color: #7b8cde; }
  .tag.network { background: #1a2e1a; color: #7bde8c; }
  .card-footer { display: flex; align-items: center; justify-content: space-between; padding-top: 6px; border-top: 1px solid #252525; }
  .added-at { font-size: 0.78rem; color: #666; }
  .type-label { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; padding: 2px 8px; border-radius: 3px; }
  .type-label.movie { background: #1a1a3e; color: #7b8cde; }
  .type-label.series { background: #1a2e1a; color: #7bde8c; }
  .type-label.episode { background: #2e1a2e; color: #de7bde; }
  .ep-code { font-size: 0.8rem; color: #de7bde; font-weight: 600; margin-top: 2px; }
  .empty { grid-column: 1/-1; text-align: center; padding: 80px 20px; color: #444; }
  #refresh-indicator { width: 8px; height: 8px; background: #2ecc71; border-radius: 50%; animation: pulse 2s infinite; margin-left: 8px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
  /* Settings panel */
  .overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; }
  .overlay.open { display: flex; align-items: flex-start; justify-content: flex-end; }
  .settings-panel { background: #141414; width: 420px; max-width: 100vw; height: 100vh; overflow-y: auto; border-left: 1px solid #2a2a2a; display: flex; flex-direction: column; }
  .settings-header { padding: 20px 24px; border-bottom: 1px solid #222; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; background: #141414; z-index: 1; }
  .settings-header h2 { font-size: 1rem; font-weight: 600; }
  .close-btn { background: none; border: none; color: #888; font-size: 1.3rem; cursor: pointer; line-height: 1; }
  .close-btn:hover { color: #fff; }
  .settings-body { padding: 24px; flex: 1; display: flex; flex-direction: column; gap: 24px; }
  .settings-section { display: flex; flex-direction: column; gap: 14px; }
  .settings-section h3 { font-size: 0.75rem; font-weight: 600; letter-spacing: 0.8px; text-transform: uppercase; color: #666; padding-bottom: 8px; border-bottom: 1px solid #222; }
  .field { display: flex; flex-direction: column; gap: 6px; }
  .field label { font-size: 0.82rem; color: #aaa; }
  .field-input { display: flex; gap: 6px; }
  .field input { background: #1e1e1e; border: 1px solid #333; color: #e0e0e0; padding: 9px 12px; border-radius: 6px; font-size: 0.88rem; width: 100%; transition: border-color 0.15s; }
  .field input:focus { outline: none; border-color: #555; }
  .toggle-pw { background: #2a2a2a; border: 1px solid #333; color: #888; padding: 0 10px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; white-space: nowrap; }
  .toggle-pw:hover { color: #fff; }
  .field .hint { font-size: 0.75rem; color: #555; }
  .settings-footer { padding: 16px 24px; border-top: 1px solid #222; display: flex; gap: 10px; position: sticky; bottom: 0; background: #141414; }
  .btn-save { background: #e50914; border: none; color: #fff; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 0.88rem; font-weight: 600; flex: 1; transition: background 0.15s; }
  .btn-save:hover { background: #c40812; }
  .btn-save:disabled { background: #555; cursor: default; }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1e1e1e; border: 1px solid #333; color: #e0e0e0; padding: 12px 20px; border-radius: 8px; font-size: 0.88rem; z-index: 200; opacity: 0; transition: opacity 0.2s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .toast.success { border-color: #2ecc71; color: #2ecc71; }
  .toast.error { border-color: #e50914; color: #e74c3c; }
</style>
</head>
<body>
<header>
  <div>
    <div style="display:flex;align-items:center;gap:10px">
      <h1>Arrivalr</h1>
      <span class="badge">LIVE</span>
      <div id="refresh-indicator"></div>
    </div>
    <div class="subtitle">Radarr &amp; Sonarr additions</div>
  </div>
  <div class="header-actions">
    <span class="role-pill" id="role-pill"></span>
    <button class="gear-btn" id="gear-btn" onclick="openSettings()" title="Settings">⚙</button>
    <a href="/logout" class="logout-btn" id="logout-btn">Sign out</a>
  </div>
</header>

<div class="controls">
  <button class="filter-btn active" data-filter="all">All</button>
  <button class="filter-btn" data-filter="movie">Movies</button>
  <button class="filter-btn" data-filter="series">Series</button>
  <button class="filter-btn" data-filter="episode">Episodes</button>
  <span class="count" id="count"></span>
</div>
<div class="grid" id="grid"></div>

<!-- Settings panel (admin only) -->
<div class="overlay" id="overlay" onclick="maybeClose(event)">
  <div class="settings-panel">
    <div class="settings-header">
      <h2>Settings</h2>
      <button class="close-btn" onclick="closeSettings()">&#x2715;</button>
    </div>
    <div class="settings-body">
      <div class="settings-section">
        <h3>Radarr</h3>
        <div class="field">
          <label>URL</label>
          <input type="text" id="radarr_url" placeholder="http://192.168.1.x:7878">
        </div>
        <div class="field">
          <label>API Key</label>
          <div class="field-input">
            <input type="password" id="radarr_api_key" placeholder="API key">
            <button class="toggle-pw" onclick="togglePw('radarr_api_key')">Show</button>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Sonarr</h3>
        <div class="field">
          <label>URL</label>
          <input type="text" id="sonarr_url" placeholder="http://192.168.1.x:8989">
        </div>
        <div class="field">
          <label>API Key</label>
          <div class="field-input">
            <input type="password" id="sonarr_api_key" placeholder="API key">
            <button class="toggle-pw" onclick="togglePw('sonarr_api_key')">Show</button>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Pushover</h3>
        <div class="field">
          <label>Application Token</label>
          <div class="field-input">
            <input type="password" id="pushover_token" placeholder="App token">
            <button class="toggle-pw" onclick="togglePw('pushover_token')">Show</button>
          </div>
        </div>
        <div class="field">
          <label>User Key</label>
          <div class="field-input">
            <input type="password" id="pushover_user" placeholder="User key">
            <button class="toggle-pw" onclick="togglePw('pushover_user')">Show</button>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>General</h3>
        <div class="field">
          <label>Poll Interval (seconds)</label>
          <input type="number" id="poll_interval" min="60" max="3600">
          <span class="hint">How often to check for new additions. Min 60s.</span>
        </div>
        <div class="field">
          <label>History Retention (days)</label>
          <input type="number" id="history_retention_days" min="1" max="365">
          <span class="hint">Cards older than this are automatically removed.</span>
        </div>
      </div>
      <div class="settings-section">
        <h3>Access Control</h3>
        <div class="field">
          <label>Admin Password</label>
          <div class="field-input">
            <input type="password" id="admin_password" placeholder="Set to enable login">
            <button class="toggle-pw" onclick="togglePw('admin_password')">Show</button>
          </div>
          <span class="hint">Full access including settings. Leave blank to disable login.</span>
        </div>
        <div class="field">
          <label>Viewer Password</label>
          <div class="field-input">
            <input type="password" id="viewer_password" placeholder="Optional read-only access">
            <button class="toggle-pw" onclick="togglePw('viewer_password')">Show</button>
          </div>
          <span class="hint">Read-only access to the history cards. Leave blank to disable.</span>
        </div>
      </div>
    </div>
    <div class="settings-footer">
      <button class="btn-save" id="save-btn" onclick="saveSettings()">Save Settings</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
  const ROLE = '__ROLE__';
  let mediaHistory = [], filter = 'all';

  // Setup header based on role
  (function() {
    const pill = document.getElementById('role-pill');
    const gear = document.getElementById('gear-btn');
    const logout = document.getElementById('logout-btn');
    if (ROLE === 'none') {
      pill.style.display = 'none';
      logout.style.display = 'none';
    } else {
      pill.textContent = ROLE === 'admin' ? 'Admin' : 'Viewer';
      pill.classList.add(ROLE);
      if (ROLE !== 'admin') gear.style.display = 'none';
    }
  })();

  async function load() {
    try {
      const r = await fetch('/api/history');
      if (r.status === 401) { location.href = '/login'; return; }
      mediaHistory = await r.json();
      render();
    } catch(e) { console.error(e); }
  }

  function fmt(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {month:'short',day:'numeric',year:'numeric'})
      + ' ' + d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
  }

  function render() {
    const items = filter === 'all' ? mediaHistory : mediaHistory.filter(h => h.type === filter);
    document.getElementById('count').textContent = items.length + ' item' + (items.length !== 1 ? 's' : '');
    const grid = document.getElementById('grid');
    if (!items.length) {
      grid.innerHTML = '<div class="empty">No additions yet</div>';
      return;
    }
    grid.innerHTML = [...items].reverse().map(h => {
      const icon = h.type === 'movie' ? '🎬' : h.type === 'episode' ? '🎞️' : '📺';
      const tags = (h.genres||[]).map(g => '<span class="tag">'+g+'</span>').join('');
      const folder = h.folder ? '<span class="tag folder">'+h.folder+'</span>' : '';
      const network = h.network ? '<span class="tag network">'+h.network+'</span>' : '';
      const seasons = h.seasons ? '<span class="tag">'+h.seasons+' season'+(h.seasons>1?'s':'')+'</span>' : '';
      const epCode = h.episode_code ? '<div class="ep-code">'+h.episode_code+(h.episode_title?' &middot; '+h.episode_title:'')+'</div>' : '';
      const subtitle = h.type === 'episode' ? '' : (h.year || '');
      return '<div class="card">'
        + '<div class="card-header">'
        + '<div class="type-icon '+h.type+'">'+icon+'</div>'
        + '<div><div class="card-title">'+h.title+'</div>'
        + (epCode || (subtitle ? '<div class="card-year">'+subtitle+'</div>' : ''))
        + '</div></div>'
        + ((tags||folder||network||seasons) ? '<div class="tags">'+tags+folder+network+seasons+'</div>' : '')
        + '<div class="card-footer">'
        + '<span class="added-at">'+fmt(h.added_at)+'</span>'
        + '<span class="type-label '+h.type+'">'+h.type+'</span>'
        + '</div></div>';
    }).join('');
  }

  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filter = btn.dataset.filter;
      render();
    });
  });

  // Settings (admin only)
  const ALL_FIELDS = ['radarr_url','radarr_api_key','sonarr_url','sonarr_api_key',
    'pushover_token','pushover_user','poll_interval','history_retention_days',
    'admin_password','viewer_password'];

  async function openSettings() {
    if (ROLE !== 'admin' && ROLE !== 'none') return;
    const r = await fetch('/api/settings');
    if (r.status === 403) { showToast('Admin access required', 'error'); return; }
    const s = await r.json();
    ALL_FIELDS.forEach(k => {
      const el = document.getElementById(k);
      if (el) el.value = s[k] || '';
    });
    document.getElementById('overlay').classList.add('open');
  }

  function closeSettings() {
    document.getElementById('overlay').classList.remove('open');
  }

  function maybeClose(e) {
    if (e.target === document.getElementById('overlay')) closeSettings();
  }

  function togglePw(id) {
    const el = document.getElementById(id);
    const btn = el.nextElementSibling;
    if (el.type === 'password') { el.type = 'text'; btn.textContent = 'Hide'; }
    else { el.type = 'password'; btn.textContent = 'Show'; }
  }

  async function saveSettings() {
    const btn = document.getElementById('save-btn');
    btn.disabled = true; btn.textContent = 'Saving…';
    const payload = {};
    ALL_FIELDS.forEach(k => {
      const el = document.getElementById(k);
      if (el) payload[k] = el.type === 'number' ? Number(el.value) : el.value;
    });
    try {
      const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      if (r.ok) { showToast('Settings saved — takes effect on next poll', 'success'); closeSettings(); }
      else { showToast('Save failed', 'error'); }
    } catch(e) { showToast('Save failed: ' + e, 'error'); }
    btn.disabled = false; btn.textContent = 'Save Settings';
  }

  function showToast(msg, type) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show ' + (type||'');
    setTimeout(() => t.className = 'toast', 3000);
  }

  load();
  setInterval(load, 30000);
</script>
</body>
</html>"""


def build_html(role):
    return HTML.replace('__ROLE__', role)


def build_login(error=False):
    err_html = '<div class="error">Invalid username or password.</div>' if error else ''
    return LOGIN_HTML.replace('__ERROR__', err_html)


def api_get(base_url, api_key, endpoint):
    req = urllib.request.Request(
        f'{base_url}/api/v3{endpoint}',
        headers={'X-Api-Key': api_key}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def pushover_send(token, user, title, message):
    data = urllib.parse.urlencode({
        'token': token,
        'user': user,
        'title': title,
        'message': message,
    }).encode()
    req = urllib.request.Request('https://api.pushover.net/1/messages.json', data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return None


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def load_history():
    if HISTORY_FILE.exists():
        return json.loads(HISTORY_FILE.read_text())
    return []


def append_history(entry):
    history = load_history()
    history.append(entry)
    HISTORY_FILE.write_text(json.dumps(history))


def prune_history(retention_days):
    history = load_history()
    if not history:
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (retention_days * 86400)
    kept = [e for e in history if datetime.fromisoformat(e['added_at'].replace('Z', '+00:00')).timestamp() >= cutoff]
    if len(kept) < len(history):
        HISTORY_FILE.write_text(json.dumps(kept))
        log.info(f'Pruned {len(history) - len(kept)} history entry/entries older than {retention_days} days.')


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def check_radarr(state, cfg):
    movies = api_get(cfg['radarr_url'], cfg['radarr_api_key'], '/movie')
    current_ids = {m['id'] for m in movies}
    seen_ids = set(state.get('radarr', []))

    if not state.get('radarr'):
        log.info(f'Radarr first run — recording {len(current_ids)} existing movies.')
        state['radarr'] = list(current_ids)
        return

    new_ids = current_ids - seen_ids
    if not new_ids:
        log.info('Radarr: no new movies.')
        return

    new_movies = sorted([m for m in movies if m['id'] in new_ids], key=lambda m: m.get('title', ''))
    for m in new_movies:
        title = m.get('title', 'Unknown')
        year = m.get('year', '')
        genres = m.get('genres', [])[:3]
        folder = m.get('rootFolderPath', '').rstrip('/').split('/')[-1]
        msg = f'{title} ({year})'
        if genres:
            msg += f'\n{", ".join(genres)}'
        if folder:
            msg += f'\nAdded to: {folder}'
        log.info(f'New movie: {title} ({year})')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Movie Added', msg)
        append_history({'type': 'movie', 'title': title, 'year': year, 'genres': genres,
                        'folder': folder or None, 'network': None, 'seasons': None, 'added_at': now_iso()})
        time.sleep(0.5)

    state['radarr'] = list(seen_ids | new_ids)
    log.info(f'Radarr: notified for {len(new_movies)} new movie(s).')


def check_sonarr(state, cfg):
    series = api_get(cfg['sonarr_url'], cfg['sonarr_api_key'], '/series')
    current_ids = {s['id'] for s in series}
    seen_ids = set(state.get('sonarr', []))

    if not state.get('sonarr'):
        log.info(f'Sonarr first run — recording {len(current_ids)} existing series.')
        state['sonarr'] = list(current_ids)
        return

    new_ids = current_ids - seen_ids
    if not new_ids:
        log.info('Sonarr: no new series.')
        return

    new_series = sorted([s for s in series if s['id'] in new_ids], key=lambda s: s.get('title', ''))
    for s in new_series:
        title = s.get('title', 'Unknown')
        year = s.get('year', '')
        genres = s.get('genres', [])[:3]
        network = s.get('network', '')
        seasons = s.get('seasonCount', '')
        msg = f'{title} ({year})'
        if genres:
            msg += f'\n{", ".join(genres)}'
        if network:
            msg += f'\n{network}'
        if seasons:
            msg += f' · {seasons} season(s)'
        log.info(f'New series: {title} ({year})')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Series Added', msg)
        append_history({'type': 'series', 'title': title, 'year': year, 'genres': genres,
                        'folder': None, 'network': network or None, 'seasons': seasons or None, 'added_at': now_iso()})
        time.sleep(0.5)

    state['sonarr'] = list(seen_ids | new_ids)
    log.info(f'Sonarr: notified for {len(new_series)} new series.')


def check_sonarr_episodes(state, cfg):
    data = api_get(cfg['sonarr_url'], cfg['sonarr_api_key'],
                   '/history?pageSize=50&sortKey=date&sortDirection=descending'
                   '&includeSeries=true&includeEpisode=true')
    records = [r for r in data.get('records', []) if r.get('eventType') == 'downloadFolderImported']
    if not records:
        return

    last_id = state.get('sonarr_last_history_id')
    if last_id is None:
        state['sonarr_last_history_id'] = records[0]['id']
        log.info(f'Sonarr episodes first run — recording history cursor at ID {records[0]["id"]}.')
        return

    new_records = [r for r in records if r['id'] > last_id]
    if not new_records:
        log.info('Sonarr: no new episode downloads.')
        return

    for r in reversed(new_records):
        series_title = (r.get('series') or {}).get('title', 'Unknown')
        ep = r.get('episode') or {}
        season = ep.get('seasonNumber')
        episode = ep.get('episodeNumber')
        ep_title = ep.get('title', '')
        network = (r.get('series') or {}).get('network', '')
        ep_code = f'S{season:02d}E{episode:02d}' if season is not None and episode is not None else ''
        msg = f'{series_title}'
        if ep_code:
            msg += f' {ep_code}'
        if ep_title:
            msg += f'\n{ep_title}'
        if network:
            msg += f'\n{network}'
        log.info(f'New episode: {series_title} {ep_code}')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Episode Downloaded', msg)
        append_history({'type': 'episode', 'title': series_title, 'year': None, 'genres': [],
                        'folder': None, 'network': network or None, 'seasons': None,
                        'episode_code': ep_code or None, 'episode_title': ep_title or None,
                        'added_at': r.get('date', now_iso())})
        time.sleep(0.5)

    state['sonarr_last_history_id'] = records[0]['id']
    log.info(f'Sonarr: notified for {len(new_records)} new episode download(s).')


def check():
    cfg = get_settings()
    state = load_state() or {}
    check_radarr(state, cfg)
    check_sonarr(state, cfg)
    check_sonarr_episodes(state, cfg)
    save_state(state)
    prune_history(cfg['history_retention_days'])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _get_role(self):
        """Returns the role for this request: 'admin', 'viewer', or None (not logged in).
        Returns 'none' when auth is disabled (no admin_password set)."""
        cfg = get_settings()
        if not cfg.get('admin_password'):
            return 'none'
        return get_session_role(self.headers.get('Cookie', ''))

    def _redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def _require_login(self):
        """Sends 401/redirect if not logged in. Returns role or None."""
        role = self._get_role()
        if role is None:
            if self.path.startswith('/api/'):
                self._json(401, {'error': 'unauthorized'})
            else:
                self._redirect('/login')
        return role

    def _require_admin(self):
        """Sends 403 if not admin. Returns role or None."""
        role = self._require_login()
        if role is None:
            return None
        if role not in ('admin', 'none'):
            self._json(403, {'error': 'forbidden'})
            return None
        return role

    def do_GET(self):
        path = self.path.split('?')[0]

        if path == '/login':
            error = 'error=1' in self.path
            data = build_login(error).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

        elif path == '/logout':
            invalidate_session(self.headers.get('Cookie', ''))
            self.send_response(302)
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'arrivalr_session=; Path=/; Max-Age=0')
            self.end_headers()

        elif path == '/api/history':
            role = self._require_login()
            if role is None:
                return
            data = json.dumps(load_history()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

        elif path == '/api/settings':
            role = self._require_admin()
            if role is None:
                return
            data = json.dumps(get_settings()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

        elif path in ('/', '/index.html'):
            role = self._require_login()
            if role is None:
                return
            data = build_html(role).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/login':
            length = int(self.headers.get('Content-Length', 0))
            body = urllib.parse.parse_qs(self.rfile.read(length).decode())
            username = body.get('username', [''])[0].strip().lower()
            password = body.get('password', [''])[0]
            cfg = get_settings()

            role = None
            if username == 'admin' and cfg.get('admin_password') and password == cfg['admin_password']:
                role = 'admin'
            elif username == 'viewer' and cfg.get('viewer_password') and password == cfg['viewer_password']:
                role = 'viewer'

            if role:
                token = create_session(role)
                log.info(f'Login: {username}')
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie',
                    f'arrivalr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
                self.end_headers()
            else:
                log.warning(f'Failed login attempt for username: {username!r}')
                self._redirect('/login?error=1')

        elif self.path == '/api/settings':
            role = self._require_admin()
            if role is None:
                return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            save_settings(body)
            log.info('Settings updated via web UI.')
            self._json(200, {'ok': True})

        else:
            self.send_response(404)
            self.end_headers()


def run_web():
    server = HTTPServer(('0.0.0.0', WEB_PORT), Handler)
    log.info(f'Web UI running on port {WEB_PORT}')
    server.serve_forever()


def main():
    cfg = get_settings()
    log.info(f'Arrivalr starting — polling every {cfg["poll_interval"]}s')
    threading.Thread(target=run_web, daemon=True).start()
    while True:
        try:
            check()
        except Exception as e:
            log.error(f'Check failed: {e}')
        time.sleep(get_settings()['poll_interval'])


if __name__ == '__main__':
    main()
