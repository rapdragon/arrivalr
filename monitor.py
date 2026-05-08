import os
import re
import json
import time
import logging
import secrets
import hashlib
import hmac
import threading
import urllib.request
import urllib.parse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

STATE_FILE   = Path(os.environ.get('STATE_FILE', '/data/seen.json'))
HISTORY_FILE = Path('/data/history.json')
LOGO_FILE    = Path('/data/logo.png')
SETTINGS_FILE = Path('/data/settings.json')
USERS_FILE   = Path('/data/users.json')
WEB_PORT     = int(os.environ.get('WEB_PORT', 7070))
SESSION_TTL  = 86400  # 24 h

ENV_DEFAULTS = {
    'radarr_url':             os.environ.get('RADARR_URL', '').rstrip('/'),
    'radarr_api_key':         os.environ.get('RADARR_API_KEY', ''),
    'sonarr_url':             os.environ.get('SONARR_URL', '').rstrip('/'),
    'sonarr_api_key':         os.environ.get('SONARR_API_KEY', ''),
    'pushover_token':         os.environ.get('PUSHOVER_TOKEN', ''),
    'pushover_user':          os.environ.get('PUSHOVER_USER', ''),
    'poll_interval':          int(os.environ.get('POLL_INTERVAL', 300)),
    'history_retention_days': int(os.environ.get('HISTORY_RETENTION_DAYS', 30)),
}

_USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
_USER_PATH_RE = re.compile(r'^/api/users/([a-f0-9]+)$')

# ── sessions ──────────────────────────────────────────────────────────────────

_sessions = {}
_sessions_lock = threading.Lock()


def create_session(username, role):
    token = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[token] = {'username': username, 'role': role,
                            'expires': time.time() + SESSION_TTL}
    return token


def get_session(cookie_header):
    for part in (cookie_header or '').split(';'):
        name, _, val = part.strip().partition('=')
        if name.strip() == 'arrivalr_session':
            with _sessions_lock:
                s = _sessions.get(val.strip())
                if s and s['expires'] > time.time():
                    return s
    return None


def invalidate_session(cookie_header):
    for part in (cookie_header or '').split(';'):
        name, _, val = part.strip().partition('=')
        if name.strip() == 'arrivalr_session':
            with _sessions_lock:
                _sessions.pop(val.strip(), None)


# ── settings ──────────────────────────────────────────────────────────────────

def get_settings():
    if SETTINGS_FILE.exists():
        saved = json.loads(SETTINGS_FILE.read_text())
        merged = {**ENV_DEFAULTS,
                  **{k: v for k, v in saved.items() if k in ENV_DEFAULTS and v not in (None, '')}}
        merged['poll_interval'] = int(merged['poll_interval'])
        merged['history_retention_days'] = int(merged['history_retention_days'])
        return merged
    return dict(ENV_DEFAULTS)


def save_settings(data):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    clean = {k: v for k, v in data.items() if k in ENV_DEFAULTS}
    SETTINGS_FILE.write_text(json.dumps(clean, indent=2))


# ── users ─────────────────────────────────────────────────────────────────────

def load_users():
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return []


def save_users(users):
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))


def has_active_admin():
    return any(u['role'] == 'admin' and u['status'] == 'active' for u in load_users())


def hash_password(password):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
    return f'pbkdf2:{salt}:{dk.hex()}'


def check_password(password, stored):
    try:
        _, salt, dk_hex = stored.split(':', 2)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def sanitize_user(u):
    return {k: v for k, v in u.items() if k != 'password_hash'}


# ── shared auth-page CSS ──────────────────────────────────────────────────────

_ACSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0f0f0f; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont,
       'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center;
       justify-content: center; padding: 20px; }
.card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 40px;
        width: 100%; max-width: 390px; display: flex; flex-direction: column; gap: 24px; }
.logo { text-align: center; }
.logo h1 { font-size: 1.6rem; font-weight: 700; color: #fff; display: flex;
           align-items: center; justify-content: center; gap: 10px; }
.badge { background: #e50914; color: #fff; font-size: .68rem; font-weight: 700;
         padding: 3px 8px; border-radius: 4px; }
.logo p { color: #555; font-size: .82rem; margin-top: 8px; }
.form { display: flex; flex-direction: column; gap: 14px; }
.form h2 { font-size: .9rem; font-weight: 600; color: #aaa; }
.field { display: flex; flex-direction: column; gap: 6px; }
.field label { font-size: .82rem; color: #aaa; }
.field input, .field textarea { background: #252525; border: 1px solid #333; color: #e0e0e0;
  padding: 11px 14px; border-radius: 6px; font-size: .9rem; width: 100%;
  transition: border-color .15s; font-family: inherit; resize: vertical; }
.field input:focus, .field textarea:focus { outline: none; border-color: #555; }
.btn { background: #e50914; border: none; color: #fff; padding: 12px; border-radius: 6px;
       cursor: pointer; font-size: .9rem; font-weight: 600; width: 100%;
       transition: background .15s; }
.btn:hover { background: #c40812; }
.link-row { text-align: center; font-size: .82rem; color: #555; }
.link-row a { color: #7b8cde; text-decoration: none; }
.link-row a:hover { text-decoration: underline; }
.alert { padding: 11px 14px; border-radius: 6px; font-size: .82rem; }
.alert.error   { background: #2e1a1a; border: 1px solid #5a2020; color: #e74c3c; }
.alert.success { background: #1a2e1a; border: 1px solid #205a20; color: #7bde8c; }
"""


def _auth_page(title, body):
    return ('<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>' + title + ' — Arrivalr</title>'
            '<style>' + _ACSS + '</style>'
            '</head><body>' + body + '</body></html>')


_ERRORS = {
    'inv_user':   'Username must be 3–32 characters: letters, numbers, _ or –.',
    'taken':      'That username is already taken.',
    'short_pw':   'Password must be at least 8 characters.',
    'mismatch':   'Passwords do not match.',
    'bad_creds':  'Invalid username or password.',
    'no_admin':   'No admin account exists yet.',
}


def _logo_html(size=60):
    if LOGO_FILE.exists():
        return f'<img src="/logo.png" alt="Arrivalr" style="height:{size}px;object-fit:contain;max-width:240px">'
    return '<span style="font-size:1.6rem;font-weight:700;color:#fff">Arrivalr</span>'


def build_login(error=None):
    alert = ('<div class="alert error">' + _ERRORS.get(error, error or '') + '</div>') if error else ''
    return _auth_page('Sign In',
        '<div class="card">'
        '<div class="logo" style="display:flex;flex-direction:column;align-items:center;gap:8px">'
        + _logo_html(60) +
        '<span class="badge">LIVE</span>'
        '<p>Media Monitor</p></div>' + alert +
        '<form method="post" action="/login" class="form">'
        '<div class="field"><label>Username</label>'
        '<input type="text" name="username" autofocus autocomplete="username"></div>'
        '<div class="field"><label>Password</label>'
        '<input type="password" name="password" autocomplete="current-password"></div>'
        '<button type="submit" class="btn">Sign In</button></form>'
        '<div class="link-row">No account? <a href="/request">Request access</a></div>'
        '</div>')


def build_setup(error=None):
    alert = ('<div class="alert error">' + _ERRORS.get(error, error or '') + '</div>') if error else ''
    return _auth_page('Setup',
        '<div class="card">'
        '<div class="logo" style="display:flex;flex-direction:column;align-items:center;gap:8px">'
        + _logo_html(60) +
        '<span class="badge">LIVE</span>'
        '<p>Media Monitor</p></div>' + alert +
        '<form method="post" action="/setup" class="form">'
        '<h2>Create your admin account to get started</h2>'
        '<div class="field"><label>Username</label>'
        '<input type="text" name="username" autofocus autocomplete="username"></div>'
        '<div class="field"><label>Password</label>'
        '<input type="password" name="password" autocomplete="new-password"></div>'
        '<div class="field"><label>Confirm Password</label>'
        '<input type="password" name="confirm" autocomplete="new-password"></div>'
        '<button type="submit" class="btn">Create Admin Account</button></form>'
        '</div>')


def build_request(error=None, success=False):
    if success:
        return _auth_page('Request Submitted',
            '<div class="card">'
            '<div class="logo" style="display:flex;flex-direction:column;align-items:center;gap:8px">'
            + _logo_html(60) +
            '<span class="badge">LIVE</span>'
            '<p>Media Monitor</p></div>'
            '<div class="alert success">Your request has been submitted. '
            'An admin will review it and grant access.</div>'
            '<div class="link-row"><a href="/login">← Back to sign in</a></div>'
            '</div>')
    alert = ('<div class="alert error">' + _ERRORS.get(error, error or '') + '</div>') if error else ''
    return _auth_page('Request Access',
        '<div class="card">'
        '<div class="logo" style="display:flex;flex-direction:column;align-items:center;gap:8px">'
        + _logo_html(60) +
        '<span class="badge">LIVE</span>'
        '<p>Media Monitor</p></div>' + alert +
        '<form method="post" action="/request" class="form">'
        '<h2>Request Access</h2>'
        '<div class="field"><label>Username</label>'
        '<input type="text" name="username" autofocus autocomplete="username"></div>'
        '<div class="field"><label>Password</label>'
        '<input type="password" name="password" autocomplete="new-password"></div>'
        '<div class="field"><label>Note <span style="color:#555">(optional)</span></label>'
        '<textarea name="note" rows="2" placeholder="Why do you need access?"></textarea></div>'
        '<button type="submit" class="btn">Request Access</button></form>'
        '<div class="link-row"><a href="/login">← Back to sign in</a></div>'
        '</div>')


# ── main app HTML ─────────────────────────────────────────────────────────────

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
  header .subtitle { font-size: .85rem; color: #888; margin-top: 2px; }
  .badge { background: #e50914; color: #fff; font-size: .7rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: .5px; }
  .header-right { display: flex; align-items: center; gap: 10px; }
  .role-pill { font-size: .72rem; font-weight: 600; letter-spacing: .5px; padding: 4px 10px; border-radius: 10px; text-transform: uppercase; }
  .role-pill.admin  { background: #1a1a3e; color: #7b8cde; }
  .role-pill.viewer { background: #1a2e1a; color: #7bde8c; }
  .gear-wrap { position: relative; display: inline-flex; }
  .gear-btn { background: none; border: 1px solid #333; color: #888; width: 36px; height: 36px; border-radius: 8px; cursor: pointer; font-size: 1.1rem; display: flex; align-items: center; justify-content: center; transition: all .15s; }
  .gear-btn:hover { border-color: #666; color: #fff; }
  .pending-dot { position: absolute; top: -5px; right: -5px; background: #e50914; color: #fff; font-size: .6rem; font-weight: 700; min-width: 16px; height: 16px; border-radius: 8px; display: flex; align-items: center; justify-content: center; padding: 0 3px; pointer-events: none; }
  .logout-btn { color: #555; font-size: .82rem; text-decoration: none; padding: 7px 12px; border: 1px solid #2a2a2a; border-radius: 6px; transition: all .15s; white-space: nowrap; }
  .logout-btn:hover { color: #ddd; border-color: #555; }
  .controls { padding: 20px 32px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .filter-btn { background: #1e1e1e; border: 1px solid #333; color: #aaa; padding: 7px 16px; border-radius: 20px; cursor: pointer; font-size: .85rem; transition: all .15s; }
  .filter-btn:hover, .filter-btn.active { background: #e50914; border-color: #e50914; color: #fff; }
  .count { margin-left: auto; font-size: .85rem; color: #666; }
  .grid { padding: 0 32px 32px; display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
  .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 10px; padding: 18px; display: flex; flex-direction: column; gap: 10px; transition: border-color .15s; }
  .card:hover { border-color: #444; }
  .card-header { display: flex; align-items: flex-start; gap: 12px; }
  .type-icon { width: 38px; height: 38px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; flex-shrink: 0; }
  .type-icon.movie   { background: #1a1a3e; }
  .type-icon.series  { background: #1a2e1a; }
  .type-icon.episode { background: #2e1a2e; }
  .card-title { font-size: 1rem; font-weight: 600; color: #fff; line-height: 1.3; }
  .card-year  { font-size: .8rem; color: #888; margin-top: 2px; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .tag { background: #252525; color: #aaa; font-size: .75rem; padding: 3px 9px; border-radius: 4px; }
  .tag.folder  { background: #1a1a2e; color: #7b8cde; }
  .tag.network { background: #1a2e1a; color: #7bde8c; }
  .card-footer { display: flex; align-items: center; justify-content: space-between; padding-top: 6px; border-top: 1px solid #252525; }
  .added-at { font-size: .78rem; color: #666; }
  .type-label { font-size: .72rem; font-weight: 600; letter-spacing: .5px; text-transform: uppercase; padding: 2px 8px; border-radius: 3px; }
  .type-label.movie   { background: #1a1a3e; color: #7b8cde; }
  .type-label.series  { background: #1a2e1a; color: #7bde8c; }
  .type-label.episode { background: #2e1a2e; color: #de7bde; }
  .ep-code { font-size: .8rem; color: #de7bde; font-weight: 600; margin-top: 2px; }
  .empty { grid-column: 1/-1; text-align: center; padding: 80px 20px; color: #444; }
  #refresh-indicator { width: 8px; height: 8px; background: #2ecc71; border-radius: 50%; animation: pulse 2s infinite; margin-left: 8px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  /* Settings overlay */
  .overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.7); z-index: 100; }
  .overlay.open { display: flex; align-items: flex-start; justify-content: flex-end; }
  .settings-panel { background: #141414; width: 440px; max-width: 100vw; height: 100vh; overflow-y: auto; border-left: 1px solid #2a2a2a; display: flex; flex-direction: column; }
  .s-head { padding: 20px 24px; border-bottom: 1px solid #222; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; background: #141414; z-index: 1; }
  .s-head h2 { font-size: 1rem; font-weight: 600; }
  .close-btn { background: none; border: none; color: #888; font-size: 1.3rem; cursor: pointer; line-height: 1; }
  .close-btn:hover { color: #fff; }
  .s-body { padding: 24px; flex: 1; display: flex; flex-direction: column; gap: 24px; }
  .s-section { display: flex; flex-direction: column; gap: 12px; }
  .s-section h3 { font-size: .75rem; font-weight: 600; letter-spacing: .8px; text-transform: uppercase; color: #666; padding-bottom: 8px; border-bottom: 1px solid #222; }
  .field { display: flex; flex-direction: column; gap: 6px; }
  .field label { font-size: .82rem; color: #aaa; }
  .field-row { display: flex; gap: 6px; }
  .field input { background: #1e1e1e; border: 1px solid #333; color: #e0e0e0; padding: 9px 12px; border-radius: 6px; font-size: .88rem; width: 100%; transition: border-color .15s; }
  .field input:focus { outline: none; border-color: #555; }
  .toggle-pw { background: #2a2a2a; border: 1px solid #333; color: #888; padding: 0 10px; border-radius: 6px; cursor: pointer; font-size: .8rem; white-space: nowrap; }
  .toggle-pw:hover { color: #fff; }
  .hint { font-size: .75rem; color: #555; }
  .s-footer { padding: 16px 24px; border-top: 1px solid #222; position: sticky; bottom: 0; background: #141414; }
  .btn-save { background: #e50914; border: none; color: #fff; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: .88rem; font-weight: 600; width: 100%; transition: background .15s; }
  .btn-save:hover { background: #c40812; }
  .btn-save:disabled { background: #555; cursor: default; }
  /* User rows */
  .user-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; padding: 10px 12px; background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px; }
  .user-row.pending { border-color: #3a2510; background: #1c1710; }
  .u-info { display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 0; }
  .uname { font-size: .88rem; font-weight: 600; color: #e0e0e0; }
  .you-tag { font-size: .65rem; background: #252525; color: #666; padding: 1px 5px; border-radius: 3px; margin-left: 5px; vertical-align: middle; }
  .u-note { font-size: .75rem; color: #888; font-style: italic; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 180px; }
  .u-time { font-size: .72rem; color: #555; }
  .u-actions { display: flex; gap: 5px; flex-shrink: 0; align-items: flex-start; flex-wrap: wrap; justify-content: flex-end; }
  .ubtn { background: #252525; border: 1px solid #333; color: #888; padding: 4px 9px; border-radius: 4px; cursor: pointer; font-size: .75rem; transition: all .15s; white-space: nowrap; }
  .ubtn:hover:not(:disabled) { border-color: #555; color: #ddd; }
  .ubtn:disabled { opacity: .35; cursor: default; }
  .ubtn.ok { color: #7bde8c; border-color: #245a24; }
  .ubtn.ok:hover:not(:disabled) { background: #1a2e1a; }
  .ubtn.danger { color: #e74c3c; border-color: #5a2020; }
  .ubtn.danger:hover:not(:disabled) { background: #2e1a1a; }
  .u-group { font-size: .72rem; color: #555; padding: 6px 0 2px; }
  .u-group.pending-lbl { color: #c07830; }
  .no-users { font-size: .82rem; color: #555; padding: 12px 0; text-align: center; }
  .add-user-box { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px; padding: 12px; display: flex; flex-direction: column; gap: 8px; }
  .add-user-row { display: flex; gap: 6px; }
  .add-user-row input { background: #252525; border: 1px solid #333; color: #e0e0e0; padding: 7px 10px; border-radius: 5px; font-size: .82rem; flex: 1; min-width: 0; }
  .add-user-row input:focus { outline: none; border-color: #555; }
  .add-user-row select { background: #252525; border: 1px solid #333; color: #e0e0e0; padding: 7px 8px; border-radius: 5px; font-size: .82rem; }
  .btn-add-user { background: none; border: 1px dashed #2a2a2a; color: #555; padding: 8px; border-radius: 6px; cursor: pointer; font-size: .82rem; width: 100%; transition: all .15s; }
  .btn-add-user:hover { border-color: #444; color: #888; }
  /* Toast */
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1e1e1e; border: 1px solid #333; color: #e0e0e0; padding: 12px 20px; border-radius: 8px; font-size: .88rem; z-index: 200; opacity: 0; transition: opacity .2s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .toast.success { border-color: #2ecc71; color: #2ecc71; }
  .toast.error   { border-color: #e50914; color: #e74c3c; }
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center;gap:14px">
    <div id="site-logo"></div>
    <div>
      <div style="display:flex;align-items:center;gap:10px">
        <h1 id="site-name">Arrivalr</h1>
        <span class="badge">LIVE</span>
        <div id="refresh-indicator"></div>
      </div>
      <div class="subtitle">Radarr &amp; Sonarr additions</div>
    </div>
  </div>
  <div class="header-right">
    <span class="role-pill __ROLE__" id="role-pill">__ROLE__</span>
    <div class="gear-wrap">
      <button class="gear-btn" id="gear-btn" onclick="openSettings()" title="Settings">&#9881;</button>
      <span class="pending-dot" id="pending-dot" style="display:none"></span>
    </div>
    <a href="/logout" class="logout-btn">Sign out</a>
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

<div class="overlay" id="overlay" onclick="maybeClose(event)">
  <div class="settings-panel" onclick="event.stopPropagation()">
    <div class="s-head">
      <h2>Settings</h2>
      <button class="close-btn" onclick="closeSettings()">&#x2715;</button>
    </div>
    <div class="s-body">
      <!-- Users section (admin only) -->
      <div class="s-section" id="users-section" style="display:none">
        <h3>Users</h3>
        <div id="users-list"></div>
        <div id="add-user-box" class="add-user-box" style="display:none">
          <div class="add-user-row">
            <input type="text" id="new-username" placeholder="Username">
            <input type="password" id="new-password" placeholder="Password">
            <select id="new-role"><option value="viewer">Viewer</option><option value="admin">Admin</option></select>
          </div>
          <div style="display:flex;gap:6px">
            <button class="ubtn ok" onclick="submitAddUser()">Add User</button>
            <button class="ubtn" onclick="cancelAddUser()">Cancel</button>
          </div>
        </div>
        <button class="btn-add-user" id="btn-add-user" onclick="showAddUserForm()">+ Add User</button>
      </div>
      <!-- App settings -->
      <div class="s-section">
        <h3>Radarr</h3>
        <div class="field"><label>URL</label>
          <input type="text" id="radarr_url" placeholder="http://192.168.1.x:7878"></div>
        <div class="field"><label>API Key</label>
          <div class="field-row">
            <input type="password" id="radarr_api_key" placeholder="API key">
            <button class="toggle-pw" onclick="togglePw('radarr_api_key')">Show</button>
          </div></div>
      </div>
      <div class="s-section">
        <h3>Sonarr</h3>
        <div class="field"><label>URL</label>
          <input type="text" id="sonarr_url" placeholder="http://192.168.1.x:8989"></div>
        <div class="field"><label>API Key</label>
          <div class="field-row">
            <input type="password" id="sonarr_api_key" placeholder="API key">
            <button class="toggle-pw" onclick="togglePw('sonarr_api_key')">Show</button>
          </div></div>
      </div>
      <div class="s-section">
        <h3>Pushover</h3>
        <div class="field"><label>Application Token</label>
          <div class="field-row">
            <input type="password" id="pushover_token" placeholder="App token">
            <button class="toggle-pw" onclick="togglePw('pushover_token')">Show</button>
          </div></div>
        <div class="field"><label>User Key</label>
          <div class="field-row">
            <input type="password" id="pushover_user" placeholder="User key">
            <button class="toggle-pw" onclick="togglePw('pushover_user')">Show</button>
          </div></div>
      </div>
      <div class="s-section">
        <h3>General</h3>
        <div class="field"><label>Poll Interval (seconds)</label>
          <input type="number" id="poll_interval" min="60" max="3600">
          <span class="hint">Min 60s.</span></div>
        <div class="field"><label>History Retention (days)</label>
          <input type="number" id="history_retention_days" min="1" max="365">
          <span class="hint">Cards older than this are pruned automatically.</span></div>
      </div>
    </div>
    <div class="s-footer">
      <button class="btn-save" id="save-btn" onclick="saveSettings()">Save Settings</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const ROLE = '__ROLE__';
const USERNAME = '__USERNAME__';
let mediaHistory = [], currentFilter = 'all';

// Load logo if available
(function() {
  var img = new Image();
  img.onload = function() {
    var el = document.getElementById('site-logo');
    var nm = document.getElementById('site-name');
    if (el) { img.style.cssText='height:48px;object-fit:contain;max-width:200px'; el.appendChild(img); }
    if (nm) nm.style.display='none';
  };
  img.src = '/logo.png';
})();

// ── history ──────────────────────────────────────────────────────────────────
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

function fmtShort(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, {month:'short',day:'numeric'});
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function render() {
  const items = currentFilter === 'all' ? mediaHistory : mediaHistory.filter(h => h.type === currentFilter);
  document.getElementById('count').textContent = items.length + ' item' + (items.length !== 1 ? 's' : '');
  const grid = document.getElementById('grid');
  if (!items.length) { grid.innerHTML = '<div class="empty">No additions yet</div>'; return; }
  grid.innerHTML = [...items].reverse().map(h => {
    const icon = h.type === 'movie' ? '🎬' : h.type === 'episode' ? '🎞️' : '📺';
    const tags = (h.genres||[]).map(g => '<span class="tag">'+esc(g)+'</span>').join('');
    const folder  = h.folder  ? '<span class="tag folder">'+esc(h.folder)+'</span>' : '';
    const network = h.network ? '<span class="tag network">'+esc(h.network)+'</span>' : '';
    const seasons = h.seasons ? '<span class="tag">'+h.seasons+' season'+(h.seasons>1?'s':'')+'</span>' : '';
    const epCode  = h.episode_code ? '<div class="ep-code">'+esc(h.episode_code)+(h.episode_title?' &middot; '+esc(h.episode_title):'')+'</div>' : '';
    const sub = h.type==='episode' ? '' : (h.year||'');
    return '<div class="card"><div class="card-header"><div class="type-icon '+h.type+'">'+icon+'</div>'
      +'<div><div class="card-title">'+esc(h.title)+'</div>'
      +(epCode||(sub?'<div class="card-year">'+sub+'</div>':''))+'</div></div>'
      +((tags||folder||network||seasons)?'<div class="tags">'+tags+folder+network+seasons+'</div>':'')
      +'<div class="card-footer"><span class="added-at">'+fmt(h.added_at)+'</span>'
      +'<span class="type-label '+h.type+'">'+h.type+'</span></div></div>';
  }).join('');
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    render();
  });
});

// Hide gear for non-admins
if (ROLE !== 'admin') {
  const g = document.getElementById('gear-btn');
  if (g) g.parentElement.style.display = 'none';
}

// ── settings ─────────────────────────────────────────────────────────────────
const SFIELDS = ['radarr_url','radarr_api_key','sonarr_url','sonarr_api_key',
                 'pushover_token','pushover_user','poll_interval','history_retention_days'];

function openSettings() {
  if (ROLE !== 'admin') return;
  document.getElementById('overlay').classList.add('open');
  _loadSettingsData();
}

async function _loadSettingsData() {
  try {
    const [sr, ur] = await Promise.all([fetch('/api/settings'), fetch('/api/users')]);
    if (sr.status === 401) { location.href = '/login'; return; }
    if (!sr.ok) { showToast('Failed to load settings ('+sr.status+')', 'error'); return; }
    const s = await sr.json();
    SFIELDS.forEach(k => { const el = document.getElementById(k); if (el) el.value = s[k]||''; });
    if (ur.ok) { const ud = await ur.json(); renderUsers(ud.users, ud.pending_count); }
    document.getElementById('users-section').style.display = '';
  } catch(err) {
    showToast('Error loading settings: ' + err.message, 'error');
    console.error(err);
  }
}

function closeSettings() { document.getElementById('overlay').classList.remove('open'); }
function maybeClose(e) { if (e.target === document.getElementById('overlay')) closeSettings(); }

function togglePw(id) {
  const el = document.getElementById(id), btn = el.nextElementSibling;
  if (el.type==='password'){el.type='text';btn.textContent='Hide';}
  else{el.type='password';btn.textContent='Show';}
}

async function saveSettings() {
  const btn = document.getElementById('save-btn');
  btn.disabled=true; btn.textContent='Saving…';
  const payload = {};
  SFIELDS.forEach(k => { const el=document.getElementById(k); if(el) payload[k]=el.type==='number'?Number(el.value):el.value; });
  try {
    const r = await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if (r.ok) { showToast('Settings saved','success'); closeSettings(); }
    else showToast('Save failed','error');
  } catch(e) { showToast('Save failed: '+e,'error'); }
  btn.disabled=false; btn.textContent='Save Settings';
}

// ── user management ───────────────────────────────────────────────────────────
// Use data-* attributes to avoid quote-nesting issues in inline onclick handlers
function _btnApprove(id, role) {
  return '<button class="ubtn ok" data-id="'+id+'" data-role="'+role+'" onclick="_onApprove(this)">'+role.charAt(0).toUpperCase()+role.slice(1)+'</button>';
}
function _btnDeny(id) {
  return '<button class="ubtn danger" data-id="'+id+'" onclick="_onDeny(this)">Deny</button>';
}
function _btnRole(id, toRole, disabled) {
  return '<button class="ubtn" data-id="'+id+'" data-role="'+toRole+'" onclick="_onChangeRole(this)"'+(disabled?' disabled':'')+'>&#8594;'+toRole.charAt(0).toUpperCase()+toRole.slice(1)+'</button>';
}
function _btnDelete(id, disabled) {
  return '<button class="ubtn danger" data-id="'+id+'" onclick="_onDelete(this)"'+(disabled?' disabled':'')+'>Delete</button>';
}
function _onApprove(btn)     { approveUser(btn.dataset.id, btn.dataset.role); }
function _onDeny(btn)        { denyUser(btn.dataset.id); }
function _onChangeRole(btn)  { changeRole(btn.dataset.id, btn.dataset.role); }
function _onDelete(btn)      { deleteUser(btn.dataset.id); }

function renderUsers(users, pendingCount) {
  updatePendingBadge(pendingCount);
  const c = document.getElementById('users-list');
  const pending = users.filter(u => u.status==='pending');
  const active  = users.filter(u => u.status==='active');
  let html = '';
  if (pending.length) {
    html += '<div class="u-group pending-lbl">Pending Requests ('+pending.length+')</div>';
    pending.forEach(u => {
      html += '<div class="user-row pending">'
        +'<div class="u-info"><span class="uname">'+esc(u.username)+'</span>'
        +(u.note?'<span class="u-note">'+esc(u.note)+'</span>':'')
        +'<span class="u-time">'+fmtShort(u.requested_at)+'</span></div>'
        +'<div class="u-actions">'
        +_btnApprove(u.id,'admin')+_btnApprove(u.id,'viewer')+_btnDeny(u.id)
        +'</div></div>';
    });
  }
  if (active.length) {
    if (pending.length) html += '<div class="u-group">Active</div>';
    active.forEach(u => {
      const isMe = u.username === USERNAME;
      const other = u.role==='admin'?'viewer':'admin';
      html += '<div class="user-row'+(isMe?' me':'')+'"><div class="u-info">'
        +'<span class="uname">'+esc(u.username)+(isMe?'<span class="you-tag">you</span>':'')+'</span>'
        +'<span class="role-pill '+u.role+'">'+u.role+'</span></div>'
        +'<div class="u-actions">'
        +_btnRole(u.id, other, isMe)+_btnDelete(u.id, isMe)
        +'</div></div>';
    });
  }
  if (!users.length) html = '<div class="no-users">No users.</div>';
  c.innerHTML = html;
}

function updatePendingBadge(count) {
  const dot = document.getElementById('pending-dot');
  if (count > 0) { dot.textContent = count; dot.style.display='flex'; }
  else dot.style.display='none';
}

async function approveUser(id, role) {
  const r = await fetch('/api/users/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'active',role})});
  if (r.ok) { showToast('Approved as '+role,'success'); await reloadUsers(); }
  else showToast('Failed','error');
}

async function denyUser(id) {
  if (!confirm('Deny and remove this request?')) return;
  const r = await fetch('/api/users/'+id,{method:'DELETE'});
  if (r.ok) { showToast('Request denied','success'); await reloadUsers(); }
  else showToast('Failed','error');
}

async function changeRole(id, role) {
  const r = await fetch('/api/users/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({role})});
  if (r.ok) { showToast('Role updated','success'); await reloadUsers(); }
  else showToast((await r.json().catch(()=>({}))).error||'Failed','error');
}

async function deleteUser(id) {
  if (!confirm('Delete this user?')) return;
  const r = await fetch('/api/users/'+id,{method:'DELETE'});
  if (r.ok) { showToast('User deleted','success'); await reloadUsers(); }
  else showToast('Failed','error');
}

async function reloadUsers() {
  const r = await fetch('/api/users');
  if (r.ok) { const d = await r.json(); renderUsers(d.users, d.pending_count); }
}

function showAddUserForm() {
  document.getElementById('add-user-box').style.display='';
  document.getElementById('btn-add-user').style.display='none';
}
function cancelAddUser() {
  document.getElementById('add-user-box').style.display='none';
  document.getElementById('btn-add-user').style.display='';
  ['new-username','new-password'].forEach(id => document.getElementById(id).value='');
  document.getElementById('new-role').value='viewer';
}
async function submitAddUser() {
  const username = document.getElementById('new-username').value.trim();
  const password = document.getElementById('new-password').value;
  const role     = document.getElementById('new-role').value;
  if (!username||!password) { showToast('Username and password required','error'); return; }
  const r = await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,role})});
  if (r.ok) { showToast('User created','success'); cancelAddUser(); await reloadUsers(); }
  else { const e=await r.json().catch(()=>({})); showToast(e.error||'Failed','error'); }
}

// ── pending badge on page load ────────────────────────────────────────────────
async function checkPending() {
  if (ROLE !== 'admin') return;
  const r = await fetch('/api/users');
  if (r.ok) { const d = await r.json(); updatePendingBadge(d.pending_count); }
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show '+(type||'');
  setTimeout(() => t.className='toast', 3000);
}

load();
checkPending();
setInterval(() => { load(); checkPending(); }, 30000);
</script>
</body>
</html>"""


def build_html(role, username):
    return HTML.replace('__ROLE__', role).replace('__USERNAME__', username)


# ── media API helpers ─────────────────────────────────────────────────────────

def api_get(base_url, api_key, endpoint):
    req = urllib.request.Request(f'{base_url}/api/v3{endpoint}',
                                 headers={'X-Api-Key': api_key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def pushover_send(token, user, title, message):
    data = urllib.parse.urlencode({'token':token,'user':user,'title':title,'message':message}).encode()
    req = urllib.request.Request('https://api.pushover.net/1/messages.json', data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def load_state():
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else None


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def load_history():
    return json.loads(HISTORY_FILE.read_text()) if HISTORY_FILE.exists() else []


def append_history(entry):
    h = load_history(); h.append(entry)
    HISTORY_FILE.write_text(json.dumps(h))


def prune_history(retention_days):
    h = load_history()
    if not h: return
    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    kept = [e for e in h if datetime.fromisoformat(e['added_at'].replace('Z','+00:00')).timestamp() >= cutoff]
    if len(kept) < len(h):
        HISTORY_FILE.write_text(json.dumps(kept))
        log.info(f'Pruned {len(h)-len(kept)} old history entries.')


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ── check functions ───────────────────────────────────────────────────────────

def check_radarr(state, cfg):
    movies = api_get(cfg['radarr_url'], cfg['radarr_api_key'], '/movie')
    current_ids = {m['id'] for m in movies}
    seen_ids = set(state.get('radarr', []))
    if not state.get('radarr'):
        log.info(f'Radarr first run — recording {len(current_ids)} existing movies.')
        state['radarr'] = list(current_ids); return
    new_ids = current_ids - seen_ids
    if not new_ids: log.info('Radarr: no new movies.'); return
    for m in sorted([m for m in movies if m['id'] in new_ids], key=lambda m: m.get('title','')):
        title  = m.get('title','Unknown')
        year   = m.get('year','')
        genres = m.get('genres',[])[:3]
        folder = m.get('rootFolderPath','').rstrip('/').split('/')[-1]
        msg    = f'{title} ({year})'
        if genres: msg += f'\n{", ".join(genres)}'
        if folder: msg += f'\nAdded to: {folder}'
        log.info(f'New movie: {title} ({year})')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Movie Added', msg)
        append_history({'type':'movie','title':title,'year':year,'genres':genres,
                        'folder':folder or None,'network':None,'seasons':None,'added_at':now_iso()})
        time.sleep(0.5)
    state['radarr'] = list(seen_ids | new_ids)
    log.info(f'Radarr: notified for {len(new_ids)} new movie(s).')


def check_sonarr(state, cfg):
    series = api_get(cfg['sonarr_url'], cfg['sonarr_api_key'], '/series')
    current_ids = {s['id'] for s in series}
    seen_ids = set(state.get('sonarr', []))
    if not state.get('sonarr'):
        log.info(f'Sonarr first run — recording {len(current_ids)} existing series.')
        state['sonarr'] = list(current_ids); return
    new_ids = current_ids - seen_ids
    if not new_ids: log.info('Sonarr: no new series.'); return
    for s in sorted([s for s in series if s['id'] in new_ids], key=lambda s: s.get('title','')):
        title   = s.get('title','Unknown')
        year    = s.get('year','')
        genres  = s.get('genres',[])[:3]
        network = s.get('network','')
        seasons = s.get('seasonCount','')
        msg = f'{title} ({year})'
        if genres:  msg += f'\n{", ".join(genres)}'
        if network: msg += f'\n{network}'
        if seasons: msg += f' · {seasons} season(s)'
        log.info(f'New series: {title} ({year})')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Series Added', msg)
        append_history({'type':'series','title':title,'year':year,'genres':genres,
                        'folder':None,'network':network or None,'seasons':seasons or None,'added_at':now_iso()})
        time.sleep(0.5)
    state['sonarr'] = list(seen_ids | new_ids)
    log.info(f'Sonarr: notified for {len(new_ids)} new series.')


def check_sonarr_episodes(state, cfg):
    data = api_get(cfg['sonarr_url'], cfg['sonarr_api_key'],
                   '/history?pageSize=50&sortKey=date&sortDirection=descending'
                   '&includeSeries=true&includeEpisode=true')
    records = [r for r in data.get('records',[]) if r.get('eventType')=='downloadFolderImported']
    if not records: return
    last_id = state.get('sonarr_last_history_id')
    if last_id is None:
        state['sonarr_last_history_id'] = records[0]['id']
        log.info(f'Sonarr episodes first run — cursor at ID {records[0]["id"]}.'); return
    new_records = [r for r in records if r['id'] > last_id]
    if not new_records: log.info('Sonarr: no new episode downloads.'); return
    for r in reversed(new_records):
        series_title = (r.get('series') or {}).get('title','Unknown')
        ep      = r.get('episode') or {}
        season  = ep.get('seasonNumber')
        episode = ep.get('episodeNumber')
        ep_title = ep.get('title','')
        network  = (r.get('series') or {}).get('network','')
        ep_code  = f'S{season:02d}E{episode:02d}' if season is not None and episode is not None else ''
        msg = series_title
        if ep_code:  msg += f' {ep_code}'
        if ep_title: msg += f'\n{ep_title}'
        if network:  msg += f'\n{network}'
        log.info(f'New episode: {series_title} {ep_code}')
        pushover_send(cfg['pushover_token'], cfg['pushover_user'], 'New Episode Downloaded', msg)
        append_history({'type':'episode','title':series_title,'year':None,'genres':[],
                        'folder':None,'network':network or None,'seasons':None,
                        'episode_code':ep_code or None,'episode_title':ep_title or None,
                        'added_at':r.get('date', now_iso())})
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


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _session(self):
        return get_session(self.headers.get('Cookie', ''))

    def _require_login(self):
        s = self._session()
        if s is None:
            if self.path.startswith('/api/'):
                self._json(401, {'error': 'unauthorized'})
            else:
                self._redirect('/login')
        return s

    def _require_admin(self):
        s = self._require_login()
        if s is None: return None
        if s['role'] != 'admin':
            self._json(403, {'error': 'forbidden'})
            return None
        return s

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header('Location', loc)
        self.end_headers()

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, body, code=200):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n))

    def _read_form(self):
        n = int(self.headers.get('Content-Length', 0))
        return urllib.parse.parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.split('?')[0]
        qs   = self.path[len(path)+1:] if '?' in self.path else ''

        if path == '/logo.png':
            if LOGO_FILE.exists():
                data = LOGO_FILE.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', len(data))
                self.send_header('Cache-Control', 'max-age=3600')
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404); self.end_headers()

        elif path == '/setup':
            if has_active_admin(): self._redirect('/'); return
            self._html(build_setup())

        elif path == '/login':
            if has_active_admin() is False and not load_users():
                self._redirect('/setup'); return
            if not has_active_admin(): self._redirect('/setup'); return
            err = urllib.parse.parse_qs(qs).get('e', [None])[0]
            self._html(build_login(err))

        elif path == '/request':
            if not has_active_admin(): self._redirect('/setup'); return
            self._html(build_request())

        elif path == '/logout':
            invalidate_session(self.headers.get('Cookie', ''))
            self.send_response(302)
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'arrivalr_session=; Path=/; Max-Age=0')
            self.end_headers()

        elif path == '/api/history':
            s = self._require_login()
            if s is None: return
            self._json(200, load_history())

        elif path == '/api/settings':
            if self._require_admin() is None: return
            self._json(200, get_settings())

        elif path == '/api/users':
            if self._require_admin() is None: return
            users = load_users()
            self._json(200, {
                'users': [sanitize_user(u) for u in users],
                'pending_count': sum(1 for u in users if u['status'] == 'pending'),
            })

        elif path in ('/', '/index.html'):
            if not has_active_admin(): self._redirect('/setup'); return
            s = self._require_login()
            if s is None: return
            self._html(build_html(s['role'], s['username']))

        else:
            self.send_response(404); self.end_headers()

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        path = self.path.split('?')[0]

        if path == '/setup':
            if has_active_admin(): self._redirect('/'); return
            f = self._read_form()
            username = f.get('username', [''])[0].strip()
            password = f.get('password', [''])[0]
            confirm  = f.get('confirm',  [''])[0]
            if not _USER_RE.match(username):
                self._html(build_setup('inv_user')); return
            if len(password) < 8:
                self._html(build_setup('short_pw')); return
            if password != confirm:
                self._html(build_setup('mismatch')); return
            users = load_users()
            users.append({'id': secrets.token_hex(8), 'username': username,
                          'password_hash': hash_password(password),
                          'role': 'admin', 'status': 'active',
                          'created_at': now_iso(), 'requested_at': None, 'note': ''})
            save_users(users)
            log.info(f'First admin created: {username}')
            token = create_session(username, 'admin')
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie',
                f'arrivalr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
            self.end_headers()

        elif path == '/login':
            if not has_active_admin(): self._redirect('/setup'); return
            f = self._read_form()
            username = f.get('username', [''])[0].strip()
            password = f.get('password', [''])[0]
            users    = load_users()
            user = next((u for u in users
                         if u['username'].lower() == username.lower()
                         and u['status'] == 'active'), None)
            if user and check_password(password, user['password_hash']):
                token = create_session(user['username'], user['role'])
                log.info(f'Login: {user["username"]} ({user["role"]})')
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie',
                    f'arrivalr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
                self.end_headers()
            else:
                log.warning(f'Failed login: {username!r}')
                self._redirect('/login?e=bad_creds')

        elif path == '/request':
            if not has_active_admin(): self._redirect('/setup'); return
            f = self._read_form()
            username = f.get('username', [''])[0].strip()
            password = f.get('password', [''])[0]
            note     = f.get('note',     [''])[0].strip()[:200]
            if not _USER_RE.match(username):
                self._html(build_request('inv_user')); return
            if len(password) < 8:
                self._html(build_request('short_pw')); return
            users = load_users()
            if any(u['username'].lower() == username.lower() for u in users):
                self._html(build_request('taken')); return
            users.append({'id': secrets.token_hex(8), 'username': username,
                          'password_hash': hash_password(password),
                          'role': 'viewer', 'status': 'pending',
                          'created_at': None, 'requested_at': now_iso(), 'note': note})
            save_users(users)
            log.info(f'Access request: {username}')
            self._html(build_request(success=True))

        elif path == '/api/settings':
            if self._require_admin() is None: return
            save_settings(self._read_json())
            log.info('Settings updated via web UI.')
            self._json(200, {'ok': True})

        elif path == '/api/users':
            s = self._require_admin()
            if s is None: return
            body = self._read_json()
            username = body.get('username', '').strip()
            password = body.get('password', '')
            role     = body.get('role', 'viewer')
            if not _USER_RE.match(username):
                self._json(400, {'error': 'Invalid username format.'}); return
            if len(password) < 8:
                self._json(400, {'error': 'Password must be at least 8 characters.'}); return
            if role not in ('admin', 'viewer'):
                self._json(400, {'error': 'Role must be admin or viewer.'}); return
            users = load_users()
            if any(u['username'].lower() == username.lower() for u in users):
                self._json(409, {'error': 'Username already taken.'}); return
            new_user = {'id': secrets.token_hex(8), 'username': username,
                        'password_hash': hash_password(password),
                        'role': role, 'status': 'active',
                        'created_at': now_iso(), 'requested_at': None, 'note': ''}
            users.append(new_user)
            save_users(users)
            log.info(f'User created by {s["username"]}: {username} ({role})')
            self._json(201, {'ok': True, 'user': sanitize_user(new_user)})

        else:
            self.send_response(404); self.end_headers()

    # ── PATCH ─────────────────────────────────────────────────────────────────

    def do_PATCH(self):
        m = _USER_PATH_RE.match(self.path.split('?')[0])
        if not m: self.send_response(404); self.end_headers(); return
        s = self._require_admin()
        if s is None: return
        user_id = m.group(1)
        body    = self._read_json()
        users   = load_users()
        user    = next((u for u in users if u['id'] == user_id), None)
        if user is None:
            self._json(404, {'error': 'User not found.'}); return
        if 'role' in body:
            if user['username'] == s['username']:
                self._json(400, {'error': 'Cannot change your own role.'}); return
            if body['role'] not in ('admin', 'viewer'):
                self._json(400, {'error': 'Invalid role.'}); return
            user['role'] = body['role']
        if 'status' in body and body['status'] in ('active', 'disabled'):
            if body['status'] == 'active' and not user.get('created_at'):
                user['created_at'] = now_iso()
            user['status'] = body['status']
        save_users(users)
        log.info(f'{s["username"]} updated user {user["username"]}: {body}')
        self._json(200, {'ok': True})

    # ── DELETE ────────────────────────────────────────────────────────────────

    def do_DELETE(self):
        m = _USER_PATH_RE.match(self.path.split('?')[0])
        if not m: self.send_response(404); self.end_headers(); return
        s = self._require_admin()
        if s is None: return
        user_id = m.group(1)
        users   = load_users()
        user    = next((u for u in users if u['id'] == user_id), None)
        if user is None:
            self._json(404, {'error': 'User not found.'}); return
        if user['username'] == s['username']:
            self._json(400, {'error': 'Cannot delete yourself.'}); return
        save_users([u for u in users if u['id'] != user_id])
        log.info(f'{s["username"]} deleted user {user["username"]}')
        self._json(200, {'ok': True})


# ── server ────────────────────────────────────────────────────────────────────

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
