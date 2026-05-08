import os
import json
import time
import logging
import threading
import urllib.request
import urllib.parse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

RADARR_URL = os.environ['RADARR_URL'].rstrip('/')
RADARR_API_KEY = os.environ['RADARR_API_KEY']
SONARR_URL = os.environ['SONARR_URL'].rstrip('/')
SONARR_API_KEY = os.environ['SONARR_API_KEY']
PUSHOVER_TOKEN = os.environ['PUSHOVER_TOKEN']
PUSHOVER_USER = os.environ['PUSHOVER_USER']
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 300))
HISTORY_RETENTION_DAYS = int(os.environ.get('HISTORY_RETENTION_DAYS', 30))
STATE_FILE = Path(os.environ.get('STATE_FILE', '/data/seen.json'))
HISTORY_FILE = Path('/data/history.json')
WEB_PORT = int(os.environ.get('WEB_PORT', 7070))

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Media Monitor</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f0f0f; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; }
  header { background: #1a1a2e; border-bottom: 1px solid #2a2a4a; padding: 20px 32px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 1.4rem; font-weight: 600; color: #fff; }
  header .subtitle { font-size: 0.85rem; color: #888; margin-top: 2px; }
  .badge { background: #e50914; color: #fff; font-size: 0.7rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.5px; }
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
  .empty { grid-column: 1/-1; text-align: center; padding: 80px 20px; color: #444; }
  .empty svg { width: 48px; height: 48px; margin-bottom: 16px; opacity: 0.3; }
  #refresh-indicator { width: 8px; height: 8px; background: #2ecc71; border-radius: 50%; animation: pulse 2s infinite; margin-left: 8px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
</style>
</head>
<body>
<header>
  <div>
    <div style="display:flex;align-items:center;gap:10px">
      <h1>Media Monitor</h1>
      <span class="badge">LIVE</span>
      <div id="refresh-indicator"></div>
    </div>
    <div class="subtitle">Radarr &amp; Sonarr additions</div>
  </div>
</header>
<div class="controls">
  <button class="filter-btn active" data-filter="all">All</button>
  <button class="filter-btn" data-filter="movie">Movies</button>
  <button class="filter-btn" data-filter="series">Series</button>
  <span class="count" id="count"></span>
</div>
<div class="grid" id="grid"></div>
<script>
  let history = [], filter = 'all';

  async function load() {
    try {
      const r = await fetch('/api/history');
      history = await r.json();
      render();
    } catch(e) { console.error(e); }
  }

  function fmt(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {month:'short',day:'numeric',year:'numeric'})
      + ' ' + d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
  }

  function render() {
    const items = filter === 'all' ? history : history.filter(h => h.type === filter);
    document.getElementById('count').textContent = items.length + ' item' + (items.length !== 1 ? 's' : '');
    const grid = document.getElementById('grid');
    if (!items.length) {
      grid.innerHTML = '<div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M3.375 19.5h17.25m-17.25 0a1.125 1.125 0 01-1.125-1.125M3.375 19.5h7.5c.621 0 1.125-.504 1.125-1.125m-9.75 0V5.625m0 12.75v-1.5c0-.621.504-1.125 1.125-1.125m18.375 2.625V5.625m0 12.75c0 .621-.504 1.125-1.125 1.125m1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125m0 3.75h-7.5A1.125 1.125 0 0112 18.375m9.75-12.75c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125m19.5 0v1.5c0 .621-.504 1.125-1.125 1.125M2.25 5.625v1.5c0 .621.504 1.125 1.125 1.125m0 0h17.25m-17.25 0c0 .621.504 1.125 1.125 1.125h17.25"/></svg><div>No additions yet</div></div>';
      return;
    }
    grid.innerHTML = [...items].reverse().map(h => {
      const icon = h.type === 'movie' ? '🎬' : '📺';
      const tags = (h.genres||[]).map(g => `<span class="tag">${g}</span>`).join('');
      const folder = h.folder ? `<span class="tag folder">${h.folder}</span>` : '';
      const network = h.network ? `<span class="tag network">${h.network}</span>` : '';
      const seasons = h.seasons ? `<span class="tag">${h.seasons} season${h.seasons>1?'s':''}</span>` : '';
      return `<div class="card">
        <div class="card-header">
          <div class="type-icon ${h.type}">${icon}</div>
          <div>
            <div class="card-title">${h.title}</div>
            <div class="card-year">${h.year||''}</div>
          </div>
        </div>
        ${tags||folder||network||seasons ? `<div class="tags">${tags}${folder}${network}${seasons}</div>` : ''}
        <div class="card-footer">
          <span class="added-at">${fmt(h.added_at)}</span>
          <span class="type-label ${h.type}">${h.type}</span>
        </div>
      </div>`;
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

  load();
  setInterval(load, 30000);
</script>
</body>
</html>"""


def api_get(base_url, api_key, endpoint):
    req = urllib.request.Request(
        f'{base_url}/api/v3{endpoint}',
        headers={'X-Api-Key': api_key}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def pushover_send(title, message):
    data = urllib.parse.urlencode({
        'token': PUSHOVER_TOKEN,
        'user': PUSHOVER_USER,
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


def prune_history():
    history = load_history()
    if not history:
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (HISTORY_RETENTION_DAYS * 86400)
    kept = [e for e in history if datetime.fromisoformat(e['added_at'].replace('Z', '+00:00')).timestamp() >= cutoff]
    if len(kept) < len(history):
        removed = len(history) - len(kept)
        HISTORY_FILE.write_text(json.dumps(kept))
        log.info(f'Pruned {removed} history entry/entries older than {HISTORY_RETENTION_DAYS} days.')


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def check_radarr(state):
    movies = api_get(RADARR_URL, RADARR_API_KEY, '/movie')
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
        pushover_send('New Movie Added', msg)
        append_history({
            'type': 'movie',
            'title': title,
            'year': year,
            'genres': genres,
            'folder': folder or None,
            'network': None,
            'seasons': None,
            'added_at': now_iso(),
        })
        time.sleep(0.5)

    state['radarr'] = list(seen_ids | new_ids)
    log.info(f'Radarr: notified for {len(new_movies)} new movie(s).')


def check_sonarr(state):
    series = api_get(SONARR_URL, SONARR_API_KEY, '/series')
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
        pushover_send('New Series Added', msg)
        append_history({
            'type': 'series',
            'title': title,
            'year': year,
            'genres': genres,
            'folder': None,
            'network': network or None,
            'seasons': seasons or None,
            'added_at': now_iso(),
        })
        time.sleep(0.5)

    state['sonarr'] = list(seen_ids | new_ids)
    log.info(f'Sonarr: notified for {len(new_series)} new series.')


def check():
    state = load_state() or {}
    check_radarr(state)
    check_sonarr(state)
    save_state(state)
    prune_history()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/api/history':
            data = json.dumps(load_history()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
        elif self.path in ('/', '/index.html'):
            data = HTML.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()


def run_web():
    server = HTTPServer(('0.0.0.0', WEB_PORT), Handler)
    log.info(f'Web UI running on port {WEB_PORT}')
    server.serve_forever()


def main():
    log.info(f'Media monitor starting — polling every {POLL_INTERVAL}s')
    threading.Thread(target=run_web, daemon=True).start()
    while True:
        try:
            check()
        except Exception as e:
            log.error(f'Check failed: {e}')
        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
