# Radarr / Sonarr Monitor

A lightweight Docker app that watches Radarr and Sonarr for new additions and sends a push notification via Pushover. Includes a web UI showing a live history of everything that's been added.

## Features

- Polls Radarr and Sonarr every 5 minutes (configurable)
- Sends a Pushover notification for each new movie or series
- Web UI at port `7070` showing all additions with title, year, genres, and timestamp
- Filter view by Movies, Series, or All
- Persists history across container restarts
- Zero external Python dependencies — stdlib only

## Screenshots

### Web UI
Cards update every 30 seconds automatically. Filter buttons at the top let you narrow by type.

```
┌─────────────────────────────────────────────────┐
│  Media Monitor                          [LIVE] ● │
│  Radarr & Sonarr additions                       │
├─────────────────────────────────────────────────┤
│  [All]  [Movies]  [Series]          42 items     │
├──────────────────┬──────────────────────────────┤
│ 🎬 Deadpool      │ 📺 1883                       │
│    2016          │    2021                       │
│    Action        │    Drama, Western             │
│    [marvel]      │    Paramount+  · 2 seasons    │
│    May 7, 23:50  │    May 7, 23:56               │
└──────────────────┴──────────────────────────────┘
```

### Pushover Notification
```
New Movie Added
Deadpool (2016)
Action, Comedy
Added to: marvel
```

## Requirements

- Docker + Docker Compose
- [Radarr](https://radarr.video) instance with API access
- [Sonarr](https://sonarr.tv) instance with API access
- [Pushover](https://pushover.net) account ($5 one-time, iOS/Android)

## Setup

### 1. Clone the repo

```bash
git clone git@gitlab.com:rapdragon/radarr-monitor.git
cd radarr-monitor
```

### 2. Configure environment

Edit `docker-compose.yml` and fill in your values:

```yaml
environment:
  RADARR_URL: http://<radarr-ip>:7878
  RADARR_API_KEY: <your-radarr-api-key>
  SONARR_URL: http://<sonarr-ip>:8989
  SONARR_API_KEY: <your-sonarr-api-key>
  PUSHOVER_TOKEN: <your-pushover-app-token>
  PUSHOVER_USER: <your-pushover-user-key>
  POLL_INTERVAL: "300"   # seconds between checks
```

**Getting your API keys:**
- Radarr: Settings → General → API Key
- Sonarr: Settings → General → API Key

**Getting your Pushover keys:**
- User Key: [pushover.net](https://pushover.net) → your dashboard
- App Token: pushover.net → Your Applications → Create Application

### 3. Run

```bash
docker compose up -d
```

Web UI will be available at `http://<host>:7070`.

## Deploying on TrueNAS Scale

TrueNAS Scale doesn't pick up `docker-compose.yml` changes automatically. When updating:

1. Copy the updated `monitor.py` to the host
2. Restart the container from the GUI or via:
   ```bash
   docker restart radarr-monitor
   ```

To add new environment variables, edit the app in **Apps → radarr-monitor → Edit**.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `RADARR_URL` | required | Base URL of your Radarr instance |
| `RADARR_API_KEY` | required | Radarr API key |
| `SONARR_URL` | required | Base URL of your Sonarr instance |
| `SONARR_API_KEY` | required | Sonarr API key |
| `PUSHOVER_TOKEN` | required | Pushover application token |
| `PUSHOVER_USER` | required | Pushover user key |
| `POLL_INTERVAL` | `300` | Seconds between checks |
| `WEB_PORT` | `7070` | Port for the web UI |
| `STATE_FILE` | `/data/seen.json` | Path to state persistence file |

## Data

The container stores two files in `/data/`:

| File | Purpose |
|---|---|
| `seen.json` | Tracks all known movie/series IDs to detect new additions |
| `history.json` | Full log of every addition shown in the web UI |

Mount a volume at `/data/` to persist these across container recreations.

## How it works

On first run the monitor records all existing movies and series without sending notifications — this prevents a flood of alerts for your existing library. From that point on, any new ID that appears in Radarr or Sonarr triggers a Pushover notification and a history entry.
