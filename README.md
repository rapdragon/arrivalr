# Arrivalr

[![Build and Push to Docker Hub](https://github.com/rapdragon/arrivalr/actions/workflows/docker.yml/badge.svg)](https://github.com/rapdragon/arrivalr/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/rapdragon/arrivalr)](https://hub.docker.com/r/rapdragon/arrivalr)

A lightweight Docker app that watches Radarr and Sonarr for new additions and episode downloads, sending push notifications via Pushover. Includes a web UI showing a live history of everything that's been added.

## Features

- Polls Radarr and Sonarr every 5 minutes (configurable)
- Pushover notification for each new movie, series, or episode download
- Web UI at port `7070` with cards for every event — auto-refreshes every 30 seconds
- Filter view by Movies, Series, Episodes, or All
- History auto-prunes entries older than a configurable number of days (default 30)
- Persists history across container restarts
- Zero external Python dependencies — stdlib only

## Web UI

Cards update every 30 seconds automatically. Filter buttons at the top let you narrow by type.

```
┌──────────────────────────────────────────────────────┐
│  Media Monitor                             [LIVE] ●  │
│  Radarr & Sonarr additions                           │
├──────────────────────────────────────────────────────┤
│  [All]  [Movies]  [Series]  [Episodes]   42 items    │
├───────────────────┬──────────────────────────────────┤
│ 🎬 Deadpool       │ 🎞️ 9-1-1                         │
│    2016           │    S09E18                        │
│    Action, Comedy │    Panic                         │
│    [marvel]       │    Fox                           │
│    May 7, 23:50   │    May 8, 07:19                  │
└───────────────────┴──────────────────────────────────┘
```

## Pushover Notifications

```
New Movie Added          New Series Added         New Episode Downloaded
────────────────         ─────────────────        ──────────────────────
Deadpool (2016)          1883 (2021)              9-1-1 S09E18
Action, Comedy           Drama, Western           Panic
Added to: marvel         Paramount+ · 2 seasons   Fox
```

## Requirements

- Docker + Docker Compose
- [Radarr](https://radarr.video) instance with API access
- [Sonarr](https://sonarr.tv) instance with API access
- [Pushover](https://pushover.net) account ($5 one-time, iOS/Android)

## Setup

### 1. Clone the repo

```bash
git clone git@github.com:rapdragon/arrivalr.git
cd arrivalr
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
  POLL_INTERVAL: "300"
  HISTORY_RETENTION_DAYS: "30"
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

TrueNAS Scale doesn't pick up `docker-compose.yml` changes automatically. When updating the code:

1. Copy the updated `monitor.py` to the host
2. Restart the container:
   ```bash
   docker restart arrivalr
   ```

To change environment variables, edit the app in **Apps → arrivalr → Edit**.

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
| `HISTORY_RETENTION_DAYS` | `30` | Days to keep history entries before pruning |
| `WEB_PORT` | `7070` | Port for the web UI |
| `STATE_FILE` | `/data/seen.json` | Path to state persistence file |

## Data

The container stores two files in `/data/`:

| File | Purpose |
|---|---|
| `seen.json` | Tracks known movie/series IDs and the Sonarr history cursor |
| `history.json` | Full log of every event shown in the web UI |

Mount a volume at `/data/` to persist these across container recreations.

## How it works

On first run the monitor snapshots your existing Radarr library, Sonarr library, and Sonarr download history — no notifications are sent for anything that already exists. From that point on:

- A new movie in Radarr → **New Movie Added** notification
- A new series in Sonarr → **New Series Added** notification
- A `downloadFolderImported` event in Sonarr history → **New Episode Downloaded** notification

History entries older than `HISTORY_RETENTION_DAYS` are pruned automatically on each poll cycle.
