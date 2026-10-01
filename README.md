# BreachChecker 🔍

Live: **https://breach.miors.art**

Self-hosted data-breach lookup — check if an **email**, **username**, or **phone number** appears in known breaches & infostealer logs.

## Features
- **Email** lookup — XposedOrNot (740+ breaches) + LeakCheck + Hudson Rock
- **Username** lookup — LeakCheck (67+ sources) + Hudson Rock
- **Phone** lookup — LeakCheck (international format)
- Hudson Rock **infostealer infection** detection (true-positive logic, no false alarms)
- Aggregated **risk score 0–100** with label
- Per-breach: source name + date; source chips show what was queried
- 1-hour result cache + (configurable) per-IP rate limit
- "What to do now" checklist (change passwords, 2FA, sessions)

## Stack
Pure **Python stdlib** (`http.server`, no dependencies) + single-page HTML/CSS/JS.
Deployed as systemd unit behind Cloudflare Tunnel. No API keys required.

## Run yourself
```bash
python3 server.py            # listens on 127.0.0.1:7430
# then reverse-proxy port 7430 with TLS (nginx/caddy/CF tunnel)
```

## Files
- `server.py` — backend: source queries, scoring, cache, rate-limit
- `index.html` — dark/gold single-page frontend
