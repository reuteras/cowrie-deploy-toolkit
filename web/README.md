# Cowrie SSH Session Playback Web Service

A Flask-based web application for viewing and replaying SSH sessions captured by Cowrie honeypot.

## Features

- **Dashboard** - Overview of attack statistics, top countries, credentials, and commands
- **Session Browser** - List all sessions with filtering and search
- **Session Details** - View full session info including IP, location, credentials, and commands
- **TTY Playback** - Watch recorded SSH sessions with asciinema-player
- **Downloads Viewer** - Browse captured malware with VirusTotal links

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Web Service Architecture                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Docker Network (cowrie-internal)                               │
│  ┌─────────────────────┐    ┌─────────────────────────────────┐ │
│  │   cowrie            │    │   cowrie-web                    │ │
│  │   (honeypot)        │    │   (session viewer)              │ │
│  │   Port 22 → 2222    │    │   Port 5000 (internal)          │ │
│  └──────────┬──────────┘    └──────────────┬──────────────────┘ │
│             │                              │                     │
│             ▼                              ▼                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              cowrie-var volume (shared)                  │   │
│  │  ├── log/cowrie/cowrie.json   (session events)           │   │
│  │  ├── lib/cowrie/tty/          (TTY recordings)           │   │
│  │  └── lib/cowrie/downloads/    (malware samples)          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Security

**The web service is NOT exposed to the public internet.**

Access methods:
1. **SSH Tunnel** (recommended for occasional access)
2. **Tailscale** (recommended for regular access)

### SSH Tunnel Access

```bash
# Create SSH tunnel from your local machine
ssh -p 2222 -L 5000:localhost:5000 root@<HONEYPOT_IP>

# Then access in browser
open http://localhost:5000
```

### Tailscale Access

1. Create a Tailscale auth key at <https://login.tailscale.com/admin/settings/keys>
2. Add to your `master-config.toml`:

```toml
[tailscale]
enabled = true
authkey = "tskey-auth-..."

[web_dashboard]
enabled = true
base_url = "https://honeypot-dashboard.your-tailnet.ts.net"
```

3. After deployment, access via: `https://honeypot-dashboard.<your-tailnet>.ts.net`

**Note**: Tailscale configuration is now centralized in the `[tailscale]` section and used for both management SSH and web dashboard access.

## Configuration

### Environment Variables

| Variable               | Default                                 | Description                   |
| ---------------------- | --------------------------------------- | ----------------------------- |
| `COWRIE_LOG_PATH`      | `/cowrie-data/log/cowrie/cowrie.json`   | Path to Cowrie JSON log       |
| `COWRIE_TTY_PATH`      | `/cowrie-data/lib/cowrie/tty`           | Path to TTY recordings        |
| `COWRIE_DOWNLOAD_PATH` | `/cowrie-data/lib/cowrie/downloads`     | Path to downloaded files      |
| `GEOIP_DB_PATH`        | `/cowrie-data/geoip/GeoLite2-City.mmdb` | Path to GeoIP database        |
| `BASE_URL`             | ``                                      | Base URL for links in reports |

### Enabling TTY Recording

TTY recording must be enabled in Cowrie's configuration. The deployment script automatically enables this when web dashboard is configured.

In `cowrie.cfg`:
```ini
[output_playlog]
enabled = true
logfile = var/lib/cowrie/tty/{session}_{timestamp}.log
```

## API Endpoints

| Endpoint                          | Description               |
| --------------------------------- | ------------------------- |
| `GET /`                           | Dashboard with statistics |
| `GET /sessions`                   | Session list with filters |
| `GET /session/<id>`               | Session details           |
| `GET /session/<id>/playback`      | TTY playback page         |
| `GET /downloads`                  | Downloaded files list     |
| `GET /api/stats`                  | JSON stats for dashboard  |
| `GET /api/sessions`               | JSON session list         |
| `GET /api/session/<id>/asciicast` | Asciicast data for player |

## Local Development

```bash
# Install dependencies
cd web
pip install -r requirements.txt

# Set environment variables
export COWRIE_LOG_PATH=/path/to/cowrie.json
export COWRIE_TTY_PATH=/path/to/tty

# Run development server
python app.py
```

## Docker Build

```bash
# Build image
cd web
docker build -t cowrie-web:local .

# Run standalone
docker run -d \
  -p 5000:5000 \
  -v /var/lib/docker/volumes/cowrie-var/_data:/cowrie-data:ro \
  cowrie-web:local
```

## Integration with Daily Reports

When web dashboard is enabled, daily email reports include links to session details:

```text
Most Active Sessions:
- Session abc123... (45 commands) → https://honeypot-dashboard.ts.net/session/abc123
- Session def456... (32 commands) → https://honeypot-dashboard.ts.net/session/def456
```

Configure the base URL in `master-config.toml`:

```toml
[web_dashboard]
enabled = true
base_url = "https://honeypot-dashboard.your-tailnet.ts.net"
```

## Screenshots

### Dashboard
![Dashboard](docs/dashboard.png)

### Session Playback
![Playback](docs/playback.png)

### Session Details
![Details](docs/details.png)

## Troubleshooting

### No sessions showing
- Check if Cowrie is logging: `tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json`
- Verify volume mount is correct

### TTY playback not working
- Ensure `[output_playlog]` is enabled in cowrie.cfg
- Check if TTY files exist: `ls /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/tty/`

### GeoIP not working
- Verify MaxMind database exists: `ls /opt/cowrie/geoip/`
- Check GeoIP auto-update cron: `crontab -l | grep geoip`
