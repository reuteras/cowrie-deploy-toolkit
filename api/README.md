# Cowrie API

FastAPI service for accessing Cowrie honeypot data remotely. Enables multi-host dashboard deployments where the dashboard runs on a separate server from the honeypot.

## Features

- **RESTful API** - Standard HTTP endpoints for accessing Cowrie data
- **Read-Only Access** - All endpoints are read-only for security
- **GeoIP Integration** - IP geolocation and ASN lookup
- **VirusTotal Integration** - Malware analysis (if API key configured)
- **Session Replay** - TTY recording retrieval
- **Statistics** - Dashboard metrics and analytics
- **Security Hardened** - Runs with dropped capabilities and read-only filesystem

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Single-Host Deployment                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                          │
│  │   Dashboard  │──────reads directly────────┐             │
│  │  (Flask App) │                             │             │
│  └──────────────┘                             ▼             │
│                                        ┌─────────────┐      │
│                                        │ Cowrie Data │      │
│                                        │  (volumes)  │      │
│                                        └─────────────┘      │
│                                                ▲             │
│                                                │             │
│                                        ┌───────┴──────┐     │
│                                        │    Cowrie    │     │
│                                        │  (honeypot)  │     │
│                                        └──────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Multi-Host Deployment                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Server 1 (Dashboard Host)          Server 2 (Honeypot)    │
│  ┌──────────────┐                   ┌──────────────┐       │
│  │   Dashboard  │───API calls───────│  Cowrie API  │       │
│  │  (Flask App) │  (via Tailscale)  │   (FastAPI)  │       │
│  └──────────────┘                   └──────┬───────┘       │
│                                             │               │
│                                             │               │
│                                     ┌───────▼───────┐       │
│                                     │ Cowrie Data   │       │
│                                     │  (volumes)    │       │
│                                     └───────▲───────┘       │
│                                             │               │
│                                     ┌───────┴───────┐       │
│                                     │    Cowrie     │       │
│                                     │  (honeypot)   │       │
│                                     └───────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Health Check

**GET** `/api/v1/health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "mode": "production"
}
```

### Sessions

**GET** `/api/v1/sessions`

List sessions with optional filtering and pagination.

**Query Parameters:**
- `hours` (int, default: 168) - Time range in hours
- `limit` (int, default: 100) - Maximum results
- `offset` (int, default: 0) - Pagination offset
- `src_ip` (string, optional) - Filter by source IP
- `username` (string, optional) - Filter by username
- `start_time` (string, optional) - Filter by start time (ISO format)
- `end_time` (string, optional) - Filter by end time (ISO format)

**Response:**
```json
{
  "total": 250,
  "sessions": [
    {
      "id": "abc123",
      "src_ip": "192.0.2.1",
      "start_time": "2025-12-26T10:30:00Z",
      "end_time": "2025-12-26T10:35:00Z",
      "duration": 300,
      "username": "root",
      "password": "admin",
      "login_success": true,
      "commands": [...],
      "downloads": [...],
      "geo": {
        "country": "United States",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "asn": 15169,
        "asn_org": "Google LLC"
      }
    }
  ]
}
```

**GET** `/api/v1/sessions/{session_id}`

Get a specific session by ID.

**Response:**
```json
{
  "id": "abc123",
  "src_ip": "192.0.2.1",
  "start_time": "2025-12-26T10:30:00Z",
  "commands": [
    {
      "command": "ls -la",
      "timestamp": "2025-12-26T10:31:00Z"
    }
  ],
  ...
}
```

**GET** `/api/v1/sessions/{session_id}/tty`

Get TTY recording for session playback (asciicast format).

**Response:**
```json
{
  "version": 1,
  "width": 120,
  "height": 30,
  "duration": 45.3,
  "command": "/bin/bash",
  "title": "Cowrie Recording",
  "stdout": [
    [0.0, "root@dmz-web01:~# "],
    [0.1, "ls\r\n"],
    ...
  ]
}
```

### Downloads

**GET** `/api/v1/downloads`

List downloaded malware files.

**Query Parameters:**
- `hours` (int, default: 168) - Time range
- `limit` (int, default: 100) - Maximum results
- `offset` (int, default: 0) - Pagination offset

**Response:**
```json
{
  "total": 15,
  "downloads": [
    {
      "shasum": "abc123...",
      "url": "http://malware.example/file.sh",
      "timestamp": "2025-12-26T10:35:00Z",
      "size": 4096,
      "file_type": "Shell Script",
      "file_category": "Script",
      "yara_matches": ["suspicious_bash", "network_scanner"],
      "vt_detections": 45,
      "vt_total": 70,
      "vt_threat_label": "trojan.generic"
    }
  ]
}
```

**GET** `/api/v1/downloads/{sha256}`

Get metadata for a specific download.

**GET** `/api/v1/downloads/{sha256}/file`

Download the raw malware file.

**Response:** Binary file content

### Statistics

**GET** `/api/v1/stats/overview`

Get dashboard statistics.

**Query Parameters:**
- `hours` (int, default: 24) - Time range

**Response:**
```json
{
  "total_sessions": 150,
  "unique_ips": 45,
  "sessions_with_commands": 30,
  "total_downloads": 12,
  "unique_downloads": 8,
  "top_countries": [
    ["United States", 50],
    ["China", 30],
    ["Russia", 20]
  ],
  "top_credentials": [
    ["root:admin", 25],
    ["admin:admin", 15]
  ],
  "top_commands": [
    ["ls -la", 10],
    ["wget http://...", 5]
  ],
  "ip_locations": [...],
  "hourly_activity": [...],
  "vt_stats": {
    "total_scanned": 8,
    "total_malicious": 6,
    "avg_detection_rate": 65.5,
    "total_threat_families": 4
  }
}
```

### Threat Intelligence

**GET** `/api/v1/threat/ip/{ip_address}`

Get threat intelligence for an IP address.

**Response:**
```json
{
  "ip": "192.0.2.1",
  "geo": {
    "country": "United States",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "asn": 15169,
    "asn_org": "Google LLC"
  },
  "greynoise": {
    "classification": "malicious",
    "message": "Known SSH scanner",
    "timestamp": "2025-12-26T10:30:00Z"
  }
}
```

## Configuration

### Single-Host Mode (Internal Network Only)

Default configuration - API only accessible within Docker network:

```toml
[api]
enabled = true
expose_via_tailscale = false
```

The API runs on `http://cowrie-api:8000` (internal Docker network).

### Multi-Host Mode (Exposed via Tailscale)

For remote dashboard access:

```toml
[api]
enabled = true
expose_via_tailscale = true
tailscale_api_hostname = "cowrie-api"
```

The API is exposed at `https://cowrie-api.<tailscale_domain>` with automatic mTLS via Tailscale.

## Security

### Network Isolation

**Single-Host:**
- API only accessible within Docker internal network
- No external exposure
- No authentication needed (internal only)

**Multi-Host:**
- API exposed via Tailscale VPN only
- Tailscale provides automatic mTLS
- Access controlled by Tailscale ACLs
- No public internet exposure

### Container Hardening

The API container runs with:
- **Read-only volumes** - All Cowrie data mounted read-only
- **Dropped capabilities** - `cap_drop: ALL`
- **No new privileges** - `no-new-privileges:true`
- **Read-only filesystem** - Container filesystem is read-only
- **Limited tmpfs** - Small temporary filesystem for cache
- **Non-root user** - Runs as `apiuser` (UID 1000)

### Data Access

- All endpoints are **read-only**
- Cannot modify Cowrie data
- Cannot access honeypot SSH
- Cannot execute commands on server

## Environment Variables

The API container uses these environment variables:

```bash
# Cowrie data paths
COWRIE_LOG_PATH=/cowrie-data/log/cowrie/cowrie.json
COWRIE_TTY_PATH=/cowrie-data/lib/cowrie/tty
COWRIE_DOWNLOADS_PATH=/cowrie-data/lib/cowrie/downloads

# GeoIP databases
GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb
GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb

# Cache databases
YARA_CACHE_DB=/opt-cowrie-data/yara-cache.db
CANARY_WEBHOOKS_DB=/opt-cowrie-data/canary-webhooks.db
IPLOCK_DB=/cowrie-data/lib/cowrie/iplock.db

# API keys (optional)
VIRUSTOTAL_API_KEY=<your_key>
ABUSEIPDB_API_KEY=<your_key>

# Logging
LOG_LEVEL=INFO
```

## Deployment Examples

### Example 1: Single-Host with API (Local Dashboard)

```toml
[api]
enabled = true
expose_via_tailscale = false

[web_dashboard]
enabled = true
mode = "local"  # Dashboard reads files directly
```

### Example 2: Multi-Host Dashboard via API

**Honeypot Server (master-config.toml):**
```toml
[api]
enabled = true
expose_via_tailscale = true
tailscale_api_hostname = "cowrie-api"

[web_dashboard]
enabled = false  # No dashboard on honeypot server
```

**Dashboard Server (separate deployment):**
```toml
[web_dashboard]
enabled = true
mode = "remote"
api_base_url = "https://cowrie-api.tail9e5e41.ts.net"
```

## Manual Testing

### Via curl (Internal Network)

From within the honeypot server:

```bash
# Health check
curl http://cowrie-api:8000/api/v1/health

# Get sessions
curl "http://cowrie-api:8000/api/v1/sessions?limit=5"

# Get stats
curl "http://cowrie-api:8000/api/v1/stats/overview?hours=24"

# Get session TTY
curl http://cowrie-api:8000/api/v1/sessions/{session_id}/tty
```

### Via curl (Tailscale)

From any device on your Tailscale network:

```bash
# Health check
curl https://cowrie-api.tail9e5e41.ts.net/api/v1/health

# Get sessions (with auth via Tailscale)
curl https://cowrie-api.tail9e5e41.ts.net/api/v1/sessions
```

## Troubleshooting

### API Not Starting

Check container logs:
```bash
ssh -p 2222 root@<server> 'docker compose logs cowrie-api'
```

Common issues:
- Volume mount paths incorrect
- GeoIP databases missing
- Insufficient permissions

### API Not Accessible

**Single-Host Mode:**
- Check Docker network: `docker network inspect cowrie-internal`
- Verify container is running: `docker compose ps`

**Multi-Host Mode:**
- Verify Tailscale Serve is configured
- Check Tailscale status: `tailscale status`
- Test connectivity: `curl https://cowrie-api.<domain>/api/v1/health`

### Performance Issues

The API is designed for read-only access with minimal overhead:
- Sessions are parsed on-demand from JSON logs
- GeoIP lookups are cached in memory
- VirusTotal results are cached in SQLite

For very large datasets:
- Use pagination (`limit` and `offset`)
- Filter by time range (`hours`)
- Consider archiving old logs

## Development

### Running Locally

```bash
cd api
pip install -r requirements.txt
export COWRIE_LOG_PATH=/path/to/cowrie.json
export COWRIE_TTY_PATH=/path/to/tty
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### Testing

```bash
# Install test dependencies
pip install pytest httpx

# Run tests (when implemented)
pytest tests/
```

### Adding New Endpoints

1. Create new route file in `api/routes/`
2. Import and register in `api/app.py`
3. Update this README with documentation
4. Add corresponding method to `web/datasource.py`

## Version History

- **v2.1.0** (2025-12-26) - Initial API implementation
  - Session endpoints
  - Download endpoints
  - Statistics endpoints
  - Threat intelligence endpoints
  - Health check
  - Docker deployment support
  - Tailscale integration

## Related Documentation

- [Dashboard DataSource Abstraction](../web/datasource.py) - Client library for API access
- [Deployment Guide](../CLAUDE.md) - Full deployment instructions
- [Migration Guide](../MIGRATION.md) - Upgrading from v2.0 to v2.1
