# Cowrie Honeypot Deployment Toolkit

## Project Overview

This project deploys realistic Cowrie SSH honeypots on Hetzner Cloud infrastructure. The toolkit creates honeypots that are difficult to fingerprint by capturing the filesystem and identity of a real Debian server.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Honeypot Deployment Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. generate_cowrie_fs_from_hetzner.sh                          │
│     → Creates temporary Hetzner server (debian-11/13)           │
│     → Installs nginx, MySQL, PHP, WordPress                     │
│     → Generates fs.pickle (filesystem snapshot)                 │
│     → Captures identity metadata (kernel, SSH banner, etc)      │
│     → Creates source_metadata.json (NEW in v2.1)                │
│     → Destroys temporary server                                 │
│                            ↓                                    │
│                   output_YYYYMMDD_HHMMSS/                       │
│                            ↓                                    │
│  2. deploy_cowrie_honeypot.sh <output_directory>                │
│     → Creates production server (debian-11/13)                  │
│     → Validates OS compatibility (NEW in v2.1)                  │
│     → Installs Docker + Tailscale (REQUIRED in v2.1)            │
│     → Deploys Cowrie API (NEW in v2.1)                          │
│     → Deploys Web Dashboard (local/remote/multi modes)          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Architecture

### File Sources and Management

The deployment uses a **git-first architecture** with clear separation between version-controlled code and deployment-specific artifacts:

#### Git-Managed (Version Controlled)
```
/opt/cowrie/ (cloned from GitHub)
├── scripts/          # Python/bash automation scripts
├── api/              # FastAPI service code
├── web/              # Flask dashboard code
├── cowrie/           # Cowrie Dockerfile and configs
├── pyproject.toml    # Python dependencies (uv)
├── docker-compose*.yml
└── README.md, CLAUDE.md
```

**Source**: `git clone https://github.com/reuteras/cowrie-deploy-toolkit.git`
**Updates**: `git pull` via `update-agent.sh`

#### SCP-Managed (Deployment Artifacts)
```
/opt/cowrie/
├── share/cowrie/
│   ├── fs.pickle              # Filesystem snapshot (from template server)
│   ├── cmdoutput.json         # Process list (from template server)
│   ├── contents/              # File contents (from template server)
│   └── txtcmds/               # Command outputs (from template server)
├── identity/                   # SSH keys, kernel info (from template server)
├── etc/
│   ├── cowrie.cfg             # Generated (SERVER_IP, etc.)
│   ├── userdb.txt             # Generated (IP-locked creds)
│   └── report.env             # Generated (API keys, SMTP)
├── var/                        # Runtime data, caches, databases
├── build/                      # Custom plugins
├── deployment.conf             # Per-deployment metadata
├── metadata.json              # Extracted from container
└── VERSION.json               # Update tracking
```

**Source**: SCP uploads from local machine or generated on server
**Updates**: Not updated (deployment-specific)
**Git**: These paths are in `.gitignore` to prevent conflicts

### Deployment Flow Details

1. **STEP 6**: `git clone` repository → All code files available immediately
2. **STEP 6.5**: Install `uv` → `uv sync` using git-provided `pyproject.toml`
3. **STEP 6.75**: Create artifact directories (share/, identity/, etc/, var/, build/)
4. **STEP 7+**: Upload template artifacts (fs.pickle, identity/, etc.) via SCP
5. **STEP 8+**: Generate configs (cowrie.cfg, userdb.txt) and upload via SCP
6. **STEP 9+**: Build and configure services using git-provided code
7. **STEP 15**: Create VERSION.json for update tracking

### Key Benefits

- **Clear ownership**: Git = code, SCP = data
- **No timing issues**: All code files available from STEP 6 onwards
- **No redundant uploads**: Each file uploaded once from correct source
- **Consistent versions**: All deployments use canonical code from GitHub
- **Simpler updates**: `update-agent.sh` only updates git files
- **Always works**: `uv` installed unconditionally (not just if reporting enabled)

## Requirements

- Hetzner Cloud account with API access
- `hcloud` CLI configured (`hcloud context create`)
- SSH keys registered in Hetzner
- `jq`, `nc`, `tar` installed locally
- Tailscale account (REQUIRED in v2.1)

## Key Features

**Anti-Fingerprinting:**
- Real Debian filesystem snapshot (not generic templates)
- Cowrie traces removed from snapshot
- IP-locked credentials (IPs locked to first successful auth)
- WordPress + MySQL with fake blog database
- Canary Tokens for exfiltration alerts

**v2.1 New Features:**
- OS Version Decoupling: Generate on debian-11, deploy on debian-13
- FastAPI Layer: Remote access to Cowrie data
- Multi-Host Dashboard: Aggregate data from multiple honeypots
- Tailscale VPN: Now REQUIRED for secure management

**Threat Intelligence:**
- GeoIP enrichment with MaxMind GeoLite2
- VirusTotal malware analysis with threat labels
- Real-time YARA scanning (~1000+ rules)
- AbuseIPDB, DShield integration
- Daily email reports with HTML/text formats

## Quick Start

### Single Honeypot

```bash
# 1. Edit master-config.toml with your settings
cp example-config.toml master-config.toml
# Edit: Tailscale keys, email config, API keys

# 2. Generate filesystem snapshot
./generate_cowrie_fs_from_hetzner.sh

# 3. Deploy honeypot
./deploy_cowrie_honeypot.sh ./output_20251226_143210
```

### Multi-Honeypot Deployment

```bash
# 1. Edit master-config.toml with [[honeypots]] array
cp example-config.toml master-config.toml
# Configure shared settings and multiple [[honeypots]] entries

# 2. Generate filesystem (once)
./generate_cowrie_fs_from_hetzner.sh

# 3. Deploy specific honeypot
./deploy_cowrie_honeypot.sh ./output_20251226_143210 --name cowrie-hp-1

# OR deploy all honeypots
./deploy_cowrie_honeypot.sh ./output_20251226_143210 --all
```

## OS Version Decoupling (NEW in v2.1)

**Generate filesystem on one Debian version, deploy on another.**

### Why Use This?

- **Realism**: Attackers see old, vulnerable-looking system (e.g., debian-11)
- **Security**: Honeypot runs on modern Debian (e.g., debian-13)
- **Flexibility**: Test filesystem compatibility across versions

### OS Version Configuration

```toml
[deployment]
generation_image = "debian-11"   # What attackers see
deployment_image = "debian-13"   # What actually runs

# LEGACY fallback (DEPRECATED)
server_image = "debian-13"
```

### OS Version Compatibility

**Generation:** Creates `source_metadata.json` with OS version info
**Deployment:** Validates compatibility, warns if gap >2 major versions

**Compatibility Rules:**
- Same version or +1/+2: Auto-proceed
- +3 or more: Warning + user confirmation
- Older deployment than source: Warning + confirmation

## Cowrie API Layer (NEW in v2.1)

**FastAPI service for remote access to Cowrie data.**

### API Features

- RESTful API with sessions, downloads, stats endpoints
- Read-only access (security hardened)
- GeoIP + VirusTotal integration
- TTY recording retrieval
- Runs with dropped capabilities and read-only filesystem

### API Configuration

**Single-Host Mode** (internal use):
```toml
[api]
enabled = true
expose_via_tailscale = false
```

**Multi-Host Mode** (exposed via Tailscale):
```toml
[api]
enabled = true
expose_via_tailscale = true
tailscale_api_hostname = "cowrie-api"
```

### Key Endpoints

| Endpoint | Description |
| -------- | ----------- |
| `GET /api/v1/health` | Health check |
| `GET /api/v1/sessions` | List sessions (filters/pagination) |
| `GET /api/v1/sessions/{id}` | Session detail |
| `GET /api/v1/sessions/{id}/tty` | TTY recording (asciicast) |
| `GET /api/v1/downloads` | Downloaded malware |
| `GET /api/v1/stats/overview` | Dashboard statistics |
| `GET /api/v1/threat/ip/{ip}` | Threat intelligence |

See [api/README.md](api/README.md) for full documentation.

## Multi-Host Dashboard (NEW in v2.1)

**Aggregate data from multiple honeypots in one dashboard.**

### Dashboard Modes

**Local Mode** (Default):
- Direct file access via volume mounts
- Same as v2.0 behavior
- Best for single-host deployments

**Remote Mode**:
- Connects to single API endpoint
- All data via HTTP/HTTPS
- Best for single remote honeypot

**Multi Mode** (Advanced):
- Aggregates from multiple honeypots
- Parallel querying with graceful degradation
- Supports different types (SSH, web, VPN)
- Best for enterprise deployments

### Configuration Examples

**Two honeypots + dashboard on one honeypot:**

```toml
[shared.tailscale]
authkey = "tskey-auth-..."
tailscale_domain = "tail9e5e41.ts.net"

# Honeypot 1 (with dashboard)
[[honeypots]]
name = "cowrie-hp-1"
hostname = "dmz-web-01"
api_enabled = true
api_expose_via_tailscale = true
dashboard_enabled = true
dashboard_mode = "multi"
dashboard_sources = ["cowrie-hp-1", "cowrie-hp-2"]  # Smart detection: local for self, remote for others

# Honeypot 2 (API only)
[[honeypots]]
name = "cowrie-hp-2"
hostname = "dmz-db-01"
api_enabled = true
api_expose_via_tailscale = true
dashboard_enabled = false
```

**Separate dashboard server:**

```toml
# Honeypot 1
[[honeypots]]
name = "cowrie-hp-1"
hostname = "dmz-web-01"
api_enabled = true
api_expose_via_tailscale = true
dashboard_enabled = false

# Honeypot 2
[[honeypots]]
name = "cowrie-hp-2"
hostname = "dmz-db-01"
api_enabled = true
api_expose_via_tailscale = true
dashboard_enabled = false

# Dashboard-only server
[[honeypots]]
name = "cowrie-dashboard"
hostname = "dashboard"
api_enabled = false
dashboard_enabled = true
dashboard_mode = "multi"
dashboard_sources = ["cowrie-hp-1", "cowrie-hp-2"]
```

### Multi-Source Features

- **Aggregated Statistics**: Combined sessions, countries, credentials, commands
- **Source Filtering**: View all or filter by specific source
- **Source Tags**: All data tagged with source identifier
- **Parallel Querying**: Fast concurrent queries
- **Graceful Degradation**: Continues if sources offline
- **Future Extensible**: Supports web, VPN, database honeypots

## Tailscale VPN (REQUIRED in v2.1)

**Tailscale is now REQUIRED for all deployments.**

### Tailscale Configuration

```toml
[tailscale]
authkey = "tskey-auth-..."  # REQUIRED - Get from https://login.tailscale.com/admin/settings/keys
tailscale_name = "cowrie-honeypot"
tailscale_domain = "tail9e5e41.ts.net"  # REQUIRED - Your tailnet domain
block_public_ssh = true  # Recommended
use_tailscale_ssh = false  # Optional
```

### Benefits

- **Zero Trust Access**: Management SSH only via Tailscale
- **Automatic mTLS**: No manual certificate management
- **Multi-Host**: Secure API access between servers
- **ACL Control**: Fine-grained access policies

### Access Methods

```bash
# Regular SSH via Tailscale IP
ssh -p 2222 root@100.x.y.z

# Tailscale SSH (if enabled)
ssh root@cowrie-honeypot  # Port 22, uses Tailscale hostname

# Web Dashboard
https://cowrie-honeypot.tail9e5e41.ts.net
```

## Web Dashboard

**Flask-based dashboard with session playback and live attack map.**

### Dashboard Features

- 📊 Dashboard with attack statistics
- 🗺️ Live attack map with geographic visualization
- 🔍 Session browser with filtering
- 🎥 TTY playback with asciinema-player
- 📁 Malware downloads with VirusTotal + YARA
- 🖥️ System information and captured identity
- 🌍 GeoIP integration (ASN, organization)
- 🔗 Email report session links
- 🔒 Tailscale/SSH tunnel only (not public)

### Dashboard Configuration

```toml
[web_dashboard]
enabled = true
mode = "local"  # or "remote" or "multi"
```

Access via: `https://<tailscale_name>.<tailscale_domain>`

## IP-Locked Credentials

**IPs locked to first successful credentials** (prevents honeypot fingerprinting).

### IP-Lock Mechanism

```text
1. IP 1.2.3.4: root:password → Success ✓ (IP locked)
2. Same IP: root:admin → Rejected ✗
3. Same IP: root:password → Success ✓
```

Database: `/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/iplock.db`

## Enhanced Realism Features

### WordPress + MySQL

- Full WordPress installation with fake blog
- Realistic wp-config.php with DB credentials
- Process list shows MySQL/nginx services
- Visible to attackers in filesystem

### Canary Tokens

Generate at <https://canarytokens.org/nest/>

**Setup:**
1. Create PDF, Excel, MySQL dump tokens
2. Save in `canary-tokens/` directory
3. Run `generate_cowrie_fs_from_hetzner.sh`
4. Tokens embedded in filesystem

**Files placed:**
- `/root/Q1_Financial_Report.xlsx`
- `/root/Network_Passwords.pdf`
- `/root/backup/mysql-backup.sql`

**Alerts include:** IP, timestamp, user agent, location

### Canary Token Webhook Receiver

**Configuration:**
```toml
[canary_webhook]
enabled = true
```

**Features:**
- Webhook endpoint for canarytokens.org
- SQLite storage: `/opt/cowrie/var/canary-webhooks.db`
- Dashboard integration with GeoIP
- Nginx reverse proxy for public access

## Daily Reporting System

**Automated email reports with threat intelligence.**

### Reporting Configuration

```toml
[honeypot]
enable_reporting = true
maxmind_account_id = "YOUR_ID"
maxmind_license_key = "YOUR_KEY"

[reporting]
virustotal_api_key = "YOUR_KEY"
email_from = "honeypot@domain.com"
email_to = "admin@domain.com"

[email]
smtp_host = "smtp.tem.scw.cloud"
smtp_port = 587
smtp_user = "USERNAME"
smtp_password = "PASSWORD"
smtp_tls = true
```

### Report Contents

1. Summary statistics (connections, IPs, sessions, downloads)
2. Top attacking countries
3. Top credentials attempted
4. Downloaded files with VirusTotal + YARA
5. Notable commands
6. Active sessions with dashboard links

### Testing

```bash
ssh -p 2222 root@<SERVER_IP>
cd /opt/cowrie
uv run scripts/daily-report.py --test
```

## Real-Time YARA Scanning

**Background daemon scans downloaded malware automatically.**

### YARA Features

- Inotify monitoring of downloads directory
- YARA Forge full ruleset (~1000+ rules)
- SQLite caching: `/opt/cowrie/var/yara-cache.db`
- File type detection and categorization
- Daily rule updates (4 AM)
- Systemd service with auto-restart

### Commands

```bash
# View daemon logs
journalctl -u yara-scanner -f

# Restart daemon
systemctl restart yara-scanner

# View cache stats
cd /opt/cowrie && uv run scripts/yara-scanner-daemon.py --stats
```

## Data Sharing & Threat Intelligence

### AbuseIPDB

Reports malicious IPs and queries reputation data.

```toml
[data_sharing]
abuseipdb_enabled = true
abuseipdb_api_key = "YOUR_KEY"
abuseipdb_tolerance_attempts = 10
```

**Free tier:** 1,000 requests/day
**Provides:** Abuse confidence score, total reports, ISP info

### DShield (SANS ISC)

Reports attack data to SANS Internet Storm Center (report-only).

```toml
[data_sharing]
dshield_enabled = true
dshield_userid = "YOUR_USERID"
dshield_auth_key = "YOUR_KEY"
```



### ASN Data

Automatically enabled with MaxMind databases.
**Displays:** ASN number, organization name (e.g., AS15169 Google LLC)

### Other Services

- **OWASP Honeypot Project**: STIX/TAXII exports for MISP
- **AlienVault OTX**: Pulse-based threat sharing
- **Shodan Honeyscore**: Check honeypot detectability

## Accessing the Honeypot

```bash
# Management SSH
ssh -p 2222 root@<SERVER_IP>

# View logs
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log'

# View JSON logs
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'

# View TTY recordings
ssh -p 2222 root@<SERVER_IP> 'ls -la /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/tty/'

# View downloads
ssh -p 2222 root@<SERVER_IP> 'ls -la /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads/'

# Container management
ssh -p 2222 root@<SERVER_IP> 'cd /opt/cowrie && docker compose logs -f'
ssh -p 2222 root@<SERVER_IP> 'cd /opt/cowrie && docker compose restart'
```

**Note**: Replace `<SERVER_IP>` with `<TAILSCALE_IP>` if `block_public_ssh = true`.

## Cleanup

```bash
# Delete honeypot server
hcloud server delete <SERVER_ID>
```

## Development Notes

- Scripts use `set -euo pipefail` for safety
- Cleanup trap removes server on deployment failure
- Docker containers with security hardening (no-new-privileges, read-only, cap_drop ALL)
- Automatic security updates (3 AM reboot window)
- All Python dependencies managed with [uv](https://github.com/astral-sh/uv)

## Additional Documentation

- [README.md](README.md) - Quick start and multi-honeypot deployment examples
- [CHANGELOG.md](CHANGELOG.md) - Version history and release notes
- [api/README.md](api/README.md) - Complete API documentation
- [web/datasource.py](web/datasource.py) - DataSource abstraction layer
- [web/multisource.py](web/multisource.py) - Multi-honeypot aggregation
- [scripts/README.md](scripts/README.md) - Detailed script documentation
