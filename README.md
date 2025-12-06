# Cowrie Deploy Toolkit

Deploy realistic [Cowrie](https://github.com/cowrie/cowrie) SSH honeypots on Hetzner Cloud with anti-fingerprinting features.

## Features

- **Realistic filesystem** - Captures actual Debian filesystem, not generic templates
- **Anti-fingerprinting** - Removes all traces of Cowrie from the snapshot
- **Authentic identity** - Uses real SSH banner, kernel version, and system files
- **Automated deployment** - Single script deploys a production-ready honeypot
- **Security hardening** - Automatic updates, Docker isolation, capability dropping

## Quick Start

### 1. Generate filesystem snapshot

```bash
./generate_cowrie_fs_from_hetzner.sh
```

This creates a temporary Hetzner server, captures its filesystem and identity, then destroys it. Output is saved to `./output_YYYYMMDD_HHMMSS/`.

### 2. Deploy honeypot

```bash
./deploy_cowrie_honeypot.sh ./output_YYYYMMDD_HHMMSS
```

This deploys a new server with Cowrie running on port 22. Real SSH is moved to port 2222.

## Requirements

- Hetzner Cloud account with API access
- `hcloud` CLI configured (`hcloud context create myproject`)
- SSH keys registered in Hetzner
- `jq`, `nc`, `tar`

## Configuration

Edit the variables at the top of each script:

```bash
# Honeypot identity
HONEYPOT_HOSTNAME="dmz-web01"

# Your Hetzner SSH key names
SSH_KEY_NAME1="SSH Key - default"
SSH_KEY_NAME2="ShellFish@iPhone-23112023"

# Ports
COWRIE_SSH_PORT="22"    # Honeypot
REAL_SSH_PORT="2222"    # Management
```

## After Deployment

```bash
# Management access
ssh -p 2222 root@<SERVER_IP>

# View attack logs
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'

# View downloaded malware
ssh -p 2222 root@<SERVER_IP> 'ls -la /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads/'

# Destroy honeypot
hcloud server delete <SERVER_ID>
```

## How It Works

```
generate_cowrie_fs_from_hetzner.sh
├── Creates temporary Debian server
├── Sets realistic hostname, installs nginx
├── Runs Cowrie's createfs.py for fs.pickle
├── Removes /root/cowrie from snapshot (anti-fingerprinting)
├── Captures identity (kernel, SSH banner, /etc/passwd, ps output)
└── Destroys temporary server

deploy_cowrie_honeypot.sh <output_dir>
├── Creates production server
├── Moves real SSH to port 2222
├── Installs Docker, configures auto-updates
├── Uploads fs.pickle, file contents, identity
├── Generates cowrie.cfg with captured identity
└── Starts Cowrie container on port 22
```

## Daily Reporting (Phase 1) ✅

**NEW:** Automated daily reports with threat intelligence integration!

```bash
# After honeypot deployment, set up reporting
cd scripts
./setup-reporting.sh

# Configure your API keys and email settings
nano /opt/cowrie/etc/report.env

# Test the report (using uv - recommended)
source /opt/cowrie/etc/report.env
cd /opt/cowrie
uv run scripts/daily-report.py --test

# Or using python3 directly
python3 scripts/daily-report.py --test
```

**Dependencies managed with [uv](https://github.com/astral-sh/uv)** - modern, fast Python package manager

**Features:**
- 📊 Comprehensive attack statistics (connections, IPs, credentials, commands)
- 🌍 GeoIP enrichment (MaxMind GeoLite2) - country, city, ASN, organization
- 🦠 VirusTotal malware analysis with SQLite caching
- 🔍 YARA rule scanning for malware classification
- 📧 Email delivery (SMTP, SendGrid, Mailgun) with beautiful HTML reports
- 🚨 Real-time alerts via webhooks (Slack, Discord, Teams)
- ⚡ Configurable thresholds for high attack volumes and malware downloads

See [scripts/README.md](scripts/README.md) for complete setup instructions.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features:
- ✅ **Phase 1 COMPLETE:** Daily email reports with GeoIP, VirusTotal, and YARA integration
- Phase 2: Dashboard visualization (Grafana + Loki)
- Phase 3: Log management and extended threat intelligence
- Future: Multi-honeypot fleet deployment, IoC sharing, IaC

## License

MIT
