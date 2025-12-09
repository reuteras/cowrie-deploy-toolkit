# Cowrie Deploy Toolkit

Deploy realistic [Cowrie](https://github.com/cowrie/cowrie) SSH honeypots on Hetzner Cloud with anti-fingerprinting features.

## Features

- **Realistic filesystem** - Captures actual Debian filesystem, not generic templates
- **Anti-fingerprinting** - Removes all traces of Cowrie from the snapshot
- **Authentic identity** - Uses real SSH banner, kernel version, and system files
- **Automated deployment** - Single script deploys a production-ready honeypot
- **Daily threat reports** - GeoIP, VirusTotal, YARA scanning with automated email delivery
- **Security hardening** - Automatic updates, Docker isolation, capability dropping

## Quick Start

### 1. Generate filesystem snapshot

```bash
./generate_cowrie_fs_from_hetzner.sh
```

This creates a temporary Hetzner server, captures its filesystem and identity, then destroys it. Output is saved to `./output_YYYYMMDD_HHMMSS/`.

### 2. Configure reporting (optional)

```bash
cp example-config.toml master-config.toml
nano master-config.toml
```

Edit `master-config.toml` with your API keys and email settings. Supports command execution for secrets (e.g., `"op read op://..."`). Set `enable_reporting = false` to skip automated reporting setup.

### 3. Deploy honeypot

```bash
./deploy_cowrie_honeypot.sh ./output_YYYYMMDD_HHMMSS
```

This deploys a new server with Cowrie running on port 22. Real SSH is moved to port 2222. If `master-config.toml` exists with `enable_reporting = true`, automatically sets up MaxMind GeoIP, Postfix email, and daily reports.

## Requirements

- Hetzner Cloud account with API access
- `hcloud` CLI configured (`hcloud context create myproject`)
- SSH keys registered in Hetzner
- `jq`, `nc`, `tar`

## Configuration

### Script Configuration

Edit the variables at the top of each script for deployment settings:

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

### Master Configuration (Reporting)

Use `master-config.toml` for automated daily reports with threat intelligence:

```bash
cp example-config.toml master-config.toml
nano master-config.toml
```

**Features:**
- **TOML format** - Clean, structured configuration
- **Command execution** - Fetch secrets from 1Password, pass, vault, AWS Secrets Manager
- **Auto-deployment** - Runs during `deploy_cowrie_honeypot.sh` if `enable_reporting = true`

**Example with 1Password:**
```toml
[honeypot]
enable_reporting = true
maxmind_account_id = "op read op://Personal/MaxMind/account_id"
maxmind_license_key = "op read op://Personal/MaxMind/license_key"

[email]
smtp_host = "smtp.tem.scw.cloud"
smtp_port = 587
smtp_user = "op read op://Personal/Scaleway/smtp_user"
smtp_password = "op read op://Personal/Scaleway/smtp_password"
```

The deployment script automatically:
1. Processes `master-config.toml` and executes commands to fetch secrets
2. Sets up MaxMind GeoIP with weekly auto-updates (Wednesdays 3 AM)
3. Configures Postfix for email delivery via Scaleway Transactional Email
4. Installs reporting dependencies and configures daily cron job

See `example-config.toml` for all available options.

## After Deployment

```bash
# Management access
ssh -p 2222 root@<SERVER_IP>
# or via Tailscale
ssh root@<TAILSCALE_SERVER_IP>

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

Automated daily reports with threat intelligence integration!

**Features:**
- 📊 Comprehensive attack statistics (connections, IPs, credentials, commands)
- 🌍 GeoIP enrichment (MaxMind GeoLite2) - country, city, ASN, organization
- 🦠 VirusTotal malware analysis with SQLite caching
- 🔍 YARA rule scanning for malware classification
- 📧 Email delivery (SMTP, SendGrid, Mailgun) with beautiful HTML reports
- 🚨 Real-time alerts via webhooks (Slack, Discord, Teams)
- ⚡ Configurable thresholds for high attack volumes and malware downloads
- 🤖 **Fully automated** - Configure once in `master-config.toml`, deploys automatically

**Setup:**
1. Copy `example-config.toml` to `master-config.toml`
2. Set `enable_reporting = true` and configure your API keys
3. Run `./deploy_cowrie_honeypot.sh` - reporting is configured automatically
4. Daily reports are emailed at the configured interval (default: 24 hours)

**Manual testing:**
```bash
# SSH to the honeypot
ssh -p 2222 root@<SERVER_IP>

# Test the report
cd /opt/cowrie
uv run scripts/daily-report.py --test
```

**Dependencies managed with [uv](https://github.com/astral-sh/uv)** - modern, fast Python package manager

See [scripts/README.md](scripts/README.md) for detailed configuration options.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features:

## License

MIT
