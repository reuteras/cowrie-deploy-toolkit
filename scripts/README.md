# Cowrie Daily Report System

Automated daily reporting with threat intelligence enrichment for Cowrie honeypots.

## Features

- **Log Analysis**: Parse Cowrie JSON logs for connections, credentials, commands, and downloads
- **GeoIP Enrichment**: Country, city, ASN, and organization lookup using MaxMind GeoLite2
- **VirusTotal Integration**: Malware detection for downloaded files with caching
- **YARA Scanning**: Local malware classification using YARA rules
- **Email Delivery**: SMTP, SendGrid, or Mailgun with HTML formatting
- **Real-time Alerts**: Webhook notifications for Slack, Discord, and Microsoft Teams
- **Threshold Alerts**: Configurable alerts for high attack volumes and malware downloads

## Quick Setup (Recommended)

**✨ NEW: Fully automated deployment using `master-config.toml`**

1. Copy the example config: `cp example-config.toml master-config.toml`
2. Edit `master-config.toml` with your API keys and settings
3. Set `enable_reporting = true` in the `[honeypot]` section
4. Run `./deploy_cowrie_honeypot.sh ./output_YYYYMMDD_HHMMSS`

The deployment script automatically:
- Sets up MaxMind GeoIP with weekly auto-updates
- Configures Postfix for email delivery
- Installs all Python dependencies with uv
- Configures daily cron job for reports

**That's it!** No manual configuration needed. See `example-config.toml` for all options.

---

## Manual Installation (Advanced)

> **Note:** The sections below are for manual setup or troubleshooting. If you use `master-config.toml` with the deployment script, these steps are handled automatically.

### 1. Install Dependencies

On your Cowrie honeypot server:

```bash
# Install uv (modern Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone or upload the cowrie-deploy-toolkit to /opt/cowrie
cd /opt/cowrie

# Install Python dependencies using uv
uv sync

# Install YARA system package (Debian/Ubuntu)
apt-get install -y yara

# Or install from source for latest version
# See: https://yara.readthedocs.io/en/stable/gettingstarted.html
```

### 2. Download MaxMind GeoLite2 Databases

Sign up for a free MaxMind account: https://www.maxmind.com/en/geolite2/signup

Download the databases:

```bash
# Create directory
mkdir -p /opt/cowrie/geoip

# Download GeoLite2-City and GeoLite2-ASN (requires MaxMind account)
# Method 1: Manual download from MaxMind website
#   - Download GeoLite2-City.mmdb
#   - Download GeoLite2-ASN.mmdb
#   - Place in /opt/cowrie/geoip/

# Method 2: Using geoipupdate tool (recommended for automatic updates)
# Install geoipupdate
apt-get install -y geoipupdate

# Configure /etc/GeoIP.conf with your MaxMind account ID and license key
# Then run:
geoipupdate

# Copy databases to cowrie directory
cp /usr/share/GeoIP/GeoLite2-City.mmdb /opt/cowrie/geoip/
cp /usr/share/GeoIP/GeoLite2-ASN.mmdb /opt/cowrie/geoip/
```

### 3. Download YARA Rules

Download community YARA rules for malware detection:

```bash
# Create rules directory
mkdir -p /opt/cowrie/yara-rules

# Clone Yara-Rules repository (community rules)
cd /tmp
git clone https://github.com/Yara-Rules/rules.git yara-community
cp yara-community/malware/*.yar /opt/cowrie/yara-rules/

# Clone Neo23x0's signature-base (Florian Roth's rules)
git clone https://github.com/Neo23x0/signature-base.git
cp signature-base/yara/*.yar /opt/cowrie/yara-rules/

# Cleanup
rm -rf /tmp/yara-community /tmp/signature-base

# Test rules
yara -r /opt/cowrie/yara-rules/ /bin/ls
```

### 4. Configure Environment Variables

Create `/opt/cowrie/etc/report.env`:

```bash
# Paths
export COWRIE_LOG_PATH="/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json"
export COWRIE_DOWNLOAD_PATH="/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"
export GEOIP_DB_PATH="/opt/cowrie/geoip/GeoLite2-City.mmdb"
export GEOIP_ASN_PATH="/opt/cowrie/geoip/GeoLite2-ASN.mmdb"
export YARA_RULES_PATH="/opt/cowrie/yara-rules"
export CACHE_DB_PATH="/opt/cowrie/var/report-cache.db"

# VirusTotal (get free API key from https://www.virustotal.com/)
export VT_API_KEY="your_virustotal_api_key_here"
export VT_ENABLED="true"

# Email Configuration
export EMAIL_ENABLED="true"
export EMAIL_FROM="honeypot@yourdomain.com"
export EMAIL_TO="admin@yourdomain.com"
export EMAIL_SUBJECT_PREFIX="[Honeypot]"

# SMTP Settings (for direct SMTP)
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your_email@gmail.com"
export SMTP_PASSWORD="your_app_password"
export SMTP_TLS="true"

# OR use SendGrid (recommended for reliability)
# export SENDGRID_API_KEY="your_sendgrid_api_key"

# OR use Mailgun
# export MAILGUN_API_KEY="your_mailgun_api_key"
# export MAILGUN_DOMAIN="mg.yourdomain.com"

# Webhook Alerts (optional)
# Get webhook URLs from Slack/Discord/Teams channel settings
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
# export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
# export TEAMS_WEBHOOK="https://outlook.office.com/webhook/YOUR/WEBHOOK/URL"

# Alert Thresholds
export ALERT_THRESHOLD_CONNECTIONS="100"
export ALERT_ON_MALWARE="true"

# Report Settings
export REPORT_HOURS="24"
```

Make the file readable only by root:

```bash
chmod 600 /opt/cowrie/etc/report.env
```

### 5. Set Up Cron Job

Add to root's crontab:

```bash
# Edit crontab
crontab -e

# Add this line to run daily at 6 AM
0 6 * * * source /opt/cowrie/etc/report.env && cd /opt/cowrie && /root/.cargo/bin/uv run scripts/daily-report.py 2>&1 | logger -t cowrie-report
```

For testing, you can run it every hour during setup:

```bash
# Run every hour (for testing)
0 * * * * source /opt/cowrie/etc/report.env && cd /opt/cowrie && /root/.cargo/bin/uv run scripts/daily-report.py 2>&1 | logger -t cowrie-report
```

## Usage

### Manual Execution

```bash
# Source environment variables
source /opt/cowrie/etc/report.env
cd /opt/cowrie

# Run report for last 24 hours (sends email)
uv run scripts/daily-report.py

# Run report for last 6 hours
uv run scripts/daily-report.py --hours 6

# Test mode: print to stdout instead of sending email
uv run scripts/daily-report.py --test

# Save to file instead of sending email
uv run scripts/daily-report.py --output /tmp/report.html
```

### Configuration File

Instead of environment variables, you can use a JSON configuration file:

Create `/opt/cowrie/etc/report-config.json`:

```json
{
  "log_path": "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json",
  "download_path": "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads",
  "geoip_db_path": "/opt/cowrie/geoip/GeoLite2-City.mmdb",
  "geoip_asn_path": "/opt/cowrie/geoip/GeoLite2-ASN.mmdb",
  "yara_rules_path": "/opt/cowrie/yara-rules",
  "cache_db_path": "/opt/cowrie/var/report-cache.db",

  "virustotal_api_key": "your_api_key",
  "virustotal_enabled": true,

  "email_enabled": true,
  "email_from": "honeypot@yourdomain.com",
  "email_to": "admin@yourdomain.com",
  "email_subject_prefix": "[Honeypot]",

  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_user": "your_email@gmail.com",
  "smtp_password": "your_password",
  "smtp_tls": true,

  "slack_webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK",
  "alert_threshold_connections": 100,
  "alert_on_malware": true,
  "report_hours": 24
}
```

Then run with:

```bash
python3 /opt/cowrie/scripts/daily-report.py --config /opt/cowrie/etc/report-config.json
```

## Report Example

The daily report includes:

### Summary Statistics
- Total connections
- Unique IP addresses
- Sessions with commands executed
- Files downloaded
- Average session duration

### Top Attacking Countries
Geographic distribution of attacks with:
- Country name
- Number of connections
- Percentage of total attacks

### Top Credentials
Most frequently attempted username:password combinations

### Downloaded Files (Malware Analysis)
For each downloaded file:
- SHA256 hash
- File size
- YARA rule matches (malware family, packer, etc.)
- VirusTotal detection ratio (e.g., "45/70 engines")
- Link to full VirusTotal report

### Notable Commands
Commands executed by attackers, including:
- Source IP address
- Full command line
- Timestamp

## Real-time Alerts

Alerts are sent via webhooks when:

1. **High Attack Volume**: Connection attempts exceed threshold (default: 100/24hr)
2. **Malware Downloaded**: Any file with VirusTotal detections

### Setting Up Webhooks

**Slack:**
1. Go to https://api.slack.com/messaging/webhooks
2. Create an incoming webhook
3. Copy the webhook URL to `SLACK_WEBHOOK`

**Discord:**
1. Edit channel → Integrations → Webhooks
2. Create webhook
3. Copy webhook URL to `DISCORD_WEBHOOK`

**Microsoft Teams:**
1. Team channel → Connectors → Incoming Webhook
2. Configure and create
3. Copy webhook URL to `TEAMS_WEBHOOK`

## Troubleshooting

### No logs found
```bash
# Verify log path
ls -la /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json

# Check if Cowrie is running
docker ps | grep cowrie

# Check Cowrie logs
docker logs cowrie
```

### GeoIP errors
```bash
# Verify database files exist
ls -la /opt/cowrie/geoip/

# Download databases if missing
# See installation section above
```

### YARA errors
```bash
# Test YARA installation
yara --version

# Validate rules
yara -r /opt/cowrie/yara-rules/ /bin/ls

# Check for syntax errors in rules
for rule in /opt/cowrie/yara-rules/*.yar; do
    echo "Testing $rule"
    yara "$rule" /bin/ls || echo "ERROR in $rule"
done
```

### Email not sending
```bash
# Test SMTP connectivity
telnet smtp.gmail.com 587

# Check authentication
# For Gmail: Use App Passwords, not regular password
# https://support.google.com/accounts/answer/185833

# Test with Python
python3 -c "import smtplib; print('SMTP OK')"

# Check logs
journalctl -t cowrie-report
```

### VirusTotal API limits
The free tier allows 4 requests per minute. The script caches results in SQLite to avoid re-querying:

```bash
# Check cache
sqlite3 /opt/cowrie/var/report-cache.db "SELECT COUNT(*) FROM vt_cache;"

# Clear cache if needed
rm /opt/cowrie/var/report-cache.db
```

## Deployment Integration

**✨ Automated deployment is now built-in!**

Reporting is automatically configured when you deploy a honeypot with `enable_reporting = true` in `master-config.toml`. The deployment script handles:

- Installing uv and Python dependencies
- Setting up MaxMind GeoIP with auto-updates
- Configuring Postfix for email delivery
- Creating cron job for daily reports

No manual steps needed! See the main [README.md](../README.md) for deployment instructions.

## Advanced Configuration

### Custom YARA Rules

Add your own rules to `/opt/cowrie/yara-rules/custom.yar`:

```yara
rule Suspicious_Cryptocurrency_Miner {
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "Your Name"

    strings:
        $xmrig = "xmrig" nocase
        $minerd = "minerd" nocase
        $stratum = "stratum+tcp://" nocase

    condition:
        any of them
}
```

### Multiple Honeypots

For centralized reporting from multiple honeypots:

1. Set up a central log collection server
2. Ship logs via syslog or rsync
3. Run daily-report.py on the central server
4. Configure separate email subjects per honeypot

```bash
# On honeypot: ship logs to central server
rsync -az /var/lib/docker/volumes/cowrie-var/_data/ central-server:/logs/honeypot-1/

# On central server: run reports for each honeypot
python3 daily-report.py --config /etc/cowrie/honeypot-1-config.json
python3 daily-report.py --config /etc/cowrie/honeypot-2-config.json
```

## Security Considerations

1. **Protect API Keys**: Never commit `report.env` or `report-config.json` to version control
2. **Secure Permissions**: `chmod 600` on configuration files
3. **VirusTotal Rate Limits**: Free tier is 4 req/min. Caching prevents excessive queries.
4. **Email Security**: Use TLS for SMTP. Consider PGP encryption for sensitive reports.
5. **Webhook Security**: Webhook URLs are secrets. Rotate if exposed.

## License

MIT (same as parent project)
