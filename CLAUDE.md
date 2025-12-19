# Cowrie Honeypot Deployment Toolkit

## Project Overview

This project provides scripts to deploy realistic Cowrie SSH honeypots on Hetzner Cloud infrastructure. The toolkit creates honeypots that are difficult to fingerprint by capturing the filesystem and identity of a real Debian server.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Honeypot Deployment Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. generate_cowrie_fs_from_hetzner.sh                          │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ Creates temporary Hetzner server                        │ │
│     │ → Sets realistic hostname (dmz-web01)                   │ │
│     │ → Installs nginx, MySQL, PHP, WordPress                 │ │
│     │ → Loads fake WordPress database with blog posts         │ │
│     │ → Copies Canary Token files to /root                    │ │
│     │ → Generates fs.pickle (filesystem snapshot)             │ │
│     │ → Captures identity metadata (kernel, SSH banner, etc)  │ │
│     │ → Collects file contents (/etc/passwd, configs, etc)    │ │
│     │ → Destroys temporary server                             │ │
│     └─────────────────────────────────────────────────────────┘ │
│                            ↓                                    │
│                   output_YYYYMMDD_HHMMSS/                       │
│                   ├── fs.pickle                                 │
│                   ├── identity/                                 │
│                   │   ├── kernel.txt                            │
│                   │   ├── hostname                              │
│                   │   ├── ssh-banner.txt                        │
│                   │   ├── ps.txt                                │
│                   │   └── ...                                   │
│                   └── contents/                                 │
│                       ├── etc/passwd                            │
│                       ├── etc/shadow                            │
│                       └── ...                                   │
│                            ↓                                    │
│  2. deploy_cowrie_honeypot.sh <output_directory>                │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ Creates production Hetzner server                       │ │
│     │ → Moves real SSH to port 2222                           │ │
│     │ → Installs Docker                                       │ │
│     │ → Configures automatic security updates                 │ │
│     │ → Uploads fs.pickle, identity, and file contents        │ │
│     │ → Generates cowrie.cfg with captured identity           │ │
│     │ → Deploys Cowrie container on port 22                   │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Scripts

### generate_cowrie_fs_from_hetzner.sh

Creates a realistic filesystem snapshot and identity from a fresh Hetzner Debian server.

**What it does:**
- Spins up a temporary cpx11 Debian 13 server
- Sets a realistic hostname (configurable: `dmz-web01`)
- Installs nginx, MySQL/MariaDB, PHP, and WordPress
- Loads fake WordPress database with realistic blog content
- Copies Canary Token files (MySQL dump, Excel, PDF) to /root
- Uses Cowrie's `createfs.py` to generate `fs.pickle`
- Removes all traces of Cowrie from the snapshot (anti-fingerprinting)
- Collects identity files: kernel version, SSH banner, /etc/passwd, etc.
- Automatically destroys the temporary server when done

**Output:** `./output_YYYYMMDD_HHMMSS/` directory

### deploy_cowrie_honeypot.sh

Deploys a Cowrie honeypot using a previously generated output directory.

**Usage:**
```bash
./deploy_cowrie_honeypot.sh ./output_20251205_140841
```

**What it does:**
- Creates a new Hetzner cpx11 server
- Moves real SSH to port 2222 (management access)
- Installs Docker and configures automatic updates
- Uploads the filesystem pickle and file contents
- Generates `cowrie.cfg` with the captured identity
- Runs Cowrie in Docker, listening on port 22

## Requirements

- Hetzner Cloud account with API access
- `hcloud` CLI tool configured (`hcloud context create`)
- SSH keys registered in Hetzner (update script variables)
- `jq`, `nc`, `tar` installed locally

## Key Anti-Fingerprinting Features

1. **Real filesystem snapshot** - Uses actual Debian filesystem, not generic templates
2. **Cowrie traces removed** - `/root/cowrie` and related paths excluded from snapshot
3. **Realistic process list** - Captures `ps` output with nginx, MySQL running
4. **Authentic SSH banner** - Uses the exact SSH banner from the source server
5. **Real file contents** - `/etc/passwd`, `/etc/shadow`, configs are from real system
6. **Matching kernel strings** - Kernel version, build string, and arch match source
7. **IP-locked credentials** - Each IP is locked to the first credentials they successfully authenticate with
8. **WordPress + MySQL** - Full WordPress installation with fake corporate blog database
9. **Database credentials** - Realistic `wp-config.php` with working database connection strings
10. **Canary Tokens** - Optional honeytokens for immediate exfiltration alerts

## IP-Locked Credential Authentication

**New in v2.0**: Enhanced anti-fingerprinting through IP-based credential locking.

### How It Works

When an attacker successfully authenticates from an IP address, that IP becomes permanently "locked" to those specific credentials. This makes the honeypot behave like a real server where credentials are fixed, not arbitrary.

**Example Scenario:**
```text
1. IP 1.2.3.4 tries: root:password → Success ✓
   → IP locked to root:password

2. Same IP tries: root:admin → Rejected ✗
   (Even though honeypot normally accepts all credentials)

3. Same IP tries: root:password → Success ✓
   (Only the locked credentials work)
```

### Benefits

- **Enhanced Realism** - Mimics real server behavior where credentials don't change
- **Anti-Fingerprinting** - Harder for attackers to identify as a honeypot by testing multiple credentials
- **Better Data Quality** - Captures authentic post-compromise behavior instead of endless credential testing
- **Persistent State** - IP locks survive container restarts and rebuilds

### Technical Details

**Plugin**: `output_iplock.py` (Cowrie output plugin)
- Intercepts `cowrie.login.success` events
- Stores IP → credential mappings in SQLite
- Database: `/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/iplock.db`
- Logs violations for analysis

**Configuration**: Automatically enabled in `cowrie.cfg`
```ini
[output_iplock]
enabled = true
db_path = var/lib/cowrie/iplock.db
```

### Accessing IP-Lock Data

```bash
# View the IP-lock database
ssh -p 2222 root@<SERVER_IP> 'sqlite3 /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/iplock.db "SELECT * FROM ip_locks LIMIT 10;"'

# Check for credential violations (IPs trying different credentials)
ssh -p 2222 root@<SERVER_IP> 'sqlite3 /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/iplock.db "SELECT src_ip, COUNT(*) as violations FROM auth_attempts WHERE is_locked = 1 AND lock_matched = 0 GROUP BY src_ip ORDER BY violations DESC LIMIT 10;"'

# View lock statistics
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log | grep IPLockAuth'
```

### Database Schema

**ip_locks table** - Tracks locked IPs
- `src_ip` (unique) - IP address
- `username` - Locked username
- `password` - Locked password
- `locked_at` - First successful login timestamp
- `login_count` - Number of successful logins with locked credentials

**auth_attempts table** - Analysis and forensics
- `src_ip` - Source IP
- `username` - Attempted username
- `password` - Attempted password
- `success` - Whether authentication succeeded
- `is_locked` - Whether IP was already locked at time of attempt
- `lock_matched` - Whether credentials matched the lock (NULL if not locked)

### Disabling IP-Lock

To disable (not recommended for production):

Edit `/opt/cowrie/etc/cowrie.cfg` on the server and set:
```ini
[output_iplock]
enabled = false
```

Then restart: `docker compose restart -d`

## Enhanced Honeypot Realism

The toolkit now includes advanced features to make the honeypot appear like a real production server, increasing the likelihood that attackers will interact with it naturally.

### WordPress and MySQL/MariaDB

**What's included:**
- **MySQL/MariaDB database** running in the filesystem snapshot
- **WordPress installation** with fake blog content
- **Realistic configuration files** with database credentials
- **Process list** shows MySQL and Apache/nginx services
- **Fake blog database** with posts, users, and comments about "internal company updates"

**Files visible to attackers:**
- `/var/www/html/blog/wp-config.php` - WordPress config with DB credentials
- `/etc/mysql/my.cnf` - MySQL configuration
- `/var/lib/mysql/` - Database files
- WordPress database with corporate blog content suggesting sensitive information

**Benefits:**
- Attackers see a realistic production environment
- Database credentials in config files attract credential collection
- Process list shows services that suggest valuable data
- More convincing target for post-compromise activity

### Canary Tokens Integration

**Canary Tokens** are special files that trigger alerts when accessed, downloaded, or opened. This toolkit supports embedding Canary Tokens to get immediate alerts when attackers exfiltrate data.

#### Setting Up Canary Tokens

1. **Generate tokens** at <https://canarytokens.org/nest/>

   **Recommended tokens:**
   - **MySQL dump** - Get alerted when someone opens a database backup
   - **Excel spreadsheet** - Triggers when opened (great for financial reports)
   - **PDF document** - Alerts when the PDF is viewed

2. **Save tokens locally** in the `canary-tokens/` directory:
   ```bash
   mkdir -p canary-tokens
   # Place your generated token files here:
   # - canary-tokens/mysql-backup.sql
   # - canary-tokens/Q1-Financial-Report.xlsx (any .xlsx file)
   # - canary-tokens/Network-Passwords.pdf (any .pdf file)
   ```

3. **Generate filesystem** - Run `generate_cowrie_fs_from_hetzner.sh` as normal:
   ```bash
   ./generate_cowrie_fs_from_hetzner.sh
   ```

   The script will automatically:
   - Copy MySQL token to `/root/backup/mysql-backup.sql`
   - Copy Excel token to `/root/Q1_Financial_Report.xlsx`
   - Copy PDF token to `/root/Network_Passwords.pdf`

4. **Deploy honeypot** - The tokens will be embedded in the filesystem snapshot

**File naming strategy:**
The toolkit uses enticing filenames to encourage attackers to download them:
- `Q1_Financial_Report.xlsx` - Suggests financial data
- `Network_Passwords.pdf` - Implies sensitive credentials
- `mysql-backup.sql` - Database backup in `/root/backup/`

**Example alert workflow:**
1. Attacker compromises honeypot
2. Explores `/root` directory
3. Downloads `Q1_Financial_Report.xlsx`
4. Opens the file on their machine
5. **You receive immediate email/SMS alert** with:
   - IP address of the opener
   - Timestamp
   - User agent / system information
   - Geographic location

**Privacy note:** The `canary-tokens/` directory is excluded from git via `.gitignore` since tokens are unique and user-specific.

#### Creating Effective Canary Tokens

**MySQL Dump Token:**
- Choose "MySQL dump" token type at canarytokens.org
- Save as `canary-tokens/mysql-backup.sql`
- Attackers often look for database backups
- Triggers when file is read/downloaded

**Excel Document Token:**
- Choose "Microsoft Excel / Word Document" type
- Use an enticing filename related to your honeypot's theme
- Example themes: financial reports, employee lists, network diagrams
- Triggers when opened in Excel/Word

**PDF Document Token:**
- Choose "Adobe PDF" token type
- Name it something that suggests sensitive information
- Examples: passwords, VPN configs, architecture diagrams
- Triggers when opened in any PDF reader

**Best practices:**
- Use realistic corporate file naming conventions
- Set up email/SMS notifications for immediate alerts
- Consider using webhook tokens for integration with SIEM
- Place tokens in directories attackers are likely to explore (`/root`, `/backup`)

## Configuration

Edit script variables at the top of each file:

```bash
# generate_cowrie_fs_from_hetzner.sh
HONEYPOT_HOSTNAME="dmz-web01"    # Hostname shown to attackers
SSH_KEY_NAME1="..."              # Your Hetzner SSH key names
SSH_KEY_NAME2="..."

# deploy_cowrie_honeypot.sh
COWRIE_SSH_PORT="22"             # Honeypot listens here
REAL_SSH_PORT="2222"             # Management SSH
```

## Tailscale for Secure Management Access

For enhanced security, you can configure management SSH (port 2222) to be accessible only via Tailscale VPN, completely removing public SSH exposure.

### Benefits with Tailscale

- **Zero Trust Access** - Management SSH only accessible through your private Tailscale network
- **No Public SSH Exposure** - Port 2222 blocked by firewall for all public IPs
- **Secure Remote Access** - Access your honeypot from anywhere via Tailscale
- **Optional Tailscale SSH** - Use Tailscale's built-in SSH with ACLs and session recording

### Configuration for Tailscale

Add to `master-config.toml`:

```toml
[tailscale]
enabled = true
authkey = "tskey-auth-..."  # Or: "op read op://Personal/Tailscale/honeypot_authkey"
tailscale_name = "cowrie-honeypot"  # Hostname shown in Tailscale admin console
tailscale_domain = "your-tailnet.ts.net"  # Your tailnet domain (for web dashboard URL)
block_public_ssh = true      # Recommended: block public access to port 2222
use_tailscale_ssh = false    # Optional: use Tailscale's SSH feature
```

### Generating a Tailscale Auth Key

1. Visit <https://login.tailscale.com/admin/settings/keys>
2. Click "Generate auth key"
3. Settings:
   - **Reusable**: ✓ (allows multiple devices)
   - **Ephemeral**: ✓ (auto-cleanup when offline)
   - **Tags**: Add tags like `tag:honeypot` for ACL control
4. Copy the key to your `master-config.toml`

### Accessing the Honeypot via Tailscale

Once deployed with Tailscale enabled:

```bash
# Connect to Tailscale on your local machine first
tailscale up

# Method 1: Regular SSH via Tailscale IP (if use_tailscale_ssh = false)
ssh -p 2222 root@100.x.y.z

# Method 2: Tailscale SSH (if use_tailscale_ssh = true)
# Uses Tailscale's built-in SSH on port 22 (not 2222!)
ssh root@cowrie-honeypot
```

**Important**: When `use_tailscale_ssh = true`, you connect on **port 22** using the Tailscale hostname, not port 2222!

### Security Notes

- **Recommended**: Always use `block_public_ssh = true` for maximum security
- The honeypot SSH (port 22) remains publicly accessible - this is intentional
- Tailscale SSH provides additional features but is experimental - test thoroughly
- Your Tailscale auth key should be kept secret and rotated periodically

## Web Dashboard (SSH Session Playback)

The toolkit includes an optional web dashboard for viewing and replaying SSH sessions built with Flask.

### Features

- **📊 Dashboard** - Overview of attack statistics with top countries, credentials, commands, and attacking IPs
- **🗺️ Live Attack Map** - Real-time geographic visualization of attacks with:
  - Live mode: Watch attacks as they happen in real-time
  - Replay mode: Replay historical attacks with timeline controls
  - Attack lines from source to honeypot with fade animations
  - Statistics on unique IPs, high-volume attackers, and total attacks
  - Time range selection (last hour, 6 hours, 24 hours, 7 days)
- **🔍 Session Browser** - List all sessions with filtering by IP, username, and date range
- **🎥 TTY Playback** - Watch recorded SSH sessions in real-time with asciinema-player
- **📁 Malware Downloads** - Browse captured files with:
  - VirusTotal threat intelligence (threat labels, categories, families)
  - YARA rule matches from real-time scanning
  - File type detection and categorization
  - Direct links to VirusTotal analysis
- **🖥️ System Information** - View honeypot details including:
  - Server IP and hostname configuration
  - Cowrie version and container build date
  - Captured identity (kernel, OS, SSH banner, architecture)
  - SSH cipher configuration
  - SSH version strings
  - Process list snapshot
- **🌍 GeoIP Integration** - View attacker locations with ASN and organization data
- **🔗 Email Integration** - Session links in daily reports link directly to TTY playback
- **🔒 Security**:
  - Only accessible via SSH tunnel or Tailscale VPN
  - NOT exposed to public internet
  - Docker container runs with capability dropping and read-only filesystem
  - tmpfs for temporary files

### Enabling the Web Dashboard

Add to `master-config.toml`:

```toml
[web_dashboard]
enabled = true
# Note: The base URL for session links in email reports is automatically
# built from tailscale_name and tailscale_domain when Tailscale is enabled.
```

### Technical Implementation

**Architecture:**
- Flask web server running in Docker container
- Reads Cowrie JSON logs directly (no database dependency)
- Bind-mounted volumes for read-only access to logs, TTY recordings, and downloads
- GeoIP lookup using MaxMind GeoLite2 databases
- VirusTotal API integration with caching
- YARA cache integration (reads from YARA scanner daemon's SQLite database)

**Docker Networking:**
- Runs on internal Docker network (`cowrie-internal`)
- Exposed on `127.0.0.1:5000` (localhost only)
- Tailscale Serve provides HTTPS access via Tailscale VPN

**File Structure:**
```text
web/
├── app.py              # Flask application with all routes
├── Dockerfile          # Container build definition
├── docker-compose.web.yml  # Service configuration
├── requirements.txt    # Python dependencies
├── static/             # CSS, JavaScript, fonts
│   ├── asciinema-player/  # TTY playback player
│   └── styles.css
├── templates/          # Jinja2 HTML templates
│   ├── base.html       # Base template with navigation
│   ├── index.html      # Dashboard overview
│   ├── sessions.html   # Session list with filtering
│   ├── session.html    # Individual session detail with TTY playback
│   └── downloads.html  # Malware browser
└── README.md           # Web dashboard documentation
```

### Accessing the Web Dashboard

When Tailscale is enabled with `tailscale_domain` configured, the web dashboard is available at:
- `https://<tailscale_name>.<tailscale_domain>` (via Tailscale Serve)

The web dashboard is NOT exposed to the public internet. You can also access via SSH tunnel:

```bash
# If using Tailscale with block_public_ssh enabled
ssh -p 2222 -L 5000:localhost:5000 root@<TAILSCALE_IP>

# Or if using public SSH access
ssh -p 2222 -L 5000:localhost:5000 root@<SERVER_IP>

# Then open in browser
open http://localhost:5000
```

**Note**: If you enabled Tailscale with `block_public_ssh = true`, you must use your Tailscale IP address (shown in deployment output).

## Canary Token Webhook Receiver

The toolkit includes a webhook receiver for Canary Tokens, providing immediate alerts when attackers exfiltrate honeytokens (PDF, Excel, MySQL dump files) from the honeypot.

### What are Canary Tokens?

Canary Tokens are special files that trigger webhooks when accessed, downloaded, or opened. When an attacker exfiltrates these files from the honeypot and opens them on their machine, you receive an immediate alert with:

- IP address of the opener
- User agent and system information
- Geographic location
- Timestamp
- HTTP referer (if applicable)

### Features Canary Token Webhook Receiver

- **🐦 Webhook Endpoint** - Receives webhooks from Canary Tokens (<https://canarytokens.org>)
- **🗄️ SQLite Storage** - Stores webhook alerts in local database
- **📊 Dashboard Integration** - View alerts in web dashboard with GeoIP enrichment
- **🌐 Public Access** - Nginx reverse proxy forwards webhooks from internet to honeypot via Tailscale
- **🔒 Security** - Rate limiting and path restrictions at reverse proxy level

### Enabling the Webhook Receiver

Add to `master-config.toml`:

```toml
[canary_webhook]
enabled = true
```

### Setup

1. **Enable in `master-config.toml`:**
   ```toml
   [canary_webhook]
   enabled = true
   ```

2. **Configure nginx reverse proxy** - See README.md "Canary Token Webhook Receiver" section for detailed nginx configuration

3. **Generate tokens** at <https://canarytokens.org/nest/>
   - Choose token type: PDF, Excel/Word, or MySQL Dump
   - Set webhook URL to: `https://<your-server>/webhook/canary` (your nginx proxy endpoint)
   - Place token files in `canary-tokens/` directory before generating filesystem
   - See "Canary Tokens Integration" section above for file naming

### Viewing Alerts

**Web Dashboard:**
- Navigate to "🐦 Canary Alerts" in the dashboard
- View recent alerts with IP, location, and token details
- Click "Manage Token" to view full details at canarytokens.org

**API Endpoint:**
```bash
curl https://<your-dashboard>/api/canary-webhooks
```

### Database Schema Webhook Receiver

Webhook alerts are stored in SQLite at `/opt/cowrie/var/canary-webhooks.db`:

```sql
CREATE TABLE canary_webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    token_type TEXT,           -- e.g., "PDF", "HTTP", "EXCEL"
    token_name TEXT,           -- User-defined name from memo field
    trigger_ip TEXT,           -- IP that triggered the token
    trigger_user_agent TEXT,   -- User agent string
    trigger_location TEXT,     -- Geographic location
    trigger_hostname TEXT,     -- Hostname if available
    referer TEXT,              -- HTTP referer
    additional_data TEXT,      -- JSON blob
    raw_payload TEXT           -- Full webhook payload
);
```

**Accessing the database:**

```bash
# SSH to honeypot
ssh -p 2222 root@<SERVER_IP>

# Query recent alerts
sqlite3 /opt/cowrie/var/canary-webhooks.db \
  "SELECT received_at, token_type, token_name, trigger_ip FROM canary_webhooks ORDER BY received_at DESC LIMIT 10;"
```

### Webhook Payload Format

Canary Tokens send webhooks in this format:

```json
{
  "channel": "PDF",
  "memo": "Network Passwords PDF",
  "src_ip": "203.0.113.42",
  "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "referer": "https://example.com/download",
  "location": "San Francisco, CA, US",
  "hostname": "attacker-machine",
  "manage_url": "https://canarytokens.org/manage?token=...",
  "time": "2025-12-19T12:34:56Z",
  "hits": 1
}
```

The webhook receiver stores all fields and enriches with GeoIP data for display in the dashboard.

## Daily Reporting System

The toolkit includes an automated daily reporting system that sends comprehensive threat intelligence reports via email.

### Features Daily Reporting System

- **📊 Comprehensive Statistics** - Total connections, unique IPs, sessions, and files downloaded
- **🌍 GeoIP Enrichment** - Country, city, ASN, and organization data using MaxMind GeoLite2
- **🦠 VirusTotal Integration** - Malware analysis with extended threat intelligence:
  - Popular threat label (e.g., `trojan.emotet`, `ransomware.wannacry`)
  - Threat categories with detection counts
  - Family labels/tags for malware classification
  - Detection ratios and links to full analysis
- **🔍 YARA Scanning** - Local malware classification using YARA Forge ruleset (~1000+ rules)
- **🔄 Real-Time Scanning** - Background daemon scans files as they're downloaded
- **📧 Email Delivery** - HTML and plain text reports via SMTP (Scaleway, SendGrid, Mailgun, etc.)
- **🔗 Session Links** - Direct links to web dashboard for TTY playback (if enabled)
- **⚡ Automatic Setup** - Fully automated via `master-config.toml` during deployment

### Configuration Daily Reporting System

Add to `master-config.toml`:

```toml
[honeypot]
enable_reporting = true
maxmind_account_id = "YOUR_ACCOUNT_ID"
maxmind_license_key = "YOUR_LICENSE_KEY"

[reporting]
max_commands_per_session = 20
virustotal_api_key = "YOUR_VT_API_KEY"
email_from = "honeypot@yourdomain.com"
email_to = "admin@yourdomain.com"
email_subject_prefix = "[Honeypot]"

[email]
scaleway_domain = "yourdomain.com"
smtp_host = "smtp.tem.scw.cloud"
smtp_port = 587
smtp_user = "YOUR_SMTP_USERNAME"
smtp_password = "YOUR_SMTP_PASSWORD"
smtp_tls = true
```

### Report Contents

Each daily report includes:

1. **Summary Statistics**
   - Total connections and unique IPs
   - Sessions with commands executed
   - Files downloaded
   - Average session duration

2. **Top Attacking Countries**
   - Geographic distribution with country names
   - Connection counts and percentages

3. **Top Credentials**
   - Most frequently attempted username:password combinations
   - Attempt counts

4. **Downloaded Files**
   - SHA256 hashes and file sizes
   - VirusTotal detection ratios and threat labels
   - YARA rule matches
   - Links to VirusTotal analysis

5. **Notable Commands**
   - Source IPs and full command lines
   - Timestamps

6. **Active Sessions**
   - Session IDs with links to web dashboard (if enabled)
   - Command counts and IP addresses

### Setup and Testing

The reporting system is automatically configured during deployment when `enable_reporting = true` in `master-config.toml`. To manually test:

```bash
# SSH to the honeypot
ssh -p 2222 root@<SERVER_IP>

# Test the report
cd /opt/cowrie
uv run scripts/daily-report.py --test

# View YARA scanner status
journalctl -u yara-scanner -f
```

### Dependencies

All dependencies are managed with [uv](https://github.com/astral-sh/uv) - a modern, fast Python package manager:
- MaxMind GeoIP databases (auto-updated weekly on Wednesdays at 3 AM)
- VirusTotal API (free tier: 4 requests/minute with caching)
- YARA rules (auto-updated daily at 4 AM)
- Postfix for email delivery (configured automatically)

### Advanced Configuration

You can customize the report interval in `master-config.toml`:

```toml
[advanced]
report_hours = 24  # Default: 24 hours (daily)
```

Reports are sent via cron job at the configured interval.

See [scripts/README.md](scripts/README.md) for detailed documentation.

## Data Sharing and Threat Intelligence

The toolkit supports sharing honeypot data with global threat intelligence communities and querying IP reputation services. This helps improve collective security and provides context about attackers.

### AbuseIPDB

**What it does:** Reports malicious IPs to AbuseIPDB and queries the AbuseIPDB database to get reputation data for attacking IPs. The web dashboard displays AbuseIPDB threat intelligence instead of DShield for richer IP reputation information.

**Configuration in `master-config.toml`:**
```toml
[data_sharing]
abuseipdb_enabled = true
abuseipdb_api_key = "YOUR_ABUSEIPDB_API_KEY"
# Or: "op read op://Personal/AbuseIPDB/api_key"
abuseipdb_tolerance_attempts = 10  # Report IPs after this many failed login attempts
abuseipdb_tolerance_window = 120   # Time window in minutes for tracking attempts
abuseipdb_rereport_after = 24       # Hours before re-reporting the same IP
```

**Getting an API Key:**
1. Sign up at <https://www.abuseipdb.com/>
2. Get your API key from <https://www.abuseipdb.com/account/api>
3. Free tier: 1,000 requests/day for reporting and checking IPs

**What you get:**
- Abuse Confidence Score (0-100%): Likelihood that an IP is malicious
- Total Reports: Number of times the IP has been reported
- IP details: ISP, usage type (Commercial, Data Center, etc.), country
- Whitelisting status: Whether the IP is on AbuseIPDB's whitelist
- Data displayed in the web dashboard's threat intelligence section

**What data is reported:**
- Source IP addresses
- Failed login attempts that exceed the tolerance threshold
- Attack timestamps and patterns

**Benefits:**
- Contribute to global IP reputation database
- Get real-time abuse confidence scores for attacking IPs
- Identify known malicious IPs vs first-time offenders
- Free API with generous daily limits
- Richer threat intelligence than report-only services

**Web Dashboard Integration:**
The web dashboard displays AbuseIPDB data with abuse confidence scores, total reports, and ISP information. This replaces the DShield display and provides more actionable intelligence for threat assessment.

### DShield (SANS Internet Storm Center)

**What it does:** Automatically shares attack data with the SANS Internet Storm Center's DShield project, contributing to global threat intelligence. This is a report-only plugin - it sends data but doesn't query for threat intelligence.

**Note:** The web dashboard displays AbuseIPDB threat intelligence instead of DShield because AbuseIPDB provides bidirectional data (both reporting and querying), while DShield is report-only. Both plugins can be enabled simultaneously to contribute to multiple threat intelligence sources.

**Configuration in `master-config.toml`:**
```toml
[data_sharing]
dshield_enabled = true
dshield_userid = "YOUR_DSHIELD_USERID"
dshield_auth_key = "YOUR_DSHIELD_AUTH_KEY"
# Or: "op read op://Personal/DShield/auth_key"
dshield_batch_size = 100  # Events to batch before sending
```

**Getting Credentials:**
1. Sign up at <https://isc.sans.edu/ssh.html>
2. Get your credentials at <https://isc.sans.edu/myaccount.html>
3. Your data will appear in DShield's global threat database

**What data is shared:** SSH connection attempts, authentication attempts, source IPs, timestamps

**Benefits:**
- Contribute to global threat intelligence
- Help security researchers identify attack patterns
- Free participation in the SANS ISC community
- View aggregated data from thousands of sensors worldwide

### GreyNoise Threat Intelligence

**What it does:** Queries GreyNoise API to identify if attacking IPs are known scanners, bots, or mass internet scanners. Enriches logs with threat classification data.

**Configuration in `master-config.toml`:**
```toml
[data_sharing]
greynoise_enabled = true
greynoise_api_key = ""  # Optional: API key for higher limits
# Or: "op read op://Personal/GreyNoise/api_key"
greynoise_tags = "all"  # Or specify: "SHODAN,JBOSS_WORM,CPANEL_SCANNER_LOW"
greynoise_debug = false
```

**Getting an API Key:**
- Free Community API: Works without a key (limited queries)
- Free API Key: <https://www.greynoise.io/> (5,000 queries/month)
- Paid plans available for higher volume

**What you get:**
- Classification: Benign, malicious, or unknown
- Actor tags: SHODAN, Censys, Mirai, etc.
- Organization information
- First/last seen dates
- Logged to `cowrie.log` for analysis

**Benefits:**
- Identify mass internet scanners vs targeted attacks
- Filter noise from security research scanners
- Understand attacker infrastructure

### ASN (Autonomous System Number) Data

**What it does:** Enriches IP data with ASN information, showing which network/organization owns the attacking IP.

**Configuration:** Automatically enabled when MaxMind databases are configured. The web dashboard's IP list displays:
- ASN number (e.g., AS15169)
- Organization name (e.g., Google LLC, DigitalOcean, Alibaba)

**No additional configuration needed** - Uses the existing MaxMind GeoLite2-ASN database that's automatically downloaded during deployment.

**Benefits:**
- Identify cloud providers hosting attacks
- Track patterns by network (e.g., attacks from specific ASNs)
- Understand infrastructure abuse patterns

### Other Honeypot Data Sharing Opportunities

Several other projects accept honeypot data contributions:

1. **OWASP Honeypot Project**
   - Open-source threat intelligence collection
   - Exports to STIX/TAXII formats for MISP integration
   - Focus: Web application attacks and SSH/telnet
   - More info: <https://github.com/OWASP/Honeypot-Project>

2. **AlienVault OTX (Open Threat Exchange)**
   - Free threat intelligence community
   - Accepts manual or automated threat submissions
   - Pulse-based sharing system
   - API available for automation
   - Sign up: <https://otx.alienvault.com/>

3. **Shodan Honeyscore**
   - Query service (not data submission)
   - Check if your honeypot is detectable as a honeypot
   - API: <https://api.shodan.io/labs/honeyscore/{ip}>
   - Helps improve anti-fingerprinting

**Note on Privacy and Legal Compliance:**
- Review each service's data handling policy
- Ensure compliance with local privacy laws (GDPR, etc.)
- Most services anonymize or aggregate data
- You control what data is shared via Cowrie output modules

## Real-Time YARA Malware Scanning

The toolkit includes a background daemon that automatically scans downloaded malware with YARA rules as files are captured.

### Features for YARA

- **🔄 Real-Time Scanning** - Automatically scans files as they're downloaded by attackers
- **📚 YARA Forge Ruleset** - Uses the comprehensive YARA Forge full ruleset (~1000+ rules)
- **🗄️ SQLite Caching** - Caches scan results to avoid re-scanning files
- **📊 File Type Detection** - Identifies file types, MIME types, and categories
- **⚡ Inotify Monitoring** - Watches download directory for new files using Linux inotify
- **🔁 Automatic Updates** - Daily cron job updates YARA rules (4 AM)
- **🐧 Systemd Service** - Runs as a hardened systemd service with automatic restart

### Technical Details for YARA

**Implementation:**
- Python daemon using `inotify` to watch `/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads`
- Scans files with compiled YARA rules on detection
- Stores results in SQLite database: `/opt/cowrie/var/yara-cache.db`
- Used by both daily-report.py and web dashboard (app.py)
- Handles race conditions during file writes

**Database Schema:**
```sql
CREATE TABLE yara_cache (
    sha256 TEXT PRIMARY KEY,
    matches TEXT NOT NULL,           -- JSON array of matched rules
    scan_timestamp INTEGER NOT NULL,
    rules_version TEXT,
    file_type TEXT,                  -- e.g., "ELF", "PE", "Shell Script"
    file_mime TEXT,                  -- e.g., "application/x-executable"
    file_category TEXT,              -- e.g., "Executable", "Script", "Archive"
    is_previewable INTEGER DEFAULT 0 -- Whether file can be previewed as text
);
```

**Systemd Service:**
```ini
[Unit]
Description=Cowrie YARA Scanner Daemon
After=network.target docker.service

[Service]
Type=simple
User=root
Environment="COWRIE_DOWNLOAD_PATH=/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"
Environment="YARA_RULES_PATH=/opt/cowrie/yara-rules"
Environment="YARA_CACHE_DB_PATH=/opt/cowrie/var/yara-cache.db"
ExecStart=/opt/cowrie/.venv/bin/python scripts/yara-scanner-daemon.py
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/cowrie/var /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads
```

**Commands:**
```bash
# View daemon logs
journalctl -u yara-scanner -f

# Restart daemon
systemctl restart yara-scanner

# Check daemon status
systemctl status yara-scanner

# View cache statistics
cd /opt/cowrie && uv run scripts/yara-scanner-daemon.py --stats

# Manually scan existing files
cd /opt/cowrie && uv run scripts/yara-scanner-daemon.py --scan-existing
```

**YARA Rules Update:**
- Daily cron job: `/opt/cowrie/scripts/update-yara-rules.sh`
- Downloads latest YARA Forge full ruleset
- Runs at 4 AM daily
- Logs to `/var/log/yara-update.log`

## Accessing the Deployed Honeypot

**Note**: Replace `<SERVER_IP>` with `<TAILSCALE_IP>` if you enabled Tailscale with `block_public_ssh = true`.

```bash
# Management SSH (real shell)
ssh -p 2222 root@<SERVER_IP>

# View honeypot logs
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log'

# View JSON logs (for parsing)
ssh -p 2222 root@<SERVER_IP> 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'

# View TTY session recordings
ssh -p 2222 root@<SERVER_IP> 'ls -la /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/tty/'

# View downloaded malware
ssh -p 2222 root@<SERVER_IP> 'ls -la /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads/'

# Container management
ssh -p 2222 root@<SERVER_IP> 'cd /opt/cowrie && docker compose logs -f'
ssh -p 2222 root@<SERVER_IP> 'cd /opt/cowrie && docker compose restart'
```

## Cleanup

```bash
# Delete honeypot server
hcloud server delete <SERVER_ID>
```

## Development Notes

- Scripts use `set -euo pipefail` for safety
- Cleanup trap removes server on deployment failure
- Docker container runs with security hardening (no-new-privileges, read-only, cap_drop ALL)
- Automatic security updates configured with 3 AM reboot window
