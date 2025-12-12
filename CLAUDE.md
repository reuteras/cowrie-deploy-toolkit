# Cowrie Honeypot Deployment Toolkit

## Project Overview

This project provides scripts to deploy realistic Cowrie SSH honeypots on Hetzner Cloud infrastructure. The toolkit creates honeypots that are difficult to fingerprint by capturing the filesystem and identity of a real Debian server.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Honeypot Deployment Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. generate_cowrie_fs_from_hetzner.sh                          │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ Creates temporary Hetzner server                        │ │
│     │ → Sets realistic hostname (dmz-web01)                   │ │
│     │ → Installs nginx for realistic process list             │ │
│     │ → Generates fs.pickle (filesystem snapshot)             │ │
│     │ → Captures identity metadata (kernel, SSH banner, etc)  │ │
│     │ → Collects file contents (/etc/passwd, configs, etc)    │ │
│     │ → Destroys temporary server                             │ │
│     └─────────────────────────────────────────────────────────┘ │
│                            ↓                                     │
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
│                            ↓                                     │
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
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Scripts

### generate_cowrie_fs_from_hetzner.sh

Creates a realistic filesystem snapshot and identity from a fresh Hetzner Debian server.

**What it does:**
- Spins up a temporary cpx11 Debian 13 server
- Sets a realistic hostname (configurable: `dmz-web01`)
- Installs nginx to have realistic services in the process list
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
3. **Realistic process list** - Captures `ps` output with nginx running
4. **Authentic SSH banner** - Uses the exact SSH banner from the source server
5. **Real file contents** - `/etc/passwd`, `/etc/shadow`, configs are from real system
6. **Matching kernel strings** - Kernel version, build string, and arch match source
7. **IP-locked credentials** - Each IP is locked to the first credentials they successfully authenticate with

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

### Benefits

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

The toolkit includes an optional web dashboard for viewing and replaying SSH sessions:

- **Dashboard** - Overview of attack statistics, top countries, credentials, and commands
- **Session Browser** - List all sessions with filtering and search
- **TTY Playback** - Watch recorded SSH sessions with asciinema-player
- **Downloads Viewer** - Browse captured malware with VirusTotal links

### Enabling the Web Dashboard

Add to `master-config.toml`:

```toml
[web_dashboard]
enabled = true
# Note: The base URL for session links in email reports is automatically
# built from tailscale_name and tailscale_domain when Tailscale is enabled.
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

## Data Sharing and Threat Intelligence

The toolkit supports sharing honeypot data with global threat intelligence communities and querying IP reputation services. This helps improve collective security and provides context about attackers.

### DShield (SANS Internet Storm Center)

**What it does:** Automatically shares attack data with the SANS Internet Storm Center's DShield project, contributing to global threat intelligence.

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
1. Sign up at https://isc.sans.edu/ssh.html
2. Get your credentials at https://isc.sans.edu/myaccount.html
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
- Free API Key: https://www.greynoise.io/ (5,000 queries/month)
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
   - More info: https://github.com/OWASP/Honeypot-Project

2. **MISP (Malware Information Sharing Platform)**
   - Open-source threat intelligence platform
   - Can import Cowrie JSON logs as MISP events
   - Community-driven threat sharing
   - Integration available via custom scripts
   - More info: https://www.misp-project.org/

3. **AlienVault OTX (Open Threat Exchange)**
   - Free threat intelligence community
   - Accepts manual or automated threat submissions
   - Pulse-based sharing system
   - API available for automation
   - Sign up: https://otx.alienvault.com/

4. **Shodan Honeyscore**
   - Query service (not data submission)
   - Check if your honeypot is detectable as a honeypot
   - API: https://api.shodan.io/labs/honeyscore/{ip}
   - Helps improve anti-fingerprinting

5. **HoneyDB**
   - Community honeypot data aggregation
   - JSON-based API for submissions
   - Provides visualization and analytics
   - More info: https://honeydb.io/

6. **CommunityHoneyNetwork (CHN)**
   - Deployment framework with central management
   - Built-in data aggregation and sharing
   - Supports multiple honeypot types
   - Self-hosted or cloud options
   - More info: https://communityhoneynetwork.readthedocs.io/

**Note on Privacy and Legal Compliance:**
- Review each service's data handling policy
- Ensure compliance with local privacy laws (GDPR, etc.)
- Most services anonymize or aggregate data
- You control what data is shared via Cowrie output modules

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
