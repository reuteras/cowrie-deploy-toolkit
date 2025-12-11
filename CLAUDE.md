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
