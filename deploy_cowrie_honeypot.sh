#!/usr/bin/env bash

# ============================================================
# Cowrie Honeypot Deployment Script
# ============================================================
# Deploys a Cowrie honeypot using a previously generated filesystem snapshot
# with automated configuration, security hardening, and optional features.
# ============================================================

# Load common functions library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scripts/common.sh"

# ============================================================
# DEPENDENCY CHECKS
# ============================================================

echo_info "Checking required dependencies..."
check_dependencies "hcloud" "jq" "nc" "tar" "ssh" "scp" "python3"

# ============================================================
# CONFIGURATION
# ============================================================

if [ $# -ne 1 ]; then
    echo_error "Usage: $0 <output_directory>"
    echo_error "Example: $0 ./output_20251204_135502"
    echo ""
    echo_error "Requires master-config.toml in project root"
    exit 1
fi

OUTPUT_DIR="$1"
IDENTITY_DIR="$OUTPUT_DIR/identity"
FS_PICKLE="$OUTPUT_DIR/fs.pickle"
MASTER_CONFIG="./master-config.toml"
DEPLOY_LOG="$OUTPUT_DIR/deploy-$(date +%Y%m%d-%H%M%S).log"

# Set up logging - all output goes to both console and log file
exec > >(tee -a "$DEPLOY_LOG") 2>&1

# Verify the required files exist
if [ ! -f "$FS_PICKLE" ]; then
    echo "Error: fs.pickle not found at $FS_PICKLE"
    exit 1
fi

if [ ! -d "$IDENTITY_DIR" ]; then
    echo "Error: identity directory not found at $IDENTITY_DIR"
    exit 1
fi

# Default deployment configuration
SERVER_TYPE="cpx11"
SERVER_IMAGE="debian-13"
SSH_KEY_NAME1="SSH Key 1"
SSH_KEY_NAME2="SSH Key 2"
COWRIE_SSH_PORT="22"        # Cowrie listens on port 22
REAL_SSH_PORT="2222"        # Move real SSH to 2222

# Check if master config exists and read settings
ENABLE_REPORTING="false"
ENABLE_WEB_DASHBOARD="false"
TAILSCALE_AUTHKEY=""
ENABLE_TAILSCALE="false"
TAILSCALE_BLOCK_PUBLIC_SSH="true"
TAILSCALE_USE_SSH="false"
TAILSCALE_NAME="cowrie-honeypot"
TAILSCALE_DOMAIN=""

if [ -f "$MASTER_CONFIG" ]; then
    echo_info "Found master-config.toml, reading deployment settings..."

    # Read deployment configuration using TOML parser
    CONFIG_SERVER_TYPE=$(read_toml_value "$MASTER_CONFIG" "deployment.server_type")
    [ -n "$CONFIG_SERVER_TYPE" ] && SERVER_TYPE="$CONFIG_SERVER_TYPE"

    CONFIG_SERVER_IMAGE=$(read_toml_value "$MASTER_CONFIG" "deployment.server_image")
    [ -n "$CONFIG_SERVER_IMAGE" ] && SERVER_IMAGE="$CONFIG_SERVER_IMAGE"

    # Read SSH keys array
    SSH_KEYS_TEMP=()
    read_toml_array "$MASTER_CONFIG" "deployment.ssh_keys" SSH_KEYS_TEMP
    if [ ${#SSH_KEYS_TEMP[@]} -ge 1 ]; then
        SSH_KEY_NAME1="${SSH_KEYS_TEMP[0]}"
    fi
    if [ ${#SSH_KEYS_TEMP[@]} -ge 2 ]; then
        SSH_KEY_NAME2="${SSH_KEYS_TEMP[1]}"
    fi

    echo_info "Using deployment config: $SERVER_TYPE, $SERVER_IMAGE"

    # Check if reporting is enabled
    CONFIG_ENABLE_REPORTING=$(read_toml_value "$MASTER_CONFIG" "honeypot.enable_reporting")
    if [ "$CONFIG_ENABLE_REPORTING" = "true" ]; then
        ENABLE_REPORTING="true"
        echo_info "Reporting is enabled in master config"
    fi

    # Check if Tailscale is enabled
    CONFIG_TAILSCALE_ENABLED=$(read_toml_value "$MASTER_CONFIG" "tailscale.enabled")
    if [ "$CONFIG_TAILSCALE_ENABLED" = "true" ]; then
        ENABLE_TAILSCALE="true"
        echo_info "Tailscale is enabled in master config"

        # Extract auth key
        TAILSCALE_AUTHKEY=$(read_toml_value "$MASTER_CONFIG" "tailscale.authkey")
        if echo "$TAILSCALE_AUTHKEY" | grep -q "^op read"; then
            TAILSCALE_AUTHKEY=$(eval "$TAILSCALE_AUTHKEY")
        fi

        # Extract tailscale_name (hostname for Tailscale)
        CONFIG_TAILSCALE_NAME=$(read_toml_value "$MASTER_CONFIG" "tailscale.tailscale_name")
        [ -n "$CONFIG_TAILSCALE_NAME" ] && TAILSCALE_NAME="$CONFIG_TAILSCALE_NAME"

        # Extract tailscale_domain (tailnet domain)
        TAILSCALE_DOMAIN=$(read_toml_value "$MASTER_CONFIG" "tailscale.tailscale_domain")

        # Extract block_public_ssh setting
        CONFIG_BLOCK_PUBLIC_SSH=$(read_toml_value "$MASTER_CONFIG" "tailscale.block_public_ssh")
        if [ "$CONFIG_BLOCK_PUBLIC_SSH" = "false" ]; then
            TAILSCALE_BLOCK_PUBLIC_SSH="false"
        fi

        # Extract use_tailscale_ssh setting
        CONFIG_USE_TAILSCALE_SSH=$(read_toml_value "$MASTER_CONFIG" "tailscale.use_tailscale_ssh")
        if [ "$CONFIG_USE_TAILSCALE_SSH" = "true" ]; then
            TAILSCALE_USE_SSH="true"
        fi
    fi

    # Check if web dashboard is enabled
    CONFIG_WEB_DASHBOARD=$(read_toml_value "$MASTER_CONFIG" "web_dashboard.enabled")
    if [ "$CONFIG_WEB_DASHBOARD" = "true" ]; then
        ENABLE_WEB_DASHBOARD="true"
        echo_info "Web dashboard is enabled in master config"
    fi

    # Check if data sharing is enabled (DShield and GreyNoise)
    DSHIELD_ENABLED="false"
    DSHIELD_USERID=""
    DSHIELD_AUTH_KEY=""
    DSHIELD_BATCH_SIZE="100"
    GREYNOISE_ENABLED="false"
    GREYNOISE_API_KEY=""
    GREYNOISE_TAGS="all"
    GREYNOISE_DEBUG="false"

    # DShield configuration
    CONFIG_DSHIELD_ENABLED=$(read_toml_value "$MASTER_CONFIG" "data_sharing.dshield_enabled")
    if [ "$CONFIG_DSHIELD_ENABLED" = "true" ]; then
        DSHIELD_ENABLED="true"
        echo_info "DShield data sharing is enabled"

        # Extract DShield credentials
        DSHIELD_USERID=$(read_toml_value "$MASTER_CONFIG" "data_sharing.dshield_userid")
        DSHIELD_AUTH_KEY=$(read_toml_value "$MASTER_CONFIG" "data_sharing.dshield_auth_key")
        CONFIG_DSHIELD_BATCH_SIZE=$(read_toml_value "$MASTER_CONFIG" "data_sharing.dshield_batch_size")

        # Execute command if it looks like "op read" command
        if echo "$DSHIELD_AUTH_KEY" | grep -q "^op read"; then
            DSHIELD_AUTH_KEY=$(eval "$DSHIELD_AUTH_KEY" 2>/dev/null || echo "")
        fi

        [ -n "$CONFIG_DSHIELD_BATCH_SIZE" ] && DSHIELD_BATCH_SIZE="$CONFIG_DSHIELD_BATCH_SIZE"
    fi

    # GreyNoise configuration
    CONFIG_GREYNOISE_ENABLED=$(read_toml_value "$MASTER_CONFIG" "data_sharing.greynoise_enabled")
    if [ "$CONFIG_GREYNOISE_ENABLED" = "true" ]; then
        GREYNOISE_ENABLED="true"
        echo_info "GreyNoise threat intelligence lookup is enabled"

        # Extract GreyNoise settings
        GREYNOISE_API_KEY=$(read_toml_value "$MASTER_CONFIG" "data_sharing.greynoise_api_key")
        CONFIG_GREYNOISE_TAGS=$(read_toml_value "$MASTER_CONFIG" "data_sharing.greynoise_tags")

        # Execute command if it looks like "op read" command
        if echo "$GREYNOISE_API_KEY" | grep -q "^op read"; then
            GREYNOISE_API_KEY=$(eval "$GREYNOISE_API_KEY" 2>/dev/null || echo "")
        fi

        CONFIG_GREYNOISE_DEBUG=$(read_toml_value "$MASTER_CONFIG" "data_sharing.greynoise_debug")
        if [ "$CONFIG_GREYNOISE_DEBUG" = "true" ]; then
            GREYNOISE_DEBUG="true"
        fi

        [ -n "$CONFIG_GREYNOISE_TAGS" ] && GREYNOISE_TAGS="$CONFIG_GREYNOISE_TAGS"
    fi
else
    echo_warn " Error: master-config.toml not found, using default settings"
    exit
fi

SERVER_NAME="cowrie-honeypot-$(date +%s)"

echo_info "Deploying Cowrie honeypot from: $OUTPUT_DIR"

# ============================================================
# STEP 1 — Create server
# ============================================================

echo_info "Creating Hetzner server: $SERVER_NAME"

SERVER_ID=$(hcloud server create \
    --name "$SERVER_NAME" \
    --type "$SERVER_TYPE" \
    --image "$SERVER_IMAGE" \
    --ssh-key "$SSH_KEY_NAME1" \
    --ssh-key "$SSH_KEY_NAME2" \
    --output json 2> /dev/null | jq -r '.server.id')

echo_info "Server created with ID: $SERVER_ID"

# Set up cleanup on error
cleanup_on_error() {
    echo ""
    echo_warn " Deployment failed! Cleaning up..."
    echo_info "Deleting server $SERVER_ID..."
    hcloud server delete "$SERVER_ID" 2>/dev/null || true
    echo_info "Server deleted."
    exit 1
}

trap cleanup_on_error ERR

# Wait for IP
echo_info "Waiting for server IP..."
sleep 5

SERVER_IP=$(hcloud server describe "$SERVER_ID" --output json | jq -r '.public_net.ipv4.ip')

echo_info "Server IP: $SERVER_IP"
echo_info "Cowrie honeypot will run on port $COWRIE_SSH_PORT"

# ============================================================
# STEP 2 — Wait for SSH
# ============================================================

echo_n_info "Waiting for SSH to become available"
until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 "root@$SERVER_IP" "echo ." 2>/dev/null; do
    printf "."
    sleep 3
done
echo_info "SSH is ready."

# ============================================================
# STEP 3 — Move SSH to alternate port
# ============================================================

echo_info "Moving SSH to port $REAL_SSH_PORT..."

# shellcheck disable=SC2087
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$SERVER_IP" bash << EOF
set -e
# Change SSH port - remove any existing Port directives and add new one
sed -i '/^#\?Port /d' /etc/ssh/sshd_config
echo "Port $REAL_SSH_PORT" >> /etc/ssh/sshd_config

# Test config before restarting
sshd -t > /dev/null

# Restart SSH
systemctl restart sshd > /dev/null
EOF

echo_info "SSH moved to port $REAL_SSH_PORT. Reconnecting..."
sleep 3

# Test new SSH port
echo_n_info "Testing SSH on port $REAL_SSH_PORT"
until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 -p "$REAL_SSH_PORT" "root@$SERVER_IP" "echo -n ." 2>/dev/null; do
    printf "."
    sleep 2
done
echo ""
echo_info "SSH confirmed on port $REAL_SSH_PORT."

# ============================================================
# STEP 3.5 — Set up Tailscale (if enabled)
# ============================================================

if [ "$ENABLE_TAILSCALE" = "true" ]; then
    if [ -z "$TAILSCALE_AUTHKEY" ]; then
        echo_warn " Error: Tailscale is enabled but no auth key provided"
        echo_warn " Add 'authkey' to the [tailscale] section in master-config.toml"
        exit 1
    fi

    echo_info "Setting up Tailscale for secure management access..."

    # shellcheck disable=SC2087
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << TAILSCALEEOF
set -e

# Install Tailscale
echo "[remote] Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh > /dev/null 2>&1

# Start and authenticate Tailscale
echo "[remote] Authenticating with Tailscale..."
tailscale up --authkey="$TAILSCALE_AUTHKEY" --ssh=${TAILSCALE_USE_SSH} --hostname="$TAILSCALE_NAME" > /dev/null 2>&1

# Get Tailscale IP
TAILSCALE_IP=\$(tailscale ip -4)
echo "[remote] Tailscale IP: \$TAILSCALE_IP"
TAILSCALEEOF

    # Get the Tailscale IP for display
    TAILSCALE_IP=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" "tailscale ip -4" 2>/dev/null)

    echo_info "Tailscale configured successfully"
    echo_info "Tailscale IP: $TAILSCALE_IP"

    if [ "$TAILSCALE_BLOCK_PUBLIC_SSH" = "true" ]; then
        echo_info "IMPORTANT: Management SSH is now ONLY accessible via Tailscale"
        echo_info "    Connect with: ssh root@$TAILSCALE_IP"
    fi
else
    echo_info "Tailscale disabled, management SSH accessible via public IP"
fi

# ============================================================
# STEP 4 — Install Docker
# ============================================================

echo_info "Installing Docker..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
set -e
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    ca-certificates \
    curl \
    gnupg \
    jq > /dev/null

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin > /dev/null

# Enable and start Docker
systemctl enable docker > /dev/null 2>&1
systemctl start docker > /dev/null
EOF

echo_info "Docker installed."

# ============================================================
# STEP 5 — Configure automatic updates and security
# ============================================================

echo_info "Configuring automatic security updates..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
set -e

# Install unattended-upgrades for automatic security updates
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y unattended-upgrades apt-listchanges > /dev/null 2>&1

# Configure unattended-upgrades for ALL updates (not just security)
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDEDEOF'
Unattended-Upgrade::Origins-Pattern {
    // Install ALL Debian updates (main repository)
    "origin=Debian,codename=${distro_codename},label=Debian";
    // Install from stable-updates
    "origin=Debian,codename=${distro_codename}-updates";
    // Install security updates
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
UNATTENDEDEOF

# Enable automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOEOF

# Ensure Docker starts on boot (for Cowrie auto-restart)
systemctl enable docker > /dev/null 2>&1

echo "[remote] Automatic updates configured for ALL packages (will reboot at 3 AM if needed)"
EOF

echo_info "Security configuration complete."

# ============================================================
# STEP 6 — Upload configuration
# ============================================================

echo_info "Uploading Cowrie configuration..."

# Create remote directory structure
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
mkdir -p /opt/cowrie/etc /opt/cowrie/var/lib/cowrie/downloads /opt/cowrie/var/log/cowrie /opt/cowrie/share/cowrie

# Set ownership to UID 999 (cowrie user in container) for writable directories
chown -R 999:999 /opt/cowrie/var
EOF

# Upload fs.pickle to share directory (bind mounted)
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    "$FS_PICKLE" "root@$SERVER_IP:/opt/cowrie/share/cowrie/fs.pickle" > /dev/null

# Generate and upload cmdoutput.json for realistic process list
if [ -f "$IDENTITY_DIR/ps.txt" ]; then
    echo_info "Generating cmdoutput.json from ps.txt..."

    # Generate cmdoutput.json using the converter script
    if command -v uv &> /dev/null; then
        CMDOUTPUT_TMP=$(create_temp_file ".json")
        uv run --quiet scripts/ps-to-cmdoutput.py "$IDENTITY_DIR/ps.txt" "$CMDOUTPUT_TMP"

        # Upload cmdoutput.json
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
            "$CMDOUTPUT_TMP" "root@$SERVER_IP:/opt/cowrie/share/cowrie/cmdoutput.json" > /dev/null

        # Set proper permissions (readable by Cowrie container)
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
            "chmod 644 /opt/cowrie/share/cowrie/cmdoutput.json"

        echo_info "fs.pickle and cmdoutput.json uploaded."
    else
        echo_warn " Warning: uv not found. Cannot generate cmdoutput.json."
        echo_info "fs.pickle uploaded (cmdoutput.json generation skipped)."
    fi
else
    echo_warn " Error ps.txt not found, exiting."
    exit 1
fi

# Upload contents directory for real file content
CONTENTS_DIR="$OUTPUT_DIR/contents"
if [ -d "$CONTENTS_DIR" ] && [ "$(ls -A "$CONTENTS_DIR" 2>/dev/null)" ]; then
    echo_info "Uploading file contents..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mkdir -p /opt/cowrie/share/cowrie/contents"

    # Upload contents as tarball for efficiency (--no-xattrs to avoid macOS extended attributes)
    CONTENTS_TAR=$(create_temp_file ".tar.gz")
    tar --no-xattrs -czf "$CONTENTS_TAR" -C "$CONTENTS_DIR" . 2>/dev/null
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        "$CONTENTS_TAR" "root@$SERVER_IP:/tmp/contents.tar.gz" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/share/cowrie/contents && tar xzf /tmp/contents.tar.gz && rm /tmp/contents.tar.gz"

    FILE_COUNT=$(find "$CONTENTS_DIR" -type f | wc -l | tr -d ' ')
    echo_info "Uploaded $FILE_COUNT files with real content"
else
    echo_warn " Warning: No contents directory found, files will have no content"
fi

# Upload txtcmds directory for real command output
CONTENTS_DIR="$OUTPUT_DIR/txtcmds"
if [ -d "$CONTENTS_DIR" ] && [ "$(ls -A "$CONTENTS_DIR" 2>/dev/null)" ]; then
    echo_info "Uploading txtcmds contents..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mkdir -p /opt/cowrie/share/cowrie/txtcmds"

    # Upload txtcmds as tarball for efficiency (--no-xattrs to avoid macOS extended attributes)
    tar --no-xattrs -czf /tmp/txtcmds.tar.gz -C "$CONTENTS_DIR" . 2>/dev/null
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        /tmp/txtcmds.tar.gz "root@$SERVER_IP:/tmp/txtcmds.tar.gz" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/share/cowrie/txtcmds && tar xzf /tmp/txtcmds.tar.gz && rm /tmp/txtcmds.tar.gz"
    rm /tmp/txtcmds.tar.gz

    FILE_COUNT=$(find "$CONTENTS_DIR" -type f | wc -l | tr -d ' ')
    echo_info "Uploaded $FILE_COUNT files with txtcmds content"
else
    echo_warn " Warning: No txtcmds directory found"
fi

# ============================================================
# STEP 6.5 — Upload Custom Cowrie Build Context
# ============================================================

echo_info "Uploading custom Cowrie build context..."

# Create build directory on server
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
    "mkdir -p /opt/cowrie/build/cowrie-plugins"

# Upload Dockerfile
if [ -f "./cowrie/Dockerfile" ]; then
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        ./cowrie/Dockerfile "root@$SERVER_IP:/opt/cowrie/build/" > /dev/null
    echo_info "Dockerfile uploaded"
else
    echo_error "Error: Dockerfile not found at ./cowrie/Dockerfile"
    exit 1
fi

# Upload userdb.txt (if exists) else upload userdb.txt.default as fallback
if [ -f "./cowrie/userdb.txt" ]; then
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        ./cowrie/userdb.txt "root@$SERVER_IP:/opt/cowrie/etc/userdb.txt" > /dev/null
    echo_info "Custom userdb.txt uploaded"
else
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        ./cowrie/userdb.txt.default "root@$SERVER_IP:/opt/cowrie/etc/userdb.txt" > /dev/null
    echo_info "Default userdb.txt uploaded"
fi

# Upload custom plugins (if any exist)
if [ -d "./cowrie-plugins" ] && [ "$(ls -A ./cowrie-plugins/*.py 2>/dev/null)" ]; then
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        ./cowrie-plugins/*.py "root@$SERVER_IP:/opt/cowrie/build/cowrie-plugins/" > /dev/null 2>&1
    echo_info "Custom plugins uploaded ($(ls -1 ./cowrie-plugins/*.py 2>/dev/null | wc -l | tr -d ' ') files)"
else
    echo_info "No custom plugins found (build will use defaults only)"
fi

# Ensure .gitkeep exists so directory isn't empty
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
    "touch /opt/cowrie/build/cowrie-plugins/.gitkeep"

# ============================================================
# ============================================================
# STEP 7 — Generate cowrie.cfg
# ============================================================

echo_info "Generating cowrie.cfg with identity data..."

# Read identity data
KERNEL_VERSION=$(cat "$IDENTITY_DIR/kernel.txt" | awk '{print $3}')
KERNEL_ARCH=$(cat "$IDENTITY_DIR/kernel.txt" | sed -E "s/.*) //" | awk '{print $1}')
HOSTNAME=$(cat "$IDENTITY_DIR/hostname" | tr -d '\n')
SSH_BANNER=$(cat "$IDENTITY_DIR/ssh-banner.txt" | sed 's/^SSH-2.0-//' | tr -d '\n')

# Extract kernel build string from proc-version (everything after last ') ')
KERNEL_BUILD=$(cat "$IDENTITY_DIR/proc-version" | sed -n 's/.*) \(#1 SMP.*\)$/\1/p')

# Extract OS info from os-release
OS_NAME=$(grep "^PRETTY_NAME=" "$IDENTITY_DIR/os-release" | cut -d'"' -f2)

# Determine arch based on kernel architecture
case "$KERNEL_ARCH" in
    x86_64) ARCH="linux-x64-lsb" ;;
    aarch64|arm64) ARCH="linux-aarch64-lsb" ;;
    *) ARCH="linux-x64-lsb" ;;
esac

# Extract VirusTotal API key if available (needed for reporting and web dashboard)
VT_API_KEY=""
if [ -f "$MASTER_CONFIG" ]; then
    VT_API_KEY=$(grep "virustotal_api_key" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')

    # Execute command if it looks like "op read" command
    if echo "$VT_API_KEY" | grep -q "^op read"; then
        VT_API_KEY=$(eval "$VT_API_KEY" 2>/dev/null || echo "")
    fi
fi

# Create cowrie.cfg
cat > /tmp/cowrie.cfg << EOFCFG
[honeypot]
hostname = $HOSTNAME
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty
# For https://github.com/cowrie/cowrie/blob/main/src/cowrie/commands/nc.py
out_addr = $SERVER_IP

[shell]
arch = $ARCH
filesystem = share/cowrie/fs.pickle
hardware_platform = $KERNEL_ARCH
kernel_build_string = $KERNEL_BUILD
kernel_version = $KERNEL_VERSION
operating_system = GNU/Linux
ssh_version = SSH-2.0-$SSH_BANNER

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
sftp_enabled = true
forwarding = true
forward_redirect = false
version = SSH-2.0-$SSH_BANNER

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log

[output_iplock]
enabled = true
db_path = var/lib/cowrie/iplock.db
EOFCFG

# Add VirusTotal configuration if API key is available
if [ -n "$VT_API_KEY" ]; then
    cat >> /tmp/cowrie.cfg << EOFVT

[output_virustotal]
enabled = true
api_key = $VT_API_KEY
upload = true
scan_file = true
scan_url = false
debug = false
# Optional: Collection name for organizing artifacts
# If not set, no collection will be created
#collection = cowrie
# Optional: Custom comment text (default: Cowrie attribution)
#commenttext = First seen by #Cowrie SSH/telnet Honeypot http://github.com/cowrie/cowrie
EOFVT
    echo_info "VirusTotal integration enabled in cowrie.cfg"
fi

# Add DShield configuration if enabled
if [ "$DSHIELD_ENABLED" = "true" ] && [ -n "$DSHIELD_USERID" ] && [ -n "$DSHIELD_AUTH_KEY" ]; then
    cat >> /tmp/cowrie.cfg << EOFDSHIELD

[output_dshield]
enabled = true
userid = $DSHIELD_USERID
auth_key = $DSHIELD_AUTH_KEY
batch_size = $DSHIELD_BATCH_SIZE
EOFDSHIELD
    echo_info "DShield data sharing enabled in cowrie.cfg"
fi

# Add GreyNoise configuration if enabled
if [ "$GREYNOISE_ENABLED" = "true" ]; then
    cat >> /tmp/cowrie.cfg << EOFGREYNOISE

[output_greynoise]
enabled = true
debug = $GREYNOISE_DEBUG
tags = $GREYNOISE_TAGS
EOFGREYNOISE

    # Add API key if provided
    if [ -n "$GREYNOISE_API_KEY" ]; then
        echo "api_key = $GREYNOISE_API_KEY" >> /tmp/cowrie.cfg
    fi

    echo_info "GreyNoise threat intelligence lookup enabled in cowrie.cfg"
fi

# Upload cowrie.cfg
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    /tmp/cowrie.cfg "root@$SERVER_IP:/opt/cowrie/etc/cowrie.cfg" > /dev/null

rm /tmp/cowrie.cfg

echo_info "Configuration uploaded."

# ============================================================
# STEP 8 — Deploy Cowrie container
# ============================================================

echo_info "Starting Cowrie container..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
set -e

# Create docker-compose.yml with custom build
cat > /opt/cowrie/docker-compose.yml << 'DOCKEREOF'
services:
  cowrie:
    build:
      context: /opt/cowrie/build
      dockerfile: Dockerfile
    image: cowrie-custom:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-etc:/cowrie/cowrie-git/etc
      - cowrie-var:/cowrie/cowrie-git/var
      - /opt/cowrie/share:/cowrie/cowrie-git/share:ro
      - /opt/cowrie/share/cowrie/cmdoutput.json:/cowrie/cowrie-git/src/cowrie/data/cmdoutput.json:ro
      - /opt/cowrie/share/cowrie/txtcmds:/cowrie/cowrie-git/src/cowrie/data/txtcmds:ro
      - /opt/cowrie/share/cowrie/contents:/cowrie/cowrie-git/honeyfs:ro
    environment:
      - COWRIE_HOSTNAME=server
    # Security hardening
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

volumes:
  cowrie-etc:
    name: cowrie-etc
  cowrie-var:
    name: cowrie-var
DOCKEREOF

echo "[remote] Building custom Cowrie image with plugins..."
cd /opt/cowrie
if ! docker compose build > /dev/null 2>&1; then
  echo "[remote] ERROR: Failed to build custom Cowrie image"
  exit 1
fi

echo "[remote] Extracting metadata.json from built image..."
docker run --rm cowrie-custom:latest -c "print(open('/cowrie/cowrie-git/metadata.json').read(), end='')" > /opt/cowrie/metadata.json

echo "[remote] Initializing Cowrie volumes with custom configuration..."

# Start container briefly to initialize volumes
if ! docker compose up -d > /dev/null 2>&1; then
  echo "[remote] ERROR: Failed to start Cowrie container"
  exit 1
fi
sleep 10
docker compose stop > /dev/null 2>&1

# Copy cowrie.cfg into etc volume
echo "[remote] Copying cowrie.cfg to volume..."
docker run --rm \
  -v cowrie-etc:/dest \
  -v /opt/cowrie/etc/cowrie.cfg:/src/cowrie.cfg:ro \
  alpine cp /src/cowrie.cfg /dest/ > /dev/null 2>&1

# Copy userdb.txt into etc volume
echo "[remote] Copying userdb.txt to volume..."
docker run --rm \
  -v cowrie-etc:/dest \
  -v /opt/cowrie/etc/userdb.txt:/src/userdb.txt:ro \
  alpine cp /src/userdb.txt /dest/ > /dev/null 2>&1

# Set proper ownership (UID 999 = cowrie user)
docker run --rm \
  -v cowrie-etc:/etc \
  -v cowrie-var:/var \
  alpine chown -R 999:999 /etc /var > /dev/null 2>&1

# Start Cowrie with custom configuration
echo "[remote] Starting Cowrie with custom configuration..."
cd /opt/cowrie
docker compose up -d > /dev/null 2>&1

# Wait for container to start
sleep 5

# Show status
docker compose ps > /dev/null || exit 1
EOF

echo_info "Cowrie container started."

# ============================================================
# STEP 9 — Verify honeypot status
# ============================================================

echo_info "Verifying honeypot container status..."
sleep 5

# Check container status instead of making a test connection
# (nc test creates noise in logs)
ssh -p "$REAL_SSH_PORT" root@"$SERVER_IP" "cd /opt/cowrie && docker compose ps | grep -q 'Up'" && \
    echo_info "Honeypot container is running!" || \
    echo_warn " Warning: Honeypot container may not be running correctly"

# ============================================================
# STEP 10 — Set up MaxMind GeoIP (if reporting enabled)
# ============================================================

if [ "$ENABLE_REPORTING" = "true" ] && [ -f "$MASTER_CONFIG" ]; then
    echo_info "Setting up MaxMind GeoIP databases..."

    # Extract MaxMind credentials from master config
    MAXMIND_ACCOUNT_ID=$(grep "maxmind_account_id" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')
    MAXMIND_LICENSE_KEY=$(grep "maxmind_license_key" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')

    # Execute commands if they look like "op read" commands
    if echo "$MAXMIND_ACCOUNT_ID" | grep -q "^op read"; then
        MAXMIND_ACCOUNT_ID=$(eval "$MAXMIND_ACCOUNT_ID")
    fi
    if echo "$MAXMIND_LICENSE_KEY" | grep -q "^op read"; then
        MAXMIND_LICENSE_KEY=$(eval "$MAXMIND_LICENSE_KEY")
    fi

    if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
        # Download databases to local cache (only if needed)
        echo_info "Downloading MaxMind databases to local cache (if not cached)..."
        if ! "$SCRIPT_DIR/scripts/download-maxmind-local.sh" "$MAXMIND_ACCOUNT_ID" "$MAXMIND_LICENSE_KEY"; then
            echo_error "Failed to download MaxMind databases locally"
            exit 1
        fi

        # Copy cached databases to server
        CACHE_DIR="$SCRIPT_DIR/.maxmind-cache"
        echo_info "Uploading cached MaxMind databases to server..."

        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
            "mkdir -p /var/lib/GeoIP"

        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
            "$CACHE_DIR"/GeoLite2-*.mmdb "root@$SERVER_IP:/var/lib/GeoIP/" > /dev/null

        # Set up automatic updates on server (weekly)
        # shellcheck disable=SC2087
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << MAXMINDEOF
set -e

# Install geoipupdate for automatic updates
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y geoipupdate > /dev/null

# Create GeoIP config
cat > /etc/GeoIP.conf << 'EOF'
AccountID $MAXMIND_ACCOUNT_ID
LicenseKey $MAXMIND_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /var/lib/GeoIP
EOF

# Set up weekly auto-updates (Wednesdays at 3 AM)
(crontab -l 2>/dev/null || echo "") | grep -v geoipupdate | crontab -
(crontab -l; echo "0 3 * * 3 /usr/bin/geoipupdate") | crontab -

echo "[remote] MaxMind GeoIP auto-update cron job configured"
MAXMINDEOF

        echo_info "MaxMind GeoIP databases uploaded and auto-update configured"
    else
        echo_warn " Warning: MaxMind credentials not found in master-config.toml"
        echo_warn " GeoIP enrichment will not be available"
    fi
fi

# ============================================================
# STEP 11 — Set up Postfix for Scaleway (if reporting enabled)
# ============================================================

if [ "$ENABLE_REPORTING" = "true" ] && [ -f "$MASTER_CONFIG" ]; then
    echo_info "Setting up Postfix for Scaleway Transactional Email..."

    # Extract SMTP credentials and domain from master config
    SMTP_USER=$(grep "smtp_user" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')
    SMTP_PASSWORD=$(grep "smtp_password" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')
    SCALEWAY_DOMAIN=$(grep "scaleway_domain" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')

    # Execute commands if they look like "op read" commands
    if echo "$SMTP_USER" | grep -q "^op read"; then
        SMTP_USER=$(eval "$SMTP_USER")
    fi
    if echo "$SMTP_PASSWORD" | grep -q "^op read"; then
        SMTP_PASSWORD=$(eval "$SMTP_PASSWORD")
    fi
    if echo "$SCALEWAY_DOMAIN" | grep -q "^op read"; then
        SCALEWAY_DOMAIN=$(eval "$SCALEWAY_DOMAIN")
    fi

    if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASSWORD" ]; then
        # shellcheck disable=SC2087
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << POSTFIXEOF
set -e

# Install Postfix
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix mailutils libsasl2-modules > /dev/null 2>&1

# Configure Postfix for Scaleway
cat > /etc/postfix/main.cf << EOF
# Postfix configuration for Scaleway Transactional Email
# Domain configuration
myhostname = $SERVER_NAME.$SCALEWAY_DOMAIN
myorigin = $SCALEWAY_DOMAIN
mydestination = localhost, $SCALEWAY_DOMAIN
masquerade_domains = $SCALEWAY_DOMAIN

# Network and interface configuration (security hardening)
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
inet_interfaces = loopback-only
inet_protocols = all

# Header rewriting
local_header_rewrite_clients = static:all
append_at_myorigin = yes

# Relay configuration
relayhost = [smtp.tem.scw.cloud]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
EOF

# Set up SASL password
cat > /etc/postfix/sasl_passwd << 'EOF'
[smtp.tem.scw.cloud]:587 $SMTP_USER:$SMTP_PASSWORD
EOF

# Secure the password file
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd

# Restart Postfix
systemctl restart postfix
systemctl enable postfix > /dev/null 2>&1

echo "[remote] Postfix configured for Scaleway Transactional Email"
POSTFIXEOF

        echo_info "Postfix configured successfully"

        # Send test email to verify configuration
        echo_info "Sending test email..."
        EMAIL_TO=$(grep "email_to" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')
        EMAIL_FROM=$(grep "email_from" "$MASTER_CONFIG" | head -1 | sed -E 's/^[^=]*= *"([^"]+)".*/\1/')

        if [ -n "$EMAIL_TO" ] && [ -n "$EMAIL_FROM" ]; then
            # shellcheck disable=SC2087
            ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << TESTEMAILEOF
set -e

# Get server IP (portable across Linux/BSD)
SERVER_IP=\$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print \$2}' | cut -d/ -f1 || echo "unavailable")

echo "Cowrie honeypot email configuration test

This is an automated test email sent during honeypot deployment.

If you receive this message, your email configuration is working correctly.

Server: \$(hostname)
IP: \$SERVER_IP
Time: \$(date)

You will receive daily reports from this honeypot at the configured interval.
" | mail -s "[Honeypot] Test Email - Configuration Successful" -a "From: $EMAIL_FROM" "$EMAIL_TO"

TESTEMAILEOF
            echo_info "Test email sent to $EMAIL_TO"
        else
            echo_warn " Warning: Email addresses not found in master-config.toml, skipping test email"
        fi
    else
        echo_warn " Warning: SMTP credentials not found in master-config.toml"
        echo_warn " Email delivery will not be available"
    fi
fi

# ============================================================
# STEP 12 — Set up reporting (if enabled)
# ============================================================

if [ "$ENABLE_REPORTING" = "true" ] && [ -f "$MASTER_CONFIG" ]; then
    echo_info "Setting up automated reporting..."

    # Process master config to generate server config
    echo_info "Processing master-config.toml..."
    if command -v uv &> /dev/null; then
        uv run --quiet scripts/process-config.py "$MASTER_CONFIG" > /tmp/server-report.env
    else
        echo_warn " Error: Neither uv nor python3 found. Cannot process config."
        exit 1
    fi

    if [ -f /tmp/server-report.env ]; then
        # Upload toolkit files to server
        echo_info "Uploading reporting toolkit..."
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" -r \
            scripts README.md pyproject.toml /tmp/server-report.env "root@$SERVER_IP:/opt/cowrie/" > /dev/null 2>&1

        # Move config to correct location
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
            "mv /opt/cowrie/server-report.env /opt/cowrie/etc/report.env && chmod 600 /opt/cowrie/etc/report.env"

        # Run setup-reporting.sh on the server
        echo_info "Running setup-reporting.sh on server..."
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'REPORTEOF'
cd /opt/cowrie
chmod +x scripts/setup-reporting.sh scripts/daily-report.py scripts/process-config.py
./scripts/setup-reporting.sh
REPORTEOF

        echo_info "Reporting configured successfully"
        rm -f /tmp/server-report.env
    else
        echo_warn " Error: Failed to process config. Skipping automated reporting setup."
        exit 1
    fi
else
    echo_info "Reporting disabled or master-config.toml not found, skipping reporting setup"
fi

# ============================================================
# STEP 13 — Set up web dashboard (if enabled)
# ============================================================

if [ "$ENABLE_WEB_DASHBOARD" = "true" ]; then
    echo_info "Setting up SSH Session Playback Web Dashboard..."

    # Build WEB_BASE_URL from Tailscale settings if available
    WEB_BASE_URL=""
    if [ "$ENABLE_TAILSCALE" = "true" ] && [ -n "$TAILSCALE_NAME" ] && [ -n "$TAILSCALE_DOMAIN" ]; then
        WEB_BASE_URL="https://${TAILSCALE_NAME}.${TAILSCALE_DOMAIN}"
        echo_info "Web dashboard base URL: $WEB_BASE_URL"
    fi

    # Upload web service files
    echo_info "Uploading web service files..."
    scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" -r \
        web "root@$SERVER_IP:/opt/cowrie/" || {
            echo_warn " Error: Failed to upload web service files"
            echo_warn " This usually means the web/ directory is missing from your local directory"
            echo_warn " Make sure you're running the script from the cowrie-deploy-toolkit directory"
            exit 1
        }

    # Set up web dashboard on server
    # shellcheck disable=SC2087
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << WEBEOF
set -e

# Create TTY log directory with correct permissions (if volume exists)
if [ -d /var/lib/docker/volumes/cowrie-var/_data ]; then
    mkdir -p /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/tty
    chown -R 999:999 /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/tty
else
    echo "[remote] Cowrie volume not yet created, will be created by docker compose"
fi

# Ensure GeoIP directory exists (web dashboard needs it even if reporting is disabled)
mkdir -p /var/lib/GeoIP

# Create web dashboard docker-compose file
cat > /opt/cowrie/docker-compose.yml << DOCKEREOF
services:
  cowrie:
    build:
      context: /opt/cowrie/build
      dockerfile: Dockerfile
    image: cowrie-custom:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-etc:/cowrie/cowrie-git/etc
      - cowrie-var:/cowrie/cowrie-git/var
      - /opt/cowrie/share:/cowrie/cowrie-git/share:ro
      - /opt/cowrie/share/cowrie/cmdoutput.json:/cowrie/cowrie-git/src/cowrie/data/cmdoutput.json:ro
      - /opt/cowrie/share/cowrie/txtcmds:/cowrie/cowrie-git/src/cowrie/data/txtcmds:ro
      - /opt/cowrie/share/cowrie/contents:/cowrie/cowrie-git/honeyfs:ro
    environment:
      - COWRIE_HOSTNAME=server
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - cowrie-internal

  cowrie-web:
    build:
      context: /opt/cowrie/web
      dockerfile: Dockerfile
    image: cowrie-web:local
    container_name: cowrie-web
    restart: unless-stopped
    ports:
      - "127.0.0.1:5000:5000"
    volumes:
      - cowrie-var:/cowrie-data:ro
      - /opt/cowrie/metadata.json:/cowrie-metadata/metadata.json:ro
      - /var/lib/GeoIP:/geoip:ro
      - /opt/cowrie/var:/yara-cache:ro
    environment:
      - COWRIE_LOG_PATH=/cowrie-data/log/cowrie/cowrie.json
      - COWRIE_TTY_PATH=/cowrie-data/lib/cowrie/tty
      - COWRIE_DOWNLOAD_PATH=/cowrie-data/lib/cowrie/downloads
      - GEOIP_DB_PATH=/geoip/GeoLite2-City.mmdb
      - GEOIP_ASN_PATH=/geoip/GeoLite2-ASN.mmdb
      - YARA_CACHE_DB_PATH=/yara-cache/yara-cache.db
      - COWRIE_METADATA_PATH=/cowrie-metadata/metadata.json
      - BASE_URL=$WEB_BASE_URL
      - VIRUSTOTAL_API_KEY=$VT_API_KEY
      - SERVER_IP=$SERVER_IP
      - HONEYPOT_HOSTNAME=$HOSTNAME
    depends_on:
      - cowrie
    networks:
      - cowrie-internal
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=10M,mode=1777

volumes:
  cowrie-etc:
    name: cowrie-etc
  cowrie-var:
    name: cowrie-var

networks:
  cowrie-internal:
    driver: bridge
DOCKEREOF

# Build and start web service
cd /opt/cowrie
echo "[remote] Building web dashboard container (this may take a minute)..."
docker compose build --quiet cowrie-web 2>&1 | grep -E "ERROR|WARN" || true
echo "[remote] Starting services..."
docker compose up -d --quiet-pull > /dev/null 2>&1

echo "[remote] Web dashboard deployed on localhost:5000"
echo "[remote] Access via SSH tunnel: ssh -p $REAL_SSH_PORT -L 5000:localhost:5000 root@$SERVER_IP"

# Configure Tailscale Serve if Tailscale is enabled
if command -v tailscale &> /dev/null; then
    echo "[remote] Configuring Tailscale Serve for web dashboard..."
    tailscale serve --bg --https=443 5000 > /dev/null 2>&1

    # Add @reboot cron job to ensure Tailscale Serve persists after reboot
    (crontab -l 2>/dev/null || echo "") | grep -v "tailscale serve" | crontab -
    (crontab -l; echo "@reboot sleep 30 && /usr/bin/tailscale serve --bg --https=443 5000 > /dev/null 2>&1") | crontab -

    echo "[remote] Web dashboard available at: https://\$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')"
fi
WEBEOF

    echo_info "Web dashboard configured successfully"
    if [ "$ENABLE_TAILSCALE" = "true" ] && [ -n "$TAILSCALE_DOMAIN" ]; then
        # Use configured Tailscale name and domain
        echo_info "Web dashboard available at: https://${TAILSCALE_NAME}.${TAILSCALE_DOMAIN}"
    elif [ "$ENABLE_TAILSCALE" = "true" ]; then
        # Tailscale enabled but no domain configured - query from Tailscale
        TAILSCALE_FQDN=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" "tailscale status --json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//' || echo '${TAILSCALE_NAME}'")
        echo_info "Web dashboard available at: https://$TAILSCALE_FQDN"
    else
        echo_info "Access via SSH tunnel: ssh -p $REAL_SSH_PORT -L 5000:localhost:5000 root@$SERVER_IP"
    fi
else
    echo_info "Web dashboard disabled, skipping setup"
fi

# ============================================================
# STEP 14 — Set up automatic Docker image updates
# ============================================================

echo_info "Setting up automatic Docker image updates..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'AUTOUPDATEEOF'
# Make auto-update script executable
chmod +x /opt/cowrie/scripts/auto-update-docker.sh

# Install cron job for daily Docker image updates at 3 AM
(crontab -l 2>/dev/null || echo "") | grep -v "auto-update-docker.sh" | crontab -
(crontab -l; echo "0 3 * * * /opt/cowrie/scripts/auto-update-docker.sh >> /var/log/cowrie-auto-update.log 2>&1") | crontab -

echo "[remote] Cron job installed for daily Docker updates at 3 AM"
AUTOUPDATEEOF

echo_info "Automatic Docker updates configured"

# ============================================================
# DONE
# ============================================================

cat << EOFINFO

============================================
  COWRIE HONEYPOT DEPLOYED SUCCESSFULLY
============================================

Server IP:       $SERVER_IP
Server ID:       $SERVER_ID
EOFINFO

# Display appropriate SSH access info based on Tailscale configuration
if [ "$ENABLE_TAILSCALE" = "true" ] && [ "$TAILSCALE_BLOCK_PUBLIC_SSH" = "true" ]; then
    # Get Tailscale hostname for Tailscale SSH (use Tailscale IP since public SSH is blocked)
    if [ "$TAILSCALE_USE_SSH" = "true" ]; then
        TS_HOSTNAME=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -p "$REAL_SSH_PORT" "root@$TAILSCALE_IP" "tailscale status --json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//' || echo ''" 2>/dev/null) || TS_HOSTNAME=""
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" "systemctl disable ssh 2>/dev/null"
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" "systemctl stop ssh 2>/dev/null"
    fi

    if [ "$TAILSCALE_USE_SSH" = "true" ] && [ -n "$TS_HOSTNAME" ]; then
cat << TSINFO

Tailscale IP:        $TAILSCALE_IP
Tailscale Hostname:  $TS_HOSTNAME

SSH Access (TAILSCALE SSH):
  Management SSH:  ssh root@$TS_HOSTNAME
  Honeypot SSH:    ssh root@$SERVER_IP (port 22 - public)
TSINFO
    else
cat << TSINFO

Tailscale IP:    $TAILSCALE_IP

SSH Access (TAILSCALE ONLY):
  Management SSH:  ssh root@$TAILSCALE_IP
  Honeypot SSH:    ssh root@$SERVER_IP (port 22 - public)
TSINFO
    fi
elif [ "$ENABLE_TAILSCALE" = "true" ]; then
cat << TSPUBLICINFO

Tailscale IP:    $TAILSCALE_IP

SSH Access (available via both public IP and Tailscale):
  Management SSH:  ssh -p $REAL_SSH_PORT root@$SERVER_IP
                   ssh root@$TAILSCALE_IP (via Tailscale)
  Honeypot SSH:    ssh root@$SERVER_IP (port 22)
TSPUBLICINFO
else
cat << PUBLICINFO

SSH Access:
  Management SSH:  ssh -p $REAL_SSH_PORT root@$SERVER_IP
  Honeypot SSH:    ssh root@$SERVER_IP (port 22)
PUBLICINFO
fi

cat << EOFINFO2

Destroy server:
  hcloud server delete $SERVER_ID

Identity used:
  Hostname:        $HOSTNAME
  Kernel:          $KERNEL_VERSION ($KERNEL_ARCH)
  Kernel Build:    $KERNEL_BUILD
  Operating System: $OS_NAME
  Architecture:    $ARCH
  SSH Banner:      $SSH_BANNER
EOFINFO2

cat << UPDATEINFO

Automatic Updates:
  Docker images:   Daily at 3 AM (auto-update-docker.sh)
  Deploy changes:  ./deploy-updates.sh $SERVER_IP $REAL_SSH_PORT
UPDATEINFO

echo "============================================"
