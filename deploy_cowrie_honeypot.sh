#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# CONFIGURATION
# ============================================================

if [ $# -ne 1 ]; then
    echo "Usage: $0 <output_directory>"
    echo "Example: $0 ./output_20251204_135502"
    exit 1
fi

OUTPUT_DIR="$1"
IDENTITY_DIR="$OUTPUT_DIR/identity"
FS_PICKLE="$OUTPUT_DIR/fs.pickle"

# Verify the required files exist
if [ ! -f "$FS_PICKLE" ]; then
    echo "Error: fs.pickle not found at $FS_PICKLE"
    exit 1
fi

if [ ! -d "$IDENTITY_DIR" ]; then
    echo "Error: identity directory not found at $IDENTITY_DIR"
    exit 1
fi

SERVER_NAME="cowrie-honeypot-$(date +%s)"
SERVER_TYPE="cpx11"
SERVER_IMAGE="debian-13"
SSH_KEY_NAME1="SSH Key - default"
SSH_KEY_NAME2="ShellFish@iPhone-23112023"
COWRIE_SSH_PORT="22"        # Cowrie listens on port 22
REAL_SSH_PORT="2222"        # Move real SSH to 2222

echo "[*] Deploying Cowrie honeypot from: $OUTPUT_DIR"

# ============================================================
# STEP 1 — Create server
# ============================================================

echo "[*] Creating Hetzner server: $SERVER_NAME"

SERVER_ID=$(hcloud server create \
    --name "$SERVER_NAME" \
    --type "$SERVER_TYPE" \
    --image "$SERVER_IMAGE" \
    --ssh-key "$SSH_KEY_NAME1" \
    --ssh-key "$SSH_KEY_NAME2" \
    --output json 2> /dev/null | jq -r '.server.id')

echo "[*] Server created with ID: $SERVER_ID"

# Set up cleanup on error
cleanup_on_error() {
    echo ""
    echo "[!] Deployment failed! Cleaning up..."
    echo "[*] Deleting server $SERVER_ID..."
    hcloud server delete "$SERVER_ID" 2>/dev/null || true
    echo "[*] Server deleted."
    exit 1
}

trap cleanup_on_error ERR

# Wait for IP
echo "[*] Waiting for server IP..."
sleep 5

SERVER_IP=$(hcloud server describe "$SERVER_ID" --output json | jq -r '.public_net.ipv4.ip')

echo "[*] Server IP: $SERVER_IP"
echo "[*] Real SSH will be available on port $REAL_SSH_PORT"
echo "[*] Cowrie honeypot will run on port $COWRIE_SSH_PORT"

# ============================================================
# STEP 2 — Wait for SSH
# ============================================================

echo -n "[*] Waiting for SSH to become available"
until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 "root@$SERVER_IP" "echo ." 2>/dev/null; do
    printf "."
    sleep 3
done
echo "[*] SSH is ready."

# ============================================================
# STEP 3 — Move SSH to alternate port
# ============================================================

echo "[*] Moving SSH to port $REAL_SSH_PORT..."

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

echo -n "[*] SSH moved to port $REAL_SSH_PORT. Reconnecting."
sleep 3

# Test new SSH port
until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 -p "$REAL_SSH_PORT" "root@$SERVER_IP" "echo -n ." 2>/dev/null; do
    printf "."
    sleep 2
done
echo "[*] SSH confirmed on port $REAL_SSH_PORT."

# ============================================================
# STEP 4 — Install Docker
# ============================================================

echo "[*] Installing Docker..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
set -e
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    ca-certificates \
    curl \
    gnupg > /dev/null

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

echo "[*] Docker installed."

# ============================================================
# STEP 5 — Configure automatic updates and security
# ============================================================

echo "[*] Configuring automatic security updates..."

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

echo "[*] Automatic updates configured for ALL packages (will reboot at 3 AM if needed)"
EOF

echo "[*] Security configuration complete."

# ============================================================
# STEP 6 — Upload configuration
# ============================================================

echo "[*] Uploading Cowrie configuration..."

# Create remote directory structure
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
mkdir -p /opt/cowrie/etc /opt/cowrie/var/lib/cowrie/downloads /opt/cowrie/var/log/cowrie /opt/cowrie/share/cowrie/txtcmds

# Set ownership to UID 999 (cowrie user in container) for writable directories
chown -R 999:999 /opt/cowrie/var
EOF

# Upload fs.pickle to share directory (bind mounted)
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    "$FS_PICKLE" "root@$SERVER_IP:/opt/cowrie/share/cowrie/fs.pickle" > /dev/null

# Upload ps.txt for realistic process list
if [ -f "$IDENTITY_DIR/ps.txt" ]; then
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        "$IDENTITY_DIR/ps.txt" "root@$SERVER_IP:/opt/cowrie/share/cowrie/txtcmds/ps" > /dev/null
    echo "[*] fs.pickle and ps.txt uploaded."
else
    echo "[*] fs.pickle uploaded (ps.txt not found, using default)."
fi

# Upload contents directory for real file content
CONTENTS_DIR="$OUTPUT_DIR/contents"
if [ -d "$CONTENTS_DIR" ] && [ "$(ls -A $CONTENTS_DIR 2>/dev/null)" ]; then
    echo "[*] Uploading file contents..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mkdir -p /opt/cowrie/share/cowrie/contents"

    # Upload contents as tarball for efficiency
    tar czf /tmp/contents.tar.gz -C "$CONTENTS_DIR" . 2>/dev/null
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        /tmp/contents.tar.gz "root@$SERVER_IP:/tmp/contents.tar.gz" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/share/cowrie/contents && tar xzf /tmp/contents.tar.gz && rm /tmp/contents.tar.gz"
    rm /tmp/contents.tar.gz

    FILE_COUNT=$(find "$CONTENTS_DIR" -type f | wc -l | tr -d ' ')
    echo "[*] Uploaded $FILE_COUNT files with real content"
else
    echo "[!] Warning: No contents directory found, files will have no content"
fi

# ============================================================
# STEP 7 — Generate cowrie.cfg
# ============================================================

echo "[*] Generating cowrie.cfg with identity data..."

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

# Create cowrie.cfg
cat > /tmp/cowrie.cfg << EOFCFG
[honeypot]
hostname = $HOSTNAME
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads

[shell]
filesystem = share/cowrie/fs.pickle
kernel_version = $KERNEL_VERSION
kernel_build_string = $KERNEL_BUILD
hardware_platform = $KERNEL_ARCH
operating_system = GNU/Linux
arch = $ARCH

[ssh]
enabled = true
version = SSH-2.0-$SSH_BANNER
listen_endpoints = tcp:2222:interface=0.0.0.0
sftp_enabled = true
forwarding = true
forward_redirect = false

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log
EOFCFG

# Upload cowrie.cfg
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    /tmp/cowrie.cfg "root@$SERVER_IP:/opt/cowrie/etc/cowrie.cfg" > /dev/null

rm /tmp/cowrie.cfg

echo "[*] Configuration uploaded."

# ============================================================
# STEP 8 — Deploy Cowrie container
# ============================================================

echo "[*] Starting Cowrie container..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
set -e

# Create docker-compose.yml with named volumes and bind mounts
cat > /opt/cowrie/docker-compose.yml << 'DOCKEREOF'
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-etc:/cowrie/cowrie-git/etc
      - cowrie-var:/cowrie/cowrie-git/var
      - /opt/cowrie/share:/cowrie/cowrie-git/share:ro
    environment:
      - COWRIE_HOSTNAME=server
    # Security hardening
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true

volumes:
  cowrie-etc:
    name: cowrie-etc
  cowrie-var:
    name: cowrie-var
DOCKEREOF

echo "[*] Initializing Cowrie volumes with custom configuration..."

# Start container briefly to initialize volumes
cd /opt/cowrie
docker compose up -d > /dev/null 2>&1
sleep 10
docker compose stop > /dev/null 2>&1

# Copy cowrie.cfg into etc volume
echo "[*] Copying cowrie.cfg to volume..."
docker run --rm \
  -v cowrie-etc:/dest \
  -v /opt/cowrie/etc/cowrie.cfg:/src/cowrie.cfg:ro \
  alpine cp /src/cowrie.cfg /dest/ > /dev/null 2>&1

# Set proper ownership (UID 999 = cowrie user)
docker run --rm \
  -v cowrie-etc:/etc \
  -v cowrie-var:/var \
  alpine chown -R 999:999 /etc /var > /dev/null 2>&1

# Start Cowrie with custom configuration
echo "[*] Starting Cowrie with custom configuration..."
cd /opt/cowrie
docker compose up -d > /dev/null 2>&1

# Wait for container to start
sleep 5

# Show status
docker compose ps > /dev/null || exit 1
EOF

echo "[*] Cowrie container started."

# ============================================================
# STEP 9 — Test honeypot
# ============================================================

echo "[*] Testing honeypot (this may take a moment)..."
sleep 5

# Test if port 22 responds with SSH
if timeout 15 bash -c "echo | nc $SERVER_IP 22" 2>/dev/null | grep -q "SSH"; then
    echo "[*] Honeypot is responding on port 22!"
else
    echo "[!] Warning: Honeypot may not be responding correctly on port 22"
fi

# ============================================================
# DONE
# ============================================================

cat << EOFINFO

============================================
  COWRIE HONEYPOT DEPLOYED SUCCESSFULLY
============================================

Server IP:       $SERVER_IP
Server ID:       $SERVER_ID

SSH Access:
  Management SSH:  ssh -p $REAL_SSH_PORT root@$SERVER_IP
  Honeypot SSH:    ssh root@$SERVER_IP (port 22)

Monitoring:
  View logs:       ssh -p $REAL_SSH_PORT root@$SERVER_IP 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log'
  JSON logs:       ssh -p $REAL_SSH_PORT root@$SERVER_IP 'tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'
  Downloads:       ssh -p $REAL_SSH_PORT root@$SERVER_IP 'file /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads/*'
  Container logs:  ssh -p $REAL_SSH_PORT root@$SERVER_IP 'cd /opt/cowrie && docker compose logs -f'

Management:
  Stop:            ssh -p $REAL_SSH_PORT root@$SERVER_IP 'cd /opt/cowrie && docker compose stop'
  Start:           ssh -p $REAL_SSH_PORT root@$SERVER_IP 'cd /opt/cowrie && docker compose start'
  Restart:         ssh -p $REAL_SSH_PORT root@$SERVER_IP 'cd /opt/cowrie && docker compose restart'

Destroy server:
  hcloud server delete $SERVER_ID

Identity used:
  Hostname:        $HOSTNAME
  Kernel:          $KERNEL_VERSION ($KERNEL_ARCH)
  Kernel Build:    $KERNEL_BUILD
  Operating System: $OS_NAME
  Architecture:    $ARCH
  SSH Banner:      $SSH_BANNER

============================================
EOFINFO
