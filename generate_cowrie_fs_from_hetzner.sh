#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# CONFIGURATION
# ============================================================

SERVER_NAME="cowrie-source-$(date +%s)"
SERVER_TYPE="cpx11"              # cheapest and fast enough
SERVER_IMAGE="debian-13"
SSH_KEY_NAME1="SSH Key - default"          # must exist in your hcloud account
SSH_KEY_NAME2="ShellFish@iPhone-23112023"          # must exist in your hcloud account
OUTPUT_DIR="./output_$(date +%Y%m%d_%H%M%S)"
IDENTITY_DIR="$OUTPUT_DIR/identity"

# Honeypot identity configuration
HONEYPOT_HOSTNAME="dmz-web01"    # Realistic hostname for the honeypot

echo "[*] Output directory: $OUTPUT_DIR"
mkdir -p "$IDENTITY_DIR"

# ============================================================
# STEP 1 — Create temporary server
# ============================================================

echo "[*] Creating temporary Hetzner server: $SERVER_NAME"

SERVER_ID=$(hcloud server create \
    --name "$SERVER_NAME" \
    --type "$SERVER_TYPE" \
    --image "$SERVER_IMAGE" \
    --ssh-key "$SSH_KEY_NAME1" \
    --ssh-key "$SSH_KEY_NAME2" \
    --output json 2> /dev/null | jq -r '.server.id')

echo "[*] Server created with ID: $SERVER_ID"

# Wait for it to get an IP
echo "[*] Waiting for server IP..."
sleep 5

SERVER_IP=$(hcloud server describe "$SERVER_ID" --output json | jq -r '.public_net.ipv4.ip')

echo "[*] Server IP: $SERVER_IP"

# ============================================================
# STEP 2 — SSH readiness check
# ============================================================

echo -n "[*] Waiting for SSH to become available"
until ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=3 "root@$SERVER_IP" "echo ." 2>/dev/null; do
    printf "."
    sleep 3
done
echo "[*] SSH is ready."

# ============================================================
# STEP 3 — Configure system identity
# ============================================================

echo "[*] Setting hostname to $HONEYPOT_HOSTNAME and installing nginx..."

ssh "root@$SERVER_IP" bash << EOF
set -e
# Set hostname
hostnamectl set-hostname $HONEYPOT_HOSTNAME
echo "127.0.0.1 localhost $HONEYPOT_HOSTNAME" > /etc/hosts
echo "::1 localhost ip6-localhost ip6-loopback $HONEYPOT_HOSTNAME" >> /etc/hosts

# Install and start nginx to have realistic services running
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y nginx > /dev/null
systemctl enable nginx > /dev/null 2>&1
systemctl start nginx

# Wait for nginx to fully start
sleep 2

echo "[*] Hostname set to $HONEYPOT_HOSTNAME, nginx installed and running"
EOF

# ============================================================
# STEP 4 — Install createfs and requirements
# ============================================================

echo "[*] Installing requirements and createfs on remote host..."

ssh "root@$SERVER_IP" bash << 'EOF'
set -e
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y python3 python3-pip python3.13-venv git findutils libssl-dev libffi-dev build-essential libpython3-dev authbind pkg-config > /dev/null

git clone https://github.com/cowrie/cowrie.git /root/cowrie > /dev/null 2>&1
cd /root/cowrie
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt > /dev/null
EOF

# ============================================================
# STEP 4 — Generate fs.pickle
# ============================================================

echo "[*] Running createfs (this may take a few minutes)..."

ssh "root@$SERVER_IP" bash << 'EOF'
# Save createfs script to temp location before cleanup
cp /root/cowrie/src/cowrie/scripts/createfs.py /tmp/createfs.py
cp -r /root/cowrie/.venv /tmp/.venv

# Prune heavy directories (optional but recommended)
# Uncomment to reduce fs.pickle size:
# rm -rf /usr/share/doc/* /usr/share/man/* /var/cache/* /var/log/*

# CRITICAL: Remove Cowrie installation to prevent honeypot fingerprinting
# Attackers can detect honeypots by finding /root/cowrie or similar directories
echo "[*] Removing Cowrie installation from filesystem snapshot..."
rm -rf /root/cowrie /root/.bash_history

# Remove other potential honeypot indicators
rm -rf /tmp/cowrie* /var/tmp/cowrie* /opt/cowrie* 2>/dev/null || true

# Create the pickle from cleaned filesystem
cd /tmp
source .venv/bin/activate
python3 createfs.py -l / -o /root/fs.pickle

# Cleanup temp files
rm -rf /tmp/.venv /tmp/createfs.py

# Capture process list with nginx running
# This gives us a realistic process list without honeypot artifacts
ps -ef > /root/ps.txt

EOF

echo "[*] Filesystem pickle created (Cowrie directories excluded)."

# ============================================================
# STEP 5 — Collect identity metadata
# ============================================================

echo "[*] Collecting identity metadata..."

ssh "root@$SERVER_IP" "uname -a"            > "$IDENTITY_DIR/kernel.txt"
ssh "root@$SERVER_IP" "cat /proc/version"   > "$IDENTITY_DIR/proc-version"
ssh "root@$SERVER_IP" "cat /etc/os-release" > "$IDENTITY_DIR/os-release"
ssh "root@$SERVER_IP" "cat /etc/debian_version" > "$IDENTITY_DIR/debian_version"
ssh "root@$SERVER_IP" "hostname"            > "$IDENTITY_DIR/hostname"
ssh "root@$SERVER_IP" "dpkg -l"             > "$IDENTITY_DIR/dpkg_list.txt"
ssh "root@$SERVER_IP" "cat /root/ps.txt"    > "$IDENTITY_DIR/ps.txt"

# SSH banner
nc -w 2 "$SERVER_IP" 22 | head -n1 > "$IDENTITY_DIR/ssh-banner.txt" || true

echo "[*] Identity data saved to $IDENTITY_DIR"
echo "[*]   - Process list (ps.txt) captured with nginx running"

# ============================================================
# STEP 6 — Collect file contents for realistic honeypot
# ============================================================

echo "[*] Collecting file contents for Cowrie contents directory..."

CONTENTS_DIR="$OUTPUT_DIR/contents"
mkdir -p "$CONTENTS_DIR"

# Create tarball of important files on remote server
ssh "root@$SERVER_IP" bash << 'EOFCONTENTS'
cd /
tar czf /tmp/contents.tar.gz \
    etc/passwd \
    etc/group \
    etc/hetzner-build \
    etc/shadow \
    etc/hosts \
    etc/hostname \
    etc/resolv.conf \
    etc/fstab \
    etc/group \
    etc/issue \
    etc/issue.net \
    etc/motd \
    etc/timezone \
    etc/sudoers \
    etc/os-release \
    etc/lsb-release \
    etc/debian_version \
    etc/nginx/nginx.conf \
    etc/nginx/sites-available/default \
    var/www/html/index.nginx-debian.html \
    proc/cpuinfo \
    proc/meminfo \
    proc/version \
    2>/dev/null || true
EOFCONTENTS

# Download and extract contents
scp "root@$SERVER_IP:/tmp/contents.tar.gz" "$CONTENTS_DIR/" > /dev/null 2>&1 || true
if [ -f "$CONTENTS_DIR/contents.tar.gz" ]; then
    cd "$CONTENTS_DIR"
    tar xzf contents.tar.gz 2>/dev/null || true
    rm contents.tar.gz
    echo "[*] File contents collected ($(find . -type f | wc -l) files)"
    cd ../..
else
    echo "[!] Warning: Could not collect file contents"
fi

# ============================================================
# STEP 7 — Download fs.pickle
# ============================================================

echo "[*] Downloading fs.pickle..."
scp "root@$SERVER_IP:/root/fs.pickle" "$OUTPUT_DIR/fs.pickle" > /dev/null

echo "[*] fs.pickle downloaded."

# ============================================================
# STEP 8 — Destroy server
# ============================================================

echo "[*] Deleting temporary server..."
hcloud server delete "$SERVER_ID"

echo "[*] Temporary server deleted."

# ============================================================
# DONE
# ============================================================

echo ""
echo "============================================"
echo "  COMPLETED SUCCESSFULLY"
echo "  Pickle + identity metadata stored in:"
echo "     $OUTPUT_DIR"
echo "============================================"
