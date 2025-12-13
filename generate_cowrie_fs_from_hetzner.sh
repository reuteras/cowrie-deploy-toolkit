#!/usr/bin/env bash

# ============================================================
# Cowrie Filesystem Generator
# ============================================================
# Creates a realistic filesystem snapshot from a fresh Hetzner server
# with anti-fingerprinting and authentic identity capture.
# ============================================================

# Load common functions library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/scripts/common.sh"

# ============================================================
# DEPENDENCY CHECKS
# ============================================================

echo_info "Checking required dependencies..."
check_dependencies "hcloud" "jq" "nc" "tar" "ssh" "scp" "python3"

# ============================================================
# CONFIGURATION
# ============================================================

# Master config file
MASTER_CONFIG="./master-config.toml"

# Check if master config exists
if [ ! -f "$MASTER_CONFIG" ]; then
    fatal_error "No master-config.toml found. Please copy example-config.toml and configure it."
fi

echo_info "Found master-config.toml, reading deployment settings..."

# Read configuration using Python TOML parser
SERVER_TYPE=$(read_toml_default "$MASTER_CONFIG" "deployment.server_type" "cpx11")
SERVER_IMAGE=$(read_toml_default "$MASTER_CONFIG" "deployment.server_image" "debian-13")
HONEYPOT_HOSTNAME=$(read_toml_default "$MASTER_CONFIG" "deployment.honeypot_hostname" "dmz-web01")

# Read SSH keys array
SSH_KEYS=()
read_toml_array "$MASTER_CONFIG" "deployment.ssh_keys" SSH_KEYS

if [ ${#SSH_KEYS[@]} -lt 1 ]; then
    fatal_error "SSH keys not configured in master-config.toml. Please add deployment.ssh_keys array."
fi

echo_info "Loaded ${#SSH_KEYS[@]} SSH key(s) from config:"
for key in "${SSH_KEYS[@]}"; do
    echo "  - $key"
done

# Validate configuration
validate_safe_string "$HONEYPOT_HOSTNAME" || fatal_error "Invalid hostname: $HONEYPOT_HOSTNAME (only alphanumeric, dash, underscore, dot allowed)"

echo_info "Using config: $SERVER_TYPE, $SERVER_IMAGE, hostname=$HONEYPOT_HOSTNAME"

# Output directory setup
SERVER_NAME="cowrie-source-$(date +%s)"
OUTPUT_DIR="./output_$(date +%Y%m%d_%H%M%S)"
IDENTITY_DIR="$OUTPUT_DIR/identity"

echo_info "Output directory: $OUTPUT_DIR"
mkdir -p "$IDENTITY_DIR"

# ============================================================
# STEP 1 — Create temporary server
# ============================================================

echo_info "Creating temporary Hetzner server: $SERVER_NAME"

# Build hcloud command with all SSH keys using array (proper quote handling)
HCLOUD_CMD=(hcloud server create --name "$SERVER_NAME" --type "$SERVER_TYPE" --image "$SERVER_IMAGE")
for key in "${SSH_KEYS[@]}"; do
    HCLOUD_CMD+=(--ssh-key "$key")
done
HCLOUD_CMD+=(--output json)

# Execute server creation
SERVER_CREATION_OUTPUT=$("${HCLOUD_CMD[@]}" 2>&1)
EXIT_CODE=$?

# Try to extract server ID even if command failed (server might have been created)
# Extract JSON from output (everything from first { to end)
JSON_OUTPUT=$(echo "$SERVER_CREATION_OUTPUT" | sed -n '/{/,$p')
SERVER_ID=$(echo "$JSON_OUTPUT" | jq -r '.server.id' 2>/dev/null)

# If server was created, set up cleanup immediately
if [ -n "$SERVER_ID" ] && [ "$SERVER_ID" != "null" ]; then
    validate_server_id "$SERVER_ID" || fatal_error "Invalid server ID received: $SERVER_ID"
    echo_info "Server created with ID: $SERVER_ID"

    # Set up cleanup on error IMMEDIATELY
    setup_server_cleanup_trap "$SERVER_ID"
fi

# Now check if creation actually failed
if [ $EXIT_CODE -ne 0 ]; then
    if [ -n "$SERVER_ID" ] && [ "$SERVER_ID" != "null" ]; then
        # Server was created but command failed - cleanup trap will handle it
        fatal_error "Server creation command failed: $SERVER_CREATION_OUTPUT"
    else
        # Server was not created, exit without cleanup
        fatal_error "Failed to create server: $SERVER_CREATION_OUTPUT"
    fi
fi

# Double-check we have a valid server ID
if [ -z "$SERVER_ID" ] || [ "$SERVER_ID" = "null" ]; then
    fatal_error "Failed to extract server ID from Hetzner response"
fi

# Wait for it to get an IP
echo_info "Waiting for server IP..."
sleep 5

SERVER_IP=$(hcloud server describe "$SERVER_ID" --output json 2>&1 | jq -r '.public_net.ipv4.ip' 2>/dev/null)
if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "null" ]; then
    fatal_error "Failed to get server IP address"
fi

# Validate IP address
validate_ip "$SERVER_IP" || fatal_error "Invalid IP address received: $SERVER_IP"

echo_info "Server IP: $SERVER_IP"

# ============================================================
# STEP 2 — SSH readiness check
# ============================================================

wait_for_ssh "root@$SERVER_IP" 22 120

# ============================================================
# STEP 3 — Configure system identity
# ============================================================

echo_info " Setting hostname to $HONEYPOT_HOSTNAME and installing services..."

ssh $SSH_OPTS "root@$SERVER_IP" bash << EOF
set -e
# Set hostname
hostnamectl set-hostname $HONEYPOT_HOSTNAME
echo "127.0.0.1 localhost $HONEYPOT_HOSTNAME" > /etc/hosts
echo "::1 localhost ip6-localhost ip6-loopback $HONEYPOT_HOSTNAME" >> /etc/hosts

# Install nginx, MySQL/MariaDB, PHP and WordPress for realistic services
echo "[remote] Installing nginx, MariaDB, PHP, and WordPress..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y nginx mariadb-server php-fpm php-mysql wordpress > /dev/null

# Start services
systemctl enable nginx > /dev/null 2>&1
systemctl start nginx
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Wait for services to fully start
sleep 3

echo "[remote] Hostname set to $HONEYPOT_HOSTNAME, services installed and running"
EOF

# ============================================================
# STEP 3.5 — Configure WordPress and setup fake data
# ============================================================

echo_info " Setting up WordPress with fake database..."

# Upload fake WordPress database SQL file
FAKE_WP_DB="./fake-data/wordpress-db.sql"
if [ -f "$FAKE_WP_DB" ]; then
    scp $SSH_OPTS "$FAKE_WP_DB" "root@$SERVER_IP:/tmp/wordpress-db.sql" > /dev/null
    echo_info " Uploaded fake WordPress database"
else
    echo_warn " Warning: $FAKE_WP_DB not found, skipping WordPress database setup"
fi

ssh $SSH_OPTS "root@$SERVER_IP" bash << 'EOF'
set -e

# Create WordPress database and import fake data if available
if [ -f /tmp/wordpress-db.sql ]; then
    mysql -e "CREATE DATABASE IF NOT EXISTS wordpress_db;"
    mysql -e "CREATE USER IF NOT EXISTS 'wp_user'@'localhost' IDENTIFIED BY 'wp_pass_2024';"
    mysql -e "GRANT ALL PRIVILEGES ON wordpress_db.* TO 'wp_user'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    mysql wordpress_db < /tmp/wordpress-db.sql
    rm /tmp/wordpress-db.sql
    echo "[remote] WordPress database created and populated"
fi

# Configure WordPress to use database
mkdir -p /var/www/html/blog
ln -sf /usr/share/wordpress /var/www/html/blog/wp
cat > /var/www/html/blog/wp-config.php << 'WPCONFIG'
<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass_2024');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

\$table_prefix = 'wp_';
define('WP_DEBUG', false);

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp/wp-settings.php';
WPCONFIG

echo "[remote] WordPress configuration created at /var/www/html/blog/wp-config.php"
EOF

# ============================================================
# STEP 3.6 — Setup Canary Token files
# ============================================================

echo_info " Setting up Canary Token files in /root/backup..."

# Create /root/backup directory on remote server
ssh $SSH_OPTS "root@$SERVER_IP" "mkdir -p /root/backup"

# Check for Canary Token files locally
CANARY_DIR="./canary-tokens"
CANARY_UPLOADED=false

# MySQL dump Canary Token
if [ -f "$CANARY_DIR/mysql-backup.sql" ]; then
    scp $SSH_OPTS "$CANARY_DIR/mysql-backup.sql" "root@$SERVER_IP:/root/backup/mysql-backup.sql" > /dev/null
    echo_info " Uploaded MySQL backup Canary Token to /root/backup/mysql-backup.sql"
    CANARY_UPLOADED=true
fi

# Excel Canary Token (look for any .xlsx file)
EXCEL_TOKEN=$(find "$CANARY_DIR" -maxdepth 1 -name "*.xlsx" -type f 2>/dev/null | head -1)
if [ -n "$EXCEL_TOKEN" ]; then
    scp $SSH_OPTS "$EXCEL_TOKEN" "root@$SERVER_IP:/root/Q1_Financial_Report.xlsx" > /dev/null
    echo_info " Uploaded Excel Canary Token to /root/Q1_Financial_Report.xlsx"
    CANARY_UPLOADED=true
fi

# PDF Canary Token (look for any .pdf file)
PDF_TOKEN=$(find "$CANARY_DIR" -maxdepth 1 -name "*.pdf" -type f 2>/dev/null | head -1)
if [ -n "$PDF_TOKEN" ]; then
    scp $SSH_OPTS "$PDF_TOKEN" "root@$SERVER_IP:/root/Network_Passwords.pdf" > /dev/null
    echo_info " Uploaded PDF Canary Token to /root/Network_Passwords.pdf"
    CANARY_UPLOADED=true
fi

if [ "$CANARY_UPLOADED" = false ]; then
    echo_warn " Warning: No Canary Token files found in $CANARY_DIR/"
    echo_warn "          Create tokens at https://canarytokens.org/nest/ and place them in:"
    echo_warn "            - $CANARY_DIR/mysql-backup.sql (MySQL dump token)"
    echo_warn "            - $CANARY_DIR/*.xlsx (Excel document token)"
    echo_warn "            - $CANARY_DIR/*.pdf (PDF document token)"
fi

# ============================================================
# STEP 4 — Install createfs and requirements
# ============================================================

echo_info " Installing requirements and createfs on remote host..."

ssh $SSH_OPTS "root@$SERVER_IP" bash << 'EOF'
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

echo_info " Running createfs (this may take a few minutes)..."

ssh $SSH_OPTS "root@$SERVER_IP" bash << 'EOF'
# Save createfs script to temp location before cleanup
cp /root/cowrie/src/cowrie/scripts/createfs.py /tmp/createfs.py
cp -r /root/cowrie/.venv /tmp/.venv

# Prune heavy directories (optional but recommended)
# Uncomment to reduce fs.pickle size:
# rm -rf /usr/share/doc/* /usr/share/man/* /var/cache/* /var/log/*

# CRITICAL: Remove Cowrie installation to prevent honeypot fingerprinting
# Attackers can detect honeypots by finding /root/cowrie or similar directories
echo "[remote] Removing Cowrie installation from filesystem snapshot..."
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
# Use 'ps aux' format for easier parsing into cmdoutput.json
ps aux > /root/ps.txt

# /bin
mkdir -p /root/txtcmds/bin
df > /root/txtcmds/bin/df 2>&1
dmesg > /root/txtcmds/bin/dmesg 2>&1
enable > /root/txtcmds/bin/enable 2>&1
stty > /root/txtcmds/bin/stty 2>&1
sync > /root/txtcmds/bin/sync 2>&1
ulimit > /root/txtcmds/bin/ulimit 2>&1

mkdir -p /root/txtcmds/usr/bin
locate > /root/txtcmds/usr/bin/locate 2>&1
lscpu > /root/txtcmds/usr/bin/lscpu 2>&1
make > /root/txtcmds/usr/bin/make 2>&1
mount > /root/txtcmds/usr/bin/mount 2>&1
EOF

echo_info " Filesystem pickle created (Cowrie directories excluded)."

# ============================================================
# STEP 5 — Collect identity metadata
# ============================================================

echo_info " Collecting identity metadata..."

ssh $SSH_OPTS "root@$SERVER_IP" "uname -a"            > "$IDENTITY_DIR/kernel.txt"
ssh $SSH_OPTS "root@$SERVER_IP" "cat /proc/version"   > "$IDENTITY_DIR/proc-version"
ssh $SSH_OPTS "root@$SERVER_IP" "cat /etc/os-release" > "$IDENTITY_DIR/os-release"
ssh $SSH_OPTS "root@$SERVER_IP" "cat /etc/debian_version" > "$IDENTITY_DIR/debian_version"
ssh $SSH_OPTS "root@$SERVER_IP" "hostname"            > "$IDENTITY_DIR/hostname"
ssh $SSH_OPTS "root@$SERVER_IP" "dpkg -l"             > "$IDENTITY_DIR/dpkg_list.txt"
ssh $SSH_OPTS "root@$SERVER_IP" "cat /root/ps.txt"    > "$IDENTITY_DIR/ps.txt"

# SSH banner
nc -w 2 "$SERVER_IP" 22 | head -n1 > "$IDENTITY_DIR/ssh-banner.txt" || true

echo_info " Identity data saved to $IDENTITY_DIR"
echo_info "   - Process list (ps.txt) captured with nginx running"

# ============================================================
# STEP 6 — Collect file contents for realistic honeypot
# ============================================================

echo_info " Collecting file contents for Cowrie contents directory..."

CONTENTS_DIR="$OUTPUT_DIR/contents"
mkdir -p "$CONTENTS_DIR"

# Create tarball of important files on remote server
ssh $SSH_OPTS "root@$SERVER_IP" bash << 'EOFCONTENTS'
cd /
tar --no-xattrs -cf /tmp/contents.tar \
    etc/debian_version \
    etc/fstab \
    etc/group \
    etc/hetzner-build \
    etc/host.conf \
    etc/hosts \
    etc/inittab \
    etc/issue \
    etc/lsb-release \
    etc/motd \
    etc/os-release \
    etc/passwd \
    etc/resolv.conf \
    etc/shadow \
    etc/sudoers \
    etc/timezone \
    etc/nginx/nginx.conf \
    etc/nginx/sites-available/default \
    etc/mysql/my.cnf \
    etc/mysql/mariadb.cnf \
    etc/php/*/fpm/php.ini \
    var/www/html/index.nginx-debian.html \
    var/www/html/blog/wp-config.php \
    root/backup \
    root/*.xlsx \
    root/*.pdf \
    2>/dev/null || true

mkdir -p tmp/proc/1 proc/net

cp /proc/cpuinfo \
    /proc/meminfo \
    /proc/mounts \
    /proc/modules \
    /proc/uptime \
    /proc/version \
    tmp/proc

cp /proc/1/mounts tmp/proc/1
cp /proc/net/arp tmp/proc/net

tar --no-xattrs -rf /tmp/contents.tar \
    tmp/proc \
    2>/dev/null || true
gzip /tmp/contents.tar
EOFCONTENTS

# Download and extract contents
scp $SSH_OPTS "root@$SERVER_IP:/tmp/contents.tar.gz" "$CONTENTS_DIR/" > /dev/null 2>&1 || true
if [ -f "$CONTENTS_DIR/contents.tar.gz" ]; then
    cd "$CONTENTS_DIR"
    tar xzf contents.tar.gz 2>/dev/null || true
    rm contents.tar.gz
    touch etc/issue.net
    echo_info " File contents collected ($(find . -type f | wc -l) files)"
    cd ../..
else
    echo_warn " Warning: Could not collect file contents"
fi


echo_info " Collecting cmd output for Cowrie txtcmds directory..."

# Copy defaults
cp -r txtcmds $OUTPUT_DIR

# Create tarball of txtcmd output
ssh $SSH_OPTS "root@$SERVER_IP" bash << 'EOFTXTCMDS'
cd /root
tar --no-xattrs -czf /tmp/txtcmds.tar.gz \
    txtcmds \
    2>/dev/null || true
EOFTXTCMDS

# Download and extract txtcmd outputs
scp $SSH_OPTS "root@$SERVER_IP:/tmp/txtcmds.tar.gz" "$OUTPUT_DIR/" > /dev/null 2>&1 || true
if [ -f "$OUTPUT_DIR/txtcmds.tar.gz" ]; then
    cd "$OUTPUT_DIR"
    tar xzf txtcmds.tar.gz 2>/dev/null || true
    rm txtcmds.tar.gz
    echo_info " Command output contents collected ($(find txtcmds -type f | wc -l) files)"
    cd ..
else
    echo_warn " Warning: Could not collect command output contents for txtcmds"
fi

# ============================================================
# STEP 7 — Download fs.pickle
# ============================================================
# STEP 7 — Download fs.pickle
# ============================================================

echo_info " Downloading fs.pickle..."
scp $SSH_OPTS "root@$SERVER_IP:/root/fs.pickle" "$OUTPUT_DIR/fs.pickle" > /dev/null

echo_info " fs.pickle downloaded."

# ============================================================
# STEP 8 — Destroy server
# ============================================================

echo_info " Deleting temporary server..."
hcloud server delete "$SERVER_ID"

echo_info " Temporary server deleted."

# ============================================================
# DONE
# ============================================================

CLEAN_OUTPUT_DIR=$(echo $OUTPUT_DIR | tr -d "./")

echo ""
echo "==========================================================="
echo "  COMPLETED SUCCESSFULLY"
echo "  Pickle + identity metadata stored in:"
echo "     $OUTPUT_DIR"
echo ""
echo "  You can deploy a honeypot with the command:"
echo "    ./deploy_cowrie_honeypot.sh $CLEAN_OUTPUT_DIR"
echo "==========================================================="
