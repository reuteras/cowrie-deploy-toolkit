#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Cowrie Daily Report System - Setup Script
# ============================================================
#
# This script installs and configures the daily reporting system
# for Cowrie honeypots with threat intelligence integration.
#
# Usage:
#   ./setup-reporting.sh
#
# Or run remotely on a deployed honeypot:
#   ssh -p 2222 root@HONEYPOT_IP 'bash -s' < setup-reporting.sh
#
# ============================================================

echo "[*] Cowrie Daily Report System - Setup"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root"
    exit 1
fi

# ============================================================
# STEP 1 — Install system dependencies
# ============================================================

echo -n "[*] Installing system dependencies..."

apt-get update -qq
apt-get install -y \
    python3 \
    yara \
    geoipupdate \
    git \
    sqlite3 \
    curl \
    > /dev/null 2>&1

echo " - Done"

# ============================================================
# STEP 2 — Install uv (modern Python package manager)
# ============================================================

echo "[*] Installing uv..."

if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
    # Add uv to PATH (installs to ~/.local/bin by default)
    export PATH="$HOME/.local/bin:$PATH"
    echo "[*] uv installed successfully"
else
    echo "[*] uv already installed"
fi

# Verify uv is available (required - no fallback)
if ! command -v uv &> /dev/null; then
    echo "[!] Error: uv installation failed and is required for this setup"
    echo "[!] Please install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# ============================================================
# STEP 3 — Install Python dependencies using uv
# ============================================================

echo -n "[*] Installing Python dependencies with uv..."

# Assume the toolkit is already in /opt/cowrie
if [ ! -f "/opt/cowrie/pyproject.toml" ]; then
    echo "[!] Error: pyproject.toml not found at /opt/cowrie/pyproject.toml"
    exit 1
fi

cd /opt/cowrie
uv sync --quiet
echo " - Done"

# ============================================================
# STEP 4 — Create directory structure
# ============================================================

echo -n "[*] Creating directory structure..."

mkdir -p /opt/cowrie/scripts
mkdir -p /opt/cowrie/etc
mkdir -p /opt/cowrie/yara-rules
mkdir -p /opt/cowrie/var

echo " - Done"

# Check if databases already exist (Debian default location)
if [ -f "/var/lib/GeoIP/GeoLite2-City.mmdb" ] && [ -f "/var/lib/GeoIP/GeoLite2-ASN.mmdb" ]; then
    echo "[*] GeoIP databases found!"
else
    echo "[!] GeoIP databases not found. Please complete steps above."
fi

# ============================================================
# STEP 6 — Download YARA rules from YARA Forge
# ============================================================

echo "[*] Downloading YARA rules from YARA Forge..."

# Install unzip if not present
if ! command -v unzip &> /dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unzip > /dev/null 2>&1
fi

# Create scripts directory
mkdir -p /opt/cowrie/scripts

# Create update script for daily cron job
cat > /opt/cowrie/scripts/update-yara-rules.sh << 'YARAUPDATE'
#!/usr/bin/env bash
# Automated YARA rules update script
# Downloads latest YARA Forge full ruleset and updates rules directory

set -e

RULES_DIR="/opt/cowrie/yara-rules"
RULES_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
TEMP_DIR=$(mktemp -d)

[[ -d "$RULES_DIR" ]] || mkdir -p "$RULES_DIR"

echo "[*] Downloading YARA Forge full ruleset..."
cd "$TEMP_DIR"

# Download latest full ruleset
if curl -sSL -o yara-rules.zip "$RULES_URL"; then
    # Clear old rules and extract new ones
    rm -rf "$RULES_DIR"/*.yar "$RULES_DIR"/*.yara 2>/dev/null || true

    # Extract rules
    unzip -q yara-rules.zip

    # Move rules to destination (handle various archive structures)
    cp packages/full/yara-rules-full.yar "$RULES_DIR/"

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    # Count rules
    RULE_COUNT=$(grep -E "^rule" $RULES_DIR/yara-rules-full.yar | wc -l)
    echo "[*] Updated YARA rules: $RULE_COUNT rules"
    logger -t yara-update "Successfully updated YARA Forge rules: $RULE_COUNT files"
else
    echo "[!] Failed to download YARA rules"
    logger -t yara-update "Failed to download YARA Forge rules"
    rm -rf "$TEMP_DIR"
    exit 1
fi
YARAUPDATE

chmod +x /opt/cowrie/scripts/update-yara-rules.sh

# Run initial update
echo "[*] Running initial YARA rules download..."
/opt/cowrie/scripts/update-yara-rules.sh

# Set up daily cron job (runs at 2 AM daily)
echo "[*] Setting up daily YARA rules update cron job..."
(crontab -l 2>/dev/null || echo "") | grep -v "update-yara-rules.sh" | crontab -
(crontab -l; echo "0 4 * * * /opt/cowrie/scripts/update-yara-rules.sh >> /var/log/yara-update.log 2>&1") | crontab -

# Count rules
RULE_COUNT=$(find /opt/cowrie/yara-rules -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)
echo "[*] Downloaded $RULE_COUNT YARA rule files from YARA Forge"
echo "[*] Daily automatic updates configured (runs at 4 AM)"

# ============================================================
# STEP 6b — Set up YARA scanner daemon (real-time scanning)
# ============================================================

echo "[*] Setting up YARA scanner daemon..."

# Create systemd service for YARA scanner
cat > /etc/systemd/system/yara-scanner.service << 'YARASERVICE'
[Unit]
Description=Cowrie YARA Scanner Daemon
Documentation=https://github.com/reuteras/cowrie-deploy-toolkit
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
Environment="COWRIE_DOWNLOAD_PATH=/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"
Environment="YARA_RULES_PATH=/opt/cowrie/yara-rules"
Environment="YARA_CACHE_DB_PATH=/opt/cowrie/var/yara-cache.db"
WorkingDirectory=/opt/cowrie
ExecStart=/root/.local/bin/uv run scripts/yara-scanner-daemon.py
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/cowrie/var /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads
PrivateTmp=true

[Install]
WantedBy=multi-user.target
YARASERVICE

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable yara-scanner.service

# Scan existing files before starting daemon
echo "[*] Scanning existing downloads with YARA..."
cd /opt/cowrie
uv run scripts/yara-scanner-daemon.py --scan-existing 2>/dev/null || true

# Start the daemon
systemctl start yara-scanner.service
echo "[*] YARA scanner daemon started"

# ============================================================
# STEP 7 — Create example configuration
# ============================================================

echo "[*] Creating example configuration..."

if [ ! -f "/opt/cowrie/etc/report.env" ]; then
    cat > /opt/cowrie/etc/report.env << 'EOF'
#!/bin/bash
# Cowrie Daily Report Configuration

# Paths
export COWRIE_LOG_PATH="/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json"
export COWRIE_DOWNLOAD_PATH="/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"
export GEOIP_DB_PATH="/var/lib/GeoIP/GeoLite2-City.mmdb"
export GEOIP_ASN_PATH="/var/lib/GeoIP/GeoLite2-ASN.mmdb"
export YARA_RULES_PATH="/opt/cowrie/yara-rules"
export CACHE_DB_PATH="/opt/cowrie/var/report-cache.db"
export YARA_CACHE_DB_PATH="/opt/cowrie/var/yara-cache.db"

# VirusTotal (get free API key from https://www.virustotal.com/)
export VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY_HERE"
export VT_ENABLED="true"

# Email Configuration
export EMAIL_ENABLED="true"
export EMAIL_FROM="honeypot@yourdomain.com"
export EMAIL_TO="admin@yourdomain.com"
export EMAIL_SUBJECT_PREFIX="[Honeypot]"

# Report Settings
export REPORT_HOURS="24"
EOF

    chmod 600 /opt/cowrie/etc/report.env
    echo "[*] Created /opt/cowrie/etc/report.env"
    echo "[!] IMPORTANT: Edit /opt/cowrie/etc/report.env with your credentials!"
else
    echo "[*] Configuration file already exists: /opt/cowrie/etc/report.env"
fi

# ============================================================
# STEP 8 — Set up cron job
# ============================================================

echo "[*] Setting up cron job..."

# Use full path to uv for cron reliability
UV_PATH="$HOME/.local/bin/uv"
CRON_ENTRY="0 5 * * * source /opt/cowrie/etc/report.env && cd /opt/cowrie && $UV_PATH run scripts/daily-report.py 2>&1 | logger -t cowrie-report"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "daily-report.py"; then
    echo "[*] Cron job already exists"
else
    # Add cron job
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    echo "[*] Cron job added (runs daily at 5 AM)"
fi

# ============================================================
# STEP 9 — Test installation
# ============================================================

echo "[*] Testing installation..."

# Test Python dependencies
echo -n "[*] Testing Python dependencies... "
cd /opt/cowrie
if uv run python -c "import requests, geoip2, yara" 2>/dev/null; then
    echo "OK"
else
    echo "FAILED"
    echo "[!] Some Python dependencies are missing"
fi

# Test YARA
echo -n "[*] Testing YARA... "
if yara --version >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
fi

# Test GeoIP databases
echo -n "[*] Testing GeoIP databases... "
if [ -f "/var/lib/GeoIP/GeoLite2-City.mmdb" ]; then
    echo "OK"
else
    echo "NOT FOUND (requires manual setup)"
fi

# Test YARA rules
echo -n "[*] Testing YARA rules... "
RULE_COUNT=$(find /opt/cowrie/yara-rules -name "*.yar" -exec grep -E "^rule" {} \; 2>/dev/null | wc -l)
if [ "$RULE_COUNT" -gt 0 ]; then
    echo "OK ($RULE_COUNT rules)"
else
    echo "NO RULES FOUND"
fi

# Test YARA scanner daemon
echo -n "[*] Testing YARA scanner daemon... "
if systemctl is-active --quiet yara-scanner.service; then
    echo "OK (running)"
else
    echo "NOT RUNNING"
fi

# ============================================================
# DONE — Summary
# ============================================================

echo ""
echo "============================================================"
echo "  Cowrie Daily Report System - Setup Complete"
echo "============================================================"
echo ""
echo "Services installed:"
echo "  - Daily report generator (cron: 5 AM daily)"
echo "  - YARA rules updater (cron: 4 AM daily)"
echo "  - YARA scanner daemon (systemd: yara-scanner.service)"
echo ""
echo "Key files:"
echo "  - Config:      /opt/cowrie/etc/report.env"
echo "  - YARA rules:  /opt/cowrie/yara-rules/"
echo "  - YARA cache:  /opt/cowrie/var/yara-cache.db"
echo "  - VT cache:    /opt/cowrie/var/report-cache.db"
echo ""
echo "Commands:"
echo "  - View YARA daemon logs:  journalctl -u yara-scanner -f"
echo "  - Restart YARA daemon:    systemctl restart yara-scanner"
echo "  - Test daily report:      cd /opt/cowrie && uv run scripts/daily-report.py --test"
echo "  - View YARA cache stats:  cd /opt/cowrie && uv run scripts/yara-scanner-daemon.py --stats"
echo ""
echo "[*] Setup completed successfully!"
