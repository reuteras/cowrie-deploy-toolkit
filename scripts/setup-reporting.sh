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
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root"
    exit 1
fi

# ============================================================
# STEP 1 — Install system dependencies
# ============================================================

echo "[*] Installing system dependencies..."

apt-get update -qq
apt-get install -y \
    python3 \
    python3-pip \
    yara \
    geoipupdate \
    git \
    sqlite3 \
    curl \
    > /dev/null 2>&1

echo "[*] System dependencies installed"

# ============================================================
# STEP 2 — Install uv (modern Python package manager)
# ============================================================

echo "[*] Installing uv..."

if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
    # Source the cargo env file created by the installer
    [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
    # Also add to PATH as fallback
    export PATH="$HOME/.cargo/bin:$PATH"
    echo "[*] uv installed successfully"
else
    echo "[*] uv already installed"
fi

# Verify uv is available
if ! command -v uv &> /dev/null; then
    echo "[!] Warning: uv installation succeeded but command not found in PATH"
    echo "[!] Will fall back to pip for dependencies"
fi

# ============================================================
# STEP 3 — Install Python dependencies using uv
# ============================================================

echo "[*] Installing Python dependencies with uv..."

# Assume the toolkit is already in /opt/cowrie
if [ -f "/opt/cowrie/pyproject.toml" ]; then
    cd /opt/cowrie
    if command -v uv &> /dev/null; then
        if uv sync --quiet 2>&1; then
            echo "[*] Python dependencies installed with uv"
        else
            echo "[!] Warning: uv sync failed, falling back to pip"
            pip3 install --quiet requests geoip2 yara-python
            echo "[*] Python dependencies installed with pip"
        fi
    else
        echo "[!] uv not available, using pip"
        pip3 install --quiet requests geoip2 yara-python
        echo "[*] Python dependencies installed with pip"
    fi
else
    echo "[!] Warning: pyproject.toml not found, installing with pip"
    pip3 install --quiet requests geoip2 yara-python
    echo "[*] Python dependencies installed with pip"
fi

# ============================================================
# STEP 4 — Create directory structure
# ============================================================

echo "[*] Creating directory structure..."

mkdir -p /opt/cowrie/scripts
mkdir -p /opt/cowrie/etc
mkdir -p /opt/cowrie/geoip
mkdir -p /opt/cowrie/yara-rules
mkdir -p /opt/cowrie/var

echo "[*] Directory structure created"

# ============================================================
# STEP 5 — Configure MaxMind GeoIP (requires manual setup)
# ============================================================

echo ""
echo "[!] MANUAL STEP REQUIRED: MaxMind GeoIP Configuration"
echo "======================================================"
echo ""
echo "You need to download MaxMind GeoLite2 databases:"
echo ""
echo "1. Sign up for free account: https://www.maxmind.com/en/geolite2/signup"
echo "2. Get your Account ID and License Key"
echo "3. Configure /etc/GeoIP.conf with:"
echo ""
echo "   AccountID YOUR_ACCOUNT_ID"
echo "   LicenseKey YOUR_LICENSE_KEY"
echo "   EditionIDs GeoLite2-City GeoLite2-ASN"
echo ""
echo "4. Run: geoipupdate"
echo "5. Copy databases:"
echo "   cp /usr/share/GeoIP/GeoLite2-City.mmdb /opt/cowrie/geoip/"
echo "   cp /usr/share/GeoIP/GeoLite2-ASN.mmdb /opt/cowrie/geoip/"
echo ""

# Check if databases already exist
if [ -f "/opt/cowrie/geoip/GeoLite2-City.mmdb" ] && [ -f "/opt/cowrie/geoip/GeoLite2-ASN.mmdb" ]; then
    echo "[*] GeoIP databases found!"
else
    echo "[!] GeoIP databases not found. Please complete steps above."
fi

echo ""

# ============================================================
# STEP 6 — Download YARA rules
# ============================================================

echo "[*] Downloading YARA rules..."

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download Yara-Rules community repository
echo "[*] Downloading community YARA rules..."
git clone --quiet --depth 1 https://github.com/Yara-Rules/rules.git yara-community 2>/dev/null || true

if [ -d "yara-community/malware" ]; then
    cp yara-community/malware/*.yar /opt/cowrie/yara-rules/ 2>/dev/null || true
fi

# Download Neo23x0's signature-base
echo "[*] Downloading signature-base YARA rules..."
git clone --quiet --depth 1 https://github.com/Neo23x0/signature-base.git 2>/dev/null || true

if [ -d "signature-base/yara" ]; then
    # Copy only malware-related rules (avoid false positives from other categories)
    cp signature-base/yara/apt_*.yar /opt/cowrie/yara-rules/ 2>/dev/null || true
    cp signature-base/yara/gen_*.yar /opt/cowrie/yara-rules/ 2>/dev/null || true
    cp signature-base/yara/mal_*.yar /opt/cowrie/yara-rules/ 2>/dev/null || true
    cp signature-base/yara/webshell_*.yar /opt/cowrie/yara-rules/ 2>/dev/null || true
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

# Count rules
RULE_COUNT=$(find /opt/cowrie/yara-rules -name "*.yar" -o -name "*.yara" | wc -l)
echo "[*] Downloaded $RULE_COUNT YARA rule files"

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
export GEOIP_DB_PATH="/opt/cowrie/geoip/GeoLite2-City.mmdb"
export GEOIP_ASN_PATH="/opt/cowrie/geoip/GeoLite2-ASN.mmdb"
export YARA_RULES_PATH="/opt/cowrie/yara-rules"
export CACHE_DB_PATH="/opt/cowrie/var/report-cache.db"

# VirusTotal (get free API key from https://www.virustotal.com/)
export VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY_HERE"
export VT_ENABLED="true"

# Email Configuration
export EMAIL_ENABLED="true"
export EMAIL_FROM="honeypot@yourdomain.com"
export EMAIL_TO="admin@yourdomain.com"
export EMAIL_SUBJECT_PREFIX="[Honeypot]"

# SMTP Settings
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your_email@gmail.com"
export SMTP_PASSWORD="your_app_password_here"
export SMTP_TLS="true"

# Alert Thresholds
export ALERT_THRESHOLD_CONNECTIONS="100"
export ALERT_ON_MALWARE="true"

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

# Use uv if available, otherwise fall back to python3
if command -v uv &> /dev/null && [ -f "/opt/cowrie/pyproject.toml" ]; then
    UV_PATH="$HOME/.cargo/bin/uv"
    CRON_ENTRY="0 6 * * * source /opt/cowrie/etc/report.env && cd /opt/cowrie && $UV_PATH run scripts/daily-report.py 2>&1 | logger -t cowrie-report"
    echo "[*] Will use uv for cron job"
else
    CRON_ENTRY="0 6 * * * source /opt/cowrie/etc/report.env && /usr/bin/python3 /opt/cowrie/scripts/daily-report.py 2>&1 | logger -t cowrie-report"
    echo "[*] Will use python3 for cron job"
fi

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "daily-report.py"; then
    echo "[*] Cron job already exists"
else
    # Add cron job
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    echo "[*] Cron job added (runs daily at 6 AM)"
fi

# ============================================================
# STEP 9 — Test installation
# ============================================================

echo ""
echo "[*] Testing installation..."
echo ""

# Test Python dependencies
echo -n "[*] Testing Python dependencies... "
if python3 -c "import requests, geoip2, yara" 2>/dev/null; then
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
if [ -f "/opt/cowrie/geoip/GeoLite2-City.mmdb" ]; then
    echo "OK"
else
    echo "NOT FOUND (requires manual setup)"
fi

# Test YARA rules
echo -n "[*] Testing YARA rules... "
RULE_COUNT=$(find /opt/cowrie/yara-rules -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)
if [ "$RULE_COUNT" -gt 0 ]; then
    echo "OK ($RULE_COUNT rules)"
else
    echo "NO RULES FOUND"
fi

# ============================================================
# DONE
# ============================================================

echo ""
echo "========================================"
echo "  SETUP COMPLETED"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Configure MaxMind GeoIP (see instructions above)"
echo ""
echo "2. Edit configuration file:"
echo "   nano /opt/cowrie/etc/report.env"
echo ""
echo "   Set your:"
echo "   - VirusTotal API key (free from virustotal.com)"
echo "   - Email settings (SMTP or SendGrid/Mailgun)"
echo "   - Webhook URLs (optional, for Slack/Discord/Teams)"
echo ""
echo "3. Test the report:"
echo "   source /opt/cowrie/etc/report.env"
if command -v uv &> /dev/null && [ -f "/opt/cowrie/pyproject.toml" ]; then
    echo "   cd /opt/cowrie && uv run scripts/daily-report.py --test"
else
    echo "   python3 /opt/cowrie/scripts/daily-report.py --test"
fi
echo ""
echo "4. Send a test email:"
echo "   source /opt/cowrie/etc/report.env"
if command -v uv &> /dev/null && [ -f "/opt/cowrie/pyproject.toml" ]; then
    echo "   cd /opt/cowrie && uv run scripts/daily-report.py --hours 168"
else
    echo "   python3 /opt/cowrie/scripts/daily-report.py --hours 168"
fi
echo ""
echo "The report will run automatically daily at 6 AM via cron."
echo ""
echo "Documentation: /opt/cowrie/scripts/README.md"
echo "========================================"
