#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Deploy Updates to Cowrie Honeypot Server
# ============================================================
# This script syncs local changes to a running Cowrie server.
# It updates scripts, web files, and configuration without
# requiring a full redeployment.
#
# Usage: ./deploy-updates.sh <server_ip> [ssh_port]
# Example: ./deploy-updates.sh 192.168.1.100 2222
# ============================================================

if [ $# -lt 1 ]; then
    echo "Usage: $0 <server_ip> [ssh_port]"
    echo "Example: $0 192.168.1.100 2222"
    echo ""
    echo "This script syncs local changes to the server:"
    echo "  - scripts/ directory (Python scripts, shell scripts)"
    echo "  - web/ directory (web dashboard files)"
    echo "  - pyproject.toml, README.md"
    echo "  - Restarts affected services"
    exit 1
fi

SERVER_IP="$1"
SSH_PORT="${2:-2222}"  # Default to 2222 if not specified

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# SSH options for convenience
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

echo_info "Deploying updates to Cowrie server at $SERVER_IP:$SSH_PORT"

# ============================================================
# Step 1: Verify connection
# ============================================================
echo_info "Verifying SSH connection..."
if ! ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" "exit" 2>/dev/null; then
    echo_error "Cannot connect to server at $SERVER_IP:$SSH_PORT"
    echo_error "Please check the server IP, SSH port, and your SSH key"
    exit 1
fi

# ============================================================
# Step 2: Check required directories exist locally
# ============================================================
REQUIRED_DIRS=("scripts" "web")
MISSING_DIRS=()

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        MISSING_DIRS+=("$dir")
    fi
done

if [ ${#MISSING_DIRS[@]} -gt 0 ]; then
    echo_error "Missing required directories: ${MISSING_DIRS[*]}"
    echo_error "Please run this script from the cowrie-deploy-toolkit directory"
    exit 1
fi

# ============================================================
# Step 3: Upload scripts directory
# ============================================================
echo_info "Uploading scripts directory..."
rsync -az --delete -e "ssh $SSH_OPTS -p $SSH_PORT" \
    scripts/ "root@$SERVER_IP:/opt/cowrie/scripts/" || {
        echo_error "Failed to upload scripts directory"
        exit 1
    }

# Make scripts executable
ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" << 'EOF'
chmod +x /opt/cowrie/scripts/*.sh /opt/cowrie/scripts/*.py 2>/dev/null || true
EOF

echo_info "Scripts uploaded successfully"

# ============================================================
# Step 4: Upload web directory (if web dashboard is running)
# ============================================================
if ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" "[ -d /opt/cowrie/web ]" 2>/dev/null; then
    echo_info "Uploading web dashboard files..."
    rsync -az --delete -e "ssh $SSH_OPTS -p $SSH_PORT" \
        web/ "root@$SERVER_IP:/opt/cowrie/web/" || {
            echo_error "Failed to upload web directory"
            exit 1
        }
    echo_info "Web dashboard files uploaded successfully"
    WEB_UPDATED=true
else
    echo_warn "Web dashboard not found on server, skipping"
    WEB_UPDATED=false
fi

# ============================================================
# Step 5: Upload project files
# ============================================================
echo_info "Uploading project files..."
scp $SSH_OPTS -P "$SSH_PORT" \
    pyproject.toml README.md "root@$SERVER_IP:/opt/cowrie/" > /dev/null 2>&1 || {
        echo_warn "Failed to upload some project files (non-critical)"
    }

# ============================================================
# Step 6: Restart services
# ============================================================
echo_info "Checking which services need restart..."

# Check if YARA scanner daemon is running (systemd service)
YARA_RUNNING=$(ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" \
    "systemctl is-active yara-scanner.service 2>/dev/null || echo 'inactive'" 2>/dev/null)

if [ "$YARA_RUNNING" = "active" ]; then
    echo_info "Restarting YARA scanner daemon..."
    ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" \
        "systemctl restart yara-scanner.service" 2>/dev/null
    echo_info "YARA scanner daemon restarted"
fi

# Check if web dashboard is running and restart if updated
if [ "$WEB_UPDATED" = "true" ]; then
    WEB_CONTAINER=$(ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" \
        "docker ps --filter 'name=cowrie-web' --format '{{.Names}}' 2>/dev/null || echo 'false'" 2>/dev/null)

    if [ "$WEB_CONTAINER" != "false" ] && [ -n "$WEB_CONTAINER" ]; then
        echo_info "Rebuilding and restarting web dashboard..."
        ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" << 'EOF'
cd /opt/cowrie
docker compose build cowrie-web
docker compose restart cowrie-web
EOF
        echo_info "Web dashboard restarted"
    fi
fi

# ============================================================
# Done
# ============================================================
echo ""
echo_info "✓ Deployment complete!"
echo ""
echo "Updated components:"
echo "  - Scripts directory synced"
[ "$WEB_UPDATED" = "true" ] && echo "  - Web dashboard updated and restarted"
[ "$YARA_RUNNING" != "false" ] && echo "  - YARA scanner daemon restarted"
echo ""
echo "Services status:"
ssh $SSH_OPTS -p "$SSH_PORT" "root@$SERVER_IP" << 'EOF'
echo "  Docker containers:"
docker ps --format "    - {{.Names}}: {{.Status}}" --filter "name=cowrie" 2>/dev/null || echo "    (none running)"
echo ""
echo "  YARA scanner:"
if systemctl is-active --quiet yara-scanner.service; then
    echo "    - Running (systemd service active)"
else
    echo "    - Not running"
fi
EOF
