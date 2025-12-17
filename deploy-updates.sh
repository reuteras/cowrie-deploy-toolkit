#!/usr/bin/env bash

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load common functions library
if [ -f "$SCRIPT_DIR/scripts/common.sh" ]; then
    source "$SCRIPT_DIR/scripts/common.sh"
else
    echo "ERROR: Cannot find scripts/common.sh"
    echo "Please run this script from the cowrie-deploy-toolkit directory"
    exit 1
fi

# Check dependencies
check_dependencies "ssh" "scp" "rsync"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <server_ip> [ssh_port]"
    echo "Example: $0 192.168.1.100 2222"
    echo ""
    echo "This script syncs local changes to the server:"
    echo "  - Latest output directory (fs.pickle, identity, contents)"
    echo "  - scripts/ directory (Python scripts, shell scripts)"
    echo "  - web/ directory (web dashboard files)"
    echo "  - pyproject.toml, README.md"
    echo "  - Restarts affected services"
    exit 1
fi

SERVER_IP="$1"
SSH_PORT="${2:-22}"  # Default to 22

# Validate inputs
validate_ip "$SERVER_IP" || fatal_error "Invalid IP address: $SERVER_IP"

# ============================================================
# Helper Functions
# ============================================================

# Find the latest output directory
find_latest_output_dir() {
    local latest_dir=""

    # Find all output_* directories and sort by modification time
    for dir in "$SCRIPT_DIR"/output_*; do
        if [ -d "$dir" ]; then
            latest_dir="$dir"
        fi
    done

    if [ -n "$latest_dir" ] && [ -d "$latest_dir" ]; then
        echo "$latest_dir"
        return 0
    else
        return 1
    fi
}

echo_info "Deploying updates to Cowrie server at $SERVER_IP:$SSH_PORT"

# ============================================================
# Step 1: Verify connection
# ============================================================
echo_info "Verifying SSH connection..."
if ! ssh_exec "root@$SERVER_IP" "exit" "$SSH_PORT" 2>/dev/null; then
    fatal_error "Cannot connect to server at $SERVER_IP:$SSH_PORT. Check IP, port, and SSH key."
fi

# ============================================================
# Step 2: Find latest output directory
# ============================================================
OUTPUT_DIR=""
if find_latest_output_dir > /dev/null 2>&1; then
    OUTPUT_DIR=$(find_latest_output_dir)
    echo_info "Found latest output directory: $(basename "$OUTPUT_DIR")"
else
    echo_warn "No output directory found (output_YYYYMMDD_HHMMSS)"
    echo_warn "Skipping filesystem and identity updates"
fi

# ============================================================
# Step 3: Check required directories exist locally
# ============================================================
REQUIRED_DIRS=("scripts")
MISSING_DIRS=()

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        MISSING_DIRS+=("$dir")
    fi
done

if [ ${#MISSING_DIRS[@]} -gt 0 ]; then
    fatal_error "Missing required directories: ${MISSING_DIRS[*]}. Run from cowrie-deploy-toolkit directory."
fi

# ============================================================
# Step 4: Sync output directory files (if available)
# ============================================================
if [ -n "$OUTPUT_DIR" ]; then
    echo_info "Syncing files from output directory..."

    # Sync fs.pickle (filesystem snapshot)
    if [ -f "$OUTPUT_DIR/fs.pickle" ]; then
        echo_info "  - Uploading fs.pickle..."
        scp_copy "$OUTPUT_DIR/fs.pickle" "root@$SERVER_IP:/opt/cowrie/" "$SSH_PORT" || \
            echo_warn "Failed to upload fs.pickle"
    fi

    # Sync identity directory
    if [ -d "$OUTPUT_DIR/identity" ]; then
        echo_info "  - Syncing identity/ directory..."
        rsync -az -e "ssh $SSH_OPTS -p $SSH_PORT" \
            "$OUTPUT_DIR/identity/" "root@$SERVER_IP:/opt/cowrie/identity/" 2>/dev/null || \
            echo_warn "Failed to sync identity directory"
    fi

    # Sync contents directory
    if [ -d "$OUTPUT_DIR/contents" ]; then
        echo_info "  - Syncing contents/ directory..."
        rsync -az -e "ssh $SSH_OPTS -p $SSH_PORT" \
            "$OUTPUT_DIR/contents/" "root@$SERVER_IP:/opt/cowrie/contents/" 2>/dev/null || \
            echo_warn "Failed to sync contents directory"
    fi

    # Sync txtcmds directory
    if [ -d "$OUTPUT_DIR/txtcmds" ]; then
        echo_info "  - Syncing txtcmds/ directory..."
        rsync -az -e "ssh $SSH_OPTS -p $SSH_PORT" \
            "$OUTPUT_DIR/txtcmds/" "root@$SERVER_IP:/opt/cowrie/txtcmds/" 2>/dev/null || \
            echo_warn "Failed to sync txtcmds directory"
    fi

    echo_info "Output directory files synced"
    OUTPUT_SYNCED=true
else
    OUTPUT_SYNCED=false
fi

# ============================================================
# Step 5: Upload scripts directory
# ============================================================
echo_info "Uploading scripts directory..."
rsync -az --delete -e "ssh $SSH_OPTS -p $SSH_PORT" \
    scripts/ "root@$SERVER_IP:/opt/cowrie/scripts/" || \
    fatal_error "Failed to upload scripts directory"

# Make scripts executable
ssh_exec "root@$SERVER_IP" "chmod +x /opt/cowrie/scripts/*.sh /opt/cowrie/scripts/*.py 2>/dev/null || true" "$SSH_PORT"

echo_info "Scripts uploaded successfully"

# ============================================================
# Step 6: Upload web directory (if web dashboard is running)
# ============================================================
if ssh_exec "root@$SERVER_IP" "[ -d /opt/cowrie/web ]" "$SSH_PORT" 2>/dev/null; then
    if [ -d "web" ]; then
        echo_info "Uploading web dashboard files..."
        rsync -az --delete -e "ssh $SSH_OPTS -p $SSH_PORT" \
            web/ "root@$SERVER_IP:/opt/cowrie/web/" || \
            echo_warn "Failed to upload web directory"
        echo_info "Web dashboard files uploaded successfully"
        WEB_UPDATED=true
    else
        echo_warn "Local web/ directory not found"
        WEB_UPDATED=false
    fi
else
    echo_warn "Web dashboard not found on server, skipping"
    WEB_UPDATED=false
fi

# ============================================================
# Step 7: Upload project files
# ============================================================
echo_info "Uploading project files..."
scp_copy "pyproject.toml" "root@$SERVER_IP:/opt/cowrie/" "$SSH_PORT" || \
    echo_warn "Failed to upload pyproject.toml"
scp_copy "README.md" "root@$SERVER_IP:/opt/cowrie/" "$SSH_PORT" || \
    echo_warn "Failed to upload README.md"

# ============================================================
# Step 8: Restart services
# ============================================================
echo_info "Checking which services need restart..."

# Check if YARA scanner daemon is running (systemd service)
YARA_RUNNING=$(ssh_exec "root@$SERVER_IP" "systemctl is-active yara-scanner.service 2>/dev/null || echo 'inactive'" "$SSH_PORT" 2>/dev/null)

if [ "$YARA_RUNNING" = "active" ]; then
    echo_info "Restarting YARA scanner daemon..."
    ssh_exec "root@$SERVER_IP" "systemctl restart yara-scanner.service" "$SSH_PORT" 2>/dev/null
    echo_info "YARA scanner daemon restarted"
fi

# Restart Cowrie if output directory was synced (filesystem/identity changes)
if [ "$OUTPUT_SYNCED" = "true" ]; then
    echo_info "Restarting Cowrie container (filesystem/identity updated)..."
    ssh_exec "root@$SERVER_IP" "cd /opt/cowrie && docker compose restart" "$SSH_PORT" 2>/dev/null
    echo_info "Cowrie container restarted"
fi

# Check if web dashboard is running and restart if updated
if [ "$WEB_UPDATED" = "true" ]; then
    echo_info "Web files updated, triggering full Docker update..."
    echo_info "This will rebuild custom Cowrie image and update containers..."

    # Call the auto-update script which handles:
    # - Rebuilding custom Cowrie image with latest base
    # - Rebuilding web dashboard
    # - Restarting containers
    # - Health checks
    ssh_exec "root@$SERVER_IP" "/opt/cowrie/scripts/auto-update-docker.sh" "$SSH_PORT"

    echo_info "Docker images and containers updated successfully"
fi

# ============================================================
# Done
# ============================================================
echo ""
echo_info "✓ Deployment complete!"
echo ""
echo "Updated components:"
[ "$OUTPUT_SYNCED" = "true" ] && echo "  - Output directory synced (fs.pickle, identity, contents)"
echo "  - Scripts directory synced"
[ "$WEB_UPDATED" = "true" ] && echo "  - Web dashboard updated and restarted"
[ "$YARA_RUNNING" = "active" ] && echo "  - YARA scanner daemon restarted"
[ "$OUTPUT_SYNCED" = "true" ] && echo "  - Cowrie container restarted"
echo ""
echo "Services status:"
ssh_exec "root@$SERVER_IP" 'docker ps --format "  - {{.Names}}: {{.Status}}" --filter "name=cowrie" 2>/dev/null || echo "  (no containers running)"' "$SSH_PORT"
if [ "$YARA_RUNNING" = "active" ]; then
    ssh_exec "root@$SERVER_IP" 'if systemctl is-active --quiet yara-scanner.service; then echo "  - YARA scanner: Running"; else echo "  - YARA scanner: Not running"; fi' "$SSH_PORT"
fi
