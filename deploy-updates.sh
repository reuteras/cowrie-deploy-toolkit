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
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/scripts/common.sh"
else
    echo "ERROR: Cannot find scripts/common.sh"
    echo "Please run this script from the cowrie-deploy-toolkit directory"
    exit 1
fi

# Check dependencies
check_dependencies "ssh" "scp" "rsync"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <server_ip_or_hostname> [ssh_port]"
    echo "   OR: $0 --all"
    echo "   OR: $0 --name <honeypot_name>"
    echo ""
    echo "Examples:"
    echo "  $0 --all                               # Update all honeypots (via Tailscale)"
    echo "  $0 --name cowrie-hp-1                  # Update specific honeypot (via Tailscale)"
    echo "  $0 cowrie-hp-1.tail9e5e41.ts.net 2222  # Update by Tailscale hostname"
    echo "  $0 192.168.1.100 2222                  # Update by IP (if not using Tailscale)"
    echo ""
    echo "This script syncs local changes to the server:"
    echo "  - Latest output directory (fs.pickle, identity, contents)"
    echo "  - scripts/ directory (Python scripts, shell scripts)"
    echo "  - web/ directory (web dashboard files)"
    echo "  - pyproject.toml, README.md"
    echo "  - Restarts affected services"
    echo ""
    echo "Note: --all and --name modes use Tailscale hostnames from master-config.toml"
    exit 1
fi

# Check for multi-deployment mode
MASTER_CONFIG="$SCRIPT_DIR/master-config.toml"

if [ "$1" = "--all" ]; then
    # Multi-deployment mode: update all honeypots
    if [ ! -f "$MASTER_CONFIG" ]; then
        fatal_error "master-config.toml not found. Required for --all mode."
    fi

    if ! has_honeypots_array "$MASTER_CONFIG"; then
        fatal_error "No [[honeypots]] array found in master-config.toml"
    fi

    # Get list of honeypot names
    HONEYPOT_NAMES=()
    get_honeypot_names "$MASTER_CONFIG" HONEYPOT_NAMES

    if [ ${#HONEYPOT_NAMES[@]} -eq 0 ]; then
        fatal_error "No honeypots defined in master-config.toml"
    fi

    echo_info "Found ${#HONEYPOT_NAMES[@]} honeypot(s): ${HONEYPOT_NAMES[*]}"
    echo ""

    # Get Tailscale domain from shared config
    SHARED_CONFIG=$(python3 "$SCRIPT_DIR/scripts/get-honeypot-config.py" "$MASTER_CONFIG" --shared 2>/dev/null || echo "{}")
    TAILSCALE_DOMAIN=$(echo "$SHARED_CONFIG" | jq -r '.tailscale_domain // empty')

    if [ -z "$TAILSCALE_DOMAIN" ]; then
        echo_warn "No tailscale_domain in shared config, will use hostname only"
    fi

    # Update each honeypot
    for name in "${HONEYPOT_NAMES[@]}"; do
        echo "========================================================================"
        echo_info "Updating honeypot: $name"
        echo "========================================================================"

        # Construct Tailscale hostname
        if [ -n "$TAILSCALE_DOMAIN" ]; then
            HP_HOSTNAME="${name}.${TAILSCALE_DOMAIN}"
        else
            HP_HOSTNAME="$name"
        fi

        echo_info "Connecting to: $HP_HOSTNAME"

        # Call this script recursively for each honeypot (port 22 for Tailscale SSH)
        "$0" "$HP_HOSTNAME" 22 "$name"
        echo ""
    done

    echo_info "✓ All honeypots updated!"
    exit 0

elif [ "$1" = "--name" ]; then
    # Single honeypot by name
    if [ -z "$2" ]; then
        fatal_error "Missing honeypot name. Usage: $0 --name <honeypot_name>"
    fi

    HP_NAME="$2"

    if [ ! -f "$MASTER_CONFIG" ]; then
        fatal_error "master-config.toml not found. Required for --name mode."
    fi

    # Get honeypot config
    HP_CONFIG=$(get_honeypot_config "$MASTER_CONFIG" "$HP_NAME")
    if [ -z "$HP_CONFIG" ]; then
        fatal_error "Honeypot '$HP_NAME' not found in master-config.toml"
    fi

    # Get Tailscale domain from shared config
    SHARED_CONFIG=$(python3 "$SCRIPT_DIR/scripts/get-honeypot-config.py" "$MASTER_CONFIG" --shared 2>/dev/null || echo "{}")
    TAILSCALE_DOMAIN=$(echo "$SHARED_CONFIG" | jq -r '.tailscale_domain // empty')

    # Construct Tailscale hostname
    if [ -n "$TAILSCALE_DOMAIN" ]; then
        SERVER_IP="${HP_NAME}.${TAILSCALE_DOMAIN}"
    else
        SERVER_IP="$HP_NAME"
    fi

    echo_info "Connecting to: $SERVER_IP"
    SSH_PORT=2222
    # Continue with normal update below...

else
    # Original mode: update by IP address or hostname
    SERVER_IP="$1"
    SSH_PORT="${2:-22}"
    HP_NAME="${3:-}"  # Optional name passed from recursive call

    # Validate inputs - allow both IP addresses and hostnames
    if ! validate_ip "$SERVER_IP" 2>/dev/null; then
        # Not an IP, assume it's a hostname (for Tailscale)
        echo_info "Using hostname: $SERVER_IP"
    fi
fi

# ============================================================
# Helper Functions
# ============================================================

# Find the latest output directory
# If HP_NAME is set, finds output_<name>_*, otherwise finds latest output_*
find_latest_output_dir() {
    local name_filter="$1"  # Optional: honeypot name
    local latest_dir=""
    local latest_time=0

    # Build pattern based on whether we have a name filter
    if [ -n "$name_filter" ]; then
        pattern="$SCRIPT_DIR/output_${name_filter}_*"
    else
        pattern="$SCRIPT_DIR/output_*"
    fi

    # Find all matching directories and get the most recent
    for dir in $pattern; do
        if [ -d "$dir" ]; then
            # Get modification time
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS
                dir_time=$(stat -f %m "$dir" 2>/dev/null || echo 0)
            else
                # Linux
                dir_time=$(stat -c %Y "$dir" 2>/dev/null || echo 0)
            fi

            if [ "$dir_time" -gt "$latest_time" ]; then
                latest_time=$dir_time
                latest_dir="$dir"
            fi
        fi
    done

    if [ -n "$latest_dir" ] && [ -d "$latest_dir" ]; then
        echo "$latest_dir"
        return 0
    else
        return 1
    fi
}

if [ -n "$HP_NAME" ]; then
    echo_info "Deploying updates to honeypot '$HP_NAME' at $SERVER_IP:$SSH_PORT"
else
    echo_info "Deploying updates to Cowrie server at $SERVER_IP:$SSH_PORT"
fi

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
if find_latest_output_dir "$HP_NAME" > /dev/null 2>&1; then
    OUTPUT_DIR=$(find_latest_output_dir "$HP_NAME")
    echo_info "Found latest output directory: $(basename "$OUTPUT_DIR")"
else
    if [ -n "$HP_NAME" ]; then
        echo_warn "No output directory found for honeypot '$HP_NAME' (output_${HP_NAME}_*)"
    else
        echo_warn "No output directory found (output_YYYYMMDD_HHMMSS)"
    fi
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
