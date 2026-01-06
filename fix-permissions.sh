#!/bin/bash
set -euo pipefail

# Fix permissions on existing honeypot volumes
# This script fixes the permission bug on deployments created before the fix

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Initialize temp files array (required by common.sh)
declare -a TEMP_FILES=()

# Source common functions
source scripts/common.sh 2>/dev/null || true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

echo_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

# Parse arguments
HONEYPOT_NAME=""
FIX_ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --name)
            HONEYPOT_NAME="$2"
            shift 2
            ;;
        --all)
            FIX_ALL=true
            shift
            ;;
        -h|--help)
            cat << EOF
Usage: $0 [OPTIONS]

Fix permissions on existing honeypot Docker volumes.

This script is needed for honeypots deployed before the permission fix
that are experiencing "Permission denied: var/log/cowrie/cowrie.json" errors.

Options:
    --name <name>    Fix specific honeypot by name
    --all            Fix all honeypots in master-config.toml
    -h, --help       Show this help message

Examples:
    # Fix single honeypot
    $0 --name cowrie-hp-1

    # Fix all honeypots
    $0 --all

The script will:
1. Stop the Cowrie containers
2. Fix volume permissions using Docker
3. Restart the containers
4. Verify the fix

Note: This does NOT affect your data - logs, downloads, and database are preserved.
EOF
            exit 0
            ;;
        *)
            echo_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate arguments
if [ "$FIX_ALL" = false ] && [ -z "$HONEYPOT_NAME" ]; then
    echo_error "Must specify either --name or --all"
    echo "Use --help for usage information"
    exit 1
fi

# Check if master-config.toml exists
if [ ! -f "master-config.toml" ]; then
    echo_error "master-config.toml not found"
    echo "Please create it from example-config.toml"
    exit 1
fi

# Function to fix permissions on a single honeypot
fix_honeypot_permissions() {
    local name="$1"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo_info "Fixing permissions for: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Get honeypot configuration
    local config
    if ! config=$(python3 scripts/get-honeypot-config.py --name "$name" 2>/dev/null); then
        echo_error "Honeypot '$name' not found in master-config.toml"
        return 1
    fi

    # Extract connection details
    local tailscale_name=$(echo "$config" | jq -r '.tailscale_name // empty')
    local server_ip=$(echo "$config" | jq -r '.server_ip // empty')
    local use_tailscale_ssh=$(echo "$config" | jq -r '.use_tailscale_ssh // false')

    # Determine SSH connection method
    local ssh_target
    local ssh_port_flag=""

    if [ "$use_tailscale_ssh" = "true" ] && [ -n "$tailscale_name" ]; then
        ssh_target="root@$tailscale_name"
        echo_info "Connecting via Tailscale SSH: $tailscale_name"
    elif [ -n "$tailscale_name" ]; then
        ssh_target="root@$tailscale_name"
        ssh_port_flag="-p 2222"
        echo_info "Connecting via Tailscale IP: $tailscale_name:2222"
    elif [ -n "$server_ip" ]; then
        ssh_target="root@$server_ip"
        ssh_port_flag="-p 2222"
        echo_info "Connecting via server IP: $server_ip:2222"
    else
        echo_error "No connection details found for $name"
        return 1
    fi

    # Test SSH connectivity
    echo_info "Testing SSH connection..."
    if ! ssh $ssh_port_flag -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$ssh_target" "echo 'Connection successful'" &>/dev/null; then
        echo_error "Cannot connect to honeypot"
        echo "Please check:"
        echo "  - Server is running: hcloud server list"
        echo "  - SSH is accessible"
        echo "  - Tailscale is connected (if using Tailscale)"
        return 1
    fi
    echo_success "SSH connection successful"

    # Execute fix on remote server
    echo_info "Executing permission fix..."

    if ! ssh $ssh_port_flag -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$ssh_target" << 'ENDSSH'; then
set -euo pipefail

cd /opt/cowrie || exit 1

echo "[1/5] Stopping containers..."
if docker compose ps | grep -q "Up"; then
    docker compose down
    echo "✓ Containers stopped"
else
    echo "⚠ Containers were already stopped"
fi

echo "[2/5] Fixing volume permissions..."
if docker run --rm \
    -v cowrie-etc:/etc \
    -v cowrie-var:/var \
    alpine sh -c '
        # Create all required directories
        mkdir -p /var/lib/cowrie/tty \
                 /var/lib/cowrie/downloads \
                 /var/log/cowrie &&
        # Set ownership to cowrie user (UID 999)
        chown -R 999:999 /etc /var &&
        # Set directory permissions
        chmod -R 755 /var/lib/cowrie /var/log/cowrie &&
        echo "✓ Permissions fixed"
    ' 2>&1; then
    echo "✓ Volume permissions updated"
else
    echo "✗ Failed to fix permissions"
    exit 1
fi

echo "[3/5] Starting containers..."
if docker compose up -d 2>&1 | grep -v "Warning"; then
    echo "✓ Containers started"
else
    echo "✗ Failed to start containers"
    exit 1
fi

echo "[4/5] Waiting for Cowrie to initialize..."
sleep 5

echo "[5/5] Verifying fix..."
if docker compose ps | grep -q "cowrie.*Up"; then
    echo "✓ Cowrie container is running"

    # Check logs for errors
    if docker compose logs cowrie --tail=20 2>&1 | grep -q "Permission denied"; then
        echo "✗ Still seeing permission errors in logs"
        echo ""
        echo "Recent logs:"
        docker compose logs cowrie --tail=20
        exit 1
    elif docker compose logs cowrie --tail=20 2>&1 | grep -q "Ready to accept SSH connections"; then
        echo "✓ Cowrie started successfully - Ready to accept connections"
    else
        echo "⚠ Cowrie is running but may still be initializing"
        echo ""
        echo "Recent logs:"
        docker compose logs cowrie --tail=20
    fi
else
    echo "✗ Cowrie container is not running"
    docker compose ps
    echo ""
    echo "Logs:"
    docker compose logs cowrie --tail=30
    exit 1
fi

echo ""
echo "✓ Permission fix completed successfully"
ENDSSH
        echo_error "Failed to fix permissions on $name"
        return 1
    fi

    echo_success "Successfully fixed permissions for $name"
    return 0
}

# Main execution
main() {
    local start_time=$(date +%s)
    local fixed_count=0
    local failed_count=0
    local honeypots_to_fix=()

    # Determine which honeypots to fix
    if [ "$FIX_ALL" = true ]; then
        echo_info "Getting list of all honeypots from master-config.toml..."

        # Get honeypot count
        local count
        if ! count=$(python3 scripts/get-honeypot-config.py --count 2>/dev/null); then
            echo_error "Failed to read honeypots from config"
            exit 1
        fi

        if [ "$count" -eq 0 ]; then
            echo_error "No honeypots defined in master-config.toml"
            exit 1
        fi

        echo_info "Found $count honeypot(s)"

        # Get all honeypot names
        readarray -t honeypots_to_fix < <(python3 scripts/get-honeypot-config.py --list 2>/dev/null)
    else
        honeypots_to_fix=("$HONEYPOT_NAME")
    fi

    # Fix each honeypot
    for honeypot in "${honeypots_to_fix[@]}"; do
        if fix_honeypot_permissions "$honeypot"; then
            ((fixed_count++))
        else
            ((failed_count++))
        fi
    done

    # Summary
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo_info "SUMMARY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Total honeypots: ${#honeypots_to_fix[@]}"
    echo_success "Fixed: $fixed_count"
    if [ $failed_count -gt 0 ]; then
        echo_error "Failed: $failed_count"
    fi
    echo "Duration: ${duration}s"
    echo ""

    if [ $failed_count -gt 0 ]; then
        echo_error "Some honeypots failed to fix. Check the output above for details."
        exit 1
    else
        echo_success "All honeypots fixed successfully!"
        echo ""
        echo "Your honeypots should now be working correctly."
        echo "You can verify by checking the logs:"
        echo "  ssh -p 2222 root@<SERVER_IP> 'cd /opt/cowrie && docker compose logs cowrie --tail=20'"
        exit 0
    fi
}

# Run main function
main
