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
# CONFIGURATION
# ============================================================

# Repository configuration (change these if forking the project)
REPO_OWNER="${REPO_OWNER:-reuteras}"
REPO_NAME="${REPO_NAME:-cowrie-deploy-toolkit}"

# ============================================================
# DEPENDENCY CHECKS
# ============================================================

echo_info "Checking required dependencies..."
check_dependencies "hcloud" "jq" "nc" "tar" "ssh" "scp" "python3" "curl" "uv"

# ============================================================
# ARGUMENT PARSING (Multi-Honeypot Support)
# ============================================================

# Parse command line arguments
# Supports two modes:
#   1. Single: ./deploy_cowrie_honeypot.sh <output_DIR> --name <honeypot-name>
#   2. All:    ./deploy_cowrie_honeypot.sh --all  (auto-finds latest outputs)

OUTPUT_DIR=""
HONEYPOT_NAME=""
DEPLOY_ALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)
            if [ -z "$2" ]; then
                echo_error "--name requires a honeypot name argument"
                exit 1
            fi
            HONEYPOT_NAME="$2"
            shift 2
            ;;
        --all)
            DEPLOY_ALL=true
            shift
            ;;
        -*)
            echo_error "Unknown option: $1"
            exit 1
            ;;
        *)
            # First non-option argument is OUTPUT_DIR (only for --name mode)
            if [ -z "$OUTPUT_DIR" ]; then
                OUTPUT_DIR="$1"
                shift
            else
                echo_error "Unexpected argument: $1"
                exit 1
            fi
            ;;
    esac
done

# Validate arguments
if [ "$DEPLOY_ALL" = false ] && [ -z "$OUTPUT_DIR" ]; then
    echo_error "Usage:"
    echo_error "  $0 <output_directory> --name HONEYPOT_NAME"
    echo_error "  $0 --all"
    echo_error ""
    echo_error "Examples:"
    echo_error "  # Deploy specific honeypot:"
    echo_error "  $0 ./output_cowrie-hp-1_20251227_135502 --name cowrie-hp-1"
    echo_error ""
    echo_error "  # Deploy all honeypots (auto-finds latest outputs):"
    echo_error "  $0 --all"
    echo_error "Requires master-config.toml in project root with [[honeypots]] array defined"
    exit 1
fi

if [ "$DEPLOY_ALL" = false ] && [ -z "$HONEYPOT_NAME" ]; then
    echo_error "When deploying a specific honeypot, --name is required"
    echo_error ""
    echo_error "Usage: $0 <output_directory> --name HONEYPOT_NAME"
    exit 1
fi

if [ "$DEPLOY_ALL" = true ] && [ -n "$OUTPUT_DIR" ]; then
    echo_error "When using --all, do not specify an output directory"
    echo_error "Latest output directories will be found automatically"
    echo_error ""
    echo_error "Usage: $0 --all"
    exit 1
fi

# ============================================================
# MULTI-HONEYPOT DEPLOYMENT (--all flag)
# ============================================================

MASTER_CONFIG="./master-config.toml"

if [ ! -f "$MASTER_CONFIG" ]; then
    echo_error "master-config.toml not found - required"
    exit 1
fi

# Helper function to find latest output directory for a honeypot
find_latest_output() {
    local honeypot_name="$1"

    # Find all matching directories, sorted by timestamp (newest first)
    # Pattern: output_<honeypot-name>_YYYYMMDD_HHMMSS
    local latest
    latest=$(find . -maxdepth 1 -type d -name "output_${honeypot_name}_*" | sort -r | head -n1)

    if [ -z "$latest" ]; then
        return 1
    fi

    echo "$latest"
    return 0
}

# Handle --all flag: deploy all honeypots sequentially
if [ "$DEPLOY_ALL" = true ]; then
    echo_info "Deploying all honeypots from master-config.toml..."

    # Check if honeypots array exists
    HAS_ARRAY=$(has_honeypots_array "$MASTER_CONFIG")
    if [ "$HAS_ARRAY" != "true" ]; then
        echo_error "No [[honeypots]] array found in master-config.toml"
        echo_error "Add honeypot definitions to use --all deployment"
        exit 1
    fi

    # Get list of honeypot names
    HONEYPOT_NAMES=()
    get_honeypot_names "$MASTER_CONFIG" HONEYPOT_NAMES

    if [ ${#HONEYPOT_NAMES[@]} -eq 0 ]; then
        echo_error "No honeypots defined in master-config.toml"
        exit 1
    fi

    echo_info "Found ${#HONEYPOT_NAMES[@]} honeypot(s): ${HONEYPOT_NAMES[*]}"

    # Find latest output directories for all honeypots
    echo_info "Finding latest output directories..."
    declare -A HONEYPOT_OUTPUTS
    MISSING_OUTPUTS=()

    for name in "${HONEYPOT_NAMES[@]}"; do
        if latest_output=$(find_latest_output "$name"); then
            HONEYPOT_OUTPUTS["$name"]="$latest_output"
            echo_info "  $name: $latest_output"
        else
            MISSING_OUTPUTS+=("$name")
        fi
    done

    # Check if any outputs are missing
    if [ ${#MISSING_OUTPUTS[@]} -gt 0 ]; then
        echo_error "Missing output directories for the following honeypots:"
        for name in "${MISSING_OUTPUTS[@]}"; do
            echo_error "  - $name (expected: output_${name}_*)"
        done
        echo_error "Please run ./generate_cowrie_fs_from_hetzner.sh first to generate filesystems"
        exit 1
    fi

    echo_info "All output directories found. Starting deployment..."

    # Deploy each honeypot
    for name in "${HONEYPOT_NAMES[@]}"; do
        output_dir="${HONEYPOT_OUTPUTS[$name]}"

        echo "========================================================================"
        echo_info "Deploying honeypot: $name"
        echo_info "Using output: $output_dir"
        echo "========================================================================"

        # Recursively call this script with --name and specific output dir
        "$0" "$output_dir" --name "$name"
        DEPLOY_STATUS=$?

        if [ $DEPLOY_STATUS -ne 0 ]; then
            echo_error "Failed to deploy honeypot: $name"
            echo_error "Stopping deployment process"
            exit $DEPLOY_STATUS
        fi

        echo_info "Successfully deployed: $name"
    done

    echo "========================================================================"
    echo_info "All honeypots deployed successfully!"
    echo "========================================================================"
    exit 0
fi

# ============================================================
# SINGLE HONEYPOT DEPLOYMENT
# ============================================================

IDENTITY_DIR="$OUTPUT_DIR/identity"
FS_PICKLE="$OUTPUT_DIR/fs.pickle"
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
SERVER_TYPE="cx23"
SERVER_IMAGE="debian-13"
COWRIE_SSH_PORT="22"        # Cowrie listens on port 22
REAL_SSH_PORT="2222"        # Move real SSH to 2222

# Check if master config exists and read settings
ENABLE_REPORTING="false"
ENABLE_WEB_DASHBOARD="false"

# Tailscale configuration
TAILSCALE_AUTHKEY=""
TAILSCALE_USE_SSH="false"
TAILSCALE_NAME="cowrie-honeypot"
TAILSCALE_DOMAIN=""

# ============================================================
# CONFIGURATION READING
# ============================================================

echo_info "Reading configuration from master-config.toml..."

# Check that [[honeypots]] array exists
HAS_HONEYPOTS=$(has_honeypots_array "$MASTER_CONFIG")
CONFIG_JSON=""

if [ "$HAS_HONEYPOTS" != "true" ]; then
    echo_error "No [[honeypots]] array found in master-config.toml"
    echo_error "Please define at least one honeypot in the [[honeypots]] array"
    echo_error "See example-config.toml for examples"
    exit 1
fi

if [ -z "$HONEYPOT_NAME" ]; then
    echo_error "[[honeypots]] array found but no --name specified"
    echo_error "Use --name to specify which honeypot to deploy, or --all to deploy all"
    exit 1
fi

# Get specific honeypot's config
echo_info "Using [[honeypots]] array configuration for: $HONEYPOT_NAME"
CONFIG_JSON=$(get_honeypot_config "$MASTER_CONFIG" "$HONEYPOT_NAME")

if [ -z "$CONFIG_JSON" ]; then
    echo_error "Failed to read configuration for honeypot: $HONEYPOT_NAME"
    exit 1
fi

# Helper function to extract value from config JSON with fallback
get_config() {
    local key="$1"
    local default="$2"
    local value
    value=$(get_json_value "$CONFIG_JSON" ".$key")
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# Helper function to execute command if it starts with "op read" or similar
execute_if_command() {
    local value="$1"
    if echo "$value" | grep -q "^op read"; then
        eval "$value" 2>/dev/null || echo ""
    else
        echo "$value"
    fi
}

# Extract deployment configuration
SERVER_TYPE=$(get_config "server_type" "cx23")
SERVER_IMAGE=$(get_config "deployment_image" "debian-13")
SERVER_LOCATION=$(get_config "location" "")
HONEYPOT_HOSTNAME=$(get_config "hostname" "dmz-web01")

# SSH Keys - read from JSON array
SSH_KEYS_RAW=$(get_json_value "$CONFIG_JSON" ".ssh_keys")
if [ -z "$SSH_KEYS_RAW" ] || [ "$SSH_KEYS_RAW" = "null" ]; then
    echo_error "SSH keys not configured in master-config.toml"
    echo_error "Please add ssh_keys array to [shared.deployment] section"
    exit 1
fi

# Build array of SSH keys for hcloud command
SSH_KEYS=()
SSH_KEY_COUNT=$(echo "$SSH_KEYS_RAW" | jq 'length')
for ((i=0; i<SSH_KEY_COUNT; i++)); do
    KEY_NAME=$(echo "$SSH_KEYS_RAW" | jq -r ".[$i]")
    SSH_KEYS+=("$KEY_NAME")
done

if [ ${#SSH_KEYS[@]} -lt 1 ]; then
    echo_error "At least one SSH key is required in ssh_keys array"
    exit 1
fi

echo_info "Deployment config: $SERVER_TYPE, $SERVER_IMAGE, hostname=$HONEYPOT_HOSTNAME"

# Reporting configuration
ENABLE_REPORTING=$(get_config "enable_reporting" "false")
if [ "$ENABLE_REPORTING" = "true" ]; then
    echo_info "Reporting is enabled"
fi

# Tailscale configuration (REQUIRED in v2.1)
echo_info "Reading Tailscale configuration (required)..."

TAILSCALE_NAME=$(get_config "name" "cowrie-honeypot")
TAILSCALE_DOMAIN=$(get_config "tailscale_domain" "")
TAILSCALE_AUTHKEY=$(get_config "authkey" "")
TAILSCALE_USE_SSH=$(get_config "use_tailscale_ssh" "false")
TAILSCALE_AUTO_CLEANUP=$(get_config "auto_cleanup_old_devices" "false")
TAILSCALE_API_KEY=$(get_config "tailscale_api_key" "")

# Execute command if needed for authkey and api key
TAILSCALE_AUTHKEY=$(execute_if_command "$TAILSCALE_AUTHKEY")
TAILSCALE_API_KEY=$(execute_if_command "$TAILSCALE_API_KEY")

# Validate Tailscale configuration
validate_tailscale_config "$TAILSCALE_AUTHKEY" "$TAILSCALE_DOMAIN"
echo_info "Tailscale: $TAILSCALE_NAME.$TAILSCALE_DOMAIN"

# Cleanup old devices if enabled
if [ "$TAILSCALE_AUTO_CLEANUP" = "true" ]; then
    if [ -z "$TAILSCALE_API_KEY" ]; then
        echo_warn "auto_cleanup_old_devices is enabled but tailscale_api_key is not set"
        echo_warn "Skipping cleanup - device may be created as ${TAILSCALE_NAME}-1"
    else
        echo_info "Auto-cleanup enabled - checking for existing devices..."
        cleanup_tailscale_device "$TAILSCALE_NAME" "$TAILSCALE_DOMAIN" "$TAILSCALE_API_KEY"
    fi
fi

# API configuration
ENABLE_API=$(get_config "api_enabled" "false")
API_EXPOSE_VIA_TAILSCALE=$(get_config "api_expose_via_tailscale" "false")
API_TAILSCALE_HOSTNAME=$(get_config "tailscale_api_hostname" "$TAILSCALE_NAME")

if [ "$ENABLE_API" = "true" ]; then
    echo_info "Cowrie API is enabled"
    if [ "$API_EXPOSE_VIA_TAILSCALE" = "true" ]; then
        echo_info "API exposed via Tailscale as: $API_TAILSCALE_HOSTNAME.$TAILSCALE_DOMAIN"
    fi
fi

# Dashboard configuration
ENABLE_WEB_DASHBOARD=$(get_config "dashboard_enabled" "false")
DASHBOARD_MODE=$(get_config "dashboard_mode" "local")
DASHBOARD_API_URL=$(get_config "dashboard_api_url" "")
DASHBOARD_SOURCES_JSON="[]"

if [ "$ENABLE_WEB_DASHBOARD" = "true" ]; then
    echo_info "Web dashboard is enabled (mode: $DASHBOARD_MODE)"

    # Smart dashboard source detection
    if [ "$DASHBOARD_MODE" = "multi" ]; then
        echo_info "Building multi-source dashboard configuration..."

        # Get dashboard_sources array from config
        DASHBOARD_SOURCES_RAW=$(get_json_value "$CONFIG_JSON" ".dashboard_sources")

        if [ -n "$DASHBOARD_SOURCES_RAW" ] && [ "$DASHBOARD_SOURCES_RAW" != "null" ]; then
            # Build sources JSON with smart local/remote detection
            SOURCES_ARRAY="[]"
            SOURCE_COUNT=$(echo "$DASHBOARD_SOURCES_RAW" | jq 'length')

            for ((i=0; i<SOURCE_COUNT; i++)); do
                SOURCE_NAME=$(echo "$DASHBOARD_SOURCES_RAW" | jq -r ".[$i]")

                # Get location for this honeypot (lookup from master config)
                SOURCE_HP_CONFIG=$(get_honeypot_config "$MASTER_CONFIG" "$SOURCE_NAME" 2>/dev/null || echo "{}")
                SOURCE_LOCATION=$(echo "$SOURCE_HP_CONFIG" | jq -r '.location // empty' 2>/dev/null || echo "")

                if [ "$SOURCE_NAME" = "$TAILSCALE_NAME" ]; then
                    # This is the current honeypot - use local mode
                    # Local mode still needs api_base_url for /api/system-info endpoint
                    SOURCE_JSON=$(cat <<EOF
{
  "name": "$SOURCE_NAME",
  "type": "cowrie-ssh",
  "api_base_url": "http://localhost:8000",
  "mode": "local",
  "location": "$SOURCE_LOCATION",
  "enabled": true
}
EOF
)
                else
                    # Different honeypot - use remote mode with API
                    API_URL="https://$SOURCE_NAME.$TAILSCALE_DOMAIN"
                    SOURCE_JSON=$(cat <<EOF
{
  "name": "$SOURCE_NAME",
  "type": "cowrie-ssh",
  "api_base_url": "$API_URL",
  "mode": "remote",
  "location": "$SOURCE_LOCATION",
  "enabled": true
}
EOF
)
                fi

                # Append to sources array
                SOURCES_ARRAY=$(echo "$SOURCES_ARRAY" | jq ". += [$SOURCE_JSON]")
            done

            DASHBOARD_SOURCES_JSON="$SOURCES_ARRAY"
            echo_info "Configured $(echo "$SOURCES_ARRAY" | jq 'length') dashboard source(s)"
            echo_info "Smart detection: local mode for self, remote mode for others"
        else
            echo_warn "Dashboard multi-source mode enabled but no sources configured"
        fi
    elif [ "$DASHBOARD_MODE" = "remote" ]; then
        if [ -n "$DASHBOARD_API_URL" ]; then
            echo_info "Dashboard API URL: $DASHBOARD_API_URL"
        fi
    fi
fi

# Data sharing configuration
ABUSEIPDB_ENABLED=$(get_config "abuseipdb_enabled" "false")
ABUSEIPDB_API_KEY=""
ABUSEIPDB_TOLERANCE_ATTEMPTS=$(get_config "abuseipdb_tolerance_attempts" "10")
ABUSEIPDB_TOLERANCE_WINDOW=$(get_config "abuseipdb_tolerance_window" "120")
ABUSEIPDB_REREPORT_AFTER=$(get_config "abuseipdb_rereport_after" "24")

if [ "$ABUSEIPDB_ENABLED" = "true" ]; then
    ABUSEIPDB_API_KEY=$(get_config "abuseipdb_api_key" "")
    ABUSEIPDB_API_KEY=$(execute_if_command "$ABUSEIPDB_API_KEY")
    echo_info "AbuseIPDB reporting enabled"
fi

DSHIELD_ENABLED=$(get_config "dshield_enabled" "false")
DSHIELD_USERID=""
DSHIELD_AUTH_KEY=""
DSHIELD_BATCH_SIZE=$(get_config "dshield_batch_size" "100")

if [ "$DSHIELD_ENABLED" = "true" ]; then
    DSHIELD_USERID=$(get_config "dshield_userid" "")
    DSHIELD_AUTH_KEY=$(get_config "dshield_auth_key" "")
    DSHIELD_AUTH_KEY=$(execute_if_command "$DSHIELD_AUTH_KEY")
    echo_info "DShield data sharing enabled"
fi

echo_info "Configuration loaded successfully"

SERVER_NAME="cowrie-honeypot-$(date +%s)"

echo_info "Deploying Cowrie honeypot from: $OUTPUT_DIR"

# ============================================================
# STEP 1 — Create server
# ============================================================

echo_info "Creating Hetzner server: $SERVER_NAME"
if [ -n "$SERVER_LOCATION" ]; then
    echo_info "Location: $SERVER_LOCATION"
fi

# Build hcloud command with all SSH keys using array
HCLOUD_CMD=(hcloud server create --name "$SERVER_NAME" --type "$SERVER_TYPE" --image "$SERVER_IMAGE")

# Add location if specified
if [ -n "$SERVER_LOCATION" ]; then
    HCLOUD_CMD+=(--location "$SERVER_LOCATION")
fi

for key in "${SSH_KEYS[@]}"; do
    HCLOUD_CMD+=(--ssh-key "$key")
done
HCLOUD_CMD+=(--output json)

# Execute server creation
SERVER_ID=$("${HCLOUD_CMD[@]}" 2>/dev/null | jq -r '.server.id')

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
echo_info "SSH confirmed on port $REAL_SSH_PORT."

# ============================================================
# STEP 3.5 — Set up Tailscale (REQUIRED)
# ============================================================

echo_info "Setting up Tailscale for secure management access..."

# shellcheck disable=SC2087
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << TAILSCALEEOF
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

# ============================================================
# STEP 4 — Install Docker
# ============================================================

echo_info "Installing Docker..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    ca-certificates \
    curl \
    gnupg \
    git \
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
# STEP 6 — Clone Git Repository
# ============================================================

echo_info "Cloning cowrie-deploy-toolkit repository..."

# Clone repository to /opt/cowrie
# This provides all version-controlled files: scripts, configs, docker files, etc.
# shellcheck disable=SC2087
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << EOF
# Clone repository
cd /opt
if [ -d "cowrie" ]; then
    echo "[remote] WARNING: /opt/cowrie already exists, removing..."
    rm -rf cowrie
fi

git clone "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" cowrie
cd cowrie

echo "[remote] Git commit: $(git rev-parse --short HEAD)"
EOF

echo_info "Repository cloned successfully"

# ============================================================
# STEP 6.5 — Install uv and Python dependencies
# ============================================================

echo_info "Installing uv and Python dependencies..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'UVEOF'
# Install uv
if ! command -v uv &> /dev/null; then
    echo "[remote] Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
    echo "[remote] uv installed successfully"
else
    echo "[remote] uv already installed"
fi

# Sync Python dependencies (pyproject.toml is now available from git)
cd /opt/cowrie || exit
export PATH="$HOME/.local/bin:$PATH"
echo "[remote] Syncing Python dependencies..."
uv sync --quiet > /dev/null 2>&1
echo "[remote] Python environment ready"
UVEOF

echo_info "uv and Python dependencies installed"

# ============================================================
# STEP 6.75 — Create deployment artifact directories
# ============================================================

echo_info "Creating deployment artifact directories..."

# Create directories for deployment-specific files (not in git)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
# Create artifact directories (gitignored, for scp'd files)
mkdir -p /opt/cowrie/share/cowrie/{contents,txtcmds}
mkdir -p /opt/cowrie/identity
mkdir -p /opt/cowrie/etc
echo "[remote] Artifact directories created"
EOF

echo_info "Artifact directories created"

# ============================================================
# STEP 7 — Upload template server artifacts
# ============================================================

echo_info "Uploading template server artifacts..."

# Create deployment config file with honeypot metadata
echo_info "Creating deployment config file..."
# shellcheck disable=SC2087
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << DEPLOYEOF
cat > /opt/cowrie/deployment.conf << 'CONFEOF'
# Cowrie Honeypot Deployment Configuration
# This file is auto-generated during deployment
# DO NOT EDIT - will be overwritten on updates

HONEYPOT_HOSTNAME="$HONEYPOT_HOSTNAME"
SERVER_IP="$SERVER_IP"
DEPLOYMENT_DATE="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
CONFEOF
DEPLOYEOF

# Upload fs.pickle to share directory (bind mounted)
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    "$FS_PICKLE" "root@$SERVER_IP:/opt/cowrie/share/cowrie/fs.pickle" > /dev/null

# Generate and upload cmdoutput.json for realistic process list
if [ -f "$IDENTITY_DIR/ps.txt" ]; then
    echo_info "Generating cmdoutput.json from ps.txt..."

    # Generate cmdoutput.json using the converter script
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

    # SECURITY: Create unpredictable remote temp file to prevent symlink attacks
    REMOTE_CONTENTS_TAR=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mktemp /tmp/cowrie.XXXXXXXXXX.tar.gz")

    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        "$CONTENTS_TAR" "root@$SERVER_IP:$REMOTE_CONTENTS_TAR" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/share/cowrie/contents && tar xzf $REMOTE_CONTENTS_TAR && rm -f $REMOTE_CONTENTS_TAR"

    FILE_COUNT=$(find "$CONTENTS_DIR" -type f | wc -l | tr -d ' ')
    echo_info "Uploaded $FILE_COUNT files with real content"
else
    echo_warn " Warning: No contents directory found, files will have no content"
    exit 1
fi

# Upload txtcmds directory for real command output
CONTENTS_DIR="$OUTPUT_DIR/txtcmds"
if [ -d "$CONTENTS_DIR" ] && [ "$(ls -A "$CONTENTS_DIR" 2>/dev/null)" ]; then
    echo_info "Uploading txtcmds contents..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mkdir -p /opt/cowrie/share/cowrie/txtcmds"

    # Upload txtcmds as tarball for efficiency (--no-xattrs to avoid macOS extended attributes)
    TXTCMDS_TAR=$(create_temp_file ".tar.gz")
    tar --no-xattrs -czf "$TXTCMDS_TAR" -C "$CONTENTS_DIR" . 2>/dev/null

    # SECURITY: Create unpredictable remote temp file to prevent symlink attacks
    REMOTE_TXTCMDS_TAR=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mktemp /tmp/cowrie.XXXXXXXXXX.tar.gz")

    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        "$TXTCMDS_TAR" "root@$SERVER_IP:$REMOTE_TXTCMDS_TAR" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/share/cowrie/txtcmds && tar xzf $REMOTE_TXTCMDS_TAR && rm -f $REMOTE_TXTCMDS_TAR"

    FILE_COUNT=$(find "$CONTENTS_DIR" -type f | wc -l | tr -d ' ')
    echo_info "Uploaded $FILE_COUNT files with txtcmds content"
else
    echo_warn " Warning: No txtcmds directory found"
    exit 1
fi

# Upload identity directory for SSH configuration and system info
if [ -d "$IDENTITY_DIR" ] && [ "$(ls -A "$IDENTITY_DIR" 2>/dev/null)" ]; then
    echo_info "Uploading identity data for web dashboard..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mkdir -p /opt/cowrie/identity"

    # Upload identity as tarball for efficiency (--no-xattrs to avoid macOS extended attributes)
    IDENTITY_TAR=$(create_temp_file ".tar.gz")
    tar --no-xattrs -czf "$IDENTITY_TAR" -C "$IDENTITY_DIR" . 2>/dev/null

    # SECURITY: Create unpredictable remote temp file to prevent symlink attacks
    REMOTE_IDENTITY_TAR=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "mktemp /tmp/cowrie.XXXXXXXXXX.tar.gz")

    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
        "$IDENTITY_TAR" "root@$SERVER_IP:$REMOTE_IDENTITY_TAR" > /dev/null
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
        "cd /opt/cowrie/identity && tar xzf $REMOTE_IDENTITY_TAR && rm -f $REMOTE_IDENTITY_TAR"

    FILE_COUNT=$(find "$IDENTITY_DIR" -type f | wc -l | tr -d ' ')
    echo_info "Uploaded $FILE_COUNT identity files (SSH config, kernel info, etc.)"
else
    echo_warn " Warning: No identity directory found, web dashboard system info will be limited"
    exit 1
fi

# ============================================================
# STEP 6.5 — Upload Custom Cowrie Build Context
# ============================================================

echo_info "Uploading custom Cowrie context..."

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

# Set correct permissions for userdb.txt (readable by all)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" \
    "root@$SERVER_IP" "chmod 644 /opt/cowrie/etc/userdb.txt"

# ============================================================
# STEP 7 — Generate cowrie.cfg
# ============================================================

echo_info "Generating cowrie.cfg with identity data..."

# SECURITY: Use mktemp for config file (prevents symlink attacks)
COWRIE_CFG_TMP=$(mktemp)

# Read identity data
KERNEL_VERSION=$(cat "$IDENTITY_DIR/kernel.txt" | awk '{print $3}')
KERNEL_ARCH=$(cat "$IDENTITY_DIR/kernel.txt" | sed -E "s/.*) //" | awk '{print $1}')
HOSTNAME=$(cat "$IDENTITY_DIR/hostname" | tr -d '\n')
SSH_BANNER=$(cat "$IDENTITY_DIR/ssh-banner.txt" | sed 's/^SSH-2.0-//' | tr -d '\n')

# Extract kernel build string from proc-version (everything after last ') ')
KERNEL_BUILD=$(cat "$IDENTITY_DIR/proc-version" | sed -n 's/.*) \(#1 SMP.*\)$/\1/p')

# Read SSH cipher configuration if available and filter against Cowrie's supported algorithms
# Based on: https://github.com/cowrie/cowrie/blob/main/src/cowrie/ssh/factory.py

# Cowrie supported ciphers (removed deprecated: 3des-cbc, blowfish-cbc, cast128-cbc)
# These are no longer supported in modern cryptography library versions
COWRIE_CIPHERS="aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc"
# Cowrie supported MACs
COWRIE_MACS="hmac-sha2-512,hmac-sha2-384,hmac-sha2-256,hmac-sha1,hmac-md5"

SSH_CIPHERS=""
SSH_MACS=""
SSH_KEX=""

if [ -f "$IDENTITY_DIR/ssh-ciphers.txt" ]; then
    # Filter captured ciphers to only include Cowrie-supported ones
    CAPTURED_CIPHERS=$(cat "$IDENTITY_DIR/ssh-ciphers.txt")
    FILTERED_CIPHERS=""

    # Convert Cowrie ciphers to array for lookup
    IFS=',' read -ra COWRIE_CIPHER_ARRAY <<< "$COWRIE_CIPHERS"

    # Filter captured ciphers preserving source server order
    while IFS= read -r cipher; do
        for supported in "${COWRIE_CIPHER_ARRAY[@]}"; do
            if [ "$cipher" = "$supported" ]; then
                if [ -z "$FILTERED_CIPHERS" ]; then
                    FILTERED_CIPHERS="$cipher"
                else
                    FILTERED_CIPHERS="$FILTERED_CIPHERS,$cipher"
                fi
                break
            fi
        done
    done <<< "$CAPTURED_CIPHERS"

    if [ -n "$FILTERED_CIPHERS" ]; then
        SSH_CIPHERS="$FILTERED_CIPHERS"
        echo_info "Loaded SSH ciphers from identity data (filtered to Cowrie-supported)"
    fi
fi

if [ -f "$IDENTITY_DIR/ssh-mac.txt" ]; then
    # Filter captured MACs to only include Cowrie-supported ones
    CAPTURED_MACS=$(cat "$IDENTITY_DIR/ssh-mac.txt")
    FILTERED_MACS=""

    # Convert Cowrie MACs to array for lookup
    IFS=',' read -ra COWRIE_MAC_ARRAY <<< "$COWRIE_MACS"

    # Filter captured MACs preserving source server order
    while IFS= read -r mac; do
        for supported in "${COWRIE_MAC_ARRAY[@]}"; do
            if [ "$mac" = "$supported" ]; then
                if [ -z "$FILTERED_MACS" ]; then
                    FILTERED_MACS="$mac"
                else
                    FILTERED_MACS="$FILTERED_MACS,$mac"
                fi
                break
            fi
        done
    done <<< "$CAPTURED_MACS"

    if [ -n "$FILTERED_MACS" ]; then
        SSH_MACS="$FILTERED_MACS"
        echo_info "Loaded SSH MACs from identity data (filtered to Cowrie-supported)"
    fi
fi

if [ -f "$IDENTITY_DIR/ssh-kex.txt" ]; then
    # For KEX algorithms, we'll include all captured ones since Cowrie uses Twisted's defaults
    # Cowrie will ignore any KEX algorithms it doesn't support
    SSH_KEX=$(cat "$IDENTITY_DIR/ssh-kex.txt" | tr '\n' ',' | sed 's/,$//')
    echo_info "Loaded SSH key exchange algorithms from identity data"
fi

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
cat > "$COWRIE_CFG_TMP" << EOFCFG
[honeypot]
hostname = $HOSTNAME
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty
logtype = rotating
# For https://github.com/cowrie/cowrie/blob/main/src/cowrie/commands/nc.py
out_addr = $SERVER_IP
auth_class = IPUserDB
userdb_path = var/lib/cowrie/userip.db
minimum_password_len = 4

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
EOFCFG

# Add SSH cipher configuration if captured from source server
if [ -n "$SSH_CIPHERS" ]; then
    echo "ciphers = $SSH_CIPHERS" >> "$COWRIE_CFG_TMP"
fi
if [ -n "$SSH_MACS" ]; then
    echo "macs = $SSH_MACS" >> "$COWRIE_CFG_TMP"
fi
if [ -n "$SSH_KEX" ]; then
    echo "key_exchange = $SSH_KEX" >> "$COWRIE_CFG_TMP"
fi

cat >> "$COWRIE_CFG_TMP" << EOFCFG

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log

[output_sqlite]
enabled = true
db_file = var/lib/cowrie/cowrie.db
EOFCFG

# Add VirusTotal configuration if API key is available
if [ -n "$VT_API_KEY" ]; then
    cat >> "$COWRIE_CFG_TMP" << EOFVT

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

# Add AbuseIPDB configuration if enabled
if [ "$ABUSEIPDB_ENABLED" = "true" ] && [ -n "$ABUSEIPDB_API_KEY" ]; then
    cat >> "$COWRIE_CFG_TMP" << EOFABUSEIPDB

[output_abuseipdb]
enabled = true
api_key = $ABUSEIPDB_API_KEY
tolerance_attempts = $ABUSEIPDB_TOLERANCE_ATTEMPTS
tolerance_window = $ABUSEIPDB_TOLERANCE_WINDOW
rereport_after = $ABUSEIPDB_REREPORT_AFTER
dump_path = var/lib/cowrie/abuseipdb
EOFABUSEIPDB
    echo_info "AbuseIPDB reporting and threat intelligence enabled in cowrie.cfg"
fi

# Add DShield configuration if enabled
if [ "$DSHIELD_ENABLED" = "true" ] && [ -n "$DSHIELD_USERID" ] && [ -n "$DSHIELD_AUTH_KEY" ]; then
    cat >> "$COWRIE_CFG_TMP" << EOFDSHIELD

[output_dshield]
enabled = true
userid = $DSHIELD_USERID
auth_key = $DSHIELD_AUTH_KEY
batch_size = $DSHIELD_BATCH_SIZE
EOFDSHIELD
    echo_info "DShield data sharing enabled in cowrie.cfg"
fi

# Upload cowrie.cfg
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
    "$COWRIE_CFG_TMP" "root@$SERVER_IP:/opt/cowrie/etc/cowrie.cfg" > /dev/null

# Set correct permissions for cowrie.cfg (readable by all)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" \
    "root@$SERVER_IP" "chmod 644 /opt/cowrie/etc/cowrie.cfg"

rm -f "$COWRIE_CFG_TMP"

echo_info "Configuration uploaded."

# ============================================================
# STEP 8 — Deploy Cowrie container
# ============================================================

echo_info "Create docker-compose.yml..."

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
# Create docker-compose.yml to pull pre-built images
cat > /opt/cowrie/docker-compose.yml << 'DOCKEREOF'
services:
  cowrie:
    image: "ghcr.io/reuteras/cowrie:latest"
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var
      - /opt/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - /opt/cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
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
  cowrie-var:
    name: cowrie-var
    external: true
DOCKEREOF

echo "[remote] Pulling pre-built Cowrie image from GitHub Container Registry..."
cd /opt/cowrie
if ! docker compose pull > /dev/null 2>&1 ; then
  echo "[remote] ERROR: Failed to pull Cowrie image"
  exit 1
fi

echo "[remote] Extracting metadata.json from pulled image..."
docker run --rm --entrypoint python3 ghcr.io/reuteras/cowrie:latest -c "print(open('/cowrie/cowrie-git/metadata.json').read(), end='')" > /opt/cowrie/metadata.json

# Create directory structure and SQLite database with correct ownership
echo "[remote] Creating directory structure and SQLite database in cowrie-var..."
docker run --rm -i \
  -v cowrie-var:/var \
  alpine sh -c '
    # Install packages
    apk add --no-cache sqlite curl > /dev/null 2>&1 &&
    # Create directories with correct ownership immediately
    mkdir -p /var/lib/cowrie/tty \
             /var/lib/cowrie/downloads \
             /var/log/cowrie &&
    # Create database
    curl -s https://raw.githubusercontent.com/cowrie/cowrie/refs/heads/main/docs/sql/sqlite3.sql | sqlite3 /var/lib/cowrie/cowrie.db &&
    chown -R 999:999 /var/lib/cowrie /var/log/cowrie &&
    echo [remote] Created cowrie.db
  '
EOF

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'EOF'
# Start Cowrie with custom configuration
echo "[remote] Starting Cowrie with custom configuration..."
cd /opt/cowrie
docker compose up -d 2>&1

# Wait for container to start
sleep 5

# Show status
docker compose ps
EOF

echo_info "Cowrie container started."

# ============================================================
# STEP 9 — Verify honeypot status
# ============================================================

echo_info "Verifying honeypot container status..."
sleep 5

# Check container status instead of making a test connection
# (nc test creates noise in logs)
if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
    "cd /opt/cowrie && docker compose ps | grep -q 'cowrie:latest'" ; then
    echo_info "Honeypot container is running!"
else
    echo_warn " Warning: Honeypot container may not be running correctly"
fi

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
    SERVER_REPORT_ENV=$(create_temp_file ".env")
    if command -v uv &> /dev/null; then
        uv run --quiet scripts/process-config.py "$MASTER_CONFIG" > "$SERVER_REPORT_ENV"
    else
        echo_warn " Error: uv not found. Cannot process config."
        exit 1
    fi

    if [ -f "$SERVER_REPORT_ENV" ]; then
        # Upload reporting config (scripts/ and pyproject.toml already from git)
        echo_info "Uploading reporting configuration..."
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P "$REAL_SSH_PORT" \
            "$SERVER_REPORT_ENV" "root@$SERVER_IP:/opt/cowrie/" > /dev/null 2>&1

        # Move config to correct location (get basename of temp file for remote path)
        REPORT_ENV_BASENAME=$(basename "$SERVER_REPORT_ENV")
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" \
            "mv /opt/cowrie/$REPORT_ENV_BASENAME /opt/cowrie/etc/report.env && chmod 600 /opt/cowrie/etc/report.env"

        # Run setup-reporting.sh on the server
        echo_info "Running setup-reporting.sh on server..."
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'REPORTEOF'
cd /opt/cowrie
chmod +x scripts/setup-reporting.sh scripts/daily-report.py scripts/process-config.py
./scripts/setup-reporting.sh
REPORTEOF

        echo_info "Reporting configured successfully"
    else
        echo_warn " Error: Failed to process config. Skipping automated reporting setup."
        exit 1
    fi
else
    echo_info "Reporting disabled or master-config.toml not found, skipping reporting setup"
fi

# ============================================================
# STEP 12.5 — Set up automatic update timer
# ============================================================

echo_info "Setting up automatic update timer..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'UPDATETIMEREOF'
# Install systemd service
cat > /etc/systemd/system/cowrie-update.service << 'SERVICE'
[Unit]
Description=Cowrie Honeypot Update Service
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/cowrie
ExecStart=/bin/bash /opt/cowrie/scripts/update-agent.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cowrie-update

# Security hardening
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
SERVICE

# Install systemd timer
cat > /etc/systemd/system/cowrie-update.timer << 'TIMER'
[Unit]
Description=Cowrie Honeypot Daily Update Timer
Requires=cowrie-update.service

[Timer]
# Run daily at 3:00 AM local time
OnCalendar=daily
# Add randomized delay of 0-30 minutes to avoid all honeypots updating simultaneously
RandomizedDelaySec=30min
# Ensure timer runs if system was down during scheduled time
Persistent=true

[Install]
WantedBy=timers.target
TIMER

# Reload systemd and enable timer
systemctl daemon-reload
systemctl enable cowrie-update.timer
systemctl start cowrie-update.timer

echo "[*] Automatic update timer installed and enabled"
echo "[*] Updates will run daily at 03:00 (+random 0-30min)"
systemctl status cowrie-update.timer --no-pager

UPDATETIMEREOF

echo_info "Automatic update timer configured successfully"


# ============================================================
# STEP 13.o — Set up Cowrie API first
# ============================================================

if [ "$ENABLE_API" = "true" ]; then
    echo_info "Setting up Cowrie API for multi-host dashboard deployment..."

    # API service files and docker-compose.api.yml already from git (STEP 6)
    # Deploy API container
    echo_info "Building and starting Cowrie API container..."
    # shellcheck disable=SC2087
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << APIEOF
cd /opt/cowrie

# Debug: Show values that will be used for replacement
echo "[remote] SERVER_IP: $SERVER_IP"
echo "[remote] HONEYPOT_HOSTNAME: $HONEYPOT_HOSTNAME"

# Replace placeholders in docker-compose.api.yml with actual values
sed -i "s|SERVER_IP_PLACEHOLDER|$SERVER_IP|g" /opt/cowrie/docker-compose.api.yml
sed -i "s|HONEYPOT_HOSTNAME_PLACEHOLDER|$HONEYPOT_HOSTNAME|g" /opt/cowrie/docker-compose.api.yml
sed -i "s|ghcr.io/reuteras/cowrie-api:latest|ghcr.io/${REPO_OWNER}/cowrie-api:latest|g" /opt/cowrie/docker-compose.api.yml

# No need to make names unique - only one honeypot per server
# docker-compose.api.yml shares volumes/networks with docker-compose.yml

# Debug: Verify replacement worked
echo "[remote] Verifying environment variable replacement..."
grep -E "SERVER_IP=|HONEYPOT_HOSTNAME=" /opt/cowrie/docker-compose.api.yml | grep -v PLACEHOLDER || echo "[remote] WARNING: Replacement may have failed"

# Pull API image
if ! docker compose -f docker-compose.api.yml pull cowrie-api 2>&1; then
    echo "[remote] ERROR: Failed to pull API image"
    exit 1
fi
echo "[remote] API image pulled successfully"

# Expose via Tailscale if configured
# IMPORTANT: Don't expose API via Tailscale if dashboard is running on this server
# because dashboard has its own /api/* endpoints that would conflict
if [ "$API_EXPOSE_VIA_TAILSCALE" = "true" ] && [ "$ENABLE_WEB_DASHBOARD" != "true" ] && command -v tailscale &> /dev/null; then
    echo "[remote] Configuring Tailscale Serve for API..."
    echo "[remote] (Dashboard not running on this server, safe to expose API)"

    # Configure Tailscale Serve for API on port 443
    tailscale serve --https=443 --bg localhost:8000 > /dev/null 2>&1

    # Add @reboot cron job to ensure Tailscale Serve persists after reboot
    # SECURITY: Use mktemp for unpredictable filename (prevents symlink attacks)
    CRON_TMP=\$(mktemp)
    # Remove old cron entry
    (crontab -l 2>/dev/null | grep -v "tailscale serve.*8000") > "\$CRON_TMP" || true
    # Add new cron entry
    echo "@reboot sleep 30 && /usr/bin/tailscale serve --https=443 --bg localhost:8000 > /dev/null 2>&1" >> "\$CRON_TMP"
    crontab "\$CRON_TMP"
    rm -f "\$CRON_TMP"

    echo "[remote] API available at: https://${API_TAILSCALE_HOSTNAME}.${TAILSCALE_DOMAIN}"
elif [ "$API_EXPOSE_VIA_TAILSCALE" = "true" ] && [ "$ENABLE_WEB_DASHBOARD" = "true" ]; then
    echo "[remote] Skipping Tailscale Serve for API (dashboard running on this server)"
    echo "[remote] Dashboard will access API via http://cowrie-api:8000 internally"
fi
APIEOF

else
    echo_info "Cowrie API disabled, skipping setup"
fi
# ============================================================
# STEP 13 — Set up web dashboard (if enabled)
# ============================================================

if [ "$ENABLE_WEB_DASHBOARD" = "true" ]; then
    echo_info "Setting up SSH Session Playback Web Dashboard..."

    # Build WEB_BASE_URL from Tailscale settings (always available in v2.1)
    WEB_BASE_URL="https://${TAILSCALE_NAME}.${TAILSCALE_DOMAIN}"
    echo_info "Web dashboard base URL: $WEB_BASE_URL"

    # Web service files already from git (STEP 6)
    # Set up web dashboard on server
    # shellcheck disable=SC2087
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << WEBEOF
# Source common functions (for create_temp_file)
source /opt/cowrie/scripts/common.sh

# Ensure GeoIP directory exists (web dashboard needs it even if reporting is disabled)
mkdir -p /var/lib/GeoIP

# Create web dashboard docker-compose file
# Use quoted heredoc to prevent variable expansion, then do manual substitution
cat > /opt/cowrie/docker-compose.yml << 'DOCKEREOF'
services:
  cowrie:
    image: "ghcr.io/reuteras/cowrie:latest"
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var
      - /opt/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - /opt/cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
      - /opt/cowrie/share:/cowrie/cowrie-git/share:ro
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
    image: "ghcr.io/reuteras/cowrie-web:latest"
    container_name: cowrie-web
    restart: unless-stopped
    ports:
      - "127.0.0.1:5000:5000"
    volumes:
      - cowrie-var:/cowrie-data:ro
      - /opt/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - /opt/cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
      - /opt/cowrie/share:/cowrie/cowrie-git/share:ro
      - /opt/cowrie/metadata.json:/cowrie-metadata/metadata.json:ro
      - /var/lib/GeoIP:/geoip:ro
      - /opt/cowrie/var:/yara-cache:ro
      - /opt/cowrie/identity:/identity:ro
      - /opt/cowrie/var:/canary-webhooks:rw
    environment:
      - COWRIE_LOG_PATH=/cowrie-data/log/cowrie/cowrie.json
      - COWRIE_TTY_PATH=/cowrie-data/lib/cowrie/tty
      - COWRIE_DOWNLOAD_PATH=/cowrie-data/lib/cowrie/downloads
      - IDENTITY_PATH=/identity
      - GEOIP_DB_PATH=/geoip/GeoLite2-City.mmdb
      - GEOIP_ASN_PATH=/geoip/GeoLite2-ASN.mmdb
      - YARA_CACHE_DB_PATH=/yara-cache/yara-cache.db
      - COWRIE_METADATA_PATH=/cowrie-metadata/metadata.json
      - BASE_URL=WEB_BASE_URL_PLACEHOLDER
      - VIRUSTOTAL_API_KEY=VT_API_KEY_PLACEHOLDER
      - SERVER_IP=SERVER_IP_PLACEHOLDER
      - HONEYPOT_HOSTNAME=HONEYPOT_HOSTNAME_PLACEHOLDER
      - CANARY_WEBHOOK_DB_PATH=/canary-webhooks/canary-webhooks.db
      - DASHBOARD_MODE=DASHBOARD_MODE_PLACEHOLDER
      - DASHBOARD_API_URL=DASHBOARD_API_URL_PLACEHOLDER
      - DASHBOARD_SOURCES=DASHBOARD_SOURCES_PLACEHOLDER
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
  cowrie-var:
    name: cowrie-var
    external: true

networks:
  cowrie-internal:
    name: cowrie-internal
    driver: bridge
DOCKEREOF

# Replace placeholders with actual values using sed on the remote server
sed -i "s|WEB_BASE_URL_PLACEHOLDER|$WEB_BASE_URL|g" /opt/cowrie/docker-compose.yml
sed -i "s|VT_API_KEY_PLACEHOLDER|$VT_API_KEY|g" /opt/cowrie/docker-compose.yml
sed -i "s|SERVER_IP_PLACEHOLDER|$SERVER_IP|g" /opt/cowrie/docker-compose.yml
sed -i "s|HONEYPOT_HOSTNAME_PLACEHOLDER|$HONEYPOT_HOSTNAME|g" /opt/cowrie/docker-compose.yml
sed -i "s|DASHBOARD_MODE_PLACEHOLDER|$DASHBOARD_MODE|g" /opt/cowrie/docker-compose.yml
sed -i "s|DASHBOARD_API_URL_PLACEHOLDER|$DASHBOARD_API_URL|g" /opt/cowrie/docker-compose.yml
sed -i "s|ghcr.io/reuteras/cowrie:latest|ghcr.io/${REPO_OWNER}/cowrie:latest|g" /opt/cowrie/docker-compose.yml
sed -i "s|ghcr.io/reuteras/cowrie-web:latest|ghcr.io/${REPO_OWNER}/cowrie-web:latest|g" /opt/cowrie/docker-compose.yml

# Write DASHBOARD_SOURCES_JSON to temp file to avoid quoting issues
DASHBOARD_SOURCES_TMP=\$(create_temp_file ".json")
cat > "\$DASHBOARD_SOURCES_TMP" << SOURCES_EOF
$DASHBOARD_SOURCES_JSON
SOURCES_EOF

# Compact JSON using jq to remove all extra whitespace
SOURCES_CONTENT=\$(jq -c '.' "\$DASHBOARD_SOURCES_TMP" 2>/dev/null || cat "\$DASHBOARD_SOURCES_TMP" | tr -d '\\n')

# Replace DASHBOARD_SOURCES using awk
awk -v sources="\$SOURCES_CONTENT" '{gsub(/DASHBOARD_SOURCES_PLACEHOLDER/, sources)}1' /opt/cowrie/docker-compose.yml > /opt/cowrie/docker-compose.yml.tmp
mv /opt/cowrie/docker-compose.yml.tmp /opt/cowrie/docker-compose.yml

# Pull and start web service
cd /opt/cowrie
echo "[remote] Pulling web dashboard image from GitHub Container Registry..."
DOCKER_PULL_WEB_LOG=\$(mktemp /tmp/cowrie.XXXXXXXXXX.log)
if ! docker compose pull > /dev/null 2>&1 ; then
  echo "[remote] ERROR: Failed to pull web dashboard image"
  exit 1
fi

echo "[remote] Starting services..."
# Clean up any existing containers (proper order: compose down first, then force remove)
echo "[remote] Cleaning up any existing Cowrie deployments..."

# First, try docker compose down (proper cleanup)
if [ "$ENABLE_API" = "true" ] && [ -f docker-compose.api.yml ]; then
  docker compose -f docker-compose.yml -f docker-compose.api.yml down --remove-orphans 2>/dev/null || true
else
  docker compose down --remove-orphans 2>/dev/null || true
fi

# Then force remove any stubborn containers
docker rm -f cowrie cowrie-web cowrie-api 2>/dev/null || true

# Include API compose file if API is enabled to avoid network conflicts
if [ "$ENABLE_API" = "true" ] && [ -f docker-compose.api.yml ]; then
  echo "[remote] API is enabled, including docker-compose.api.yml"
  if ! docker compose -f docker-compose.yml -f docker-compose.api.yml up -d 2>&1; then
    echo "[remote] ERROR: Failed to start services. Checking status..."
    docker compose -f docker-compose.yml -f docker-compose.api.yml ps
    docker compose -f docker-compose.yml -f docker-compose.api.yml logs --tail=50
    exit 1
  fi
else
  if ! docker compose up -d 2>&1; then
    echo "[remote] ERROR: Failed to start services. Checking status..."
    docker compose ps
    docker compose logs --tail=50
    exit 1
  fi
fi

# Configure Tailscale Serve if Tailscale is enabled
if command -v tailscale &> /dev/null; then
    echo "[remote] Configuring Tailscale Serve for web dashboard..."

    # Check if API will also be exposed via Tailscale (requires path-based routing)
    if [ "$ENABLE_API" = "true" ] && [ "$API_EXPOSE_VIA_TAILSCALE" = "true" ]; then
        echo "[remote] API will also be exposed - using path-based routing"
        echo "[remote] Dashboard: / -> port 5000, API: /api -> port 8000"

        # Configure dashboard on root path
        tailscale serve --https=443 --bg localhost:5000 > /dev/null 2>&1

        # Configure API on /api path
        tailscale serve --https=443 --set-path=/api --bg localhost:8000 > /dev/null 2>&1

        # Add @reboot cron jobs (path-based routing for both dashboard and API)
        # Sleep 30 to ensure Tailscale is ready (35 for API to ensure dashboard is up first)
        # SECURITY: Use mktemp for unpredictable filename (prevents symlink attacks)
        CRON_TMP=\$(mktemp)
        # Remove old cron entries for these services
        (crontab -l 2>/dev/null | grep -v "tailscale serve.*5000" | grep -v "tailscale serve.*8000") > "\$CRON_TMP" || true
        # Add new cron entries
        echo "@reboot sleep 30 && /usr/bin/tailscale serve --https=443 --bg localhost:5000 > /dev/null 2>&1" >> "\$CRON_TMP"
        echo "@reboot sleep 35 && /usr/bin/tailscale serve --https=443 --set-path=/api --bg localhost:8000 > /dev/null 2>&1" >> "\$CRON_TMP"
        crontab "\$CRON_TMP"
        rm -f "\$CRON_TMP"
    else
        echo "[remote] Dashboard only - using direct port mapping"
        tailscale serve --bg --https=443 5000 > /dev/null 2>&1

        # Add @reboot cron job (direct port mapping)
        # SECURITY: Use mktemp for unpredictable filename (prevents symlink attacks)
        CRON_TMP=\$(mktemp)
        # Remove old cron entry
        (crontab -l 2>/dev/null | grep -v "tailscale serve.*5000") > "\$CRON_TMP" || true
        # Add new cron entry
        echo "@reboot sleep 30 && /usr/bin/tailscale serve --bg --https=443 5000 > /dev/null 2>&1" >> "\$CRON_TMP"
        crontab "\$CRON_TMP"
        rm -f "\$CRON_TMP"
    fi

    echo "[remote] Web dashboard available at: https://\$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')"
fi
WEBEOF

    echo_info "Web dashboard configured successfully and available at: https://${TAILSCALE_NAME}.${TAILSCALE_DOMAIN}"
else
    echo_info "Web dashboard disabled, skipping setup"
fi

# ============================================================
# STEP 13.6 — Set up Cowrie Event Indexer Daemon
# ============================================================

echo_info "Setting up Cowrie Event Indexer Daemon..."

# Event indexer script and schema are already from git (STEP 6)
# Just install and configure the systemd service

# Install and start event indexer daemon
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'INDEXEREOF'

# Make script executable
chmod +x /opt/cowrie/scripts/event-indexer.py

# Detect uv path
UV_PATH=$(command -v uv 2>/dev/null || echo "")

if [ -z "${UV_PATH}" ]; then
    echo "[remote] ERROR: uv not found in PATH"
    echo "[remote] Event indexer requires uv to be installed"
    exit 1
fi

echo "[remote] Detected uv at: ${UV_PATH}"

# Replace UV_PATH_PLACEHOLDER with actual path and install service
# (Service file is from git clone in STEP 6)
sed "s|UV_PATH_PLACEHOLDER|${UV_PATH}|g" \
    /opt/cowrie/scripts/cowrie-event-indexer.service \
    > /etc/systemd/system/cowrie-event-indexer.service

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable cowrie-event-indexer.service

# Start the service
systemctl start cowrie-event-indexer.service

echo "[remote] Event indexer daemon installed and started"
echo "[remote] Indexing events from Cowrie JSON logs into SQLite database"
systemctl status cowrie-event-indexer.service --no-pager

INDEXEREOF

echo_info "Cowrie Event Indexer Daemon configured successfully"

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
# STEP 15 — Create VERSION.json
# ============================================================

echo_info "Creating VERSION.json tracking file..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p "$REAL_SSH_PORT" "root@$SERVER_IP" bash << 'VERSIONEOF'
cd /opt/cowrie
export PATH="$HOME/.local/bin:$PATH"

# Create initial VERSION.json (git repo already exists from STEP 6)
echo "[remote] Creating initial VERSION.json..."
bash /opt/cowrie/scripts/update-agent.sh --init-version

echo "[remote] VERSION.json created"
VERSIONEOF

echo_info "VERSION.json created successfully"

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

# Display SSH access information (Tailscale always configured in v2.1)
cat << SSHINFO

Tailscale IP:    $TAILSCALE_IP

SSH Access:
  Management SSH (Recommended - via Tailscale):
    ssh root@$TAILSCALE_IP

  Management SSH (Fallback - public):
    ssh -p $REAL_SSH_PORT root@$SERVER_IP

  Honeypot SSH (public - port 22):
    ssh root@$SERVER_IP
SSHINFO

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

Update System:
  Code updates:        ./update-honeypots.sh --all
  Filesystem updates:  ./update-honeypots.sh --all --filesystem
  Full updates:        ./update-honeypots.sh --all --full
  Smart auto-detect:   ./update-honeypots.sh --all --auto
  Check status:        ./update-honeypots.sh --status
UPDATEINFO

echo "============================================"
