#!/usr/bin/env bash
#
# Update Agent - Runs on Honeypot Servers
#
# This script performs actual updates on honeypot servers. It is executed
# remotely by update-honeypots.sh via SSH.
#
# Features:
#   - Git-based updates for scripts and configuration
#   - Container registry pulls for web/API images
#   - Health checks after each phase
#   - Automatic rollback on failure
#   - VERSION.json tracking
#
# Usage:
#   bash scripts/update-agent.sh              # Normal update
#   bash scripts/update-agent.sh --rollback   # Manual rollback
#   bash scripts/update-agent.sh --init-version # Initialize VERSION.json
#

set -euo pipefail

# Configuration
COWRIE_DIR="/opt/cowrie"
ROLLBACK_DIR="${COWRIE_DIR}/.rollback"
VERSION_FILE="${COWRIE_DIR}/VERSION.json"
MAX_ROLLBACK_SNAPSHOTS=5
GIT_REMOTE="https://github.com/reuteras/cowrie-deploy-toolkit.git"
GIT_BRANCH="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handler
error_handler() {
    local line_number=$1
    log_error "Update failed at line ${line_number}"
    log_error "Rolling back to previous state..."
    perform_rollback
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# Create rollback snapshot
create_snapshot() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local snapshot_dir="${ROLLBACK_DIR}/${timestamp}"

    log_info "Creating rollback snapshot: ${snapshot_dir}"

    mkdir -p "${snapshot_dir}"

    # Backup critical files and directories
    if [ -f "${VERSION_FILE}" ]; then
        cp "${VERSION_FILE}" "${snapshot_dir}/VERSION.json"
    fi

    # Backup git state
    if [ -d "${COWRIE_DIR}/.git" ]; then
        git -C "${COWRIE_DIR}" rev-parse HEAD > "${snapshot_dir}/git-commit.txt" 2>/dev/null || echo "unknown" > "${snapshot_dir}/git-commit.txt"
    fi

    # Backup Docker image IDs
    docker compose -f "${COWRIE_DIR}/docker-compose.yml" images --format json > "${snapshot_dir}/docker-images.json" 2>/dev/null || echo "[]" > "${snapshot_dir}/docker-images.json"

    # Keep only last N snapshots
    cleanup_old_snapshots

    log_success "Snapshot created: ${snapshot_dir}"
}

# Cleanup old rollback snapshots
cleanup_old_snapshots() {
    if [ ! -d "${ROLLBACK_DIR}" ]; then
        return
    fi

    local snapshots
    mapfile -t snapshots < <(ls -1t "${ROLLBACK_DIR}" 2>/dev/null || true)

    if [ ${#snapshots[@]} -le ${MAX_ROLLBACK_SNAPSHOTS} ]; then
        return
    fi

    log_info "Cleaning up old rollback snapshots (keeping ${MAX_ROLLBACK_SNAPSHOTS})"

    for ((i=MAX_ROLLBACK_SNAPSHOTS; i<${#snapshots[@]}; i++)); do
        local old_snapshot="${ROLLBACK_DIR}/${snapshots[$i]}"
        log_info "Removing old snapshot: ${old_snapshot}"
        rm -rf "${old_snapshot}"
    done
}

# Perform rollback
perform_rollback() {
    log_warning "Performing rollback..."

    # Find latest snapshot
    if [ ! -d "${ROLLBACK_DIR}" ]; then
        log_error "No rollback directory found: ${ROLLBACK_DIR}"
        return 1
    fi

    local snapshots
    mapfile -t snapshots < <(ls -1t "${ROLLBACK_DIR}" 2>/dev/null || true)

    local latest_snapshot=""
    if [ ${#snapshots[@]} -gt 0 ]; then
        latest_snapshot="${snapshots[0]}"
    fi

    if [ -z "${latest_snapshot}" ]; then
        log_error "No rollback snapshots found"
        return 1
    fi

    local snapshot_path="${ROLLBACK_DIR}/${latest_snapshot}"
    log_info "Rolling back to snapshot: ${snapshot_path}"

    # Restore git state
    if [ -f "${snapshot_path}/git-commit.txt" ]; then
        local git_commit
        git_commit=$(cat "${snapshot_path}/git-commit.txt")

        if [ "${git_commit}" != "unknown" ] && [ -d "${COWRIE_DIR}/.git" ]; then
            log_info "Restoring git to commit: ${git_commit}"
            git -C "${COWRIE_DIR}" reset --hard "${git_commit}"
        fi
    fi

    # Restore VERSION.json
    if [ -f "${snapshot_path}/VERSION.json" ]; then
        cp "${snapshot_path}/VERSION.json" "${VERSION_FILE}"
    fi

    # Restart all containers
    log_info "Restarting Docker containers..."
    cd "${COWRIE_DIR}"
    docker compose restart

    log_success "Rollback completed"
}

# Initialize git repository
init_git() {
    log_info "Initializing git repository..."

    cd "${COWRIE_DIR}"

    if [ ! -d ".git" ]; then
        log_info "Creating new git repository"
        git init
        git remote add origin "${GIT_REMOTE}"
    else
        log_info "Git repository already exists"

        # Check if remote exists
        if ! git remote get-url origin &>/dev/null; then
            git remote add origin "${GIT_REMOTE}"
        fi
    fi

    # Fetch and reset to main branch
    log_info "Fetching from ${GIT_REMOTE}..."
    git fetch origin "${GIT_BRANCH}"

    log_info "Resetting to origin/${GIT_BRANCH}..."
    git reset --hard "origin/${GIT_BRANCH}"

    log_success "Git initialized and synced"
}

# Update scripts and configuration via git
update_scripts() {
    log_info "Phase 1: Updating scripts and configuration via git..."

    cd "${COWRIE_DIR}"

    # Ensure git is initialized
    if [ ! -d ".git" ]; then
        init_git
    fi

    # Get current commit before update
    local old_commit
    old_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

    # Save API port configuration before git reset (if API is exposed via Tailscale)
    local api_ports_enabled=false
    if [ -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        if grep -q "^ports:" "${COWRIE_DIR}/docker-compose.api.yml"; then
            api_ports_enabled=true
            log_info "Detected API ports exposed (Tailscale Serve mode) - will preserve after update"
        fi
    fi

    # Pull latest changes
    log_info "Pulling latest changes from ${GIT_BRANCH}..."
    git fetch origin "${GIT_BRANCH}" >/dev/null 2>&1 || log_warning "Failed to fetch from remote, continuing with local state"
    git reset --hard "origin/${GIT_BRANCH}" >/dev/null 2>&1 || log_warning "Failed to reset to origin/${GIT_BRANCH}, continuing with local state"

    # Restore API port configuration if it was enabled before update
    if [ "${api_ports_enabled}" = "true" ] && [ -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        log_info "Restoring API port exposure for Tailscale Serve..."
        sed -i 's/# ports:/ports:/' "${COWRIE_DIR}/docker-compose.api.yml"
        sed -i 's/#   - "127.0.0.1:8000:8000"/  - "127.0.0.1:8000:8000"/' "${COWRIE_DIR}/docker-compose.api.yml"
    fi

    # Get new commit
    local new_commit
    new_commit=$(git rev-parse HEAD)

    if [ "${old_commit}" == "${new_commit}" ]; then
        log_info "Scripts already up to date (commit: ${new_commit:0:10})"
    else
        log_success "Scripts updated: ${old_commit:0:10} -> ${new_commit:0:10}"

        # Restart systemd services if they exist
        if systemctl is-active --quiet yara-scanner.service 2>/dev/null; then
            log_info "Restarting YARA scanner service..."
            systemctl restart yara-scanner.service
        fi
    fi

    log_success "Phase 1 complete: Scripts updated"
}

# Update web container
update_web() {
    # Check if web dashboard service is defined
    if ! docker compose config --services 2>/dev/null | grep -q "^cowrie-web$"; then
        log_info "Phase 2: Web dashboard not configured, skipping"
        return 0
    fi

    log_info "Phase 2: Updating web dashboard container..."

    cd "${COWRIE_DIR}"

    # Get current image ID
    local old_image_id
    old_image_id=$(docker compose images cowrie-web --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')

    # Pull latest image
    log_info "Pulling latest web image from registry..."
    if docker compose pull cowrie-web 2>/dev/null; then
        log_success "Web image pulled successfully"
    else
        log_warning "Failed to pull web image, will rebuild locally"
        docker compose build cowrie-web
    fi

    # Recreate container
    log_info "Recreating web container..."
    docker compose up -d --no-deps --force-recreate cowrie-web >/dev/null 2>&1

    # Get new image ID
    local new_image_id
    new_image_id=$(docker compose images cowrie-web --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')

    if [ "${old_image_id}" == "${new_image_id}" ]; then
        log_info "Web image already up to date"
    else
        log_success "Web image updated: ${old_image_id:0:12} -> ${new_image_id:0:12}"
    fi

    # Health check (wait for Flask to fully start)
    log_info "Waiting for web dashboard to start..."
    sleep 3
    log_info "Running health check for web dashboard..."
    if bash "${COWRIE_DIR}/scripts/health-check.sh" --web; then
        log_success "Web dashboard health check passed"
    else
        log_error "Web dashboard health check failed"
        return 1
    fi

    log_success "Phase 2 complete: Web dashboard updated"
}

# Update API container
update_api() {
    # Check if API is enabled
    if [ ! -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        log_info "Phase 3: API not enabled, skipping"
        return 0
    fi

    log_info "Phase 3: Updating API container..."

    cd "${COWRIE_DIR}"

    # Replace placeholders in docker-compose.api.yml with actual values from deployment config
    # Extract SERVER_IP and HONEYPOT_HOSTNAME from deployment.conf
    local server_ip honeypot_hostname
    log_info "Configuring API container with current SERVER_IP and HONEYPOT_HOSTNAME..."

    # Try to read from deployment.conf first (new method, works for all honeypots)
    if [ -f "deployment.conf" ]; then
        # shellcheck disable=SC1091
        source deployment.conf
        # shellcheck disable=SC2153
        server_ip="${SERVER_IP}"
        # shellcheck disable=SC2153
        honeypot_hostname="${HONEYPOT_HOSTNAME}"
    else
        # Fallback to old method for backwards compatibility
        server_ip=$(grep "out_addr = " etc/cowrie.cfg | head -1 | sed 's/.*out_addr = //' | sed 's/ *#.*//')
        honeypot_hostname=$(grep "HONEYPOT_HOSTNAME=" docker-compose.yml 2>/dev/null | head -1 | sed 's/.*HONEYPOT_HOSTNAME=//' | sed 's/ *#.*//')
    fi

    log_info "Using SERVER_IP: ${server_ip}"
    log_info "Using HONEYPOT_HOSTNAME: ${honeypot_hostname}"
    if [ -n "$server_ip" ] && [ -n "$honeypot_hostname" ]; then
        sed -i "s|SERVER_IP_PLACEHOLDER|$server_ip|g" docker-compose.api.yml
        sed -i "s|HONEYPOT_HOSTNAME_PLACEHOLDER|$honeypot_hostname|g" docker-compose.api.yml
    else
        log_warning "Could not determine SERVER_IP or HONEYPOT_HOSTNAME"
    fi

    # Get current image ID
    log_info "Retrieving current API image ID..."
    local old_image_id
    old_image_id=$(docker compose -f docker-compose.yml -f docker-compose.api.yml images cowrie-api --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')

    # Pull latest image
    log_info "Pulling latest API image from registry..."
    if docker compose -f docker-compose.yml -f docker-compose.api.yml pull cowrie-api 2>/dev/null; then
        log_success "API image pulled successfully"
    else
        log_warning "Failed to pull API image, will rebuild locally"
        docker compose -f docker-compose.yml -f docker-compose.api.yml build cowrie-api >/dev/null 2>&1
    fi

    # Recreate container
    log_info "Recreating API container..."
    docker compose -f docker-compose.yml -f docker-compose.api.yml up -d --no-deps --force-recreate cowrie-api >/dev/null 2>&1

    # Get new image ID
    local new_image_id
    new_image_id=$(docker compose -f docker-compose.yml -f docker-compose.api.yml images cowrie-api --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')

    if [ "${old_image_id}" == "${new_image_id}" ]; then
        log_info "API image already up to date"
    else
        log_success "API image updated: ${old_image_id:0:12} -> ${new_image_id:0:12}"
    fi

    # Health check (wait for FastAPI to fully start)
    log_info "Waiting for API to start..."
    sleep 3
    log_info "Running health check for API..."
    if bash "${COWRIE_DIR}/scripts/health-check.sh" --api; then
        log_success "API health check passed"
    else
        log_error "API health check failed"
        return 1
    fi

    log_success "Phase 3 complete: API updated"
}

# Update VERSION.json
update_version_file() {
    log_info "Phase 4: Updating VERSION.json..."

    cd "${COWRIE_DIR}"

    # Get current information
    local honeypot_name
    honeypot_name=$(hostname)

    local git_commit
    git_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

    local git_branch
    git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

    local web_image_id
    web_image_id=$(docker compose images cowrie-web --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')

    local web_version
    web_version=$(docker compose exec -T cowrie-web python -c "import sys; sys.path.insert(0, '/app'); from app import __version__; print(__version__)" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\000-\037' | sed 's/[[:space:]]*$//' || echo "unknown")

    local api_image_id="N/A"
    local api_version="N/A"

    if [ -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        api_image_id=$(docker compose -f docker-compose.yml -f docker-compose.api.yml images cowrie-api --format json 2>/dev/null | jq -r '.[0].ID // "unknown"')
        api_version=$(docker compose -f docker-compose.yml -f docker-compose.api.yml exec -T cowrie-api python -c "import sys; sys.path.insert(0, '/app'); from app import __version__; print(__version__)" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\000-\037' | sed 's/[[:space:]]*$//' || echo "unknown")
    fi

    local tailscale_ip
    tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "unknown")

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Create VERSION.json
    cat > "${VERSION_FILE}" << EOF
{
  "honeypot_name": "${honeypot_name}",
  "last_updated": "${timestamp}",
  "components": {
    "scripts": {
      "type": "git",
      "commit": "${git_commit}",
      "branch": "${git_branch}",
      "url": "${GIT_REMOTE}"
    },
    "web": {
      "type": "container",
      "image": "ghcr.io/reuteras/cowrie-web:latest",
      "image_id": "${web_image_id}",
      "version": "${web_version}"
    },
    "api": {
      "type": "container",
      "image": "ghcr.io/reuteras/cowrie-api:latest",
      "image_id": "${api_image_id}",
      "version": "${api_version}"
    },
    "cowrie": {
      "type": "container",
      "base_image": "cowrie/cowrie:latest"
    }
  },
  "system": {
    "tailscale_ip": "${tailscale_ip}",
    "honeypot_ssh": "22",
    "management_ssh": "2222"
  }
}
EOF

    log_success "VERSION.json updated"

    log_success "Phase 4 complete: VERSION.json updated"
}

# Initialize VERSION.json (for first-time setup)
init_version_file() {
    log_info "Initializing VERSION.json..."

    cd "${COWRIE_DIR}"

    # Ensure git is initialized first
    if [ ! -d ".git" ]; then
        init_git
    fi

    update_version_file
    log_success "VERSION.json initialized"
}

# Main update process
main_update() {
    log_info "=== Starting Honeypot Update ==="
    log_info "Timestamp: $(date)"
    log_info "Hostname: $(hostname)"

    # Create rollback snapshot
    local snapshot_dir
    snapshot_dir=$(create_snapshot)

    # Phase 1: Update scripts and configuration
    update_scripts

    # Phase 2: Update web dashboard
    update_web

    # Phase 3: Update API
    update_api

    # Phase 4: Update VERSION.json
    update_version_file

    log_success "=== Update Completed Successfully ==="
    log_info "Rollback snapshot available at: ${snapshot_dir}"
}

# Main entry point
main() {
    local operation="${1:-update}"

    cd "${COWRIE_DIR}"

    case "${operation}" in
        --rollback)
            perform_rollback
            ;;
        --init-version)
            init_version_file
            ;;
        --init-git)
            init_git
            ;;
        update|"")
            main_update
            ;;
        *)
            log_error "Unknown operation: ${operation}"
            echo "Usage: $0 [--rollback|--init-version|--init-git]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
