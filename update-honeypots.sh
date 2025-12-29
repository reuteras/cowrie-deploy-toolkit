#!/usr/bin/env bash
#
# Unified Update Script for Cowrie Honeypots
#
# This script handles ALL updates to honeypot servers:
#   - Code updates (scripts, web, API) via git + Docker registry
#   - Filesystem updates (fs.pickle, identity, contents) via rsync
#   - Smart auto-detection of what needs updating
#
# Usage:
#   ./update-honeypots.sh --all                     # Update code (default)
#   ./update-honeypots.sh --all --filesystem        # Update filesystem only
#   ./update-honeypots.sh --all --full              # Update both
#   ./update-honeypots.sh --all --auto              # Smart detection
#   ./update-honeypots.sh --name cowrie-hp-1        # Update specific honeypot
#   ./update-honeypots.sh --status                  # Show versions
#   ./update-honeypots.sh --rollback hp-1           # Manual rollback
#
# Requirements:
#   - master-config.toml with honeypot configuration
#   - Tailscale VPN connection active
#   - SSH access to honeypots on port 2222
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/master-config.toml}"
LOG_FILE="${SCRIPT_DIR}/updates.log"
SSH_PORT=2222
SSH_TIMEOUT=10
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# Update modes
UPDATE_CODE=false
UPDATE_FILESYSTEM=false
UPDATE_AUTO=false

# Logging functions
log() {
    echo -e "${1}" | tee -a "${LOG_FILE}"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

log_mode() {
    log "${CYAN}[MODE]${NC} $1"
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Unified update script for Cowrie honeypots - handles code AND filesystem updates.

UPDATE MODES:
    --code                  Update code only (scripts, web, API) [default]
    --filesystem            Update filesystem only (fs.pickle, identity, contents)
    --full                  Update both code and filesystem
    --auto                  Smart mode - auto-detect what needs updating

HONEYPOT SELECTION:
    --all                   Update all honeypots in master-config.toml
    --name NAME             Update specific honeypot by name

OTHER OPTIONS:
    --status                Show version information for all honeypots
    --rollback NAME         Rollback specific honeypot to previous state
    --parallel              Update multiple honeypots in parallel (default: sequential)
    --config FILE           Use alternative config file (default: master-config.toml)
    --help                  Show this help message

EXAMPLES:
    # Code updates (most common - scripts/web/API)
    $0 --all                           # Update code on all honeypots
    $0 --name cowrie-hp-1 --code       # Update code on one honeypot

    # Filesystem updates (after regenerating fs.pickle)
    $0 --all --filesystem              # Update filesystem on all

    # Full update (both code and filesystem)
    $0 --all --full                    # Update everything

    # Smart mode (auto-detects what changed)
    $0 --all --auto                    # Checks timestamps, updates as needed

    # Status and rollback
    $0 --status                        # Check versions
    $0 --rollback cowrie-hp-1          # Rollback to previous version

UPDATE MODES EXPLAINED:
    --code:       Git pull + Docker pull from GHCR (fast, atomic)
    --filesystem: Rsync fs.pickle, identity, contents (for new snapshots)
    --full:       Both code and filesystem
    --auto:       Detects which is needed based on file timestamps

DEFAULT: If no mode specified, --code is assumed (most common use case)

EOF
    exit 1
}

# Check dependencies
check_dependencies() {
    local deps=("python3" "jq" "ssh" "tailscale" "rsync" "scp")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            missing+=("${dep}")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Please install missing dependencies and try again."
        exit 1
    fi
}

# Check Tailscale connectivity
check_tailscale() {
    if ! tailscale status &> /dev/null; then
        log_error "Tailscale is not running or not connected"
        log_error "Please start Tailscale and try again: tailscale up"
        exit 1
    fi
    log_info "Tailscale connection: OK"
}

# Get honeypot configuration
get_honeypot_config() {
    local name="$1"

    if ! python3 "${SCRIPT_DIR}/scripts/get-honeypot-config.py" "${CONFIG_FILE}" --name "${name}" 2>/dev/null; then
        log_error "Failed to get configuration for honeypot: ${name}"
        return 1
    fi
}

# List all honeypots
list_honeypots() {
    python3 "${SCRIPT_DIR}/scripts/get-honeypot-config.py" "${CONFIG_FILE}" --list 2>/dev/null || {
        log_error "Failed to list honeypots from config file"
        exit 1
    }
}

# Get Tailscale IP for honeypot
get_tailscale_ip() {
    local name="$1"
    local config

    config=$(get_honeypot_config "${name}") || return 1

    # Extract tailscale_name from config
    local tailscale_name
    tailscale_name=$(echo "${config}" | jq -r '.tailscale_name // empty')

    if [ -z "${tailscale_name}" ]; then
        log_error "No tailscale_name found for honeypot: ${name}"
        return 1
    fi

    # Get Tailscale IP from status
    local ts_ip
    ts_ip=$(tailscale status --json | jq -r ".Peer[] | select(.HostName == \"${tailscale_name}\") | .TailscaleIPs[0]" 2>/dev/null)

    if [ -z "${ts_ip}" ] || [ "${ts_ip}" == "null" ]; then
        log_error "Could not find Tailscale IP for ${tailscale_name}"
        return 1
    fi

    echo "${ts_ip}"
}

# Check SSH connectivity
check_ssh() {
    local host="$1"
    local port="${2:-${SSH_PORT}}"

    if ssh -o ConnectTimeout="${SSH_TIMEOUT}" -o BatchMode=yes -p "${port}" "root@${host}" "exit" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# SSH execute command
ssh_exec() {
    local host="$1"
    local cmd="$2"
    local port="${3:-${SSH_PORT}}"

    # shellcheck disable=SC2086
    ssh ${SSH_OPTS} -p "${port}" "root@${host}" "${cmd}"
}

# SCP copy file
scp_copy() {
    local src="$1"
    local dest="$2"
    local port="${3:-${SSH_PORT}}"

    scp ${SSH_OPTS} -P "${port}" "${src}" "${dest}"
}

# Find latest output directory for honeypot
find_latest_output_dir() {
    local name="${1:-}"
    local pattern

    if [ -n "${name}" ]; then
        pattern="${SCRIPT_DIR}/output_${name}_*"
    else
        pattern="${SCRIPT_DIR}/output_*"
    fi

    local latest_dir=""
    local latest_time=0

    for dir in ${pattern}; do
        if [ -d "${dir}" ]; then
            # Get modification time
            if [[ "$OSTYPE" == "darwin"* ]]; then
                dir_time=$(stat -f %m "${dir}" 2>/dev/null || echo 0)
            else
                dir_time=$(stat -c %Y "${dir}" 2>/dev/null || echo 0)
            fi

            if [ "${dir_time}" -gt "${latest_time}" ]; then
                latest_time=${dir_time}
                latest_dir="${dir}"
            fi
        fi
    done

    if [ -n "${latest_dir}" ]; then
        echo "${latest_dir}"
        return 0
    else
        return 1
    fi
}

# Get version information from honeypot
get_version_info() {
    local name="$1"
    local ts_ip

    ts_ip=$(get_tailscale_ip "${name}") || {
        log_error "Failed to get Tailscale IP for ${name}"
        return 1
    }

    # Check SSH connectivity
    if ! check_ssh "${ts_ip}"; then
        log_error "Cannot connect to ${name} at ${ts_ip}:${SSH_PORT}"
        return 1
    fi

    # Get VERSION.json if it exists
    local version_json
    version_json=$(ssh_exec "${ts_ip}" "cat /opt/cowrie/VERSION.json 2>/dev/null || echo '{}'")

    echo "${version_json}"
}

# Show status for all honeypots
show_status() {
    log_info "Checking status of all honeypots..."
    echo ""

    local honeypots
    readarray -t honeypots < <(list_honeypots)

    if [ ${#honeypots[@]} -eq 0 ]; then
        log_warning "No honeypots found in ${CONFIG_FILE}"
        return
    fi

    printf "%-20s %-15s %-12s %-10s %-20s\n" "NAME" "TAILSCALE_IP" "GIT_COMMIT" "WEB_VER" "LAST_UPDATED"
    printf "%-20s %-15s %-12s %-10s %-20s\n" "----" "------------" "----------" "-------" "------------"

    for hp in "${honeypots[@]}"; do
        local ts_ip
        ts_ip=$(get_tailscale_ip "${hp}" 2>/dev/null || echo "N/A")

        local version_info
        version_info=$(get_version_info "${hp}" 2>/dev/null || echo '{}')

        local git_commit
        git_commit=$(echo "${version_info}" | jq -r '.components.scripts.commit // "N/A"' | cut -c1-10)

        local web_version
        web_version=$(echo "${version_info}" | jq -r '.components.web.version // "N/A"')

        local last_updated
        last_updated=$(echo "${version_info}" | jq -r '.last_updated // "N/A"')

        printf "%-20s %-15s %-12s %-10s %-20s\n" "${hp}" "${ts_ip}" "${git_commit}" "${web_version}" "${last_updated}"
    done

    echo ""
}

# Sync filesystem to honeypot
sync_filesystem() {
    local name="$1"
    local ts_ip="$2"
    local output_dir

    log_info "Finding latest output directory for ${name}..."

    if ! output_dir=$(find_latest_output_dir "${name}"); then
        log_error "No output directory found for ${name} (output_${name}_*)"
        log_error "Generate filesystem first: ./generate_cowrie_fs_from_hetzner.sh"
        return 1
    fi

    log_info "Using output directory: $(basename "${output_dir}")"

    # Sync fs.pickle
    if [ -f "${output_dir}/fs.pickle" ]; then
        log_info "  - Uploading fs.pickle..."
        if ! scp_copy "${output_dir}/fs.pickle" "root@${ts_ip}:/opt/cowrie/share/cowrie/" "${SSH_PORT}"; then
            log_error "Failed to upload fs.pickle"
            return 1
        fi
    else
        log_warning "fs.pickle not found in ${output_dir}"
    fi

    # Sync identity directory
    if [ -d "${output_dir}/identity" ]; then
        log_info "  - Syncing identity/ directory..."
        if ! rsync -az -e "ssh ${SSH_OPTS} -p ${SSH_PORT}" \
            "${output_dir}/identity/" "root@${ts_ip}:/opt/cowrie/identity/"; then
            log_error "Failed to sync identity directory"
            return 1
        fi
    fi

    # Sync contents directory
    if [ -d "${output_dir}/contents" ]; then
        log_info "  - Syncing contents/ directory..."
        if ! rsync -az -e "ssh ${SSH_OPTS} -p ${SSH_PORT}" \
            "${output_dir}/contents/" "root@${ts_ip}:/opt/cowrie/share/cowrie/contents/"; then
            log_error "Failed to sync contents directory"
            return 1
        fi
    fi

    # Sync txtcmds directory
    if [ -d "${output_dir}/txtcmds" ]; then
        log_info "  - Syncing txtcmds/ directory..."
        if ! rsync -az -e "ssh ${SSH_OPTS} -p ${SSH_PORT}" \
            "${output_dir}/txtcmds/" "root@${ts_ip}:/opt/cowrie/share/cowrie/txtcmds/"; then
            log_error "Failed to sync txtcmds directory"
            return 1
        fi
    fi

    log_success "Filesystem synced successfully"

    # Restart Cowrie container to pick up new filesystem
    log_info "Restarting Cowrie container..."
    if ssh_exec "${ts_ip}" "cd /opt/cowrie && docker compose restart cowrie"; then
        log_success "Cowrie container restarted"
    else
        log_error "Failed to restart Cowrie container"
        return 1
    fi

    return 0
}

# Update honeypot code (via update-agent.sh)
update_code() {
    local name="$1"
    local ts_ip="$2"

    log_info "Executing update-agent.sh on ${name}..."

    if ssh_exec "${ts_ip}" "cd /opt/cowrie && bash scripts/update-agent.sh" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Code update completed successfully for ${name}"
        return 0
    else
        log_error "Code update failed for ${name}"
        return 1
    fi
}

# Auto-detect what needs updating
auto_detect_updates() {
    local name="$1"
    local ts_ip="$2"

    log_mode "Auto-detection mode for ${name}..."

    local needs_code=false
    local needs_filesystem=false

    # Check if git has updates
    local remote_commit
    remote_commit=$(ssh_exec "${ts_ip}" "cd /opt/cowrie && git rev-parse origin/main 2>/dev/null || echo 'unknown'")

    local local_commit
    local_commit=$(ssh_exec "${ts_ip}" "cd /opt/cowrie && git rev-parse HEAD 2>/dev/null || echo 'unknown'")

    if [ "${remote_commit}" != "${local_commit}" ] && [ "${remote_commit}" != "unknown" ]; then
        log_info "Git updates available: ${local_commit:0:10} -> ${remote_commit:0:10}"
        needs_code=true
    else
        log_info "Git is up to date"
    fi

    # Check if filesystem needs updating
    local output_dir
    if output_dir=$(find_latest_output_dir "${name}"); then
        log_info "Found output directory: $(basename "${output_dir}")"

        # Check if fs.pickle on server is older than local
        if [ -f "${output_dir}/fs.pickle" ]; then
            local local_fs_time
            if [[ "$OSTYPE" == "darwin"* ]]; then
                local_fs_time=$(stat -f %m "${output_dir}/fs.pickle" 2>/dev/null || echo 0)
            else
                local_fs_time=$(stat -c %Y "${output_dir}/fs.pickle" 2>/dev/null || echo 0)
            fi

            local remote_fs_time
            remote_fs_time=$(ssh_exec "${ts_ip}" "stat -c %Y /opt/cowrie/share/cowrie/fs.pickle 2>/dev/null || echo 0" || echo 0)

            if [ "${local_fs_time}" -gt "${remote_fs_time}" ]; then
                log_info "Local fs.pickle is newer than remote"
                needs_filesystem=true
            else
                log_info "Filesystem is up to date"
            fi
        fi
    else
        log_info "No output directory found for filesystem comparison"
    fi

    # Determine what to update
    if [ "${needs_code}" = "true" ] && [ "${needs_filesystem}" = "true" ]; then
        log_mode "Auto-detected: Both code AND filesystem need updating"
        UPDATE_CODE=true
        UPDATE_FILESYSTEM=true
    elif [ "${needs_code}" = "true" ]; then
        log_mode "Auto-detected: Code needs updating"
        UPDATE_CODE=true
    elif [ "${needs_filesystem}" = "true" ]; then
        log_mode "Auto-detected: Filesystem needs updating"
        UPDATE_FILESYSTEM=true
    else
        log_mode "Auto-detected: Everything is up to date"
        log_success "${name} is already up to date"
        return 0
    fi

    # Perform detected updates
    if [ "${UPDATE_FILESYSTEM}" = "true" ]; then
        if ! sync_filesystem "${name}" "${ts_ip}"; then
            return 1
        fi
    fi

    if [ "${UPDATE_CODE}" = "true" ]; then
        if ! update_code "${name}" "${ts_ip}"; then
            return 1
        fi
    fi

    return 0
}

# Update single honeypot
update_honeypot() {
    local name="$1"
    local ts_ip

    log_info "===================================================================="
    log_info "Starting update for honeypot: ${name}"
    log_info "===================================================================="

    # Get Tailscale IP
    ts_ip=$(get_tailscale_ip "${name}") || {
        log_error "Failed to get Tailscale IP for ${name}"
        return 1
    }

    log_info "Connecting to ${name} at ${ts_ip}:${SSH_PORT}"

    # Check SSH connectivity
    if ! check_ssh "${ts_ip}"; then
        log_error "Cannot connect to ${name} at ${ts_ip}:${SSH_PORT}"
        return 1
    fi

    log_success "SSH connection to ${name}: OK"

    # Show version before update
    log_info "Version before update:"
    get_version_info "${name}" | jq '.' 2>/dev/null || log_warning "VERSION.json not found"
    echo ""

    # Auto-detection mode
    if [ "${UPDATE_AUTO}" = "true" ]; then
        auto_detect_updates "${name}" "${ts_ip}"
        local result=$?
        echo ""
        return ${result}
    fi

    # Manual mode - update based on flags
    local updated=false

    if [ "${UPDATE_FILESYSTEM}" = "true" ]; then
        log_mode "Filesystem update mode"
        if sync_filesystem "${name}" "${ts_ip}"; then
            updated=true
        else
            return 1
        fi
        echo ""
    fi

    if [ "${UPDATE_CODE}" = "true" ]; then
        log_mode "Code update mode"
        if update_code "${name}" "${ts_ip}"; then
            updated=true
        else
            return 1
        fi
        echo ""
    fi

    if [ "${updated}" = "false" ]; then
        log_warning "No update mode selected, nothing to do"
        return 0
    fi

    # Show version after update
    log_info "Version after update:"
    get_version_info "${name}" | jq '.' 2>/dev/null || log_warning "VERSION.json not found"
    echo ""

    log_success "Update completed successfully for ${name}"
    return 0
}

# Rollback honeypot
rollback_honeypot() {
    local name="$1"
    local ts_ip

    log_info "Starting rollback for honeypot: ${name}"

    # Get Tailscale IP
    ts_ip=$(get_tailscale_ip "${name}") || {
        log_error "Failed to get Tailscale IP for ${name}"
        return 1
    }

    log_info "Connecting to ${name} at ${ts_ip}:${SSH_PORT}"

    # Check SSH connectivity
    if ! check_ssh "${ts_ip}"; then
        log_error "Cannot connect to ${name} at ${ts_ip}:${SSH_PORT}"
        return 1
    fi

    # Execute rollback
    log_warning "Executing rollback on ${name}..."

    if ssh_exec "${ts_ip}" "cd /opt/cowrie && bash scripts/update-agent.sh --rollback" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Rollback completed successfully for ${name}"
        return 0
    else
        log_error "Rollback failed for ${name}"
        return 1
    fi
}

# Update all honeypots
update_all_honeypots() {
    local parallel="${1:-false}"

    log_info "Updating all honeypots (parallel=${parallel})..."

    local honeypots
    readarray -t honeypots < <(list_honeypots)

    if [ ${#honeypots[@]} -eq 0 ]; then
        log_warning "No honeypots found in ${CONFIG_FILE}"
        return
    fi

    log_info "Found ${#honeypots[@]} honeypot(s): ${honeypots[*]}"

    if [ "${parallel}" == "true" ]; then
        # Update in parallel
        local pids=()

        for hp in "${honeypots[@]}"; do
            update_honeypot "${hp}" &
            pids+=($!)
        done

        # Wait for all updates to complete
        local failed=0
        for pid in "${pids[@]}"; do
            if ! wait "${pid}"; then
                failed=$((failed + 1))
            fi
        done

        if [ ${failed} -gt 0 ]; then
            log_error "${failed} honeypot(s) failed to update"
            return 1
        fi
    else
        # Update sequentially
        local failed=0

        for hp in "${honeypots[@]}"; do
            if ! update_honeypot "${hp}"; then
                failed=$((failed + 1))
            fi
            echo ""
        done

        if [ ${failed} -gt 0 ]; then
            log_error "${failed} honeypot(s) failed to update"
            return 1
        fi
    fi

    log_success "All honeypots updated successfully"
}

# Main script
main() {
    local operation=""
    local honeypot_name=""
    local parallel="false"

    # Default to code update if no mode specified
    local mode_specified=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)
                operation="update-all"
                shift
                ;;
            --name)
                operation="update-one"
                honeypot_name="$2"
                shift 2
                ;;
            --status)
                operation="status"
                shift
                ;;
            --rollback)
                operation="rollback"
                honeypot_name="$2"
                shift 2
                ;;
            --code)
                UPDATE_CODE=true
                mode_specified=true
                shift
                ;;
            --filesystem)
                UPDATE_FILESYSTEM=true
                mode_specified=true
                shift
                ;;
            --full)
                UPDATE_CODE=true
                UPDATE_FILESYSTEM=true
                mode_specified=true
                shift
                ;;
            --auto)
                UPDATE_AUTO=true
                mode_specified=true
                shift
                ;;
            --parallel)
                parallel="true"
                shift
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Default to --code if no mode specified
    if [ "${mode_specified}" = "false" ] && [ "${operation}" != "status" ] && [ "${operation}" != "rollback" ]; then
        UPDATE_CODE=true
        log_mode "No update mode specified, defaulting to --code"
    fi

    # Validate operation
    if [ -z "${operation}" ]; then
        log_error "No operation specified"
        usage
    fi

    # Check dependencies
    check_dependencies

    # Check config file exists
    if [ ! -f "${CONFIG_FILE}" ]; then
        log_error "Config file not found: ${CONFIG_FILE}"
        exit 1
    fi

    log_info "Using config file: ${CONFIG_FILE}"
    log_info "Log file: ${LOG_FILE}"
    echo ""

    # Execute operation
    case "${operation}" in
        status)
            check_tailscale
            show_status
            ;;
        update-all)
            check_tailscale
            update_all_honeypots "${parallel}"
            ;;
        update-one)
            if [ -z "${honeypot_name}" ]; then
                log_error "Honeypot name required for --name option"
                exit 1
            fi
            check_tailscale
            update_honeypot "${honeypot_name}"
            ;;
        rollback)
            if [ -z "${honeypot_name}" ]; then
                log_error "Honeypot name required for --rollback option"
                exit 1
            fi
            check_tailscale
            rollback_honeypot "${honeypot_name}"
            ;;
        *)
            log_error "Unknown operation: ${operation}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
