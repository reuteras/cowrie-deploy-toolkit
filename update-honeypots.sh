#!/usr/bin/env bash
#
# Update Honeypots Without Full Redeployment
#
# This script orchestrates updates to honeypot servers without requiring
# full redeployment. It connects via Tailscale SSH and runs update-agent.sh
# on each honeypot.
#
# Usage:
#   ./update-honeypots.sh --all                  # Update all honeypots
#   ./update-honeypots.sh --name cowrie-hp-1     # Update specific honeypot
#   ./update-honeypots.sh --status               # Show versions
#   ./update-honeypots.sh --rollback hp-1        # Manual rollback
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
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/master-config.toml}"
LOG_FILE="${SCRIPT_DIR}/updates.log"
SSH_PORT=2222
SSH_TIMEOUT=10

# Logging functions
log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
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

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Update honeypots without full redeployment.

OPTIONS:
    --all                   Update all honeypots in master-config.toml
    --name NAME             Update specific honeypot by name
    --status                Show version information for all honeypots
    --rollback NAME         Rollback specific honeypot to previous state
    --parallel              Update multiple honeypots in parallel (default: sequential)
    --config FILE           Use alternative config file (default: master-config.toml)
    --help                  Show this help message

EXAMPLES:
    # Update all honeypots sequentially
    $0 --all

    # Update specific honeypot
    $0 --name cowrie-hp-1

    # Check status of all honeypots
    $0 --status

    # Rollback honeypot to previous version
    $0 --rollback cowrie-hp-1

    # Update all honeypots in parallel
    $0 --all --parallel

EOF
    exit 1
}

# Check dependencies
check_dependencies() {
    local deps=("python3" "jq" "ssh" "tailscale")
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

# Get version information from honeypot
get_version_info() {
    local name="$1"
    local ts_ip

    log_info "Getting version info for ${name}..."

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
    version_json=$(ssh -p "${SSH_PORT}" "root@${ts_ip}" "cat /opt/cowrie/VERSION.json 2>/dev/null || echo '{}'")

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

# Update single honeypot
update_honeypot() {
    local name="$1"
    local ts_ip

    log_info "Starting update for honeypot: ${name}"

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
    get_version_info "${name}" | jq '.' || true

    # Execute update-agent.sh on remote honeypot
    log_info "Executing update-agent.sh on ${name}..."

    if ssh -p "${SSH_PORT}" "root@${ts_ip}" "cd /opt/cowrie && bash scripts/update-agent.sh" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Update completed successfully for ${name}"

        # Show version after update
        log_info "Version after update:"
        get_version_info "${name}" | jq '.' || true

        return 0
    else
        log_error "Update failed for ${name}"
        return 1
    fi
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

    if ssh -p "${SSH_PORT}" "root@${ts_ip}" "cd /opt/cowrie && bash scripts/update-agent.sh --rollback" 2>&1 | tee -a "${LOG_FILE}"; then
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
