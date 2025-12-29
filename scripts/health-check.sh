#!/usr/bin/env bash
#
# Health Check Script - Validates Honeypot Health
#
# This script validates the health of various honeypot components.
# Used by update-agent.sh to verify successful updates.
#
# Exit codes:
#   0 = Healthy
#   1 = Critical failure (should trigger rollback)
#   2 = Warning (log but continue)
#
# Usage:
#   bash scripts/health-check.sh           # Check all components
#   bash scripts/health-check.sh --web     # Check web dashboard only
#   bash scripts/health-check.sh --api     # Check API only
#   bash scripts/health-check.sh --cowrie  # Check Cowrie SSH only
#   bash scripts/health-check.sh --yara    # Check YARA daemon only
#

set -euo pipefail

# Configuration
COWRIE_DIR="/opt/cowrie"
COWRIE_SSH_PORT=22
WEB_PORT=5000
API_PORT=8000
HEALTH_TIMEOUT=10

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
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Check if port is listening
check_port() {
    local host="${1:-localhost}"
    local port="$2"
    local timeout="${3:-${HEALTH_TIMEOUT}}"

    if timeout "${timeout}" bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Check HTTP endpoint
check_http() {
    local url="$1"
    local timeout="${2:-${HEALTH_TIMEOUT}}"

    if timeout "${timeout}" curl -sf "${url}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Check Cowrie SSH honeypot
check_cowrie() {
    log_info "Checking Cowrie SSH honeypot (port ${COWRIE_SSH_PORT})..."

    if check_port localhost "${COWRIE_SSH_PORT}" 5; then
        log_success "Cowrie SSH is listening on port ${COWRIE_SSH_PORT}"

        # Verify it's actually Cowrie (not real SSH)
        local ssh_banner
        ssh_banner=$(timeout 3 nc localhost "${COWRIE_SSH_PORT}" 2>/dev/null | head -n 1 || echo "")

        if [ -n "${ssh_banner}" ]; then
            log_info "SSH Banner: ${ssh_banner}"
        fi

        return 0
    else
        log_error "Cowrie SSH is not responding on port ${COWRIE_SSH_PORT}"
        return 1
    fi
}

# Check Docker container health
check_docker() {
    log_info "Checking Docker containers..."

    cd "${COWRIE_DIR}"

    # Check if docker compose is running
    if ! docker compose ps &>/dev/null; then
        log_error "Docker compose is not available"
        return 1
    fi

    # Get container status
    local containers
    containers=$(docker compose ps --format json 2>/dev/null || echo "[]")

    if [ "${containers}" == "[]" ]; then
        log_error "No Docker containers found"
        return 1
    fi

    # Check each container
    local failed=0

    # Check cowrie container
    local cowrie_status
    cowrie_status=$(echo "${containers}" | jq -r 'select(.Service == "cowrie") | .State' 2>/dev/null || echo "not found")

    if [ "${cowrie_status}" == "running" ]; then
        log_success "Cowrie container: running"
    else
        log_error "Cowrie container: ${cowrie_status}"
        failed=1
    fi

    # Check web container
    local web_status
    web_status=$(echo "${containers}" | jq -r 'select(.Service == "cowrie-web") | .State' 2>/dev/null || echo "not found")

    if [ "${web_status}" == "running" ]; then
        log_success "Web dashboard container: running"
    elif [ "${web_status}" == "not found" ]; then
        log_warning "Web dashboard container: not found (may not be enabled)"
    else
        log_error "Web dashboard container: ${web_status}"
        failed=1
    fi

    # Check API container (if enabled)
    if [ -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        local api_containers
        api_containers=$(docker compose -f docker-compose.yml -f docker-compose.api.yml ps --format json 2>/dev/null || echo "[]")

        local api_status
        api_status=$(echo "${api_containers}" | jq -r 'select(.Service == "cowrie-api") | .State' 2>/dev/null || echo "not found")

        if [ "${api_status}" == "running" ]; then
            log_success "API container: running"
        elif [ "${api_status}" == "not found" ]; then
            log_warning "API container: not found"
        else
            log_error "API container: ${api_status}"
            failed=1
        fi
    fi

    return ${failed}
}

# Check web dashboard
check_web() {
    log_info "Checking web dashboard (port ${WEB_PORT})..."

    # Check if port is listening
    if ! check_port localhost "${WEB_PORT}" 5; then
        log_error "Web dashboard is not listening on port ${WEB_PORT}"
        return 1
    fi

    log_success "Web dashboard is listening on port ${WEB_PORT}"

    # Check health endpoint
    if check_http "http://localhost:${WEB_PORT}/health" 5; then
        log_success "Web dashboard /health endpoint: OK"

        # Get version info if available
        local health_response
        health_response=$(timeout 5 curl -s "http://localhost:${WEB_PORT}/health" 2>/dev/null || echo "{}")

        local status
        status=$(echo "${health_response}" | jq -r '.status // "unknown"')

        local version
        version=$(echo "${health_response}" | jq -r '.version // "unknown"')

        log_info "Status: ${status}, Version: ${version}"

        return 0
    else
        log_error "Web dashboard /health endpoint failed"
        return 1
    fi
}

# Check API service
check_api() {
    log_info "Checking API service (port ${API_PORT})..."

    # Check if API is enabled
    if [ ! -f "${COWRIE_DIR}/docker-compose.api.yml" ]; then
        log_warning "API not enabled (docker-compose.api.yml not found)"
        return 0
    fi

    # Check if port is listening
    if ! check_port localhost "${API_PORT}" 5; then
        log_error "API service is not listening on port ${API_PORT}"
        return 1
    fi

    log_success "API service is listening on port ${API_PORT}"

    # Check health endpoint
    if check_http "http://localhost:${API_PORT}/health" 5; then
        log_success "API /health endpoint: OK"

        # Get version info if available
        local health_response
        health_response=$(timeout 5 curl -s "http://localhost:${API_PORT}/health" 2>/dev/null || echo "{}")

        local status
        status=$(echo "${health_response}" | jq -r '.status // "unknown"')

        local version
        version=$(echo "${health_response}" | jq -r '.version // "unknown"')

        log_info "Status: ${status}, Version: ${version}"

        return 0
    else
        log_error "API /health endpoint failed"
        return 1
    fi
}

# Check YARA scanner daemon
check_yara() {
    log_info "Checking YARA scanner daemon..."

    # Check if systemd service exists
    if ! systemctl list-unit-files yara-scanner.service &>/dev/null; then
        log_warning "YARA scanner service not installed"
        return 0
    fi

    # Check service status
    if systemctl is-active --quiet yara-scanner.service 2>/dev/null; then
        log_success "YARA scanner daemon: running"

        # Check if it's actually processing files
        local process_count
        process_count=$(pgrep -f "yara-scanner-daemon.py" | wc -l)

        if [ "${process_count}" -gt 0 ]; then
            log_info "YARA scanner processes: ${process_count}"
        else
            log_warning "YARA scanner service running but no processes found"
        fi

        return 0
    else
        log_error "YARA scanner daemon: not running"
        return 1
    fi
}

# Check all components
check_all() {
    log_info "=== Running Full Health Check ==="
    echo ""

    local failed=0

    # Docker containers
    if ! check_docker; then
        failed=1
    fi
    echo ""

    # Cowrie SSH
    if ! check_cowrie; then
        failed=1
    fi
    echo ""

    # Web dashboard
    if ! check_web; then
        failed=1
    fi
    echo ""

    # API service
    if ! check_api; then
        failed=1
    fi
    echo ""

    # YARA daemon
    if ! check_yara; then
        # YARA is optional, so don't fail if it's not running
        log_warning "YARA daemon check failed, but continuing (non-critical)"
    fi
    echo ""

    if [ ${failed} -eq 0 ]; then
        log_success "=== All Health Checks Passed ==="
        return 0
    else
        log_error "=== Health Check Failed ==="
        return 1
    fi
}

# Main entry point
main() {
    local check="${1:-all}"

    case "${check}" in
        --cowrie)
            check_cowrie
            ;;
        --docker)
            check_docker
            ;;
        --web)
            check_web
            ;;
        --api)
            check_api
            ;;
        --yara)
            check_yara
            ;;
        --all|all|"")
            check_all
            ;;
        *)
            log_error "Unknown check: ${check}"
            echo "Usage: $0 [--cowrie|--docker|--web|--api|--yara|--all]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
