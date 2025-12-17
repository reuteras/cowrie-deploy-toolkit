#!/usr/bin/env bash
# ============================================================
# Common Functions Library for Cowrie Deployment Scripts
# ============================================================
# This library provides shared functionality for all deployment scripts:
# - Color output functions
# - Dependency checking
# - Error handling and validation
# - SSH connection helpers
# - TOML configuration reading
# - Temporary file management
#
# Usage:
#   source scripts/common.sh
# ============================================================

# ============================================================
# Output Functions
# ============================================================

echo_info() {
    echo -e "[*] $1"
}

echo_n_info() {
    echo -e -n "[*] $1"
}

echo_warn() {
    echo -e "[!] $1"
}

echo_error() {
    echo -e "[ERROR] $1"
}

# Fatal error - print message and exit
fatal_error() {
    echo_error "$1"
    exit 1
}

# ============================================================
# Dependency Checking
# ============================================================

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required dependencies and exit if any are missing
# Usage: check_dependencies "cmd1" "cmd2" "cmd3"
check_dependencies() {
    local missing_deps=()

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo ""
        echo "Please install missing dependencies and try again."
        exit 1
    fi
}

# ============================================================
# TOML Configuration Reading
# ============================================================

# Read value from TOML config using Python reader
# Usage: read_toml_value "config.toml" "section.key"
# Returns: value or empty string if not found
read_toml_value() {
    local toml_file="$1"
    local key_path="$2"
    local script_dir

    # Get script directory (handle both sourced and executed)
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Check if TOML file exists
    if [ ! -f "$toml_file" ]; then
        echo_error "TOML file not found: $toml_file"
        return 1
    fi

    # Call Python TOML reader
    python3 "$script_dir/read-toml.py" "$toml_file" "$key_path" 2>/dev/null || echo ""
}

# Read TOML value with default fallback
# Usage: read_toml_default "config.toml" "section.key" "default_value"
read_toml_default() {
    local toml_file="$1"
    local key_path="$2"
    local default="$3"
    local value

    value=$(read_toml_value "$toml_file" "$key_path")

    if [ -z "$value" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# Read TOML array into bash array variable
# Usage: read_toml_array "config.toml" "section.key" array_var_name
# Example: read_toml_array "config.toml" "deployment.ssh_keys" SSH_KEYS
read_toml_array() {
    local toml_file="$1"
    local key_path="$2"
    local -n array_ref="$3"  # nameref to the array variable

    array_ref=()  # Clear the array

    # Read values line by line into array
    # Note: Also handles last line without trailing newline
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -n "$line" ]; then
            array_ref+=("$line")
        fi
    done < <(read_toml_value "$toml_file" "$key_path")
}

# ============================================================
# SSH Connection Helpers
# ============================================================

# Default SSH options for all connections
# Disable host key checking (deployment use case)
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# Execute SSH command with standard options
# Usage: ssh_exec "user@host" "command"
ssh_exec() {
    local host="$1"
    local cmd="$2"
    local port="${3:-22}"

    # shellcheck disable=SC2086
    ssh $SSH_OPTS -p "$port" "$host" "$cmd"
}

# Copy file via SCP with standard options
# Usage: scp_copy "local_file" "user@host:remote_path" [port]
scp_copy() {
    local source="$1"
    local dest="$2"
    local port="${3:-22}"

    # shellcheck disable=SC2086
    scp $SSH_OPTS -P "$port" "$source" "$dest" > /dev/null 2>&1
}

# Wait for SSH to become available
# Usage: wait_for_ssh "user@host" [port] [timeout_seconds]
wait_for_ssh() {
    local host="$1"
    local port="${2:-22}"
    local timeout="${3:-60}"
    local elapsed=0

    echo_n_info "Waiting for SSH to become available"
    # shellcheck disable=SC2086
    while ! ssh $SSH_OPTS -p "$port" -o ConnectTimeout=3 "$host" "exit" 2>/dev/null; do
        printf "."
        sleep 3
        elapsed=$((elapsed + 3))

        if [ $elapsed -ge $timeout ]; then
            echo ""
            fatal_error "SSH connection timeout after ${timeout}s"
        fi
    done
    echo ""
    echo_info "SSH is ready"
}

# ============================================================
# Validation Functions
# ============================================================

# Validate IP address format
# Usage: validate_ip "192.168.1.1"
validate_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! $ip =~ $regex ]]; then
        return 1
    fi

    # Check each octet is <= 255
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [ "$octet" -gt 255 ]; then
            return 1
        fi
    done

    return 0
}

# Validate that a string is safe for shell use (no special chars)
# Usage: validate_safe_string "hostname"
validate_safe_string() {
    local str="$1"

    # Allow alphanumeric, dash, underscore, dot
    if [[ ! $str =~ ^[a-zA-Z0-9._-]+$ ]]; then
        return 1
    fi

    return 0
}

# Validate server ID (numeric)
# Usage: validate_server_id "12345"
validate_server_id() {
    local id="$1"

    if [[ ! $id =~ ^[0-9]+$ ]]; then
        return 1
    fi

    return 0
}

# ============================================================
# Temporary File Management
# ============================================================

# Array to track temp files for cleanup
declare -a TEMP_FILES=()

# Create a temporary file and track it for cleanup
# Usage: temp_file=$(create_temp_file [suffix])
create_temp_file() {
    local suffix="${1:-}"
    local temp_file

    if [ -n "$suffix" ]; then
        temp_file=$(mktemp /tmp/cowrie"${suffix}".XXXXXXXXXX)
    else
        temp_file=$(mktemp /tmp/cowrie.XXXXXXXXXX)
    fi

    TEMP_FILES+=("$temp_file")
    echo "$temp_file"
}

# Create a temporary directory and track it for cleanup
# Usage: temp_dir=$(create_temp_dir)
create_temp_dir() {
    local temp_dir

    temp_dir=$(mktemp -d /tmp/cowrie.XXXXXXXXXX)
    TEMP_FILES+=("$temp_dir")
    echo "$temp_dir"
}

# Clean up all tracked temporary files
cleanup_temp_files() {
    for file in "${TEMP_FILES[@]}"; do
        if [ -e "$file" ]; then
            rm -rf "$file" 2>/dev/null || true
        fi
    done
    TEMP_FILES=()
}

# Set up cleanup trap (call this in main script)
# Usage: setup_cleanup_trap
setup_cleanup_trap() {
    trap cleanup_temp_files EXIT INT TERM
}

# ============================================================
# Error Handling
# ============================================================

# Set up error handling (exit on error, undefined variables)
# Usage: setup_error_handling
setup_error_handling() {
    set -euo pipefail
}

# ============================================================
# Server Cleanup (for deployment scripts)
# ============================================================

# Clean up Hetzner server on error
# Usage: setup_server_cleanup_trap "server_id"
setup_server_cleanup_trap() {
    # Store server_id in a global variable so trap can access it
    CLEANUP_SERVER_ID="$1"
    CLEANUP_DONE=false

    # shellcheck disable=SC2329
    cleanup_server() {
        local exit_code="$?"

        # Prevent double cleanup (trap fires on both ERR and EXIT)
        if [ "$CLEANUP_DONE" = true ]; then
            return 0
        fi
        CLEANUP_DONE=true

        # Only cleanup on error (non-zero exit code)
        if [ "$exit_code" -ne 0 ]; then
            echo ""
            echo_warn "Deployment failed! Cleaning up..."
            echo_info "Deleting server $CLEANUP_SERVER_ID..."
            if hcloud server delete "$CLEANUP_SERVER_ID" 2>/dev/null; then
                echo_info "Server deleted successfully."
            else
                echo_error "Failed to delete server automatically."
                echo_error "Please manually delete: hcloud server delete $CLEANUP_SERVER_ID"
            fi
        fi
        cleanup_temp_files
    }

    # Trap both ERR and EXIT to catch all failure modes
    trap cleanup_server ERR EXIT
}

# ============================================================
# Validation Messages
# ============================================================

# Validate and provide helpful error for common issues
# Usage: validate_with_message <condition> "error message"
validate_or_fail() {
    local condition="$1"
    local message="$2"

    if ! eval "$condition"; then
        fatal_error "$message"
    fi
}

# ============================================================
# Library Initialization
# ============================================================

# This runs when the library is sourced
# Set up basic error handling
setup_error_handling
setup_cleanup_trap

# Export functions for use in subshells if needed
export -f echo_info echo_warn echo_error fatal_error
export -f command_exists check_dependencies
export -f read_toml_value read_toml_default read_toml_array
export -f validate_ip validate_safe_string validate_server_id
export -f create_temp_file create_temp_dir cleanup_temp_files
