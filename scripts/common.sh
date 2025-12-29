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

        # Prevent double cleanup (trap fires on multiple signals)
        if [ "$CLEANUP_DONE" = true ]; then
            return 0
        fi
        CLEANUP_DONE=true

        # Only cleanup on error (non-zero exit code) or interrupt
        # Exit code 130 = SIGINT (Ctrl+C), 143 = SIGTERM
        if [ "$exit_code" -ne 0 ]; then
            echo ""
            if [ "$exit_code" -eq 130 ]; then
                echo_warn "Script interrupted (Ctrl+C)! Cleaning up..."
            else
                echo_warn "Deployment failed! Cleaning up..."
            fi
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

    # Trap ERR, EXIT, INT (Ctrl+C), and TERM to catch all failure modes
    trap cleanup_server ERR EXIT INT TERM
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

# Cleanup old Tailscale device with same hostname
# Usage: cleanup_tailscale_device "hostname" "tailscale_domain" "api_key"
cleanup_tailscale_device() {
    local hostname="$1"
    local domain="$2"
    local api_key="$3"

    # Extract tailnet from domain (e.g., "tail12345" from "tail12345.ts.net")
    local tailnet="${domain%%.*}"

    if [ -z "$tailnet" ]; then
        echo_warn "Could not extract tailnet from domain: $domain"
        return 1
    fi

    echo_info "Searching for existing device: $hostname in tailnet: $tailnet"

    # List all devices in the tailnet
    local devices_json
    devices_json=$(curl -s -H "Authorization: Bearer $api_key" \
        "https://api.tailscale.com/api/v2/tailnet/$tailnet/devices" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$devices_json" ]; then
        echo_warn "Failed to fetch devices from Tailscale API"
        return 1
    fi

    # Find device IDs matching the hostname (could be multiple: hostname, hostname-1, hostname-2, etc)
    local device_ids
    device_ids=$(echo "$devices_json" | jq -r --arg name "$hostname" \
        '.devices[] | select(.hostname == $name or (.hostname | startswith($name + "-"))) | .id' 2>/dev/null)

    if [ -z "$device_ids" ]; then
        echo_info "No existing devices found with hostname: $hostname"
        return 0
    fi

    # Delete each matching device
    local count=0
    while IFS= read -r device_id; do
        if [ -n "$device_id" ]; then
            local device_name
            device_name=$(echo "$devices_json" | jq -r --arg id "$device_id" \
                '.devices[] | select(.id == $id) | .hostname' 2>/dev/null)

            echo_info "Deleting device: $device_name (ID: $device_id)"

            local delete_result
            delete_result=$(curl -s -X DELETE -H "Authorization: Bearer $api_key" \
                "https://api.tailscale.com/api/v2/device/$device_id" 2>/dev/null)

            if [ $? -eq 0 ]; then
                echo_info "Successfully deleted device: $device_name"
                ((count++))
            else
                echo_warn "Failed to delete device: $device_name"
            fi
        fi
    done <<< "$device_ids"

    if [ $count -gt 0 ]; then
        echo_info "Cleaned up $count old device(s)"
    fi

    return 0
}

# Validate Tailscale configuration (NEW in v2.1)
# Usage: validate_tailscale_config <authkey> <tailscale_domain>
validate_tailscale_config() {
    local authkey="$1"
    local tailscale_domain="$2"

    # Check authkey is provided
    if [ -z "$authkey" ]; then
        fatal_error "Tailscale authkey is REQUIRED but not set in master-config.toml

Generate an authkey at: https://login.tailscale.com/admin/settings/keys
Add to master-config.toml:
  [tailscale]
  authkey = \"tskey-auth-...\""
    fi

    # Check authkey format
    if [[ ! "$authkey" =~ ^tskey- ]]; then
        fatal_error "Invalid Tailscale authkey format. Expected: tskey-auth-...

Current value: $authkey

Generate a valid authkey at: https://login.tailscale.com/admin/settings/keys"
    fi

    # Check tailscale_domain is provided
    if [ -z "$tailscale_domain" ]; then
        fatal_error "Tailscale domain is REQUIRED but not set in master-config.toml

Find your Tailscale domain at: https://login.tailscale.com/admin/dns
Add to master-config.toml:
  [tailscale]
  tailscale_domain = \"your-tailnet.ts.net\""
    fi

    # Check domain format (warn only, don't fail)
    if [[ ! "$tailscale_domain" =~ \.ts\.net$ ]]; then
        echo_warn "Warning: Tailscale domain doesn't end with .ts.net: $tailscale_domain"
        echo_warn "This may be correct for custom domains, but double-check"
    fi
}

# ============================================================
# Honeypot Configuration Functions (NEW in v2.1)
# ============================================================

# Check if honeypots array exists in config
# Usage: has_honeypots_array "config.toml"
# Returns: "true" or "false"
has_honeypots_array() {
    local toml_file="$1"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    python3 "$script_dir/get-honeypot-config.py" "$toml_file" --has-array 2>/dev/null || echo "false"
}

# Get count of honeypots in config
# Usage: get_honeypot_count "config.toml"
# Returns: number of honeypots
get_honeypot_count() {
    local toml_file="$1"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    python3 "$script_dir/get-honeypot-config.py" "$toml_file" --count 2>/dev/null || echo "0"
}

# Get list of honeypot names
# Usage: get_honeypot_names "config.toml" array_var_name
# Example: get_honeypot_names "config.toml" HONEYPOT_NAMES
get_honeypot_names() {
    local toml_file="$1"
    local -n array_ref="$2"  # nameref to the array variable
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    array_ref=()  # Clear the array

    # Read names line by line into array
    while IFS= read -r name; do
        if [ -n "$name" ]; then
            array_ref+=("$name")
        fi
    done < <(python3 "$script_dir/get-honeypot-config.py" "$toml_file" --list 2>/dev/null)
}

# Get honeypot configuration (merged with shared settings)
# Usage: get_honeypot_config "config.toml" "honeypot-name"
# Returns: JSON configuration
get_honeypot_config() {
    local toml_file="$1"
    local name="$2"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    python3 "$script_dir/get-honeypot-config.py" "$toml_file" --name "$name" 2>/dev/null
}


# Read value from JSON config using jq
# Usage: get_json_value "$json" ".key.path"
# Returns: value or empty string if not found
get_json_value() {
    local json="$1"
    local key_path="$2"

    echo "$json" | jq -r "$key_path // empty" 2>/dev/null || echo ""
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
export -f validate_ip validate_safe_string validate_server_id validate_tailscale_config cleanup_tailscale_device
export -f create_temp_file create_temp_dir cleanup_temp_files
export -f has_honeypots_array get_honeypot_count get_honeypot_names get_honeypot_config get_json_value
