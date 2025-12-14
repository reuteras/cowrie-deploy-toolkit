#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Download MaxMind GeoIP Databases Locally (with caching)
# ============================================================
# Downloads MaxMind GeoLite2 databases to local cache directory.
# Only re-downloads if cache is older than 1 day.
# Usage: ./download-maxmind-local.sh <account_id> <license_key>
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

if [ $# -ne 2 ]; then
    echo_error "Usage: $0 <account_id> <license_key>"
    echo_error "Example: $0 123456 abcdef1234567890"
    exit 1
fi

ACCOUNT_ID="$1"
LICENSE_KEY="$2"

# Cache directory in project root
CACHE_DIR="$(dirname "$SCRIPT_DIR")/.maxmind-cache"
mkdir -p "$CACHE_DIR"

DATABASES=("GeoLite2-City" "GeoLite2-ASN")
MAX_AGE_SECONDS=$((7 * 24 * 60 * 60))  # 7 days

download_database() {
    local db_name="$1"
    local db_file="$CACHE_DIR/${db_name}.mmdb"
    local download_url="https://download.maxmind.com/app/geoip_download?edition_id=${db_name}&license_key=${LICENSE_KEY}&suffix=tar.gz"

    # Check if file exists and is recent
    if [ -f "$db_file" ]; then
        local file_age=$(($(date +%s) - $(stat -f %m "$db_file" 2>/dev/null || stat -c %Y "$db_file" 2>/dev/null)))

        if [ "$file_age" -lt "$MAX_AGE_SECONDS" ]; then
            local hours_old=$((file_age / 3600))
            echo_info "$db_name is ${hours_old}h old (cached, skipping download)"
            return 0
        else
            echo_info "$db_name cache expired (>24h old), re-downloading..."
        fi
    else
        echo_info "Downloading $db_name for the first time..."
    fi

    # Download to temp directory
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    if ! curl -fsSL "$download_url" -o "$temp_dir/${db_name}.tar.gz" 2>/dev/null; then
        echo_error "Failed to download $db_name"
        return 1
    fi

    # Extract .mmdb file
    tar -xzf "$temp_dir/${db_name}.tar.gz" -C "$temp_dir"

    # Find and move the .mmdb file
    local mmdb_file=$(find "$temp_dir" -name "*.mmdb" -type f)
    if [ -z "$mmdb_file" ]; then
        echo_error "Failed to find .mmdb file in archive"
        return 1
    fi

    mv "$mmdb_file" "$db_file"
    echo_info "✓ $db_name downloaded and cached"

    rm -rf "$temp_dir"
}

echo_info "MaxMind GeoIP Database Local Cache"
echo_info "Cache directory: $CACHE_DIR"

# Download each database
for db in "${DATABASES[@]}"; do
    if ! download_database "$db"; then
        echo_error "Failed to download $db"
        exit 1
    fi
done

echo_info "✓ All databases ready in cache"
echo_info "Cache location: $CACHE_DIR"
echo_info "Cached files:"
ls -lh "$CACHE_DIR"/*.mmdb 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
