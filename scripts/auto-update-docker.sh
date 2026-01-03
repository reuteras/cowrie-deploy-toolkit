#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Auto-Update Docker Images for Cowrie Honeypot
# ============================================================
# This script pulls the latest Docker images and recreates
# containers if updates are available. Safe to run from cron.
#
# Installation:
#   Place in /opt/cowrie/scripts/auto-update-docker.sh
#   Add to crontab: 0 3 * * * /opt/cowrie/scripts/auto-update-docker.sh
#
# The script will:
#   1. Pull latest images (cowrie/cowrie:latest)
#   2. Compare image IDs to detect updates
#   3. Recreate containers if new images are available
#   4. Log all actions to /var/log/cowrie-auto-update.log
# ============================================================

LOG_FILE="/var/log/cowrie-auto-update.log"
COMPOSE_DIR="/opt/cowrie"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log "ERROR: This script must be run as root"
    exit 1
fi

# Check if docker compose directory exists
if [ ! -d "$COMPOSE_DIR" ]; then
    log "ERROR: Docker compose directory not found: $COMPOSE_DIR"
    exit 1
fi

cd "$COMPOSE_DIR"

# Check if docker-compose.yml exists
if [ ! -f docker-compose.yml ]; then
    log "ERROR: docker-compose.yml not found in $COMPOSE_DIR"
    exit 1
fi

log "Starting auto-update check..."

# ============================================================
# Step 1: Update images based on available services
# ============================================================

# Get list of services in main docker-compose.yml
AVAILABLE_SERVICES=$(docker compose config --services 2>/dev/null || echo "")

# Pull cowrie image (now using pre-built from GHCR)
if echo "$AVAILABLE_SERVICES" | grep -q "^cowrie$"; then
    log "Pulling Cowrie image from registry..."
    if ! docker compose pull cowrie >> "$LOG_FILE" 2>&1 ; then
        log "ERROR: Failed to pull Cowrie image"
        exit 1
    fi
else
    log "WARNING: cowrie service not found in docker-compose.yml"
fi

# Pull cowrie-web image if service exists
if echo "$AVAILABLE_SERVICES" | grep -q "^cowrie-web$"; then
    log "Pulling cowrie-web image from registry..."
    if ! docker compose pull cowrie-web >> "$LOG_FILE" 2>&1 ; then
        log "ERROR: Failed to pull web dashboard image"
        exit 1
    fi
else
    log "cowrie-web service not found, skipping..."
fi

# Handle cowrie-api if docker-compose.api.yml exists
if [ -f "docker-compose.api.yml" ]; then
    API_SERVICES=$(docker compose -f docker-compose.yml -f docker-compose.api.yml config --services 2>/dev/null || echo "")
    if echo "$API_SERVICES" | grep -q "^cowrie-api$"; then
        log "Pulling cowrie-api image from registry..."
        if ! docker compose -f docker-compose.yml -f docker-compose.api.yml pull cowrie-api >> "$LOG_FILE" 2>&1 ; then
            log "ERROR: Failed to pull API image"
            exit 1
        fi

# Note: cowrie-api now uses pre-built images from GHCR, no local build needed
    fi
else
    log "docker-compose.api.yml not found, skipping API updates..."
fi

# ============================================================
# Step 2: Recreate containers (only if images changed)
# ============================================================
log "Updating containers..."

# Update main containers
if docker compose up -d >> "$LOG_FILE" 2>&1 ; then
    log "Main containers updated successfully"
else
    log "ERROR: Failed to update main containers"
    exit 1
fi

# Update API containers if they exist
if [ -f "docker-compose.api.yml" ]; then
    if docker compose -f docker-compose.yml -f docker-compose.api.yml up -d >> "$LOG_FILE" 2>&1 ; then
        log "API containers updated successfully"
    else
        log "ERROR: Failed to update API containers"
        exit 1
    fi
fi

# Wait a few seconds for containers to start
sleep 5

# Clean up old images
log "Cleaning up old images..."
docker image prune -f >> "$LOG_FILE" 2>&1

log "Auto-update completed successfully"

# ============================================================
# Step 5: Health check
# ============================================================
log "Running health check..."


# Wait before check
sleep 5

# Check if Cowrie container is running
if docker ps --filter "name=cowrie" --filter "status=running" | grep -q cowrie; then
    log "✓ Cowrie container is running"
else
    log "ERROR: Cowrie container is not running!"
    docker compose ps >> "$LOG_FILE" 2>&1
    exit 1
fi

# Check if web dashboard is running (if it exists)
if echo "$AVAILABLE_SERVICES" | grep -q "^cowrie-web$"; then
    if docker ps --filter "name=cowrie-web" --filter "status=running" | grep -q cowrie-web; then
        log "✓ Web dashboard is running"
    else
        log "WARNING: Web dashboard container is not running"
    fi
fi

# Check if API is running (if docker-compose.api.yml exists)
if [ -f "docker-compose.api.yml" ]; then
    if docker ps --filter "name=cowrie-api" --filter "status=running" | grep -q cowrie-api; then
        log "✓ API container is running"
    else
        log "WARNING: API container is not running"
    fi
fi

log "Auto-update check completed"

exit 0
