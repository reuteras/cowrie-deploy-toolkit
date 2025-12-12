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
# Step 1: Get current image IDs
# ============================================================
log "Checking current image versions..."

IMAGES=$(docker compose config --images 2>/dev/null)
if [ -z "$IMAGES" ]; then
    log "ERROR: Failed to get images from docker-compose.yml"
    exit 1
fi

# Store current image IDs
declare -A CURRENT_IMAGES
for img in $IMAGES; do
    IMAGE_ID=$(docker images --quiet "$img" 2>/dev/null || echo "")
    if [ -n "$IMAGE_ID" ]; then
        CURRENT_IMAGES["$img"]="$IMAGE_ID"
        log "Current image: $img = $IMAGE_ID"
    fi
done

# ============================================================
# Step 2: Pull latest images
# ============================================================
log "Pulling latest images..."

if ! docker compose pull --quiet 2>&1 | tee -a "$LOG_FILE"; then
    log "ERROR: Failed to pull images"
    exit 1
fi

# ============================================================
# Step 3: Check for updates
# ============================================================
log "Checking for image updates..."

UPDATES_AVAILABLE=false
for img in "${!CURRENT_IMAGES[@]}"; do
    NEW_IMAGE_ID=$(docker images --quiet "$img" 2>/dev/null || echo "")

    if [ -n "$NEW_IMAGE_ID" ] && [ "$NEW_IMAGE_ID" != "${CURRENT_IMAGES[$img]}" ]; then
        log "Update available: $img (${CURRENT_IMAGES[$img]:0:12} -> ${NEW_IMAGE_ID:0:12})"
        UPDATES_AVAILABLE=true
    else
        log "No update: $img (${CURRENT_IMAGES[$img]:0:12})"
    fi
done

# ============================================================
# Step 4: Apply updates if available
# ============================================================
if [ "$UPDATES_AVAILABLE" = "true" ]; then
    log "Applying updates..."

    # Recreate containers with new images
    if docker compose up -d --force-recreate 2>&1 | tee -a "$LOG_FILE"; then
        log "Containers recreated successfully"

        # Wait a few seconds for containers to start
        sleep 5

        # Show container status
        log "Container status:"
        docker compose ps 2>&1 | tee -a "$LOG_FILE"

        # Clean up old images
        log "Cleaning up old images..."
        docker image prune -f 2>&1 | tee -a "$LOG_FILE"

        log "Auto-update completed successfully"
    else
        log "ERROR: Failed to recreate containers"
        log "Attempting to restore service..."
        docker compose up -d 2>&1 | tee -a "$LOG_FILE"
        exit 1
    fi
else
    log "No updates available, containers are up to date"
fi

# ============================================================
# Step 5: Health check
# ============================================================
log "Running health check..."

# Check if Cowrie container is running
if docker ps --filter "name=cowrie" --filter "status=running" | grep -q cowrie; then
    log "✓ Cowrie container is running"
else
    log "ERROR: Cowrie container is not running!"
    docker compose ps 2>&1 | tee -a "$LOG_FILE"
    exit 1
fi

# Check if web dashboard is running (if it exists)
if docker compose config --services 2>/dev/null | grep -q cowrie-web; then
    if docker ps --filter "name=cowrie-web" --filter "status=running" | grep -q cowrie-web; then
        log "✓ Web dashboard is running"
    else
        log "WARNING: Web dashboard container is not running"
    fi
fi

log "Auto-update check completed"
log "---"

exit 0
