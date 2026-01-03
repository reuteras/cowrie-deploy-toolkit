#!/bin/bash
# Quick diagnostic script to check API environment variables on deployed honeypot

echo "=== Checking API Environment Variables ==="
echo

echo "1. Values in docker-compose.api.yml:"
grep -E "SERVER_IP=|HONEYPOT_HOSTNAME=" /opt/cowrie/docker-compose.api.yml

echo
echo "2. Environment variables in running API container:"
docker exec cowrie-api env | grep -E "SERVER_IP=|HONEYPOT_HOSTNAME="

echo
echo "3. Testing API endpoint:"
curl -s http://localhost:8000/api/v1/system-info | jq '{server_ip, honeypot_hostname}'

echo
echo "=== If values show PLACEHOLDER or are empty ==="
echo "Run this fix:"
echo
echo "cd /opt/cowrie"
echo "# Get current server IP"
echo "export SERVER_IP=\$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print \$2}' | cut -d/ -f1)"
echo "# Get hostname from deployment.conf or set manually"
echo "export HONEYPOT_HOSTNAME=dmz-web-01  # CHANGE THIS"
echo
echo "# Fix docker-compose.api.yml"
echo "sed -i \"s|SERVER_IP_PLACEHOLDER|\$SERVER_IP|g\" /opt/cowrie/docker-compose.api.yml"
echo "sed -i \"s|HONEYPOT_HOSTNAME_PLACEHOLDER|\$HONEYPOT_HOSTNAME|g\" /opt/cowrie/docker-compose.api.yml"
echo
echo "# Restart API container"
echo "docker compose -f docker-compose.yml -f docker-compose.api.yml up -d cowrie-api"
