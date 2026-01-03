#!/bin/bash
# Fix missing api_base_url for local mode sources in multi-source dashboard

echo "=== Fixing Multi-Source Dashboard Configuration ==="
echo

CONFIG_FILE="/opt/cowrie/etc/datasources.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[!] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo "1. Current configuration:"
cat "$CONFIG_FILE" | jq '.'

echo
echo "2. Adding api_base_url to local mode sources..."

# Use jq to add api_base_url to all sources that have mode="local" but no api_base_url
jq '
  map(
    if .mode == "local" and (.api_base_url == null or .api_base_url == "") then
      . + {"api_base_url": "http://localhost:8000"}
    else
      .
    end
  )
' "$CONFIG_FILE" > "$CONFIG_FILE.tmp"

mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"

echo "3. Updated configuration:"
cat "$CONFIG_FILE" | jq '.'

echo
echo "4. Restarting web dashboard..."
cd /opt/cowrie
docker compose -f docker-compose.yml -f docker-compose.web-dashboard.yml restart web-dashboard

echo
echo "✓ Fix applied! Refresh your browser to see both honeypots."
