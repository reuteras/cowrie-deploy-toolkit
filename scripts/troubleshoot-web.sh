#!/usr/bin/env bash
#
# Troubleshoot Web Dashboard Issues
#
# This script helps diagnose why the web dashboard isn't accessible
#

set -euo pipefail

echo "=== Cowrie Web Dashboard Troubleshooting ==="
echo ""

# Check if we're on the honeypot server
if [ ! -d "/opt/cowrie" ]; then
    echo "ERROR: This script should be run on the honeypot server"
    echo "Run: ssh -p 2222 root@<TAILSCALE_IP> 'bash /opt/cowrie/scripts/troubleshoot-web.sh'"
    exit 1
fi

cd /opt/cowrie

echo "1. Docker Container Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker compose ps
echo ""

echo "2. Tailscale Serve Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
if command -v tailscale &>/dev/null; then
    tailscale serve status 2>/dev/null || echo "Tailscale serve not configured"
else
    echo "Tailscale not installed"
fi
echo ""

echo "3. Test Web Dashboard (port 5000)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s http://localhost:5000/ | head -20 || echo "ERROR: Web dashboard not responding"
echo ""

echo "4. Test API (port 8000)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s http://localhost:8000/ 2>/dev/null | head -5 || echo "API not running or not accessible"
echo ""

echo "5. Check if API is enabled"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ -f docker-compose.api.yml ]; then
    echo "✓ API is enabled (docker-compose.api.yml exists)"
    grep -A2 "cowrie-api:" docker-compose.api.yml | head -5
else
    echo "✗ API is not enabled"
fi
echo ""

echo "6. Recent Web Dashboard Logs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker compose logs cowrie-web --tail=20
echo ""

if [ -f docker-compose.api.yml ]; then
    echo "7. Recent API Logs"
    echo "━━━━━━━━━━━━━━━━━━━━━━"
    docker compose -f docker-compose.yml -f docker-compose.api.yml logs cowrie-api --tail=20
    echo ""
fi

echo "8. Recommended Actions"
echo "━━━━━━━━━━━━━━━━━━━━━━"
echo ""
if ! docker compose ps | grep -q "cowrie-web.*Up"; then
    echo "⚠ Web container is not running!"
    echo "  Fix: docker compose up -d cowrie-web"
    echo ""
fi

if tailscale serve status 2>/dev/null | grep -q "localhost:8000"; then
    if ! tailscale serve status 2>/dev/null | grep -q "localhost:5000"; then
        echo "⚠ API is exposed but web dashboard is not!"
        echo "  This means / routes to API instead of dashboard"
        echo "  Fix: Run these commands:"
        echo "    tailscale serve --https=443 --bg localhost:5000"
        echo ""
    fi
fi

echo "9. Quick Fix Commands"
echo "━━━━━━━━━━━━━━━━━━━━━"
echo "Restart web container:"
echo "  docker compose restart cowrie-web"
echo ""
echo "Re-configure Tailscale routing:"
echo "  tailscale serve reset"
echo "  tailscale serve --https=443 --bg localhost:5000"
if [ -f docker-compose.api.yml ]; then
    echo "  sleep 5  # Wait for web dashboard to be ready"
    echo "  tailscale serve --https=443 --set-path=/api --bg localhost:8000"
fi
echo ""
echo "Update crontab for persistence:"
echo "  crontab -l | grep -v 'tailscale serve' | crontab -"
echo "  (crontab -l; echo '@reboot sleep 30 && /usr/bin/tailscale serve --https=443 --bg localhost:5000 > /dev/null 2>&1') | crontab -"
if [ -f docker-compose.api.yml ]; then
    echo "  (crontab -l; echo '@reboot sleep 45 && /usr/bin/tailscale serve --https=443 --set-path=/api --bg localhost:8000 > /dev/null 2>&1') | crontab -"
fi
echo ""
