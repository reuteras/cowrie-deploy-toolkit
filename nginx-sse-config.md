# Nginx Configuration for Live Dashboard SSE Support

If you're accessing the Cowrie web dashboard via an nginx reverse proxy, you need special configuration for the live attack map to work. The live map uses **Server-Sent Events (SSE)** for real-time streaming, which requires disabling nginx buffering.

## Configuration

Add this to your nginx server block (where you're proxying to the Cowrie dashboard):

```nginx
server {
    listen 443 ssl http2;
    server_name your-server.com;

    # Your existing SSL certificates
    ssl_certificate /etc/letsencrypt/live/your-server.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-server.com/privkey.pem;

    # SSE endpoint for live attack map - CRITICAL SETTINGS
    location /api/attack-stream {
        # Proxy to honeypot via Tailscale
        proxy_pass https://<tailscale_name>.<tailscale_domain>/api/attack-stream;

        # REQUIRED: Disable buffering for SSE
        proxy_buffering off;

        # REQUIRED: Keep connection alive
        proxy_http_version 1.1;
        proxy_set_header Connection '';

        # REQUIRED: Set chunked transfer encoding
        chunked_transfer_encoding on;

        # Headers for proper proxying
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Disable caching for live data
        proxy_cache off;
        proxy_no_cache 1;
        proxy_cache_bypass 1;

        # Extended timeouts for long-lived connections
        proxy_connect_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;

        # Content type
        proxy_set_header Accept text/event-stream;
    }

    # General dashboard proxy (all other routes)
    location / {
        # Proxy to honeypot via Tailscale
        proxy_pass https://<tailscale_name>.<tailscale_domain>;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Standard timeouts for regular requests
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Canary webhook endpoint (if enabled)
    location /webhook/canary {
        limit_req zone=canary_limit burst=5 nodelay;
        proxy_pass https://<tailscale_name>.<tailscale_domain>/webhook/canary;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
}
```

## Key Points

### Why SSE needs special configuration

1. **`proxy_buffering off`** - CRITICAL: nginx buffers responses by default. This breaks SSE because events are buffered and not sent to the client immediately.

2. **`proxy_http_version 1.1`** - SSE requires HTTP/1.1 for persistent connections

3. **`proxy_set_header Connection ''`** - Prevents nginx from closing the connection

4. **`chunked_transfer_encoding on`** - Enables chunked transfer for streaming data

5. **Extended timeouts** - SSE connections stay open for hours. Default nginx timeout (60s) would close the connection.

### Testing the configuration

1. Apply the configuration:
   ```bash
   nginx -t
   systemctl reload nginx
   ```

2. Visit the live attack map:
   ```
   https://your-server.com/attack-map
   ```

3. Click "📡 Go Live" - you should see:
   - Mode indicator changes to "🔴 LIVE"
   - Live clock updates every second
   - Real-time attacks appear as they happen

4. Check browser developer console (F12):
   ```javascript
   // Should see:
   // SSE stream connected: Live stream connected
   ```

### Troubleshooting

**Problem:** Live mode shows "🔄 Reconnecting..." repeatedly

**Solution:** Check nginx error log:
```bash
tail -f /var/log/nginx/error.log
```

**Common issues:**
- Missing `proxy_buffering off` - Events don't stream
- Timeout too short - Connection closes after 60s
- Missing HTTP/1.1 - Connection doesn't upgrade properly
- SSL/TLS issues - Check certificate validity

**Problem:** "Connection Failed - Max retries exceeded"

**Solution:** Ensure:
1. Tailscale is running on proxy server: `tailscale status`
2. Dashboard is accessible: `curl https://<tailscale_name>.<tailscale_domain>/api/attack-stream`
3. nginx can resolve Tailscale hostname

## Minimal Configuration (Just SSE)

If you only want to fix the SSE issue and already have other routes configured:

```nginx
location /api/attack-stream {
    proxy_pass https://<tailscale_name>.<tailscale_domain>/api/attack-stream;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    chunked_transfer_encoding on;
    proxy_read_timeout 3600s;
}
```

This is the absolute minimum needed for SSE to work through nginx.
