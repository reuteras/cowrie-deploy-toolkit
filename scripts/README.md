# Cowrie Daily Report System

Automated daily reporting with threat intelligence enrichment for Cowrie honeypots.

## Features

- **Log Analysis**: Parse Cowrie JSON logs for connections, credentials, commands, and downloads
- **GeoIP Enrichment**: Country, city, ASN, and organization lookup using MaxMind GeoLite2
- **VirusTotal Integration**: Malware detection for downloaded files with caching
- **YARA Scanning**: Local malware classification using YARA rules
- **Email Delivery**: Via local Postfix with HTML formatting

## Quick Setup

**✨ NEW: Fully automated deployment using `master-config.toml`**

1. Copy the example config: `cp example-config.toml master-config.toml`
2. Edit `master-config.toml` with your API keys and settings
3. Set `enable_reporting = true` in the `[honeypot]` section
4. Run `./deploy_cowrie_honeypot.sh ./output_YYYYMMDD_HHMMSS`

The deployment script automatically:
- Sets up MaxMind GeoIP with weekly auto-updates
- Configures Postfix for email delivery
- Installs all Python dependencies with uv
- Configures daily cron job for reports

**That's it!** No manual configuration needed. See `example-config.toml` for all options.

## Report Example

The daily report includes:

### Summary Statistics

- Total connections
- Unique IP addresses
- Sessions with commands executed
- Files downloaded
- Average session duration

### Top Attacking Countries

Geographic distribution of attacks with:

- Country name
- Number of connections
- Percentage of total attacks

### Top Credentials

Most frequently attempted username:password combinations

### Downloaded Files (Malware Analysis)

For each downloaded file:

- SHA256 hash
- File size
- YARA rule matches (malware family, packer, etc.)
- VirusTotal detection ratio (e.g., "45/70 engines")
- Link to full VirusTotal report

### Notable Commands

Commands executed by attackers, including:

- Source IP address
- Full command line
- Timestamp

## Troubleshooting

### No logs found

```bash
# Verify log path
ls -la /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json

# Check if Cowrie is running
docker ps | grep cowrie

# Check Cowrie logs
docker logs cowrie
```

### GeoIP errors

```bash
# Verify database files exist (Debian default location)
ls -la /var/lib/GeoIP/

# Download databases if missing
# See installation section above
```

### YARA errors

```bash
# Test YARA installation
yara --version

# Validate rules
yara -r /opt/cowrie/yara-rules/ /bin/ls

# Check for syntax errors in rules
for rule in /opt/cowrie/yara-rules/*.yar; do
    echo "Testing $rule"
    yara "$rule" /bin/ls || echo "ERROR in $rule"
done
```

# Check logs
journalctl -t cowrie-report
```

### VirusTotal API limits

The free tier allows 4 requests per minute. The script caches results in SQLite to avoid re-querying:

```bash
# Check cache
sqlite3 /opt/cowrie/var/report-cache.db "SELECT COUNT(*) FROM vt_cache;"

# Clear cache if needed
rm /opt/cowrie/var/report-cache.db
```

## Deployment Integration

**✨ Automated deployment is now built-in!**

Reporting is automatically configured when you deploy a honeypot with `enable_reporting = true` in `master-config.toml`. The deployment script handles:

- Installing uv and Python dependencies
- Setting up MaxMind GeoIP with auto-updates
- Configuring Postfix for email delivery
- Creating cron job for daily reports

No manual steps needed! See the main [README.md](../README.md) for deployment instructions.

## Advanced Configuration

### Custom YARA Rules

Add your own rules to `/opt/cowrie/yara-rules/custom.yar`:

```yara
rule Suspicious_Cryptocurrency_Miner {
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "Your Name"

    strings:
        $xmrig = "xmrig" nocase
        $minerd = "minerd" nocase
        $stratum = "stratum+tcp://" nocase

    condition:
        any of them
}
```

### Multiple Honeypots

For centralized reporting from multiple honeypots:

1. Set up a central log collection server
2. Ship logs via syslog or rsync
3. Run daily-report.py on the central server
4. Configure separate email subjects per honeypot

```bash
# On honeypot: ship logs to central server
rsync -az /var/lib/docker/volumes/cowrie-var/_data/ central-server:/logs/honeypot-1/

# On central server: run reports for each honeypot
python3 daily-report.py --config /etc/cowrie/honeypot-1-config.json
python3 daily-report.py --config /etc/cowrie/honeypot-2-config.json
```

## Security Considerations

1. **Protect API Keys**: Never commit `report.env` or `report-config.json` to version control
2. **Secure Permissions**: `chmod 600` on configuration files
3. **VirusTotal Rate Limits**: Free tier is 4 req/min. Caching prevents excessive queries.

## License

MIT (same as parent project)
