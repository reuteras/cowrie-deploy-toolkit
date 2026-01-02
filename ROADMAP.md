# Roadmap

Future enhancements for the Cowrie honeypot deployment toolkit.

## Phase 1: Daily Email Reports with Threat Intelligence ✅ COMPLETED

The first milestone combines daily reporting with essential threat intelligence enrichment.

**Implementation:**
- `scripts/daily-report.py` - Full-featured reporting system with threat intelligence
- `scripts/process-config.py` - Master config processor with command execution
- `example-config.toml` - Template configuration with TOML format
- **Automated deployment integration** - Fully automated setup via `deploy_cowrie_honeypot.sh`

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

- [x] Integration with Scaleway API for reliability
- [x] HTML email with inline styling (no external dependencies)
- [x] Cron job: `0 6 * * * /opt/cowrie/scripts/daily-report.py`

### Master Configuration System
- [x] TOML-based configuration (`master-config.toml`)
- [x] Command execution for secret management
  - 1Password CLI (`op read op://...`)
  - pass, vault, AWS Secrets Manager
- [x] Config processor (`scripts/process-config.py`)
- [x] Integration with deployment script
- [x] Automatic MaxMind GeoIP setup with weekly updates
- [x] Automatic Postfix configuration for Scaleway Transactional Email
- [x] Configurable reporting intervals and thresholds

## Phase 2: Dashboard & Visualization ✅ COMPLETED

### Custom Flask Web Dashboard
- [x] Simple Flask web app
- [x] Read from JSON logs directly
- [x] Display features:
  - [x] Dashboard with attack statistics
  - [x] Recent sessions with TTY replay capability (asciinema-player)
  - [x] GeoIP integration with ASN data
  - [x] Top attackers by country, IP, credentials
  - [x] Downloaded file browser with VirusTotal links and YARA matches
  - [x] Session filtering by IP, username, date range
  - [x] Integration with email reports (session links)
  - [x] Tailscale Serve for HTTPS access
  - [x] Docker deployment with security hardening

## Phase 3: Extended Features & Integrations

### Log Management
- [ ] Ship logs to central syslog server
- [ ] S3/MinIO backup for long-term storage
- [ ] Log rotation configuration
- [ ] Retention policies (e.g., 90 days on-disk, 1 year archived)
- [ ] ElasticSearch/OpenSearch integration for advanced querying

### Extended Threat Intelligence ⚡ PARTIALLY COMPLETED

Completed integrations:
- [x] VirusTotal with extended threat intelligence (threat labels, categories, families)

- [x] DShield (SANS ISC) data sharing
- [x] MaxMind GeoIP with ASN enrichment
- [x] YARA scanning with real-time daemon (YARA Forge ruleset)

Future integrations:
- [ ] AbuseIPDB reputation lookup and reporting
- [ ] Shodan host information enrichment
- [ ] AlienVault OTX pulse correlation
- [ ] MISP event creation and sharing
- [ ] Hybrid Analysis sandbox submission
- [ ] URLhaus malicious URL correlation

## Phase 4: Security Hardening & Code Quality ⚡ PARTIALLY COMPLETED

Based on security analysis, the following improvements have been implemented or are planned:

### Critical Security Fixes
- [x] **COMPLETED**: Replace sed/grep TOML parsing with proper TOML parser
  - Implemented `scripts/read-toml.py` using Python's builtin `tomllib` (Python 3.11+)
  - Eliminates shell injection risks from TOML parsing
- [x] **COMPLETED**: Add input validation for TOML config values
  - Implemented validation functions: `validate_ip`, `validate_safe_string`, `validate_server_id`
  - Deployed in all scripts that process user/config input
- [ ] Whitelist and validate secret manager commands (currently only checks for "op read" prefix)
- [ ] Add checksum verification for downloaded scripts (Docker install, Tailscale)
- [ ] Implement proper SSH host key verification instead of `-o StrictHostKeyChecking=no`

### Code Quality Improvements ✅ MOSTLY COMPLETED
- [x] **COMPLETED**: Add dependency checking (jq, nc, tar, hcloud) before execution
  - Created `check_dependencies` function in `scripts/common.sh`
  - All deployment scripts now fail fast with helpful messages if dependencies are missing
- [x] **COMPLETED**: Extract common SSH connection options into variables
  - Implemented `ssh_exec`, `scp_copy`, `wait_for_ssh` helper functions
  - Centralized SSH options in `scripts/common.sh`
- [x] **COMPLETED**: Consolidate TOML parsing logic into shared functions
  - Created `read_toml_value` and `read_toml_default` functions
  - All scripts use unified TOML reading approach
- [x] **COMPLETED**: Improve error messages with specific failure details
  - Implemented color-coded output: `echo_info`, `echo_warn`, `echo_error`, `fatal_error`
  - Standardized error messages across all scripts
- [x] **COMPLETED**: Add cleanup traps for all temporary files
  - Created `create_temp_file`, `create_temp_dir`, `cleanup_temp_files` functions
  - Automatic cleanup on EXIT, INT, TERM signals
  - Secure random temp file names using `mktemp`
- [x] **COMPLETED**: Configurable paths via master-config.toml
  - Added `[advanced.paths]` section to `example-config.toml`
  - Eliminates hardcoded paths throughout the codebase
- [x] **PARTIALLY COMPLETED**: Replace fixed sleep statements with service readiness polling
  - Implemented `wait_for_ssh` function with timeout and exponential backoff
  - Fixed sleeps still used in some deployment steps (can be improved)
- [ ] Add comprehensive logging of deployment actions to syslog

### Web Dashboard Security ⚡ PARTIALLY COMPLETED
- [x] **COMPLETED**: Password-protected ZIP downloads for malware samples
  - Implemented using pyzipper with AES encryption
  - Standard password: "infected" (malware research convention)
- [x] **COMPLETED**: XSS protection verified (Jinja2 auto-escaping enabled by default)
- [ ] Add rate limiting to API endpoints
- [ ] Add CSRF tokens for any write operations (currently read-only dashboard)
- [ ] Add authentication layer for production deployments (currently secured via Tailscale)

## Phase 5: Honeypot Enhancements

### Additional Realism ⚡ PARTIALLY COMPLETED

Completed:
- [x] WordPress with fake corporate blog database
- [x] MySQL/MariaDB with realistic wp-config.php
- [x] Canary Token integration (MySQL dump, Excel, PDF)
- [x] Custom txtcmds for realistic command output
- [x] Process list with nginx and MySQL

Future enhancements:
- [ ] More custom txtcmds (df, free, top, netstat with realistic data)
- [ ] Realistic cron jobs in process list
- [ ] Multiple fake user home directories with SSH keys and files
- [ ] Web honeypot on port 80/443 (nginx with fake admin panels, phpMyAdmin)
- [ ] Fake .git repositories with commit history
- [ ] Fake CI/CD configuration files (.github/workflows, .gitlab-ci.yml)
- [ ] Additional Canary Token types (AWS credentials, Kubeconfig, browser saved passwords)

### Multiple Honeypot Deployment

- [ ] Deploy fleet across multiple Hetzner locations
- [ ] Centralized log collection with aggregation dashboard
- [ ] Configuration management (Ansible playbooks)
- [ ] Automated honeypot rotation (destroy and redeploy weekly)
- [ ] Distributed intelligence sharing between honeypots

## Phase 6: Advanced Analytics

### Machine Learning & Behavioral Analysis
- [ ] Anomaly detection for unusual attack patterns
- [ ] Attacker profiling and tracking across sessions
- [ ] Automated IOC extraction and threat hunting
- [ ] Predictive analytics for attack forecasting
- [ ] Clustering of similar attack campaigns

### Advanced Visualizations
- [ ] Interactive attack timeline with D3.js
- [ ] Geospatial heatmap of attacks over time
- [ ] Network graph of attacker infrastructure
- [ ] Credential wordcloud with frequency analysis
- [ ] Command execution flow diagrams

