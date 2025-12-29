# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-12-27

### Added

- **OS Version Decoupling**: Generate filesystem on one Debian version, deploy on another
  - `generation_image` and `deployment_image` configuration fields
  - `source_metadata.json` tracks generation OS version
  - Automatic compatibility validation with warnings for large version gaps
  - Enables using EOL Debian versions for realism while running on modern versions for security

- **FastAPI Layer**: RESTful API for remote access to Cowrie data
  - API endpoints for sessions, downloads, stats, threat intelligence
  - Read-only access with security hardening (dropped capabilities, read-only filesystem)
  - GeoIP and VirusTotal integration
  - TTY recording retrieval in asciicast format
  - Health check endpoint
  - See [api/README.md](api/README.md) for full documentation

- **Multi-Host Dashboard**: Centralized monitoring from multiple honeypots
  - Dashboard modes: `local` (direct files), `remote` (single API), `multi` (aggregate multiple)
  - Multi-source support with parallel querying
  - Source filtering and tagging
  - Graceful degradation when sources are offline
  - Extensible architecture for future honeypot types (web, VPN, database)
  - `web/datasource.py`: DataSource abstraction layer
  - `web/multisource.py`: Multi-source aggregation with concurrent queries

- **Configuration Enhancements**:
  - `[api]` section for API configuration
  - `[web_dashboard]` section with mode selection
  - `[[web_dashboard.sources]]` arrays for multi-source configuration
  - `expose_via_tailscale` option for API
  - `tailscale_api_hostname` for custom API hostnames

- **Documentation**:
  - [api/README.md](api/README.md): Complete API documentation
  - Multi-honeypot deployment examples in README.md
  - Helper script examples for multi-deployment workflows

### Changed

- **BREAKING**: Tailscale VPN is now REQUIRED (no longer optional)
  - Removed `enabled` field from `[tailscale]` section (always enabled)
  - Removed `block_public_ssh` field (warnings only, no firewall blocking)
  - `authkey` field is now REQUIRED
  - `tailscale_domain` field is now REQUIRED
  - Simplified deployment with ~150 lines of conditional logic removed
  - Pre-flight validation ensures Tailscale configuration before deployment

- **BREAKING**: Configuration schema changes
  - `server_image` deprecated in favor of `generation_image` and `deployment_image`
  - New required fields: `tailscale.authkey`, `tailscale.domain`
  - Dashboard configuration moved to dedicated `[web_dashboard]` section

- Updated README.md with v2.1 features and multi-honeypot examples
- Compacted CLAUDE.md from 1199 to 514 lines while preserving all essential information

### Removed

- MIGRATION.md (no external users, migration guide not needed)
- Conditional Tailscale logic from deployment scripts
- `enabled` and `block_public_ssh` from Tailscale configuration

### Fixed

- Version alignment: pyproject.toml now matches documentation references

## [2.0.0] - 2025-XX-XX

### Added

- **IP-Locked Credential Authentication**: Enhanced anti-fingerprinting
  - IPs locked to first successful credentials
  - `output_iplock.py` Cowrie plugin
  - SQLite database: `/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/iplock.db`
  - Tracks violations and authentication attempts
  - Persistent across container restarts

- **Enhanced Honeypot Realism**:
  - WordPress installation with fake corporate blog
  - MySQL/MariaDB database with realistic content
  - Database credentials in wp-config.php
  - Process list shows MySQL and nginx services

- **Canary Tokens Integration**:
  - Support for PDF, Excel, and MySQL dump tokens
  - Automatic embedding during filesystem generation
  - Enticing filenames (Q1_Financial_Report.xlsx, Network_Passwords.pdf)
  - Webhook receiver for immediate exfiltration alerts
  - SQLite storage: `/opt/cowrie/var/canary-webhooks.db`
  - Dashboard integration with GeoIP enrichment

- **Web Dashboard**:
  - Flask-based interactive interface
  - TTY session playback with asciinema-player
  - Live attack map with geographic visualization
  - Session browser with filtering
  - Malware downloads browser with VirusTotal + YARA
  - System information display
  - GeoIP integration with ASN data
  - Email report session links

- **Daily Reporting System**:
  - Automated email reports with threat intelligence
  - GeoIP enrichment (country, city, ASN, organization)
  - VirusTotal integration with threat labels
  - YARA scanning with ~1000+ rules
  - HTML and plain text formats
  - Fully automated via master-config.toml
  - Managed with [uv](https://github.com/astral-sh/uv) package manager

- **Real-Time YARA Scanning**:
  - Background daemon with inotify monitoring
  - YARA Forge full ruleset
  - SQLite caching: `/opt/cowrie/var/yara-cache.db`
  - File type detection and categorization
  - Daily rule updates (4 AM)
  - Systemd service with auto-restart

- **Threat Intelligence Integration**:
  - AbuseIPDB: IP reputation with abuse confidence scores
  - DShield: SANS Internet Storm Center data sharing
  - GreyNoise: Scanner and bot identification
  - ASN data with MaxMind GeoLite2-ASN

- **Tailscale VPN** (Optional in v2.0):
  - Zero-trust management access
  - Optional public SSH blocking
  - Tailscale SSH support
  - Web dashboard via Tailscale Serve

- **Security Enhancements**:
  - Docker security hardening (no-new-privileges, read-only, cap_drop ALL)
  - Automatic security updates
  - Read-only container filesystems
  - tmpfs for temporary files

### Changed

- Deployment scripts use TOML configuration (master-config.toml)
- Command execution support for secrets (1Password, vault, etc.)
- MaxMind GeoIP with weekly auto-updates
- Postfix email delivery configuration

### Fixed

- Various deployment script improvements
- Error handling and validation

## [1.0.0] - 2025-XX-XX

### Added

- Initial release
- Hetzner Cloud deployment automation
- Realistic Debian filesystem capture
- Anti-fingerprinting features
- SSH banner and kernel version spoofing
- Real file contents (/etc/passwd, configs)
- Automated deployment scripts
- Docker containerization
- Basic configuration via script variables

[2.1.0]: https://github.com/reuteras/cowrie-deploy-toolkit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/reuteras/cowrie-deploy-toolkit/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/reuteras/cowrie-deploy-toolkit/releases/tag/v1.0.0
