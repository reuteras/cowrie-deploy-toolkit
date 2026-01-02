#!/usr/bin/env python3
"""
Cowrie Honeypot Daily Report Generator

Generates daily reports from Cowrie JSON logs with:
- Connection statistics and top attackers
- GeoIP enrichment (MaxMind GeoLite2)
- VirusTotal malware analysis
- YARA rule scanning
- Email delivery with HTML formatting
"""

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    import geoip2.database
    import requests
    import yara
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install dependencies with: cd /opt/cowrie && uv sync")
    sys.exit(1)


class Config:
    """Configuration management for the reporting system."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.getenv("COWRIE_REPORT_CONFIG", "/opt/cowrie/etc/report-config.json")
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from file or environment variables."""
        config = {
            # Paths
            "log_path": os.getenv("COWRIE_LOG_PATH", "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json"),
            "download_path": os.getenv(
                "COWRIE_DOWNLOAD_PATH", "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"
            ),
            "geoip_db_path": os.getenv("GEOIP_DB_PATH", "/var/lib/GeoIP/GeoLite2-City.mmdb"),
            "geoip_asn_path": os.getenv("GEOIP_ASN_PATH", "/var/lib/GeoIP/GeoLite2-ASN.mmdb"),
            "yara_rules_path": os.getenv("YARA_RULES_PATH", "/opt/cowrie/yara-rules"),
            "cache_db_path": os.getenv("CACHE_DB_PATH", "/opt/cowrie/var/report-cache.db"),
            "yara_cache_db_path": os.getenv("YARA_CACHE_DB_PATH", "/opt/cowrie/var/yara-cache.db"),
            # VirusTotal
            "virustotal_api_key": os.getenv("VT_API_KEY") or "",
            "virustotal_enabled": os.getenv("VT_ENABLED", "true").lower() == "true",
            # Email settings
            "email_enabled": os.getenv("EMAIL_ENABLED", "true").lower() == "true",
            "email_from": os.getenv("EMAIL_FROM", "honeypot@example.com"),
            "email_to": os.getenv("EMAIL_TO", "admin@example.com"),
            "email_subject_prefix": os.getenv("EMAIL_SUBJECT_PREFIX", "[Honeypot]"),
            # SMTP settings
            "smtp_host": os.getenv("SMTP_HOST", "localhost"),
            "smtp_port": int(os.getenv("SMTP_PORT", "25")),
            "smtp_user": os.getenv("SMTP_USER") or None,
            "smtp_password": os.getenv("SMTP_PASSWORD") or None,
            "smtp_tls": os.getenv("SMTP_TLS", "false").lower() == "true",
            # Report settings
            "report_hours": int(os.getenv("REPORT_HOURS", "24")),
            "max_commands_per_session": int(os.getenv("MAX_COMMANDS_PER_SESSION", "20")),
            "include_map": os.getenv("INCLUDE_MAP", "true").lower() == "true",
            # Web dashboard settings
            "web_base_url": os.getenv("WEB_BASE_URL", ""),
        }

        # Load from file if exists
        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                file_config = json.load(f)
                config.update(file_config)

        return config

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)


class CacheDB:
    """SQLite cache for VirusTotal results to avoid API rate limits."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize cache database."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def get_vt_result(self, sha256: str) -> Optional[dict]:
        """Get cached VirusTotal result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT result FROM vt_cache WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return json.loads(row[0])
        return None

    def set_vt_result(self, sha256: str, result: dict):
        """Cache VirusTotal result."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO vt_cache (sha256, result, timestamp) VALUES (?, ?, ?)",
            (sha256, json.dumps(result), int(datetime.now().timestamp())),
        )
        conn.commit()
        conn.close()


class YARACache:
    """SQLite cache for YARA scan results and file type info."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize cache database."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)

        # Check if we need to migrate the schema
        cursor = conn.execute("PRAGMA table_info(yara_cache)")
        columns = {row[1] for row in cursor.fetchall()}

        if "file_type" not in columns:
            if "yara_cache" in [
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            ]:
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_type TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_mime TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_category TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN is_previewable INTEGER DEFAULT 0")
            else:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS yara_cache (
                        sha256 TEXT PRIMARY KEY,
                        matches TEXT NOT NULL,
                        scan_timestamp INTEGER NOT NULL,
                        rules_version TEXT,
                        file_type TEXT,
                        file_mime TEXT,
                        file_category TEXT,
                        is_previewable INTEGER DEFAULT 0
                    )
                """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_yara_timestamp
            ON yara_cache(scan_timestamp)
        """)
        conn.commit()
        conn.close()

    def get_result(self, sha256: str) -> Optional[dict]:
        """Get cached scan result including file type."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            """SELECT matches, scan_timestamp, rules_version,
                      file_type, file_mime, file_category
               FROM yara_cache WHERE sha256 = ?""",
            (sha256,),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "sha256": sha256,
                "matches": json.loads(row[0]) if row[0] else [],
                "scan_timestamp": row[1],
                "rules_version": row[2],
                "file_type": row[3],
                "file_mime": row[4],
                "file_category": row[5],
            }
        return None

    def set_result(
        self,
        file_hash: str,
        matches: list[str],
        rules_version: Optional[str] = None,
        file_type: Optional[str] = None,
        file_mime: Optional[str] = None,
        file_category: Optional[str] = None,
    ):
        """Cache scan result with optional file type info."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """INSERT OR REPLACE INTO yara_cache
               (sha256, matches, scan_timestamp, rules_version, file_type, file_mime, file_category)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                file_hash,
                json.dumps(matches),
                int(datetime.now().timestamp()),
                rules_version,
                file_type,
                file_mime,
                file_category,
            ),
        )
        conn.commit()
        conn.close()


class LogParser:
    """Parse Cowrie JSON logs and extract statistics."""

    def __init__(self, log_path: str, hours: int = 24):
        self.log_path = log_path
        self.hours = hours
        self.cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Statistics
        self.total_connections = 0
        self.unique_ips = set()
        self.credentials = Counter()
        self.successful_credentials = set()  # Track which credentials succeeded
        self.commands = []
        self.command_counts = Counter()  # Track command frequency
        self.sessions = defaultdict(dict)
        self.session_commands = defaultdict(list)  # Track commands per session
        self.downloads = []
        self.download_counts = Counter()  # Track download frequency by hash
        self.ip_list = []

    def parse(self) -> dict:
        """Parse logs and return statistics."""
        print(f"[*] Parsing logs from: {self.log_path}")
        print(f"[*] Looking for events in the last {self.hours} hours")

        if not os.path.exists(self.log_path):
            print(f"[!] Warning: Log file not found: {self.log_path}")
            return self._get_stats()

        with open(self.log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    # Check timestamp
                    timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                    if timestamp < self.cutoff_time:
                        continue

                    self._process_entry(entry)

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        return self._get_stats()

    def _process_entry(self, entry: dict):
        """Process a single log entry."""
        event_id = entry.get("eventid")
        session = entry.get("session")
        src_ip = entry.get("src_ip")

        # Connection events
        if event_id == "cowrie.session.connect":
            self.total_connections += 1
            if src_ip:
                self.unique_ips.add(src_ip)
                self.ip_list.append(src_ip)
            if session:
                self.sessions[session]["start"] = entry["timestamp"]
                self.sessions[session]["src_ip"] = src_ip

        # Login attempts
        elif event_id == "cowrie.login.failed" or event_id == "cowrie.login.success":
            username = entry.get("username", "")
            password = entry.get("password", "")
            if username and password:
                cred = f"{username}:{password}"
                self.credentials[cred] += 1
                # Track successful logins
                if event_id == "cowrie.login.success":
                    self.successful_credentials.add(cred)

        # Commands
        elif event_id == "cowrie.command.input":
            command = entry.get("input", "").strip()
            if command:
                self.commands.append(
                    {"command": command, "timestamp": entry["timestamp"], "session": session, "src_ip": src_ip}
                )
                self.command_counts[command] += 1
                if session:
                    self.session_commands[session].append(command)

        # File downloads
        elif event_id == "cowrie.session.file_download":
            shasum = entry.get("shasum", "")
            self.downloads.append(
                {
                    "url": entry.get("url", ""),
                    "shasum": shasum,
                    "outfile": entry.get("outfile", ""),
                    "timestamp": entry["timestamp"],
                    "src_ip": src_ip,
                }
            )
            if shasum:
                self.download_counts[shasum] += 1

        # Session close
        elif event_id == "cowrie.session.closed":
            if session and session in self.sessions:
                self.sessions[session]["end"] = entry["timestamp"]

    def _get_stats(self) -> dict:
        """Compile statistics."""
        # Calculate session durations
        durations = []
        for session_data in self.sessions.values():
            if "start" in session_data and "end" in session_data:
                start = datetime.fromisoformat(session_data["start"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(session_data["end"].replace("Z", "+00:00"))
                duration = (end - start).total_seconds()
                durations.append(duration)

        avg_duration = sum(durations) / len(durations) if durations else 0

        # Get unique downloads (deduplicated by hash)
        unique_downloads = {}
        for download in self.downloads:
            shasum = download["shasum"]
            if shasum and shasum not in unique_downloads:
                unique_downloads[shasum] = download

        # Sort sessions by number of commands (most interesting first)
        sessions_by_activity = sorted(self.session_commands.items(), key=lambda x: len(x[1]), reverse=True)

        return {
            "total_connections": self.total_connections,
            "unique_ips": len(self.unique_ips),
            "ip_list": self.ip_list,
            "unique_ip_set": self.unique_ips,
            "top_credentials": self.credentials.most_common(10),
            "successful_credentials": self.successful_credentials,
            "commands": self.commands,
            "top_commands": self.command_counts.most_common(20),  # Top 20 commands with counts
            "sessions_with_commands": len({cmd["session"] for cmd in self.commands if cmd["session"]}),
            "sessions_by_activity": sessions_by_activity,  # Sessions sorted by command count
            "downloads": self.downloads,
            "unique_downloads": unique_downloads,  # Deduplicated downloads
            "download_counts": self.download_counts,  # Download frequency
            "avg_session_duration": avg_duration,
            "total_sessions": len(self.sessions),
        }


class GeoIPEnricher:
    """Enrich IP addresses with GeoIP data using MaxMind GeoLite2."""

    def __init__(self, city_db_path: str, asn_db_path: Optional[str] = None):
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
        self.city_reader = None
        self.asn_reader = None

        if os.path.exists(city_db_path):
            self.city_reader = geoip2.database.Reader(city_db_path)
        else:
            print(f"[!] Warning: GeoIP City database not found: {city_db_path}")

        if asn_db_path and os.path.exists(asn_db_path):
            self.asn_reader = geoip2.database.Reader(asn_db_path)

    def lookup(self, ip: str) -> dict:
        """Lookup IP address and return geo data."""
        result = {
            "ip": ip,
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "Unknown",
            "organization": "Unknown",
        }

        if not self.city_reader:
            return result

        try:
            response = self.city_reader.city(ip)
            result.update(
                {
                    "country": response.country.name or "Unknown",
                    "country_code": response.country.iso_code or "XX",
                    "city": response.city.name or "Unknown",
                    "latitude": response.location.latitude or 0.0,
                    "longitude": response.location.longitude or 0.0,
                }
            )
        except Exception:
            pass

        if self.asn_reader:
            try:
                asn_response = self.asn_reader.asn(ip)
                result.update(
                    {
                        "asn": f"AS{asn_response.autonomous_system_number}",
                        "organization": asn_response.autonomous_system_organization or "Unknown",
                    }
                )
            except Exception:
                pass

        return result

    def enrich_ip_list(self, ip_list: list[str]) -> tuple[dict, Counter]:
        """Enrich list of IPs and return geo data and country counts."""
        geo_data = {}
        country_counter = Counter()

        for ip in set(ip_list):
            geo_info = self.lookup(ip)
            geo_data[ip] = geo_info
            country_counter[geo_info["country"]] += ip_list.count(ip)

        return geo_data, country_counter

    def close(self):
        """Close database readers."""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()


class VirusTotalScanner:
    """Scan files using VirusTotal API."""

    def __init__(self, api_key: str, cache: CacheDB):
        self.api_key = api_key
        self.cache = cache
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan_file(self, file_path: str, sha256: str) -> Optional[dict]:
        """Scan file and return results."""
        if not self.api_key:
            return None

        # Check cache first
        cached = self.cache.get_vt_result(sha256)
        if cached:
            print(f"[*] Using cached VT result for {sha256[:16]}...")
            return cached

        # Query VirusTotal
        print(f"[*] Querying VirusTotal for {sha256[:16]}...")
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(f"{self.base_url}/files/{sha256}", headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                attributes = data["data"]["attributes"]

                result = {
                    "sha256": sha256,
                    "detections": attributes["last_analysis_stats"]["malicious"],
                    "total_engines": sum(attributes["last_analysis_stats"].values()),
                    "link": f"https://www.virustotal.com/gui/file/{sha256}",
                }

                # Extract threat intelligence fields if available
                threat_class = attributes.get("popular_threat_classification", {})
                if threat_class:
                    if "suggested_threat_label" in threat_class:
                        result["threat_label"] = threat_class["suggested_threat_label"]

                    if "popular_threat_category" in threat_class:
                        # Extract category values and counts
                        categories = threat_class["popular_threat_category"]
                        if categories:
                            result["threat_categories"] = [
                                {"name": cat["value"], "count": cat["count"]} for cat in categories
                            ]

                # Extract family labels from tags
                if "tags" in attributes and attributes["tags"]:
                    result["family_labels"] = attributes["tags"]

                # Cache result
                self.cache.set_vt_result(sha256, result)
                return result

            elif response.status_code == 404:
                print(f"[*] File not found in VT database: {sha256[:16]}")
                return None

        except Exception as e:
            print(f"[!] VirusTotal API error: {e}")

        return None


class YARAScanner:
    """Scan files using YARA rules with caching support."""

    def __init__(self, rules_path: str, cache: Optional[YARACache] = None):
        self.rules_path = rules_path
        self.cache = cache
        self.rules = None
        self.rules_version = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from directory."""
        if not os.path.exists(self.rules_path):
            print(f"[!] Warning: YARA rules directory not found: {self.rules_path}")
            return

        rule_files = {}
        for root, _, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    rule_path = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = rule_path

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                # Use modification time of rules directory as version
                self.rules_version = str(int(os.path.getmtime(self.rules_path)))
                print(f"[*] Loaded {len(rule_files)} YARA rule files")
            except Exception as e:
                print(f"[!] Error loading YARA rules: {e}")

    def scan_file(self, file_path: str, sha256: Optional[str] = None) -> list[str]:
        """Scan file and return matched rule names.

        Args:
            file_path: Path to the file to scan
            sha256: Optional SHA256 hash for cache lookup (derived from filename if not provided)
        """
        if not os.path.exists(file_path):
            return []

        # Get SHA256 from filename if not provided (Cowrie stores files by hash)
        if sha256 is None:
            sha256 = os.path.basename(file_path)

        # Check cache first
        if self.cache:
            cached = self.cache.get_result(sha256)
            if cached:
                print(f"[*] Using cached YARA result for {sha256[:16]}...")
                return cached["matches"]

        if not self.rules:
            return []

        try:
            matches = self.rules.match(file_path)
            match_names = [match.rule for match in matches]

            # Cache the result
            if self.cache:
                self.cache.set_result(sha256, match_names, self.rules_version)

            return match_names
        except Exception as e:
            print(f"[!] YARA scan error: {e}")
            return []


class ReportGenerator:
    """Generate HTML and text reports."""

    def __init__(self, stats: dict, geo_data: dict, country_counts: Counter, file_analysis: list[dict], config: Config):
        self.stats = stats
        self.geo_data = geo_data
        self.country_counts = country_counts
        self.file_analysis = file_analysis
        self.config = config
        self.max_commands = config.get("max_commands_per_session") or 20
        self.web_base_url = (config.get("web_base_url") or "").rstrip("/")

    def generate_text_report(self) -> str:
        """Generate plain text report."""
        report_date = datetime.now().strftime("%Y-%m-%d")

        lines = []
        lines.append(f"COWRIE HONEYPOT DAILY REPORT - {report_date}")
        lines.append("=" * 70)
        lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Connections:              {self.stats['total_connections']}")
        lines.append(f"Unique IPs:               {self.stats['unique_ips']}")
        lines.append(f"Sessions with commands:   {self.stats['sessions_with_commands']}")
        lines.append(
            f"Files downloaded:         {len(self.stats['downloads'])} ({len(self.stats['unique_downloads'])} unique)"
        )
        lines.append(f"Avg session duration:     {self.stats['avg_session_duration']:.1f} seconds")
        lines.append("")

        # Top countries
        if self.country_counts:
            lines.append("TOP ATTACKING COUNTRIES")
            lines.append("-" * 70)
            total = sum(self.country_counts.values())
            for country, count in self.country_counts.most_common(10):
                pct = (count / total * 100) if total > 0 else 0
                lines.append(f"{country:20s} {count:6d} ({pct:5.1f}%)")
            lines.append("")

        # Top credentials
        if self.stats["top_credentials"]:
            lines.append("TOP CREDENTIALS ATTEMPTED")
            lines.append("-" * 70)
            for cred, count in self.stats["top_credentials"]:
                success_marker = " ✓ SUCCESS" if cred in self.stats["successful_credentials"] else ""
                lines.append(f"{cred:40s} ({count} attempts){success_marker}")
            lines.append("")

        # Downloaded files
        if self.file_analysis:
            lines.append("DOWNLOADED FILES")
            lines.append("-" * 70)
            for file_info in self.file_analysis:
                sha256 = file_info["sha256"]
                download_count = self.stats["download_counts"].get(sha256, 1)
                lines.append(f"SHA256: {sha256}")
                lines.append(f"  Downloads:   {download_count}x")
                lines.append(f"  Size:        {file_info['size']} bytes")
                if file_info.get("file_type"):
                    file_type = file_info["file_type"]
                    if len(file_type) > 60:
                        file_type = file_type[:60] + "..."
                    lines.append(f"  Type:        {file_type}")
                if file_info.get("file_category"):
                    lines.append(f"  Category:    {file_info['file_category']}")
                if file_info.get("yara_matches"):
                    lines.append(f"  YARA:        {', '.join(file_info['yara_matches'])}")
                if file_info.get("vt_result"):
                    vt = file_info["vt_result"]
                    lines.append(f"  VirusTotal:  {vt['detections']}/{vt['total_engines']} detections")
                    if vt.get("threat_label"):
                        lines.append(f"  Threat:      {vt['threat_label']}")
                    if vt.get("threat_categories"):
                        categories = ", ".join([f"{cat['name']} ({cat['count']})" for cat in vt["threat_categories"]])
                        lines.append(f"  Categories:  {categories}")
                    if vt.get("family_labels"):
                        families = ", ".join(vt["family_labels"][:5])  # Limit to first 5 tags
                        if len(vt["family_labels"]) > 5:
                            families += f", +{len(vt['family_labels']) - 5} more"
                        lines.append(f"  Families:    {families}")
                    lines.append(f"  VT Link:     {vt['link']}")
                lines.append("")

        # Top commands (deduplicated with counts)
        if self.stats["top_commands"]:
            lines.append("TOP COMMANDS")
            lines.append("-" * 70)
            for command, count in self.stats["top_commands"]:
                lines.append(f"{count:4d}x | {command}")
            lines.append("")

        # Most active sessions
        if self.stats["sessions_by_activity"]:
            lines.append("MOST ACTIVE SESSIONS (by command count)")
            lines.append("-" * 70)
            for session_id, commands in self.stats["sessions_by_activity"][:10]:
                session_header = f"Session {session_id[:16]}... ({len(commands)} commands)"
                if self.web_base_url:
                    session_header += f" → {self.web_base_url}/session/{session_id}"
                lines.append(session_header)
                for cmd in commands[: self.max_commands]:
                    lines.append(f"  → {cmd}")
                if len(commands) > self.max_commands:
                    lines.append(f"  ... and {len(commands) - self.max_commands} more commands")
            lines.append("")

        # Add web dashboard link if configured
        if self.web_base_url:
            lines.append("-" * 70)
            lines.append(f"Web Dashboard: {self.web_base_url}")
            lines.append("")

        return "\n".join(lines)

    def generate_html_report(self) -> str:
        """Generate HTML report with inline styling."""
        report_date = datetime.now().strftime("%Y-%m-%d")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 8px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ecf0f1;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .malware-alert {{
            background-color: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }}
        .command {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 8px;
            border-left: 3px solid #3498db;
            margin: 8px 0;
            overflow-x: auto;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 Cowrie Honeypot Daily Report</h1>
        <p><strong>Report Date:</strong> {report_date}</p>

        <div class="summary">
            <div class="stat-box">
                <div class="stat-label">Total Connections</div>
                <div class="stat-value">{self.stats["total_connections"]}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Unique IPs</div>
                <div class="stat-value">{self.stats["unique_ips"]}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Sessions with Commands</div>
                <div class="stat-value">{self.stats["sessions_with_commands"]}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Files Downloaded</div>
                <div class="stat-value">{len(self.stats["downloads"])}</div>
                <div class="stat-label" style="margin-top:5px;font-size:12px;">({len(self.stats["unique_downloads"])} unique)</div>
            </div>
        </div>
"""

        # Top countries
        if self.country_counts:
            html += """
        <h2>🌍 Top Attacking Countries</h2>
        <table>
            <tr>
                <th>Country</th>
                <th>Connections</th>
                <th>Percentage</th>
            </tr>
"""
            total = sum(self.country_counts.values())
            for country, count in self.country_counts.most_common(10):
                pct = (count / total * 100) if total > 0 else 0
                html += f"""
            <tr>
                <td>{country}</td>
                <td>{count}</td>
                <td>{pct:.1f}%</td>
            </tr>
"""
            html += """
        </table>
"""

        # Top credentials
        if self.stats["top_credentials"]:
            html += """
        <h2>🔐 Top Credentials Attempted</h2>
        <table>
            <tr>
                <th>Username:Password</th>
                <th>Attempts</th>
                <th>Status</th>
            </tr>
"""
            for cred, count in self.stats["top_credentials"]:
                success = cred in self.stats["successful_credentials"]
                status_badge = (
                    '<span style="background: #28a745; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em;">✓ SUCCESS</span>'
                    if success
                    else '<span style="background: #6c757d; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em;">Failed</span>'
                )
                html += f"""
            <tr>
                <td><code>{cred}</code></td>
                <td>{count}</td>
                <td>{status_badge}</td>
            </tr>
"""
            html += """
        </table>
"""

        # Downloaded files
        if self.file_analysis:
            html += """
        <h2>📦 Downloaded Files (Malware Analysis)</h2>
"""
            for file_info in self.file_analysis:
                has_detections = file_info.get("vt_result", {}).get("detections", 0) > 0

                if has_detections:
                    html += """
        <div class="malware-alert">
            <strong>⚠️ MALWARE DETECTED</strong>
        </div>
"""

                sha256 = file_info["sha256"]
                download_count = self.stats["download_counts"].get(sha256, 1)

                # File type badge colors
                category_colors = {
                    "executable": "#dc3545",
                    "script": "#ffc107",
                    "archive": "#17a2b8",
                    "document": "#007bff",
                    "data": "#6c757d",
                }
                file_category = file_info.get("file_category", "unknown")
                category_color = category_colors.get(file_category, "#6c757d")

                html += f"""
        <table>
            <tr>
                <td><strong>SHA256:</strong></td>
                <td><code>{sha256}</code></td>
            </tr>
            <tr>
                <td><strong>Downloads:</strong></td>
                <td>{download_count}x</td>
            </tr>
            <tr>
                <td><strong>Size:</strong></td>
                <td>{file_info["size"]} bytes</td>
            </tr>
"""
                if file_info.get("file_type"):
                    file_type = file_info["file_type"]
                    if len(file_type) > 80:
                        file_type = file_type[:80] + "..."
                    html += f"""
            <tr>
                <td><strong>File Type:</strong></td>
                <td>
                    <span style="background: {category_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; margin-right: 8px;">{file_category}</span>
                    {file_type}
                </td>
            </tr>
"""

                if file_info.get("yara_matches"):
                    html += f"""
            <tr>
                <td><strong>YARA Matches:</strong></td>
                <td><code>{", ".join(file_info["yara_matches"])}</code></td>
            </tr>
"""

                if file_info.get("vt_result"):
                    vt = file_info["vt_result"]
                    html += f"""
            <tr>
                <td><strong>VirusTotal:</strong></td>
                <td>{vt["detections"]}/{vt["total_engines"]} engines detected malware</td>
            </tr>
"""
                    if vt.get("threat_label"):
                        html += f"""
            <tr>
                <td><strong>Threat Label:</strong></td>
                <td><span style="background: #fff3cd; padding: 2px 8px; border-radius: 4px; font-weight: bold;">{vt["threat_label"]}</span></td>
            </tr>
"""
                    if vt.get("threat_categories"):
                        categories_html = ", ".join(
                            [f"{cat['name']} <small>({cat['count']})</small>" for cat in vt["threat_categories"]]
                        )
                        html += f"""
            <tr>
                <td><strong>Threat Categories:</strong></td>
                <td>{categories_html}</td>
            </tr>
"""
                    if vt.get("family_labels"):
                        families = vt["family_labels"][:8]  # Show first 8 tags in HTML
                        families_html = " ".join(
                            [
                                f'<span style="background: #e7f3ff; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; font-size: 12px;">{tag}</span>'
                                for tag in families
                            ]
                        )
                        if len(vt["family_labels"]) > 8:
                            families_html += f" <small>+{len(vt['family_labels']) - 8} more</small>"
                        html += f"""
            <tr>
                <td><strong>Family Labels:</strong></td>
                <td>{families_html}</td>
            </tr>
"""
                    html += f"""
            <tr>
                <td><strong>VT Link:</strong></td>
                <td><a href="{vt["link"]}">{vt["link"]}</a></td>
            </tr>
"""

                html += """
        </table>
"""

        # Top commands
        if self.stats["top_commands"]:
            html += """
        <h2>💻 Top Commands Executed</h2>
        <table>
            <tr>
                <th>Count</th>
                <th>Command</th>
            </tr>
"""
            for command, count in self.stats["top_commands"]:
                html += f"""
            <tr>
                <td>{count}</td>
                <td><code>{command}</code></td>
            </tr>
"""
            html += """
        </table>
"""

        # Most active sessions
        if self.stats["sessions_by_activity"]:
            html += """
        <h2>🎯 Most Active Sessions</h2>
"""
            for session_id, commands in self.stats["sessions_by_activity"][:10]:
                if self.web_base_url:
                    session_link = f'<a href="{self.web_base_url}/session/{session_id}">{session_id[:16]}...</a>'
                    playback_link = f' <a href="{self.web_base_url}/session/{session_id}/playback" style="font-size: 0.8em; margin-left: 10px;">▶ Watch Recording</a>'
                else:
                    session_link = f"{session_id[:16]}..."
                    playback_link = ""
                html += f"""
        <h3>Session {session_link} ({len(commands)} commands){playback_link}</h3>
"""
                for cmd in commands[: self.max_commands]:
                    html += f"""
        <div class="command">
            {cmd}
        </div>
"""
                if len(commands) > self.max_commands:
                    html += f"""
        <p><em>... and {len(commands) - self.max_commands} more commands</em></p>
"""

        # Add web dashboard link if configured
        if self.web_base_url:
            html += f"""
        <div style="margin-top: 30px; padding: 20px; background: #e8f4f8; border-radius: 8px; text-align: center;">
            <p style="margin: 0; font-size: 14px;">
                <strong>🖥️ Web Dashboard:</strong>
                <a href="{self.web_base_url}" style="color: #3498db;">{self.web_base_url}</a>
            </p>
        </div>
"""

        html += """
        <div class="footer">
            <p>Generated by Cowrie Honeypot Daily Report System</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class EmailSender:
    """Send reports via email using SMTP or API services."""

    def __init__(self, config: Config):
        self.config = config

    def send(self, subject: str, text_body: str, html_body: str) -> bool:
        """Send email report."""
        if not self.config.get("email_enabled"):
            print("[*] Email delivery disabled")
            return False

        # Use SMTP (Scaleway)
        return self._send_smtp(subject, text_body, html_body)

    def _send_smtp(self, subject: str, text_body: str, html_body: str) -> bool:
        """Send via SMTP."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"{self.config.get('email_subject_prefix') or '[Honeypot]'} {subject}"
            msg["From"] = self.config.get("email_from") or "honeypot@example.com"
            msg["To"] = self.config.get("email_to") or "admin@example.com"

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            smtp_host = self.config.get("smtp_host") or "localhost"
            smtp_port = self.config.get("smtp_port") or 25

            if self.config.get("smtp_tls"):
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)

            smtp_user = self.config.get("smtp_user")
            smtp_password = self.config.get("smtp_password")
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)

            server.send_message(msg)
            server.quit()

            print(f"[*] Email sent via SMTP to {self.config.get('email_to')}")
            return True

        except Exception as e:
            print(f"[!] SMTP error: {e}")
            return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Cowrie Honeypot Daily Report Generator")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--hours", type=int, help="Hours to look back (default: 24)")
    parser.add_argument("--output", help="Output file path (instead of email)")
    parser.add_argument("--test", action="store_true", help="Test mode: print to stdout")

    args = parser.parse_args()

    # Load configuration
    config = Config(args.config)
    if args.hours:
        config.config["report_hours"] = args.hours

    print("[*] Starting Cowrie daily report generator")
    report_hours = config.get("report_hours") or 24
    print(f"[*] Report period: last {report_hours} hours")

    # Parse logs
    parser = LogParser(
        config.get("log_path") or "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json", hours=report_hours
    )
    stats = parser.parse()

    print(f"[*] Parsed {stats['total_connections']} connections from {stats['unique_ips']} unique IPs")

    # GeoIP enrichment
    geo_enricher = GeoIPEnricher(
        config.get("geoip_db_path") or "/var/lib/GeoIP/GeoLite2-City.mmdb",
        config.get("geoip_asn_path") or "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    )
    geo_data, country_counts = geo_enricher.enrich_ip_list(stats["ip_list"])
    print(f"[*] Enriched {len(geo_data)} unique IPs with GeoIP data")

    # Analyze downloaded files
    file_analysis = []
    cache = CacheDB(config.get("cache_db_path") or "/opt/cowrie/var/report-cache.db")

    if stats["unique_downloads"]:
        total_downloads = len(stats["downloads"])
        unique_downloads = len(stats["unique_downloads"])
        print(f"[*] Analyzing {unique_downloads} unique files ({total_downloads} total downloads)...")

        vt_scanner = None
        vt_api_key = config.get("virustotal_api_key") or ""
        if config.get("virustotal_enabled") and vt_api_key:
            vt_scanner = VirusTotalScanner(vt_api_key, cache)

        yara_cache = YARACache(config.get("yara_cache_db_path") or "/opt/cowrie/var/yara-cache.db")
        yara_scanner = YARAScanner(config.get("yara_rules_path") or "/opt/cowrie/yara-rules", yara_cache)

        download_path = config.get("download_path") or "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"

        for sha256, download in stats["unique_downloads"].items():
            file_path = os.path.join(download_path, sha256) if download_path else None

            file_info = {"sha256": sha256, "url": download.get("url", ""), "size": 0}

            if file_path and os.path.exists(file_path):
                file_info["size"] = os.path.getsize(file_path)

                # YARA scan (with caching) - also gets file type if available
                yara_matches = yara_scanner.scan_file(file_path, sha256)
                if yara_matches:
                    file_info["yara_matches"] = yara_matches

                # Get file type from YARA cache (populated by yara-scanner-daemon)
                yara_cached = yara_cache.get_result(sha256)
                if yara_cached:
                    if yara_cached.get("file_type"):
                        file_info["file_type"] = yara_cached["file_type"]
                    if yara_cached.get("file_category"):
                        file_info["file_category"] = yara_cached["file_category"]

                # VirusTotal scan
                if vt_scanner:
                    vt_result = vt_scanner.scan_file(file_path, sha256)
                    if vt_result:
                        file_info["vt_result"] = vt_result

            file_analysis.append(file_info)

    # Generate reports
    report_gen = ReportGenerator(stats, geo_data, country_counts, file_analysis, config)
    text_report = report_gen.generate_text_report()
    html_report = report_gen.generate_html_report()

    # Test mode: print to stdout
    if args.test:
        print("\n" + "=" * 70)
        print(text_report)
        print("=" * 70)
        return

    # Save to file
    if args.output:
        with open(args.output, "w") as f:
            f.write(html_report)
        print(f"[*] Report saved to: {args.output}")
        return

    # Send email
    report_date = datetime.now().strftime("%Y-%m-%d")
    subject = f"Daily Report - {report_date} - {stats['total_connections']} attacks from {stats['unique_ips']} IPs"

    email_sender = EmailSender(config)
    email_sender.send(subject, text_report, html_report)

    print("[*] Daily report completed successfully")

    # Cleanup
    geo_enricher.close()


if __name__ == "__main__":
    main()
