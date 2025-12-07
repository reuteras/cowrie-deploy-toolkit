#!/usr/bin/env python3
"""
Cowrie Honeypot Daily Report Generator

Generates daily reports from Cowrie JSON logs with:
- Connection statistics and top attackers
- GeoIP enrichment (MaxMind GeoLite2)
- VirusTotal malware analysis
- YARA rule scanning
- Email delivery with HTML formatting
- Real-time webhook alerts (Slack, Discord, Teams)
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import sqlite3
import tempfile

try:
    import requests
    import geoip2.database
    import yara
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install dependencies with: pip install -r requirements.txt")
    sys.exit(1)


class Config:
    """Configuration management for the reporting system."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.getenv('COWRIE_REPORT_CONFIG', '/opt/cowrie/etc/report-config.json')
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from file or environment variables."""
        config = {
            # Paths
            'log_path': os.getenv('COWRIE_LOG_PATH', '/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'),
            'download_path': os.getenv('COWRIE_DOWNLOAD_PATH', '/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads'),
            'geoip_db_path': os.getenv('GEOIP_DB_PATH', '/opt/cowrie/geoip/GeoLite2-City.mmdb'),
            'geoip_asn_path': os.getenv('GEOIP_ASN_PATH', '/opt/cowrie/geoip/GeoLite2-ASN.mmdb'),
            'yara_rules_path': os.getenv('YARA_RULES_PATH', '/opt/cowrie/yara-rules'),
            'cache_db_path': os.getenv('CACHE_DB_PATH', '/opt/cowrie/var/report-cache.db'),

            # VirusTotal
            'virustotal_api_key': os.getenv('VT_API_KEY'),
            'virustotal_enabled': os.getenv('VT_ENABLED', 'true').lower() == 'true',

            # Email settings
            'email_enabled': os.getenv('EMAIL_ENABLED', 'true').lower() == 'true',
            'email_from': os.getenv('EMAIL_FROM', 'honeypot@example.com'),
            'email_to': os.getenv('EMAIL_TO', 'admin@example.com'),
            'email_subject_prefix': os.getenv('EMAIL_SUBJECT_PREFIX', '[Honeypot]'),

            # SMTP settings
            'smtp_host': os.getenv('SMTP_HOST', 'localhost'),
            'smtp_port': int(os.getenv('SMTP_PORT', '25')),
            'smtp_user': os.getenv('SMTP_USER'),
            'smtp_password': os.getenv('SMTP_PASSWORD'),
            'smtp_tls': os.getenv('SMTP_TLS', 'false').lower() == 'true',

            # SendGrid/Mailgun API (alternative to SMTP)
            'sendgrid_api_key': os.getenv('SENDGRID_API_KEY'),
            'mailgun_api_key': os.getenv('MAILGUN_API_KEY'),
            'mailgun_domain': os.getenv('MAILGUN_DOMAIN'),

            # Webhook alerts
            'slack_webhook': os.getenv('SLACK_WEBHOOK'),
            'discord_webhook': os.getenv('DISCORD_WEBHOOK'),
            'teams_webhook': os.getenv('TEAMS_WEBHOOK'),

            # Alert thresholds
            'alert_threshold_connections': int(os.getenv('ALERT_THRESHOLD_CONNECTIONS', '100')),
            'alert_on_malware': os.getenv('ALERT_ON_MALWARE', 'true').lower() == 'true',

            # Report settings
            'report_hours': int(os.getenv('REPORT_HOURS', '24')),
            'include_map': os.getenv('INCLUDE_MAP', 'true').lower() == 'true',
        }

        # Load from file if exists
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def get_vt_result(self, sha256: str) -> Optional[dict]:
        """Get cached VirusTotal result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('SELECT result FROM vt_cache WHERE sha256 = ?', (sha256,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return json.loads(row[0])
        return None

    def set_vt_result(self, sha256: str, result: dict):
        """Cache VirusTotal result."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'INSERT OR REPLACE INTO vt_cache (sha256, result, timestamp) VALUES (?, ?, ?)',
            (sha256, json.dumps(result), int(datetime.now().timestamp()))
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
        self.commands = []
        self.sessions = defaultdict(dict)
        self.downloads = []
        self.ip_list = []

    def parse(self) -> dict:
        """Parse logs and return statistics."""
        print(f"[*] Parsing logs from: {self.log_path}")
        print(f"[*] Looking for events in the last {self.hours} hours")

        if not os.path.exists(self.log_path):
            print(f"[!] Warning: Log file not found: {self.log_path}")
            return self._get_stats()

        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    # Check timestamp
                    timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                    if timestamp < self.cutoff_time:
                        continue

                    self._process_entry(entry)

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    continue

        return self._get_stats()

    def _process_entry(self, entry: dict):
        """Process a single log entry."""
        event_id = entry.get('eventid')
        session = entry.get('session')
        src_ip = entry.get('src_ip')

        # Connection events
        if event_id == 'cowrie.session.connect':
            self.total_connections += 1
            if src_ip:
                self.unique_ips.add(src_ip)
                self.ip_list.append(src_ip)
            if session:
                self.sessions[session]['start'] = entry['timestamp']
                self.sessions[session]['src_ip'] = src_ip

        # Login attempts
        elif event_id == 'cowrie.login.failed' or event_id == 'cowrie.login.success':
            username = entry.get('username', '')
            password = entry.get('password', '')
            if username and password:
                self.credentials[f"{username}:{password}"] += 1

        # Commands
        elif event_id == 'cowrie.command.input':
            command = entry.get('input', '').strip()
            if command:
                self.commands.append({
                    'command': command,
                    'timestamp': entry['timestamp'],
                    'session': session,
                    'src_ip': src_ip
                })

        # File downloads
        elif event_id == 'cowrie.session.file_download':
            self.downloads.append({
                'url': entry.get('url', ''),
                'shasum': entry.get('shasum', ''),
                'outfile': entry.get('outfile', ''),
                'timestamp': entry['timestamp'],
                'src_ip': src_ip
            })

        # Session close
        elif event_id == 'cowrie.session.closed':
            if session and session in self.sessions:
                self.sessions[session]['end'] = entry['timestamp']

    def _get_stats(self) -> dict:
        """Compile statistics."""
        # Calculate session durations
        durations = []
        for session_data in self.sessions.values():
            if 'start' in session_data and 'end' in session_data:
                start = datetime.fromisoformat(session_data['start'].replace('Z', '+00:00'))
                end = datetime.fromisoformat(session_data['end'].replace('Z', '+00:00'))
                duration = (end - start).total_seconds()
                durations.append(duration)

        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            'total_connections': self.total_connections,
            'unique_ips': len(self.unique_ips),
            'ip_list': self.ip_list,
            'unique_ip_set': self.unique_ips,
            'top_credentials': self.credentials.most_common(10),
            'commands': self.commands,
            'sessions_with_commands': len(set(cmd['session'] for cmd in self.commands if cmd['session'])),
            'downloads': self.downloads,
            'avg_session_duration': avg_duration,
            'total_sessions': len(self.sessions)
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
            'ip': ip,
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'asn': 'Unknown',
            'organization': 'Unknown'
        }

        if not self.city_reader:
            return result

        try:
            response = self.city_reader.city(ip)
            result.update({
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX',
                'city': response.city.name or 'Unknown',
                'latitude': response.location.latitude or 0.0,
                'longitude': response.location.longitude or 0.0
            })
        except Exception:
            pass

        if self.asn_reader:
            try:
                asn_response = self.asn_reader.asn(ip)
                result.update({
                    'asn': f"AS{asn_response.autonomous_system_number}",
                    'organization': asn_response.autonomous_system_organization or 'Unknown'
                })
            except Exception:
                pass

        return result

    def enrich_ip_list(self, ip_list: List[str]) -> Tuple[Dict, Counter]:
        """Enrich list of IPs and return geo data and country counts."""
        geo_data = {}
        country_counter = Counter()

        for ip in set(ip_list):
            geo_info = self.lookup(ip)
            geo_data[ip] = geo_info
            country_counter[geo_info['country']] += ip_list.count(ip)

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
        self.base_url = 'https://www.virustotal.com/api/v3'

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
        headers = {'x-apikey': self.api_key}

        try:
            response = requests.get(
                f'{self.base_url}/files/{sha256}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                result = {
                    'sha256': sha256,
                    'detections': data['data']['attributes']['last_analysis_stats']['malicious'],
                    'total_engines': sum(data['data']['attributes']['last_analysis_stats'].values()),
                    'link': f"https://www.virustotal.com/gui/file/{sha256}"
                }

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
    """Scan files using YARA rules."""

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from directory."""
        if not os.path.exists(self.rules_path):
            print(f"[!] Warning: YARA rules directory not found: {self.rules_path}")
            return

        rule_files = {}
        for root, dirs, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    rule_path = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = rule_path

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"[*] Loaded {len(rule_files)} YARA rule files")
            except Exception as e:
                print(f"[!] Error loading YARA rules: {e}")

    def scan_file(self, file_path: str) -> List[str]:
        """Scan file and return matched rule names."""
        if not self.rules or not os.path.exists(file_path):
            return []

        try:
            matches = self.rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[!] YARA scan error: {e}")
            return []


class ReportGenerator:
    """Generate HTML and text reports."""

    def __init__(self, stats: dict, geo_data: dict, country_counts: Counter,
                 file_analysis: List[dict], config: Config):
        self.stats = stats
        self.geo_data = geo_data
        self.country_counts = country_counts
        self.file_analysis = file_analysis
        self.config = config

    def generate_text_report(self) -> str:
        """Generate plain text report."""
        report_date = datetime.now().strftime('%Y-%m-%d')

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
        lines.append(f"Files downloaded:         {len(self.stats['downloads'])}")
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
        if self.stats['top_credentials']:
            lines.append("TOP CREDENTIALS ATTEMPTED")
            lines.append("-" * 70)
            for cred, count in self.stats['top_credentials']:
                lines.append(f"{cred:40s} ({count} attempts)")
            lines.append("")

        # Downloaded files
        if self.file_analysis:
            lines.append("DOWNLOADED FILES")
            lines.append("-" * 70)
            for file_info in self.file_analysis:
                lines.append(f"SHA256: {file_info['sha256']}")
                lines.append(f"  Size:        {file_info['size']} bytes")
                if file_info.get('yara_matches'):
                    lines.append(f"  YARA:        {', '.join(file_info['yara_matches'])}")
                if file_info.get('vt_result'):
                    vt = file_info['vt_result']
                    lines.append(f"  VirusTotal:  {vt['detections']}/{vt['total_engines']} detections")
                    lines.append(f"  VT Link:     {vt['link']}")
                lines.append("")

        # Notable commands
        if self.stats['commands']:
            lines.append("NOTABLE COMMANDS")
            lines.append("-" * 70)
            for cmd in self.stats['commands'][:20]:  # Top 20 commands
                lines.append(f"{cmd['src_ip']:15s} | {cmd['command']}")
            if len(self.stats['commands']) > 20:
                lines.append(f"... and {len(self.stats['commands']) - 20} more commands")
            lines.append("")

        return "\n".join(lines)

    def generate_html_report(self) -> str:
        """Generate HTML report with inline styling."""
        report_date = datetime.now().strftime('%Y-%m-%d')

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
                <div class="stat-value">{self.stats['total_connections']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Unique IPs</div>
                <div class="stat-value">{self.stats['unique_ips']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Sessions with Commands</div>
                <div class="stat-value">{self.stats['sessions_with_commands']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Files Downloaded</div>
                <div class="stat-value">{len(self.stats['downloads'])}</div>
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
        if self.stats['top_credentials']:
            html += """
        <h2>🔐 Top Credentials Attempted</h2>
        <table>
            <tr>
                <th>Username:Password</th>
                <th>Attempts</th>
            </tr>
"""
            for cred, count in self.stats['top_credentials']:
                html += f"""
            <tr>
                <td><code>{cred}</code></td>
                <td>{count}</td>
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
                has_detections = file_info.get('vt_result', {}).get('detections', 0) > 0

                if has_detections:
                    html += f"""
        <div class="malware-alert">
            <strong>⚠️ MALWARE DETECTED</strong>
        </div>
"""

                html += f"""
        <table>
            <tr>
                <td><strong>SHA256:</strong></td>
                <td><code>{file_info['sha256']}</code></td>
            </tr>
            <tr>
                <td><strong>Size:</strong></td>
                <td>{file_info['size']} bytes</td>
            </tr>
"""

                if file_info.get('yara_matches'):
                    html += f"""
            <tr>
                <td><strong>YARA Matches:</strong></td>
                <td><code>{', '.join(file_info['yara_matches'])}</code></td>
            </tr>
"""

                if file_info.get('vt_result'):
                    vt = file_info['vt_result']
                    html += f"""
            <tr>
                <td><strong>VirusTotal:</strong></td>
                <td>{vt['detections']}/{vt['total_engines']} engines detected malware</td>
            </tr>
            <tr>
                <td><strong>VT Link:</strong></td>
                <td><a href="{vt['link']}">{vt['link']}</a></td>
            </tr>
"""

                html += """
        </table>
"""

        # Notable commands
        if self.stats['commands']:
            html += """
        <h2>💻 Notable Commands Executed</h2>
"""
            for cmd in self.stats['commands'][:20]:
                html += f"""
        <div class="command">
            <strong>{cmd['src_ip']}</strong> &gt; {cmd['command']}
        </div>
"""
            if len(self.stats['commands']) > 20:
                html += f"""
        <p><em>... and {len(self.stats['commands']) - 20} more commands</em></p>
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
        if not self.config.get('email_enabled'):
            print("[*] Email delivery disabled")
            return False

        # Try SendGrid first
        if self.config.get('sendgrid_api_key'):
            return self._send_sendgrid(subject, text_body, html_body)

        # Try Mailgun
        elif self.config.get('mailgun_api_key'):
            return self._send_mailgun(subject, text_body, html_body)

        # Fall back to SMTP
        else:
            return self._send_smtp(subject, text_body, html_body)

    def _send_smtp(self, subject: str, text_body: str, html_body: str) -> bool:
        """Send via SMTP."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"{self.config.get('email_subject_prefix')} {subject}"
            msg['From'] = self.config.get('email_from')
            msg['To'] = self.config.get('email_to')

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            smtp_host = self.config.get('smtp_host')
            smtp_port = self.config.get('smtp_port')

            if self.config.get('smtp_tls'):
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)

            if self.config.get('smtp_user'):
                server.login(
                    self.config.get('smtp_user'),
                    self.config.get('smtp_password')
                )

            server.send_message(msg)
            server.quit()

            print(f"[*] Email sent via SMTP to {self.config.get('email_to')}")
            return True

        except Exception as e:
            print(f"[!] SMTP error: {e}")
            return False

    def _send_sendgrid(self, subject: str, text_body: str, html_body: str) -> bool:
        """Send via SendGrid API."""
        try:
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {
                'Authorization': f"Bearer {self.config.get('sendgrid_api_key')}",
                'Content-Type': 'application/json'
            }

            data = {
                'personalizations': [{
                    'to': [{'email': self.config.get('email_to')}]
                }],
                'from': {'email': self.config.get('email_from')},
                'subject': f"{self.config.get('email_subject_prefix')} {subject}",
                'content': [
                    {'type': 'text/plain', 'value': text_body},
                    {'type': 'text/html', 'value': html_body}
                ]
            }

            response = requests.post(url, headers=headers, json=data, timeout=10)

            if response.status_code == 202:
                print(f"[*] Email sent via SendGrid to {self.config.get('email_to')}")
                return True
            else:
                print(f"[!] SendGrid error: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] SendGrid error: {e}")
            return False

    def _send_mailgun(self, subject: str, text_body: str, html_body: str) -> bool:
        """Send via Mailgun API."""
        try:
            url = f"https://api.mailgun.net/v3/{self.config.get('mailgun_domain')}/messages"

            response = requests.post(
                url,
                auth=('api', self.config.get('mailgun_api_key')),
                data={
                    'from': self.config.get('email_from'),
                    'to': self.config.get('email_to'),
                    'subject': f"{self.config.get('email_subject_prefix')} {subject}",
                    'text': text_body,
                    'html': html_body
                },
                timeout=10
            )

            if response.status_code == 200:
                print(f"[*] Email sent via Mailgun to {self.config.get('email_to')}")
                return True
            else:
                print(f"[!] Mailgun error: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] Mailgun error: {e}")
            return False


class WebhookAlerter:
    """Send real-time alerts via webhooks."""

    def __init__(self, config: Config):
        self.config = config

    def send_alert(self, title: str, message: str, severity: str = 'info'):
        """Send alert to all configured webhooks."""
        if self.config.get('slack_webhook'):
            self._send_slack(title, message, severity)

        if self.config.get('discord_webhook'):
            self._send_discord(title, message, severity)

        if self.config.get('teams_webhook'):
            self._send_teams(title, message, severity)

    def _send_slack(self, title: str, message: str, severity: str):
        """Send Slack notification."""
        try:
            color = {'info': '#36a64f', 'warning': '#ff9900', 'critical': '#e74c3c'}.get(severity, '#36a64f')

            payload = {
                'attachments': [{
                    'color': color,
                    'title': title,
                    'text': message,
                    'footer': 'Cowrie Honeypot Alert',
                    'ts': int(datetime.now().timestamp())
                }]
            }

            response = requests.post(
                self.config.get('slack_webhook'),
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                print("[*] Slack alert sent")

        except Exception as e:
            print(f"[!] Slack webhook error: {e}")

    def _send_discord(self, title: str, message: str, severity: str):
        """Send Discord notification."""
        try:
            color_map = {'info': 3447003, 'warning': 16760576, 'critical': 15158332}

            payload = {
                'embeds': [{
                    'title': title,
                    'description': message,
                    'color': color_map.get(severity, 3447003),
                    'footer': {'text': 'Cowrie Honeypot Alert'},
                    'timestamp': datetime.now().isoformat()
                }]
            }

            response = requests.post(
                self.config.get('discord_webhook'),
                json=payload,
                timeout=10
            )

            if response.status_code == 204:
                print("[*] Discord alert sent")

        except Exception as e:
            print(f"[!] Discord webhook error: {e}")

    def _send_teams(self, title: str, message: str, severity: str):
        """Send Microsoft Teams notification."""
        try:
            color = {'info': '00ff00', 'warning': 'ff9900', 'critical': 'ff0000'}.get(severity, '00ff00')

            payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': title,
                'themeColor': color,
                'title': title,
                'text': message
            }

            response = requests.post(
                self.config.get('teams_webhook'),
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                print("[*] Teams alert sent")

        except Exception as e:
            print(f"[!] Teams webhook error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Cowrie Honeypot Daily Report Generator')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--hours', type=int, help='Hours to look back (default: 24)')
    parser.add_argument('--output', help='Output file path (instead of email)')
    parser.add_argument('--test', action='store_true', help='Test mode: print to stdout')

    args = parser.parse_args()

    # Load configuration
    config = Config(args.config)
    if args.hours:
        config.config['report_hours'] = args.hours

    print(f"[*] Starting Cowrie daily report generator")
    print(f"[*] Report period: last {config.get('report_hours')} hours")

    # Parse logs
    parser = LogParser(
        config.get('log_path'),
        hours=config.get('report_hours')
    )
    stats = parser.parse()

    print(f"[*] Parsed {stats['total_connections']} connections from {stats['unique_ips']} unique IPs")

    # GeoIP enrichment
    geo_enricher = GeoIPEnricher(
        config.get('geoip_db_path'),
        config.get('geoip_asn_path')
    )
    geo_data, country_counts = geo_enricher.enrich_ip_list(stats['ip_list'])
    print(f"[*] Enriched {len(geo_data)} unique IPs with GeoIP data")

    # Analyze downloaded files
    file_analysis = []
    cache = CacheDB(config.get('cache_db_path'))

    if stats['downloads']:
        print(f"[*] Analyzing {len(stats['downloads'])} downloaded files...")

        vt_scanner = None
        if config.get('virustotal_enabled') and config.get('virustotal_api_key'):
            vt_scanner = VirusTotalScanner(config.get('virustotal_api_key'), cache)

        yara_scanner = YARAScanner(config.get('yara_rules_path'))

        download_path = config.get('download_path')

        for download in stats['downloads']:
            sha256 = download['shasum']
            file_path = os.path.join(download_path, sha256) if download_path else None

            file_info = {
                'sha256': sha256,
                'url': download.get('url', ''),
                'size': 0
            }

            if file_path and os.path.exists(file_path):
                file_info['size'] = os.path.getsize(file_path)

                # YARA scan
                yara_matches = yara_scanner.scan_file(file_path)
                if yara_matches:
                    file_info['yara_matches'] = yara_matches

                # VirusTotal scan
                if vt_scanner:
                    vt_result = vt_scanner.scan_file(file_path, sha256)
                    if vt_result:
                        file_info['vt_result'] = vt_result

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
        with open(args.output, 'w') as f:
            f.write(html_report)
        print(f"[*] Report saved to: {args.output}")
        return

    # Send email
    report_date = datetime.now().strftime('%Y-%m-%d')
    subject = f"Daily Report - {report_date} - {stats['total_connections']} attacks from {stats['unique_ips']} IPs"

    email_sender = EmailSender(config)
    email_sender.send(subject, text_report, html_report)

    # Send alerts if thresholds exceeded
    alerter = WebhookAlerter(config)

    if stats['total_connections'] > config.get('alert_threshold_connections'):
        alerter.send_alert(
            '⚠️ High Attack Volume',
            f"Detected {stats['total_connections']} connection attempts in the last {config.get('report_hours')} hours",
            'warning'
        )

    if config.get('alert_on_malware') and file_analysis:
        for file_info in file_analysis:
            if file_info.get('vt_result', {}).get('detections', 0) > 0:
                vt = file_info['vt_result']
                alerter.send_alert(
                    '🚨 Malware Downloaded',
                    f"SHA256: {file_info['sha256'][:16]}...\nVirusTotal: {vt['detections']}/{vt['total_engines']} detections\n{vt['link']}",
                    'critical'
                )

    print("[*] Daily report completed successfully")

    # Cleanup
    geo_enricher.close()


if __name__ == '__main__':
    main()
