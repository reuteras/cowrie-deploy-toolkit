#!/usr/bin/env python3
"""
Cowrie SSH Session Playback Web Service

Provides a web interface for viewing and replaying SSH sessions captured by Cowrie.
"""

import json
import os
import queue
import sqlite3
import struct
import tempfile
import threading
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

try:
    import geoip2.database
except ImportError:
    geoip2 = None

__version__ = "2.1.0"

app = Flask(__name__)

# Configuration from environment variables
CONFIG = {
    "log_path": os.getenv("COWRIE_LOG_PATH", "/cowrie-data/log/cowrie/cowrie.json"),
    "tty_path": os.getenv("COWRIE_TTY_PATH", "/cowrie-data/lib/cowrie/tty"),
    "download_path": os.getenv("COWRIE_DOWNLOAD_PATH", "/cowrie-data/lib/cowrie/downloads"),
    "honeyfs_path": os.getenv("HONEYFS_PATH", "/cowrie-data/share/cowrie/contents"),
    "identity_path": os.getenv("IDENTITY_PATH", "/identity"),
    "geoip_db_path": os.getenv("GEOIP_DB_PATH", "/cowrie-data/geoip/GeoLite2-City.mmdb"),
    "geoip_asn_path": os.getenv("GEOIP_ASN_PATH", "/cowrie-data/geoip/GeoLite2-ASN.mmdb"),
    "base_url": os.getenv("BASE_URL", ""),
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "cache_db_path": os.getenv("CACHE_DB_PATH", "/tmp/vt-cache.db"),
    "yara_cache_db_path": os.getenv("YARA_CACHE_DB_PATH", "/cowrie-data/var/yara-cache.db"),
    "metadata_path": os.getenv("COWRIE_METADATA_PATH", "/cowrie-metadata/metadata.json"),
    "server_ip": os.getenv("SERVER_IP", ""),
    "honeypot_hostname": os.getenv("HONEYPOT_HOSTNAME", ""),
    "canary_webhook_db_path": os.getenv("CANARY_WEBHOOK_DB_PATH", "/cowrie-data/var/canary-webhooks.db"),
    # Dashboard mode configuration (NEW in v2.1)
    "dashboard_mode": os.getenv("DASHBOARD_MODE", "local"),
    "dashboard_api_url": os.getenv("DASHBOARD_API_URL", ""),
}


class GeoIPLookup:
    """Simple GeoIP lookup wrapper with ASN support."""

    def __init__(self, db_path: str, asn_db_path: Optional[str] = None):
        self.reader = None
        self.asn_reader = None
        if geoip2 and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
                print(f"[GeoIP] Loaded City database from {db_path}")
            except Exception as e:
                print(f"[GeoIP] Failed to load City database from {db_path}: {e}")

        # Initialize ASN database if provided
        if geoip2 and asn_db_path:
            if os.path.exists(asn_db_path):
                try:
                    self.asn_reader = geoip2.database.Reader(asn_db_path)
                    print(f"[GeoIP] Loaded ASN database from {asn_db_path}")
                except Exception as e:
                    print(f"[GeoIP] Failed to load ASN database from {asn_db_path}: {e}")
            else:
                print(f"[GeoIP] ASN database not found at {asn_db_path}")

    def lookup(self, ip: str) -> dict:
        """Lookup IP and return geo data with ASN information."""
        result = {"country": "-", "country_code": "XX", "city": "-"}
        if not self.reader:
            return result
        try:
            response = self.reader.city(ip)
            result["country"] = response.country.name or "-"
            result["country_code"] = response.country.iso_code or "XX"
            result["city"] = response.city.name or "-"
            result["latitude"] = response.location.latitude
            result["longitude"] = response.location.longitude
        except Exception:
            pass

        # Add ASN information if available
        if self.asn_reader:
            try:
                asn_response = self.asn_reader.asn(ip)
                result["asn"] = asn_response.autonomous_system_number
                result["asn_org"] = asn_response.autonomous_system_organization
            except Exception:
                pass

        return result


class CacheDB:
    """Simple SQLite cache for VirusTotal results."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        # Create parent directories if they don't exist
        from pathlib import Path

        db_path_obj = Path(self.db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result TEXT,
                timestamp INTEGER
            )
        """)
        conn.commit()
        conn.close()

    def get_vt_result(self, sha256: str) -> Optional[dict]:
        """Get cached VT result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT result FROM vt_cache WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def set_vt_result(self, sha256: str, result: dict):
        """Cache VT result."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO vt_cache (sha256, result, timestamp) VALUES (?, ?, ?)",
            (sha256, json.dumps(result), int(time.time())),
        )
        conn.commit()
        conn.close()


class YARACache:
    """SQLite cache for YARA scan results and file type info (read-only for web app)."""

    # Maximum file size for preview (1MB)
    MAX_PREVIEW_SIZE = 1024 * 1024

    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_result(self, sha256: str) -> Optional[dict]:
        """Get cached scan result including file type."""
        if not os.path.exists(self.db_path):
            return None

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                """SELECT matches, scan_timestamp, file_type, file_mime,
                          file_category, is_previewable
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
                    "file_type": row[2],
                    "file_mime": row[3],
                    "file_category": row[4],
                    "is_previewable": bool(row[5]) if row[5] is not None else False,
                }
        except Exception:
            pass
        return None


class CanaryWebhookDB:
    """SQLite database for storing Canary Token webhook alerts."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        # Create parent directories if they don't exist
        from pathlib import Path

        db_path_obj = Path(self.db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS canary_webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                token_type TEXT,
                token_name TEXT,
                trigger_ip TEXT,
                trigger_user_agent TEXT,
                trigger_location TEXT,
                trigger_hostname TEXT,
                referer TEXT,
                additional_data TEXT,
                raw_payload TEXT
            )
        """)
        conn.commit()
        conn.close()

    def add_webhook(self, webhook_data: dict) -> int:
        """Add a webhook alert to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            """INSERT INTO canary_webhooks
               (token_type, token_name, trigger_ip, trigger_user_agent,
                trigger_location, trigger_hostname, referer, additional_data, raw_payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                webhook_data.get("token_type"),
                webhook_data.get("token_name"),
                webhook_data.get("trigger_ip"),
                webhook_data.get("trigger_user_agent"),
                webhook_data.get("trigger_location"),
                webhook_data.get("trigger_hostname"),
                webhook_data.get("referer"),
                json.dumps(webhook_data.get("additional_data", {})),
                json.dumps(webhook_data.get("raw_payload", {})),
            ),
        )
        webhook_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return webhook_id

    def get_recent_webhooks(self, limit: int = 100) -> list:
        """Get recent webhook alerts."""
        if not os.path.exists(self.db_path):
            return []

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """SELECT * FROM canary_webhooks
                   ORDER BY received_at DESC LIMIT ?""",
                (limit,),
            )
            rows = cursor.fetchall()
            conn.close()

            results = []
            for row in rows:
                # Parse received_at timestamp string to datetime object
                received_at = row["received_at"]
                if received_at:
                    try:
                        # SQLite CURRENT_TIMESTAMP format: "YYYY-MM-DD HH:MM:SS"
                        received_at = datetime.strptime(received_at, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        # Fallback: keep as string if parsing fails
                        pass

                results.append(
                    {
                        "id": row["id"],
                        "received_at": received_at,
                        "token_type": row["token_type"],
                        "token_name": row["token_name"],
                        "trigger_ip": row["trigger_ip"],
                        "trigger_user_agent": row["trigger_user_agent"],
                        "trigger_location": row["trigger_location"],
                        "trigger_hostname": row["trigger_hostname"],
                        "referer": row["referer"],
                        "additional_data": json.loads(row["additional_data"]) if row["additional_data"] else {},
                        "raw_payload": json.loads(row["raw_payload"]) if row["raw_payload"] else {},
                    }
                )
            return results
        except Exception as e:
            print(f"[!] Error fetching webhooks: {e}")
            return []

    def get_webhook_count(self, hours: int = 24) -> int:
        """Get count of webhooks received in the last N hours."""
        if not os.path.exists(self.db_path):
            return 0

        try:
            conn = sqlite3.connect(self.db_path)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cursor = conn.execute(
                """SELECT COUNT(*) FROM canary_webhooks
                   WHERE received_at >= ?""",
                (cutoff.isoformat(),),
            )
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0


class VirusTotalScanner:
    """Scan files using VirusTotal API."""

    def __init__(self, api_key: str, cache: CacheDB):
        self.api_key = api_key
        self.cache = cache
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan_file(self, sha256: str) -> Optional[dict]:
        """Scan file and return results."""
        if not self.api_key:
            return None

        # Check cache first
        cached = self.cache.get_vt_result(sha256)
        if cached:
            return cached

        # Query VirusTotal
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

                # Extract threat label if available
                threat_class = attributes.get("popular_threat_classification", {})
                if threat_class and "suggested_threat_label" in threat_class:
                    result["threat_label"] = threat_class["suggested_threat_label"]

                # Cache result
                self.cache.set_vt_result(sha256, result)
                return result

            elif response.status_code == 404:
                return None

        except Exception as e:
            print(f"[!] VirusTotal API error: {e}")

        return None


class SessionParser:
    """Parse Cowrie JSON logs and extract session data."""

    def __init__(self, log_path: str, geoip_instance=None):
        self.log_path = log_path
        self.sessions = {}
        # Use provided GeoIP instance or create a new one (for backwards compatibility)
        self.geoip = (
            geoip_instance if geoip_instance else GeoIPLookup(CONFIG["geoip_db_path"], CONFIG.get("geoip_asn_path"))
        )

    def parse_all(self, hours: int = 168) -> dict:
        """Parse all sessions from logs within the specified hours."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        sessions = defaultdict(
            lambda: {
                "id": None,
                "src_ip": None,
                "start_time": None,
                "end_time": None,
                "duration": 0,
                "username": None,
                "password": None,
                "commands": [],
                "downloads": [],
                "tty_logs": [],  # Changed to list to collect all TTY files
                "tty_log": None,  # Keep for backwards compatibility (last TTY file)
                "client_version": None,
                "geo": {},
                "login_success": False,
            }
        )

        if not os.path.exists(self.log_path):
            return {}

        for logfile in Path(self.log_path).parent.rglob("*json*"):
            with open(logfile) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))

                        if timestamp < cutoff_time:
                            continue

                        session_id = entry.get("session")
                        if not session_id:
                            continue

                        event_id = entry.get("eventid", "")
                        session = sessions[session_id]
                        session["id"] = session_id

                        if event_id == "cowrie.session.connect":
                            session["src_ip"] = entry.get("src_ip")
                            session["start_time"] = entry["timestamp"]
                            if session["src_ip"]:
                                session["geo"] = self.geoip.lookup(session["src_ip"])

                        elif event_id == "cowrie.client.version":
                            session["client_version"] = entry.get("version")

                        elif event_id == "cowrie.login.success":
                            session["username"] = entry.get("username")
                            session["password"] = entry.get("password")
                            session["login_success"] = True

                        elif event_id == "cowrie.login.failed":
                            if not session["username"]:
                                session["username"] = entry.get("username")
                                session["password"] = entry.get("password")

                        elif event_id == "cowrie.command.input":
                            session["commands"].append(
                                {"command": entry.get("input", ""), "timestamp": entry["timestamp"]}
                            )

                        elif event_id == "cowrie.session.file_download":
                            session["downloads"].append(
                                {
                                    "url": entry.get("url", ""),
                                    "shasum": entry.get("shasum", ""),
                                    "timestamp": entry["timestamp"],
                                }
                            )

                        elif event_id == "cowrie.log.closed":
                            tty_log = entry.get("ttylog")
                            if tty_log:
                                # Append to list of all TTY logs for this session
                                session["tty_logs"].append(
                                    {
                                        "ttylog": tty_log,
                                        "timestamp": entry["timestamp"],
                                        "duration": entry.get("duration", "0"),
                                        "size": entry.get("size", 0),
                                    }
                                )
                                # Keep last one for backwards compatibility
                                session["tty_log"] = tty_log

                        elif event_id == "cowrie.session.closed":
                            session["end_time"] = entry["timestamp"]
                            if session["start_time"]:
                                start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
                                end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
                                session["duration"] = (end - start).total_seconds()

                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue

        return dict(sessions)

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a specific session by ID."""
        sessions = self.parse_all(hours=720)  # Look back 30 days
        return sessions.get(session_id)

    def get_session_events(self, session_id: str) -> list:
        """Get all events for a specific session."""
        events = []
        if not os.path.exists(self.log_path):
            return events

        with open(self.log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get("session") == session_id:
                        events.append(entry)
                except (json.JSONDecodeError, KeyError):
                    continue

        # Sort by timestamp
        events.sort(key=lambda x: x.get("timestamp", ""))
        return events

    def get_threat_intel_for_ip(self, ip_address: str) -> dict:
        """Get threat intelligence data for a specific IP address."""
        result = {}

        if not os.path.exists(self.log_path):
            return result

        with open(self.log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    entry.get("eventid", "")
                    src_ip = entry.get("src_ip")

                    if src_ip != ip_address:
                        continue

                    # Future threat intelligence integrations can be added here

                except (json.JSONDecodeError, KeyError):
                    continue

        return result

    def get_stats(self, hours: int = 24) -> dict:
        """Get statistics for the dashboard."""
        sessions = self.parse_all(hours=hours)

        if not sessions:
            return {
                "total_sessions": 0,
                "unique_ips": 0,
                "sessions_with_commands": 0,
                "total_downloads": 0,
                "unique_downloads": 0,
                "ip_list": [],
                "ip_locations": [],
                "top_countries": [],
                "top_credentials": [],
                "successful_credentials": [],
                "top_commands": [],
                "top_clients": [],
                "top_asns": [],
                "hourly_activity": [],
                "vt_stats": {
                    "total_scanned": 0,
                    "total_malicious": 0,
                    "avg_detection_rate": 0.0,
                    "total_threat_families": 0,
                },
            }

        # Calculate stats
        ips = set()
        ip_details = defaultdict(
            lambda: {"count": 0, "geo": None, "last_seen": None, "successful_logins": 0, "failed_logins": 0}
        )
        country_counter = Counter()
        credential_counter = Counter()
        successful_credentials = set()
        command_counter = Counter()
        client_version_counter = Counter()
        asn_counter = Counter()  # Track sessions by ASN
        asn_details = {}  # ASN -> {asn_org, asn_number}
        sessions_with_cmds = 0
        total_downloads = 0
        unique_downloads = set()
        hourly_activity = defaultdict(int)
        ip_locations = []  # For map

        for session in sessions.values():
            if session["src_ip"]:
                ips.add(session["src_ip"])
                ip = session["src_ip"]
                ip_details[ip]["count"] += 1
                ip_details[ip]["geo"] = session.get("geo", {})
                ip_details[ip]["last_seen"] = session["start_time"]

                # Track login attempts for this IP
                if session.get("login_success"):
                    ip_details[ip]["successful_logins"] += 1
                elif session.get("username"):  # Had login attempt but not successful
                    ip_details[ip]["failed_logins"] += 1

                # Collect IP locations for map
                geo = session.get("geo", {})
                if geo and "latitude" in geo and "longitude" in geo:
                    ip_locations.append(
                        {
                            "ip": ip,
                            "lat": geo["latitude"],
                            "lon": geo["longitude"],
                            "country": geo.get("country", "Unknown"),
                            "city": geo.get("city", "Unknown"),
                        }
                    )

                country = session.get("geo", {}).get("country", "Unknown")
                country_counter[country] += 1

                # Track ASN data
                asn = session.get("geo", {}).get("asn")
                asn_org = session.get("geo", {}).get("asn_org")
                if asn:
                    asn_key = f"AS{asn}"
                    asn_counter[asn_key] += 1
                    if asn_key not in asn_details:
                        asn_details[asn_key] = {"asn_number": asn, "asn_org": asn_org or "Unknown Organization"}

            if session["username"] and session["password"]:
                cred = f"{session['username']}:{session['password']}"
                credential_counter[cred] += 1
                # Track successful logins
                if session.get("login_success"):
                    successful_credentials.add(cred)

            if session["commands"]:
                sessions_with_cmds += 1
                for cmd in session["commands"]:
                    command_counter[cmd["command"]] += 1

            # Track SSH client versions
            if session.get("client_version"):
                client_version_counter[session["client_version"]] += 1

            # Track downloads
            for download in session["downloads"]:
                total_downloads += 1
                if download["shasum"]:
                    unique_downloads.add(download["shasum"])

            if session["start_time"]:
                try:
                    hour = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00")).strftime(
                        "%Y-%m-%d %H:00"
                    )
                    hourly_activity[hour] += 1
                except Exception:
                    pass

        # Sort hourly activity
        sorted_hours = sorted(hourly_activity.items())

        # Sort IP details by session count
        sorted_ips = sorted(
            [{"ip": ip, **details} for ip, details in ip_details.items()], key=lambda x: x["count"], reverse=True
        )

        # Build top ASNs list with details
        top_asns = []
        for asn_key, count in asn_counter.most_common(10):
            details = asn_details.get(asn_key, {})
            top_asns.append(
                {
                    "asn": asn_key,
                    "asn_number": details.get("asn_number", 0),
                    "asn_org": details.get("asn_org", "Unknown"),
                    "count": count,
                }
            )

        # Collect malicious downloads with VT scores
        download_path = CONFIG["download_path"]
        all_downloads = []
        for session in sessions.values():
            for download in session["downloads"]:
                all_downloads.append(
                    {
                        "session_id": session["id"],
                        "src_ip": session["src_ip"],
                        "shasum": download["shasum"],
                        "url": download.get("url", ""),
                        "timestamp": download["timestamp"],
                    }
                )

        # Deduplicate by shasum and get VT scores
        all_scanned_files = {}
        vt_total_scanned = 0
        vt_total_malicious = 0
        vt_total_detections = 0
        vt_total_engines = 0
        vt_threat_families = set()

        for dl in all_downloads:
            shasum = dl["shasum"]
            if shasum and shasum not in all_scanned_files:
                file_path = os.path.join(download_path, shasum)
                dl["exists"] = os.path.exists(file_path)
                if dl["exists"]:
                    dl["size"] = os.path.getsize(file_path)
                else:
                    dl["size"] = 0

                # Get YARA matches and file type
                yara_result = yara_cache.get_result(shasum)
                if yara_result:
                    dl["file_type"] = yara_result.get("file_type")
                    dl["file_category"] = yara_result.get("file_category")
                    dl["yara_matches"] = yara_result.get("matches", [])

                # Get VirusTotal score
                if vt_scanner:
                    vt_result = vt_scanner.scan_file(shasum)
                    if vt_result:
                        vt_total_scanned += 1
                        detections = vt_result["detections"]
                        total_eng = vt_result["total_engines"]

                        dl["vt_detections"] = detections
                        dl["vt_total"] = total_eng
                        dl["vt_link"] = vt_result["link"]
                        dl["vt_threat_label"] = vt_result.get("threat_label", "")

                        # Aggregate stats
                        vt_total_detections += detections
                        vt_total_engines += total_eng

                        # Track all scanned files (including clean files with 0 detections)
                        all_scanned_files[shasum] = dl

                        if detections > 0:
                            vt_total_malicious += 1

                            # Track threat families
                            threat_label = vt_result.get("threat_label", "")
                            if threat_label:
                                vt_threat_families.add(threat_label)

        # Calculate VirusTotal statistics
        vt_stats = {
            "total_scanned": vt_total_scanned,
            "total_malicious": vt_total_malicious,
            "avg_detection_rate": (vt_total_detections / vt_total_engines * 100) if vt_total_engines > 0 else 0.0,
            "total_threat_families": len(vt_threat_families),
        }

        # Sort by VT detections (most detected first, but include all files)
        top_downloads = sorted(all_scanned_files.values(), key=lambda x: x.get("vt_detections", 0), reverse=True)[:10]

        return {
            "total_sessions": len(sessions),
            "unique_ips": len(ips),
            "sessions_with_commands": sessions_with_cmds,
            "total_downloads": total_downloads,
            "unique_downloads": len(unique_downloads),
            "ip_list": sorted_ips,
            "ip_locations": ip_locations,
            "top_countries": country_counter.most_common(10),
            "top_credentials": credential_counter.most_common(10),
            "successful_credentials": list(successful_credentials),
            "top_commands": command_counter.most_common(20),
            "top_clients": client_version_counter.most_common(10),
            "top_asns": top_asns,
            "top_malicious_downloads": top_downloads,
            "vt_stats": vt_stats,
            "hourly_activity": sorted_hours[-48:],  # Last 48 hours
        }

    def get_all_commands(self, hours: int = 168) -> list:
        """Get a flat list of all commands from all sessions."""
        sessions = self.parse_all(hours=hours)
        all_commands = []
        for session in sessions.values():
            if session["commands"]:
                for cmd in session["commands"]:
                    all_commands.append(
                        {
                            "timestamp": cmd["timestamp"],
                            "command": cmd["command"],
                            "src_ip": session["src_ip"],
                            "session_id": session["id"],
                        }
                    )

        # Sort by timestamp, most recent first
        return sorted(all_commands, key=lambda x: x["timestamp"], reverse=True)


class TTYLogParser:
    """Parse Cowrie TTY log files and convert to asciicast format."""

    # Cowrie TTY log opcodes
    OP_OPEN = 1
    OP_CLOSE = 2
    OP_WRITE = 3
    OP_EXEC = 4

    # Cowrie TTY stream types
    TYPE_INPUT = 1
    TYPE_OUTPUT = 2
    TYPE_INTERACT = 3

    def __init__(self, tty_path: str):
        self.tty_path = tty_path

    def find_tty_file(self, tty_log_name: str) -> Optional[str]:
        """Find a TTY log file by name."""
        if not tty_log_name:
            return None

        original_tty_log_name = tty_log_name
        # Strip common Cowrie path prefixes if present
        # Sessions may store paths like "var/lib/cowrie/tty/HASH"
        for prefix in ["var/lib/cowrie/tty/", "lib/cowrie/tty/", "tty/"]:
            if tty_log_name.startswith(prefix):
                tty_log_name = tty_log_name[len(prefix) :]
                break

        # Try direct path (just the hash/filename)
        direct_path = os.path.join(self.tty_path, tty_log_name)
        if os.path.exists(direct_path):
            return direct_path

        # Try with various date-based subdirectories
        for root, _, files in os.walk(self.tty_path):
            if tty_log_name in files:
                return os.path.join(root, tty_log_name)

        print(
            f"[!] TTY file lookup failed. Searched for '{tty_log_name}' (from '{original_tty_log_name}') in '{self.tty_path}' but it was not found."
        )
        return None

    def parse_tty_log(self, tty_log_name: str) -> Optional[dict]:
        """Parse a Cowrie TTY log file and return asciicast v1 format."""
        file_path = self.find_tty_file(tty_log_name)
        if not file_path:
            # Error is logged in find_tty_file
            return None

        stdout = []
        width = 80
        height = 24
        duration = 0.0
        currtty = 0
        prevtime = 0

        # Cowrie ttylog format: <iLiiLL = op, tty, length, direction, sec, usec
        record_size = struct.calcsize("<iLiiLL")

        try:
            with open(file_path, "rb") as f:
                while True:
                    # Read record header
                    record_data = f.read(record_size)
                    if not record_data:
                        break  # End of file

                    if len(record_data) < record_size:
                        print(f"[!] Incomplete record in TTY log, stopping parse: {file_path}")
                        break

                    try:
                        op, tty, length, direction, sec, usec = struct.unpack("<iLiiLL", record_data)
                    except struct.error as e:
                        print(f"[!] Corrupt record in TTY log, stopping parse: {file_path} - {e}")
                        break

                    if length > 10 * 1024 * 1024:  # 10MB limit
                        print(f"[!] Unreasonable TTY record size ({length} bytes), stopping parse: {file_path}")
                        break

                    # Read data payload
                    data = f.read(length)
                    if len(data) < length:
                        print(
                            f"[!] Truncated data record in TTY log (expected {length}, got {len(data)}), stopping parse: {file_path}"
                        )
                        break

                    # Track the first TTY we see
                    if currtty == 0:
                        currtty = tty

                    # Only process events for the primary TTY
                    if tty == currtty:
                        if op == self.OP_OPEN:
                            # Try to extract terminal dimensions
                            try:
                                if len(data) >= 8:
                                    width, height = struct.unpack("<II", data[:8])
                            except struct.error:
                                # Ignore if terminal size parsing fails
                                pass

                        elif op == self.OP_WRITE:
                            # Only capture TYPE_OUTPUT (2) which contains everything shown on terminal:
                            # - Login banners and prompts
                            # - Echoed commands (character by character)
                            # - Command output
                            # Skip TYPE_INPUT (1) = raw keystrokes (duplicates TYPE_OUTPUT echo)
                            # Skip TYPE_INTERACT (3) = can cause ordering issues with prompts
                            if direction == self.TYPE_OUTPUT:
                                # Calculate timestamp
                                curtime = float(sec) + float(usec) / 1000000.0
                                if prevtime != 0:
                                    sleeptime = curtime - prevtime
                                else:
                                    sleeptime = 0.0
                                prevtime = curtime

                                # Decode the data without modifying newlines
                                # Asciinema player handles terminal control characters correctly
                                try:
                                    text = data.decode("utf-8", errors="replace")
                                except Exception:
                                    text = data.decode("latin-1", errors="replace")

                                # Add to stdout (v1 format uses [time, data])
                                stdout.append([sleeptime, text])
                                duration += sleeptime

                        elif op == self.OP_CLOSE:
                            # Don't break - continue parsing to capture all commands
                            # OP_CLOSE can occur after each command, not just at session end
                            pass

        except OSError as e:
            print(f"[!] I/O error reading TTY log '{file_path}': {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected exception in parse_tty_log for '{file_path}': {e}")
            return None

        # Return asciicast v1 format (matches Cowrie's asciinema.py)
        return {
            "version": 1,
            "width": min(width, 200),
            "height": min(height, 50),
            "duration": duration,
            "command": "/bin/bash",
            "title": "Cowrie Recording",
            "env": {"SHELL": "/bin/bash", "TERM": "xterm256-color"},
            "stdout": stdout,
        }

    def merge_tty_logs(self, session: dict, hostname: str = "dmz-web01") -> Optional[dict]:
        """Merge multiple TTY log files from a session into a single asciicast.

        Args:
            session: Session dict containing tty_logs list and commands list
            hostname: Honeypot hostname for the prompt

        Returns:
            Merged asciicast dict in v1 format
        """
        tty_logs = session.get("tty_logs", [])
        commands = session.get("commands", [])
        session.get("username", "root")

        print(f"[DEBUG] merge_tty_logs: Found {len(tty_logs)} TTY logs and {len(commands)} commands")

        if not tty_logs:
            print("[DEBUG] merge_tty_logs: No TTY logs found, returning None")
            return None

        merged_stdout = []
        total_duration = 0.0
        width = 120
        height = 30

        # Sort TTY logs by timestamp for proper chronological order
        sorted_ttys = sorted(tty_logs, key=lambda x: x.get("timestamp", ""))

        # Simply concatenate all TTY logs in order
        # Don't inject prompts/commands - they're already in the TTY logs from TYPE_OUTPUT
        # TYPE_OUTPUT contains everything shown on terminal: prompts, echoed commands, output
        for tty_entry in sorted_ttys:
            tty_log_name = tty_entry.get("ttylog")
            if tty_log_name:
                asciicast = self.parse_tty_log(tty_log_name)
                if asciicast:
                    # Update dimensions if needed
                    width = max(width, asciicast.get("width", 120))
                    height = max(height, asciicast.get("height", 30))

                    # Add all events from this TTY log
                    # Don't modify the data - asciinema player handles it correctly
                    for event in asciicast.get("stdout", []):
                        merged_stdout.append([event[0], event[1]])
                        total_duration += event[0]

        print(
            f"[DEBUG] merge_tty_logs: Created asciicast with {len(merged_stdout)} events, duration={total_duration:.2f}s"
        )

        return {
            "version": 1,
            "width": min(width, 200),
            "height": min(height, 50),
            "duration": total_duration,
            "command": "/bin/bash",
            "title": "Cowrie Recording (Merged)",
            "env": {"SHELL": "/bin/bash", "TERM": "xterm256-color"},
            "stdout": merged_stdout,
        }


# Global GeoIP lookup instance (singleton to avoid reloading databases)
# Initialize this FIRST so all other components can use it
print("[+] Loading GeoIP databases (one-time initialization)...")
global_geoip = GeoIPLookup(CONFIG["geoip_db_path"], CONFIG.get("geoip_asn_path"))
print("[+] GeoIP databases loaded successfully")

# Initialize parsers (pass global GeoIP instance to avoid reloading)
session_parser = SessionParser(CONFIG["log_path"], geoip_instance=global_geoip)
tty_parser = TTYLogParser(CONFIG["tty_path"])

# Initialize VirusTotal scanner if API key is provided
vt_scanner = None
if CONFIG["virustotal_api_key"]:
    cache_db = CacheDB(CONFIG["cache_db_path"])
    vt_scanner = VirusTotalScanner(CONFIG["virustotal_api_key"], cache_db)

# Initialize YARA cache (reads results from yara-scanner-daemon)
yara_cache = YARACache(CONFIG["yara_cache_db_path"])

# Initialize Canary Webhook database
canary_webhook_db = CanaryWebhookDB(CONFIG["canary_webhook_db_path"])

# Initialize DataSource abstraction (NEW in v2.1)
# Supports local, remote, and multi-source modes
datasource = None
multisource = None

try:
    dashboard_mode = CONFIG["dashboard_mode"]

    if dashboard_mode == "multi":
        # Multi-source mode: aggregate data from multiple honeypots
        from multisource import HoneypotSource, MultiSourceDataSource

        # Read sources from environment variable (JSON format)
        # Format: [{"name": "...", "type": "...", "api_base_url": "...", "enabled": true}, ...]
        sources_json = os.getenv("DASHBOARD_SOURCES", "[]")
        try:
            import json

            sources_config = json.loads(sources_json)
            sources = []

            for sc in sources_config:
                sources.append(
                    HoneypotSource(
                        name=sc.get("name"),
                        source_type=sc.get("type", "cowrie-ssh"),
                        mode=sc.get("mode", "remote"),
                        api_base_url=sc.get("api_base_url"),
                        location=sc.get("location"),
                        enabled=sc.get("enabled", True),
                    )
                )

            if sources:
                session_parser = MultiSourceDataSource(sources)
                print(f"[+] MultiSourceDataSource initialized with {len(sources)} sources")
            else:
                print("[!] Warning: Multi-source mode enabled but no sources configured")
                print("[!] Dashboard will operate in local mode only")

        except Exception as e:
            print(f"[!] Error parsing DASHBOARD_SOURCES: {e}")
            print("[!] Dashboard will operate in local mode only")

    elif dashboard_mode in ["remote", "local"]:
        # Single-source mode via API (local or remote)
        from datasource import DataSource

        # IMPORTANT: "local" mode now means "use local API" not "parse files directly"
        # This ensures we always benefit from fast SQLite queries
        if dashboard_mode == "local":
            api_url = "http://cowrie-api:8000"
            print(f"[+] DataSource initialized in local mode (using local API at {api_url})")
        else:
            api_url = CONFIG["dashboard_api_url"]
            print(f"[+] DataSource initialized in remote mode (API: {api_url})")

        datasource = DataSource(
            mode="remote",  # Always use remote mode (API-based)
            api_base_url=api_url,
        )
        print("[+] API-based datasource ready")

    else:
        print(f"[!] Unknown dashboard mode: {dashboard_mode}")
        print("[!] Dashboard will operate in local mode only")

except Exception as e:
    print(f"[!] Warning: DataSource initialization failed: {e}")
    print("[!] Dashboard will operate in local mode only")

# Global queue for real-time canary token events (for SSE streaming)
canary_event_queue = queue.Queue(maxsize=1000)
canary_queue_lock = threading.Lock()


# Hetzner datacenter locations (approximate coordinates)
HETZNER_LOCATIONS = {
    "fsn1": {"lat": 50.1109, "lon": 8.6821, "city": "Falkenstein", "country": "Germany"},
    "nbg1": {"lat": 49.4521, "lon": 11.0767, "city": "Nuremberg", "country": "Germany"},
    "hel1": {"lat": 60.1699, "lon": 24.9384, "city": "Helsinki", "country": "Finland"},
    "ash": {"lat": 39.0438, "lon": -77.4874, "city": "Ashburn", "country": "USA"},
    "hil": {"lat": 45.5231, "lon": -122.6765, "city": "Hillsboro", "country": "USA"},
}


@app.route("/health")
def health():
    """Health check endpoint for update validation."""
    # Check if critical data sources are accessible
    data_sources_ok = True
    errors = []

    # Check log path
    log_path = Path(CONFIG["log_path"])
    if not log_path.exists() and not log_path.parent.exists():
        data_sources_ok = False
        errors.append(f"Log path not accessible: {CONFIG['log_path']}")

    # Check TTY path
    tty_path = Path(CONFIG["tty_path"])
    if not tty_path.exists():
        # TTY path might not exist initially, but parent should
        if not tty_path.parent.exists():
            data_sources_ok = False
            errors.append(f"TTY path parent not accessible: {CONFIG['tty_path']}")

    status = "healthy" if data_sources_ok else "degraded"

    return jsonify(
        {
            "status": status,
            "version": __version__,
            "data_sources": {
                "cowrie_log": log_path.exists() or log_path.parent.exists(),
                "tty_recordings": tty_path.exists(),
                "downloads": Path(CONFIG["download_path"]).exists(),
            },
            "errors": errors if errors else None,
        }
    )


@app.route("/favicon.ico")
def favicon():
    """Serve favicon to prevent 404 errors in browser console."""
    # Return SVG favicon with honey pot emoji
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
        <text y=".9em" font-size="90">🍯</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml")


@app.route("/")
def index():
    """Dashboard page."""
    hours = request.args.get("hours", 24, type=int)
    source_filter = request.args.get("source", None)
    stats = session_parser.get_stats(hours=hours, source_filter=source_filter)

    # Get honeypot locations for map markers
    honeypot_locations = []

    # For multi-source mode, get all honeypot locations
    if hasattr(session_parser, "sources"):
        # Multi-source mode
        for source_name, source in session_parser.sources.items():
            # Get location from source config and map to coordinates
            location_info = {}
            if source.location and source.location in HETZNER_LOCATIONS:
                location_info = HETZNER_LOCATIONS[source.location]
                honeypot_locations.append(
                    {
                        "name": source_name,
                        "lat": location_info["lat"],
                        "lon": location_info["lon"],
                        "city": location_info.get("city", source_name),
                        "country": location_info.get("country", "-"),
                        "type": "honeypot",
                    }
                )
            else:
                # No location configured - skip marker for this honeypot
                print(f"[Dashboard] No location configured for source: {source_name}")
    else:
        # Single source mode - use server IP
        if CONFIG.get("server_ip"):
            honeypot_geo = global_geoip.lookup(CONFIG["server_ip"])
            if "latitude" in honeypot_geo and "longitude" in honeypot_geo:
                honeypot_locations.append(
                    {
                        "name": CONFIG.get("honeypot_hostname", "local"),
                        "lat": honeypot_geo["latitude"],
                        "lon": honeypot_geo["longitude"],
                        "city": honeypot_geo.get("city", "-"),
                        "country": honeypot_geo.get("country", "-"),
                        "type": "honeypot",
                    }
                )

    # Get recent canary webhook alerts (last 5)
    recent_webhooks = canary_webhook_db.get_recent_webhooks(limit=5)

    # Filter out test tokens older than 10 minutes
    filtered_webhooks = []
    now = datetime.now()
    for webhook in recent_webhooks:
        token_name = webhook.get("token_name", "")
        received_at = webhook.get("received_at")

        # Check if this is a test token
        is_test = token_name.startswith("Test ") or token_name.startswith("Congrats!")

        if is_test and received_at:
            # Only show test tokens if received within last 10 minutes
            age_minutes = (now - received_at).total_seconds() / 60
            if age_minutes <= 10:
                filtered_webhooks.append(webhook)
        elif not is_test:
            # Always show non-test tokens
            filtered_webhooks.append(webhook)

    # Enrich webhooks with GeoIP data (use global instance)
    for webhook in filtered_webhooks:
        if webhook.get("trigger_ip"):
            webhook["geo"] = global_geoip.lookup(webhook["trigger_ip"])

    # Check if user is accessing via proxy (hide manage links if proxied)
    is_proxied = "X-Forwarded-For" in request.headers

    # Get list of available sources for filter dropdown (multi-source mode only)
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    return render_template(
        "index.html",
        stats=stats,
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
        recent_webhooks=filtered_webhooks,
        is_proxied=is_proxied,
        honeypot_locations=honeypot_locations,
    )


@app.route("/attack-map")
def attack_map_page():
    """Attack visualization map page."""
    hours = request.args.get("hours", 24, type=int)
    source_filter = request.args.get("source", "")

    # Get sessions with source filter
    # Limit to 5000 most recent sessions per source for performance (map plotting)
    sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=5000)

    # Get available sources for multi-honeypot mode
    available_sources = []
    honeypot_locations = {}  # Map of source -> location

    if hasattr(session_parser, "sources"):
        # Multi-source mode
        available_sources = list(session_parser.sources.keys())

        # Get location for each honeypot
        for source_name in available_sources:
            try:
                source = session_parser.sources[source_name]
                api_url = source.datasource.api_base_url
                response = requests.get(f"{api_url}/api/v1/system-info", timeout=5)
                if response.ok:
                    info = response.json()
                    server_ip = info.get("server_ip")
                    honeypot_hostname = info.get("honeypot_hostname", source_name)
                    if server_ip:
                        honeypot_geo = global_geoip.lookup(server_ip)
                        if "latitude" in honeypot_geo and "longitude" in honeypot_geo:
                            honeypot_locations[source_name] = {
                                "name": honeypot_hostname,
                                "lat": honeypot_geo["latitude"],
                                "lon": honeypot_geo["longitude"],
                                "city": honeypot_geo.get("city", "-"),
                                "country": honeypot_geo.get("country", "-"),
                            }
            except Exception as e:
                app.logger.warning(f"Failed to get location for {source_name}: {e}")

    # Get local honeypot location for single-source or local mode
    honeypot_location = None
    if CONFIG["server_ip"]:
        honeypot_geo = global_geoip.lookup(CONFIG["server_ip"])
        if "latitude" in honeypot_geo and "longitude" in honeypot_geo:
            honeypot_location = {
                "name": CONFIG.get("honeypot_hostname", "local"),
                "lat": honeypot_geo["latitude"],
                "lon": honeypot_geo["longitude"],
                "city": honeypot_geo.get("city", "-"),
                "country": honeypot_geo.get("country", "-"),
            }
            # Add to honeypot_locations if not multi-source
            if not honeypot_locations:
                honeypot_locations["local"] = honeypot_location

    # Collect attack data with timestamps for animation
    attacks = []
    sessions_without_geo = 0
    sessions_without_coords = 0

    for session in sessions.values():
        if not session.get("src_ip"):
            continue

        if not session.get("geo"):
            sessions_without_geo += 1
            continue

        geo = session["geo"]
        if "latitude" not in geo or "longitude" not in geo:
            sessions_without_coords += 1
            continue

        attack = {
            "session_id": session["id"],
            "ip": session["src_ip"],
            "lat": geo["latitude"],
            "lon": geo["longitude"],
            "city": geo.get("city", "-"),
            "country": geo.get("country", "-"),
            "timestamp": session.get("start_time", ""),
            "username": session.get("username", ""),
            "password": session.get("password", ""),
            "login_success": session.get("login_success", False),
            "_source": session.get("_source", "local"),  # Track which honeypot
        }
        attacks.append(attack)

    # Sort by timestamp
    attacks.sort(key=lambda x: x["timestamp"])

    return render_template(
        "attack_map.html",
        attacks=attacks,
        honeypot_location=honeypot_location,
        honeypot_locations=honeypot_locations,
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/sessions")
def sessions():
    """Session listing page."" - returns HTML immediately, data loaded via AJAX.""
    hours = request.args.get("hours", 168, type=int)
    page = request.args.get("page", 1, type=int)
    per_page = 50
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "sessions.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        ip_filter=request.args.get("ip", ""),
        country_filter=request.args.get("country", ""),
        credentials_filter=request.args.get("credentials", ""),
        client_version_filter=request.args.get("client_version", ""),
        command_filter=request.args.get("command", ""),
        has_commands=request.args.get("has_commands", ""),
        has_tty=request.args.get("has_tty", ""),
        successful_login=request.args.get("successful_login", ""),
        config=CONFIG,
    )


@app.route("/session/<session_id>")
def session_detail(session_id: str):
    """Session detail page."""
    session = session_parser.get_session(session_id)
    if not session:
        return render_template("404.html", message="Session not found"), 404

    # Check if TTY log exists (new multi-file format or old single-file format)
    has_tty = False
    if session.get("tty_logs"):
        # New format: check if we have any TTY logs
        has_tty = len(session["tty_logs"]) > 0
    elif session.get("tty_log"):
        # Old format: check if single TTY file exists
        tty_file = tty_parser.find_tty_file(session["tty_log"])
        has_tty = tty_file is not None

    # Get all events for this session
    events = session_parser.get_session_events(session_id)

    # Get threat intelligence for this IP
    threat_intel = {}
    if session.get("src_ip"):
        threat_intel = session_parser.get_threat_intel_for_ip(session["src_ip"])

    return render_template(
        "session_detail.html", session=session, has_tty=has_tty, events=events, threat_intel=threat_intel, config=CONFIG
    )


@app.route("/session/<session_id>/playback")
def session_playback(session_id: str):
    """Session playback page with asciinema player."""
    session = session_parser.get_session(session_id)
    if not session:
        return render_template("404.html", message="Session not found"), 404

    # Check for TTY logs (new format) or tty_log (old format)
    if not session.get("tty_logs") and not session.get("tty_log"):
        return render_template("404.html", message="No TTY recording for this session"), 404

    # Use merged TTY logs if available (multiple commands), otherwise fall back to single file
    hostname = CONFIG.get("honeypot_hostname", "dmz-web01")
    if session.get("tty_logs") and len(session["tty_logs"]) > 0:
        asciicast = tty_parser.merge_tty_logs(session, hostname=hostname)
    else:
        # Fallback to single TTY file for backwards compatibility
        asciicast = tty_parser.parse_tty_log(session["tty_log"])

    if not asciicast:
        print(f"[!] Failed to parse TTY log for playback: {session.get('tty_logs', session.get('tty_log'))}")
        return render_template("404.html", message="Failed to parse TTY log for playback"), 404

    return render_template("playback.html", session=session, asciicast=asciicast, config=CONFIG)


@app.route("/api/session/<session_id>/asciicast")
def session_asciicast(session_id: str):
    """Return asciicast data for a session."""
    session = session_parser.get_session(session_id)
    if not session:
        print(f"[!] Session not found: {session_id}")
        return jsonify({"error": "Session not found"}), 404

    if not session.get("tty_logs") and not session.get("tty_log"):
        print(f"[!] No TTY recording for session {session_id}")
        return jsonify({"error": "No TTY recording"}), 404

    # Use merged TTY logs if available, otherwise fall back to single file
    hostname = CONFIG.get("honeypot_hostname", "dmz-web01")
    if session.get("tty_logs") and len(session["tty_logs"]) > 0:
        asciicast = tty_parser.merge_tty_logs(session, hostname=hostname)
    else:
        # Fallback to single TTY file for backwards compatibility
        tty_file = tty_parser.find_tty_file(session["tty_log"])
        if not tty_file:
            print(f"[!] TTY file not found: {session['tty_log']}")
            return jsonify({"error": "TTY recording file not found"}), 404
        asciicast = tty_parser.parse_tty_log(session["tty_log"])

    if not asciicast:
        print(f"[!] Failed to parse TTY log: {session_id}")
        return jsonify({"error": "Failed to parse TTY log"}), 404

    return jsonify(asciicast)


@app.route("/api/stats")
def api_stats():
    """API endpoint for dashboard stats."""
    hours = request.args.get("hours", 24, type=int)
    stats = session_parser.get_stats(hours=hours)
    return jsonify(stats)


@app.route("/api/sessions")
def api_sessions():
    """API endpoint for sessions list."""
    hours = request.args.get("hours", 168, type=int)
    limit = request.args.get("limit", 100, type=int)

    # Fetch up to 1000 sessions (more than requested limit for sorting)
    all_sessions = session_parser.parse_all(hours=hours, max_sessions=1000)
    sorted_sessions = sorted(all_sessions.values(), key=lambda x: x["start_time"] or "", reverse=True)[:limit]

    return jsonify(sorted_sessions)


@app.route("/api/system-info")
def api_system_info():
    """API endpoint for honeypot system information."""
    # Check if multi-source mode
    if hasattr(session_parser, "sources"):
        # Multi-source mode - return info for all honeypots
        honeypots = []

        for source_name, source in session_parser.sources.items():
            info = {
                "name": source_name,
                "server_ip": None,
                "honeypot_hostname": None,
                "cowrie_version": "unknown",
                "git_commit": None,
                "build_date": None,
                "uptime_seconds": None,
            }

            # Fetch from source's API (local or remote)
            try:
                api_url = source.datasource.api_base_url
                response = requests.get(
                    f"{api_url}/api/v1/system-info",
                    timeout=5,
                )
                if response.ok:
                    remote_info = response.json()
                    info["server_ip"] = remote_info.get("server_ip")
                    info["honeypot_hostname"] = remote_info.get("honeypot_hostname")
                    info["cowrie_version"] = remote_info.get("cowrie_version", "unknown")
                    info["build_date"] = remote_info.get("build_date")
            except Exception as e:
                app.logger.warning(f"Failed to fetch system info from {source_name}: {e}")

            honeypots.append(info)

        return jsonify({"honeypots": honeypots})
    else:
        # Single source mode - return single honeypot info
        info = {
            "server_ip": CONFIG["server_ip"],
            "honeypot_hostname": CONFIG["honeypot_hostname"],
            "cowrie_version": "unknown",
            "git_commit": None,
            "build_date": None,
            "uptime_seconds": None,
        }

        # Try to read metadata from Cowrie container
        metadata_path = CONFIG["metadata_path"]
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path) as f:
                    metadata = json.load(f)
                    info["cowrie_version"] = metadata.get("cowrie_version", "unknown")
                    info["git_commit"] = metadata.get("git_commit")
                    info["build_date"] = metadata.get("build_date")

                    # Calculate uptime from build timestamp
                    build_ts = metadata.get("build_timestamp")
                    if build_ts:
                        info["uptime_seconds"] = int(time.time() - build_ts)
            except Exception as e:
                app.logger.warning(f"Failed to read metadata: {e}")

        return jsonify(info)


@app.route("/api/canary-tokens")
def api_canary_tokens():
    """API endpoint for Canary Token information."""
    # In v2.1, when using API-based data access (local/remote mode),
    # proxy the request to the cowrie-api instead of reading filesystem directly
    dashboard_mode = CONFIG.get("dashboard_mode", "local")

    if dashboard_mode in ["local", "remote"] and datasource:
        # Use API-based access
        try:
            response = datasource.session.get(f"{datasource.api_base_url}/canary-tokens")
            response.raise_for_status()
            return jsonify(response.json())
        except Exception as e:
            print(f"[!] Error fetching canary tokens from API: {e}")
            # Fallback to direct filesystem access
            pass

    # Fallback: Direct filesystem access (legacy behavior)
    honeyfs_path = CONFIG.get("honeyfs_path", "/cowrie-data/share/cowrie/contents")

    tokens = []

    # Check for MySQL backup token
    mysql_token_path = os.path.join(honeyfs_path, "root/backup/mysql-backup.sql")
    if os.path.exists(mysql_token_path):
        stat_info = os.stat(mysql_token_path)
        tokens.append(
            {
                "type": "MySQL Dump",
                "icon": "🗄️",
                "path": "/root/backup/mysql-backup.sql",
                "size": stat_info.st_size,
                "description": "Database backup file",
            }
        )

    # Check for Excel token
    excel_token_path = os.path.join(honeyfs_path, "root/Q1_Financial_Report.xlsx")
    if os.path.exists(excel_token_path):
        stat_info = os.stat(excel_token_path)
        tokens.append(
            {
                "type": "Excel Document",
                "icon": "📊",
                "path": "/root/Q1_Financial_Report.xlsx",
                "size": stat_info.st_size,
                "description": "Financial report spreadsheet",
            }
        )

    # Check for PDF token
    pdf_token_path = os.path.join(honeyfs_path, "root/Network_Passwords.pdf")
    if os.path.exists(pdf_token_path):
        stat_info = os.stat(pdf_token_path)
        tokens.append(
            {
                "type": "PDF Document",
                "icon": "📄",
                "path": "/root/Network_Passwords.pdf",
                "size": stat_info.st_size,
                "description": "Password documentation",
            }
        )

    return jsonify({"tokens": tokens, "total": len(tokens)})


@app.route("/system-info")
def system_info():
    """Extended system information page with SSH config and canary tokens."""
    # Check if multi-source mode
    if hasattr(session_parser, "sources"):
        # Multi-source mode - show basic info for all honeypots
        honeypots = []

        for source_name, source in session_parser.sources.items():
            info = {
                "name": source_name,
                "server_ip": None,
                "honeypot_hostname": None,
                "cowrie_version": "unknown",
                "build_date": None,
            }

            # Fetch from source's API
            try:
                api_url = source.datasource.api_base_url
                response = requests.get(
                    f"{api_url}/api/v1/system-info",
                    timeout=5,
                )
                if response.ok:
                    remote_info = response.json()
                    info.update(remote_info)
            except Exception as e:
                app.logger.warning(f"Failed to fetch system info from {source_name}: {e}")

            honeypots.append(info)

        return render_template("system_info.html", honeypots=honeypots, multi_source=True, config=CONFIG)

    # Single source mode - show detailed info
    identity_path = CONFIG.get("identity_path", "/cowrie-data/identity")

    # Read system information
    system_data = {
        "server_ip": CONFIG["server_ip"],
        "honeypot_hostname": CONFIG["honeypot_hostname"],
        "cowrie_version": "unknown",
        "build_date": None,
        "kernel": None,
        "arch": None,
        "os_release": None,
        "ssh_banner": None,
        "ssh_ciphers": [],
        "ssh_macs": [],
        "ssh_kex": [],
        "ssh_keys": [],
        "kernel_build": None,
        "debian_version": None,
        "userdb_entries": [],  # User database entries
    }

    # Read metadata
    metadata_path = CONFIG["metadata_path"]
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                metadata = json.load(f)
                system_data["cowrie_version"] = metadata.get("cowrie_version", "unknown")
                system_data["build_date"] = metadata.get("build_date")
        except Exception as e:
            app.logger.warning(f"Failed to read metadata: {e}")

    # Read identity data if available
    def read_identity_file(filename):
        path = os.path.join(identity_path, filename)
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return f.read().strip()
            except Exception as e:
                app.logger.warning(f"Failed to read {filename}: {e}")
        return None

    def read_identity_lines(filename):
        path = os.path.join(identity_path, filename)
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                app.logger.warning(f"Failed to read {filename}: {e}")
        return []

    # Read basic identity
    system_data["kernel"] = read_identity_file("kernel.txt")
    system_data["ssh_banner"] = read_identity_file("ssh-banner.txt")
    system_data["kernel_build"] = read_identity_file("proc-version")
    system_data["debian_version"] = read_identity_file("debian_version")
    system_data["hostname_file"] = read_identity_file("hostname")

    # Read OS release
    os_release_content = read_identity_file("os-release")
    if os_release_content:
        for line in os_release_content.split("\n"):
            if line.startswith("PRETTY_NAME="):
                system_data["os_release"] = line.split("=", 1)[1].strip('"')
                break

    # Extract architecture from kernel
    if system_data["kernel"]:
        parts = system_data["kernel"].split()
        if len(parts) >= 3:
            system_data["arch"] = parts[-1]

    # Read SSH configuration
    system_data["ssh_ciphers"] = read_identity_lines("ssh-ciphers.txt")
    system_data["ssh_macs"] = read_identity_lines("ssh-mac.txt")
    system_data["ssh_kex"] = read_identity_lines("ssh-kex.txt")
    system_data["ssh_keys"] = read_identity_lines("ssh-key.txt")

    # Read userdb.txt (authentication database)
    # Try multiple possible locations for userdb.txt
    userdb_locations = [
        "/cowrie-etc/userdb.txt",  # Mounted from cowrie-etc volume
        "/cowrie-data/etc/userdb.txt",
        "/opt/cowrie/etc/userdb.txt",
        "/etc/cowrie/userdb.txt",
        os.path.join(identity_path, "userdb.txt"),
    ]

    print("[DEBUG] Looking for userdb.txt in the following locations:")
    for loc in userdb_locations:
        exists = os.path.exists(loc)
        print(f"[DEBUG]   {loc} - {'EXISTS' if exists else 'NOT FOUND'}")

    for userdb_path in userdb_locations:
        if os.path.exists(userdb_path):
            try:
                with open(userdb_path) as f:
                    userdb_lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    system_data["userdb_entries"] = userdb_lines
                    system_data["userdb_path"] = userdb_path
                    print(f"[+] Loaded userdb from {userdb_path}: {len(userdb_lines)} entries")
                    break
            except Exception as e:
                print(f"[!] Failed to read {userdb_path}: {e}")

    if not system_data["userdb_entries"]:
        print("[!] No userdb.txt found in any location")

    # Get canary token information
    honeyfs_path = CONFIG.get("honeyfs_path", "/cowrie-data/share/cowrie/contents")
    canary_tokens = []

    # Check for canary tokens in filesystem
    token_locations = [
        ("/root/backup/mysql-backup.sql", "🗄️ MySQL Dump", "Database backup file"),
        ("/root/Q1_Financial_Report.xlsx", "📊 Excel Document", "Financial report"),
        ("/root/Network_Passwords.pdf", "📄 PDF Document", "Password documentation"),
    ]

    for path, icon, description in token_locations:
        full_path = os.path.join(honeyfs_path, path.lstrip("/"))
        if os.path.exists(full_path):
            stat_info = os.stat(full_path)
            canary_tokens.append(
                {
                    "path": path,
                    "icon": icon,
                    "description": description,
                    "size": stat_info.st_size,
                }
            )

    return render_template(
        "system_info.html", system=system_data, canary_tokens=canary_tokens, multi_source=False, config=CONFIG
    )


@app.route("/downloads")
def downloads():
    """Downloaded files listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "downloads.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/api/downloads-data")
def downloads_data():
    """API endpoint for downloads data - called via AJAX from downloads page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Extract downloads from sessions (they include database metadata)
    # Limit to 5000 most recent sessions per source for performance
    all_sessions = session_parser.parse_all(
        hours=hours,
        source_filter=source_filter if source_filter else None,
        max_sessions=5000
    )

    # Collect all downloads from sessions
    all_downloads = []
    for session in all_sessions.values():
        for download in session.get("downloads", []):
            # Add session context to each download
            download_with_context = download.copy()
            download_with_context["session_id"] = session["id"]
            download_with_context["src_ip"] = session.get("src_ip")
            download_with_context["_source"] = session.get("_source", "local")
            all_downloads.append(download_with_context)

    # Deduplicate by shasum
    unique_downloads = {}
    for dl in all_downloads:
        shasum = dl.get("shasum")
        if not shasum:
            continue

        if shasum not in unique_downloads:
            unique_downloads[shasum] = dl
            unique_downloads[shasum]["count"] = 1
        else:
            unique_downloads[shasum]["count"] += 1

    # Check which files exist on disk and get VT/YARA scores
    download_path = CONFIG["download_path"]
    for shasum, dl in unique_downloads.items():
        file_path = os.path.join(download_path, shasum)
        dl["exists"] = os.path.exists(file_path)
        if dl["exists"]:
            dl["size"] = os.path.getsize(file_path)
        else:
            dl["size"] = 0

        # Get YARA matches and file type from cache
        yara_result = yara_cache.get_result(shasum)
        if yara_result:
            if yara_result.get("matches"):
                dl["yara_matches"] = yara_result["matches"]
            if yara_result.get("file_type"):
                dl["file_type"] = yara_result["file_type"]
                dl["file_mime"] = yara_result.get("file_mime")
                dl["file_category"] = yara_result.get("file_category")
                dl["is_previewable"] = yara_result.get("is_previewable", False)

        # Get VirusTotal score if scanner is available
        if vt_scanner and shasum:
            vt_result = vt_scanner.scan_file(shasum)
            if vt_result:
                dl["vt_detections"] = vt_result["detections"]
                dl["vt_total"] = vt_result["total_engines"]
                dl["vt_link"] = vt_result["link"]
                dl["vt_threat_label"] = vt_result.get("threat_label", "")

    downloads_list = sorted(unique_downloads.values(), key=lambda x: x.get("timestamp", ""), reverse=True)

    return jsonify({
        "downloads": downloads_list,
        "count": len(downloads_list)
    })


@app.route("/api/ips-data")
def ips_data():
    """API endpoint for IPs data - called via AJAX from IPs page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")
    asn_filter = request.args.get("asn", "")
    country_filter = request.args.get("country", "")
    city_filter = request.args.get("city", "")

    # Get stats (IPs returned without API limit after PR #116)
    stats = session_parser.get_stats(hours=hours, source_filter=source_filter)

    # Apply filters
    filtered_ips = stats["ip_list"]
    if asn_filter:
        filtered_ips = [
            ip for ip in filtered_ips if ip.get("geo", {}).get("asn") and f"AS{ip['geo']['asn']}" == asn_filter
        ]
    if country_filter:
        filtered_ips = [ip for ip in filtered_ips if ip.get("geo", {}).get("country") == country_filter]
    if city_filter:
        filtered_ips = [ip for ip in filtered_ips if ip.get("geo", {}).get("city") == city_filter]

    return jsonify({
        "ips": filtered_ips,
        "count": len(filtered_ips)
    })


@app.route("/api/sessions-data")
def sessions_data():
    """API endpoint for sessions data - called via AJAX from sessions page."""
    hours = request.args.get("hours", 168, type=int)
    page = request.args.get("page", 1, type=int)
    per_page = 50
    source_filter = request.args.get("source", "")

    # Fetch sessions with limit for performance
    all_sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=10000)

    # Sort by start time (most recent first)
    sorted_sessions = sorted(all_sessions.values(), key=lambda x: x["start_time"] or "", reverse=True)

    # Apply filters
    ip_filter = request.args.get("ip", "")
    country_filter = request.args.get("country", "")
    credentials_filter = request.args.get("credentials", "")
    client_version_filter = request.args.get("client_version", "")
    command_filter = request.args.get("command", "")
    has_commands = request.args.get("has_commands", "")
    has_tty = request.args.get("has_tty", "")
    successful_login = request.args.get("successful_login", "")

    if ip_filter:
        sorted_sessions = [s for s in sorted_sessions if s["src_ip"] == ip_filter]
    if country_filter:
        sorted_sessions = [s for s in sorted_sessions if s.get("geo", {}).get("country") == country_filter]
    if credentials_filter:
        sorted_sessions = [
            s for s in sorted_sessions if f"{s.get('username', '')}:{s.get('password', '')}" == credentials_filter
        ]
    if client_version_filter:
        sorted_sessions = [s for s in sorted_sessions if s.get("client_version") == client_version_filter]
    if command_filter:
        sorted_sessions = [
            s for s in sorted_sessions if any(cmd["command"] == command_filter for cmd in s.get("commands", []))
        ]
    if has_commands == "1":
        sorted_sessions = [s for s in sorted_sessions if s.get("commands")]
    if has_tty == "1":
        sorted_sessions = [s for s in sorted_sessions if s.get("tty_log")]
    if successful_login == "1":
        sorted_sessions = [s for s in sorted_sessions if s.get("login_success") is True]

    # Paginate
    total = len(sorted_sessions)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = sorted_sessions[start:end]

    return jsonify({
        "sessions": paginated,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    })


@app.route("/api/countries-data")
def countries_data():
    """API endpoint for countries data - called via AJAX from countries page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get all countries
    sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=5000)
    country_counter = Counter()
    for session in sessions.values():
        if session.get("src_ip"):
            country = session.get("geo", {}).get("country", "Unknown")
            country_counter[country] += 1

    all_countries = country_counter.most_common()

    return jsonify({
        "countries": [{"country": c, "count": count} for c, count in all_countries],
        "total": len(all_countries)
    })


@app.route("/api/credentials-data")
def credentials_data():
    """API endpoint for credentials data - called via AJAX from credentials page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get all credentials
    sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=5000)
    credential_counter = Counter()
    successful_credentials = set()
    for session in sessions.values():
        if session["username"] and session["password"]:
            cred = f"{session['username']}:{session['password']}"
            credential_counter[cred] += 1
            if session.get("login_success"):
                successful_credentials.add(cred)

    all_credentials = credential_counter.most_common()

    return jsonify({
        "credentials": [{"credential": c, "count": count} for c, count in all_credentials],
        "successful": list(successful_credentials),
        "total": len(all_credentials)
    })


@app.route("/api/clients-data")
def clients_data():
    """API endpoint for SSH clients data - called via AJAX from clients page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get all client versions
    sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=5000)
    client_version_counter = Counter()
    for session in sessions.values():
        if session.get("client_version"):
            client_version_counter[session["client_version"]] += 1

    all_clients = client_version_counter.most_common()

    return jsonify({
        "clients": [{"client": c, "count": count} for c, count in all_clients],
        "total": len(all_clients)
    })


@app.route("/api/asns-data")
def asns_data():
    """API endpoint for ASNs data - called via AJAX from ASNs page."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get all ASNs
    sessions = session_parser.parse_all(hours=hours, source_filter=source_filter, max_sessions=5000)
    asn_counter = Counter()
    asn_details = {}
    for session in sessions.values():
        if session.get("src_ip"):
            asn = session.get("geo", {}).get("asn")
            asn_org = session.get("geo", {}).get("asn_org")
            if asn:
                asn_key = f"AS{asn}"
                asn_counter[asn_key] += 1
                if asn_key not in asn_details:
                    asn_details[asn_key] = {"asn_number": asn, "asn_org": asn_org or "Unknown Organization"}

    # Build full ASNs list with details
    all_asns = []
    for asn_key, count in asn_counter.most_common():
        details = asn_details.get(asn_key, {})
        all_asns.append({
            "asn": asn_key,
            "asn_number": details.get("asn_number", 0),
            "asn_org": details.get("asn_org", "Unknown"),
            "count": count,
        })

    return jsonify({
        "asns": all_asns,
        "total": len(all_asns)
    })


@app.route("/api/commands-data")
def commands_data():
    """API endpoint for commands data - called via AJAX from commands page."""
    hours = request.args.get("hours", 168, type=int)
    unique_only = request.args.get("unique", "")
    source_filter = request.args.get("source", "")

    all_commands = session_parser.get_all_commands(hours=hours, source_filter=source_filter)

    # Filter to unique commands if requested
    if unique_only == "1":
        seen_commands = set()
        unique_commands = []
        for cmd in all_commands:
            if cmd["command"] not in seen_commands:
                seen_commands.add(cmd["command"])
                unique_commands.append(cmd)
        all_commands = unique_commands

    return jsonify({
        "commands": all_commands,
        "count": len(all_commands)
    })




@app.route("/download/<shasum>.zip")
def download_zip(shasum: str):
    """Download a malware sample as a password-protected ZIP file.

    Password: infected
    """
    download_path = CONFIG["download_path"]
    file_path = os.path.join(download_path, shasum)

    # Check if file exists
    if not os.path.exists(file_path):
        return render_template("404.html", message="File not found"), 404

    # Create a temporary password-protected ZIP file
    # Password is "infected" (standard for malware samples)
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    temp_zip.close()

    try:
        # Create password-protected ZIP with AES encryption
        with zipfile.ZipFile(temp_zip.name, "w") as zipf:
            # Add file with just the SHA256 as filename
            zipf.write(file_path, arcname=shasum)
            zipf.setpassword(b"infected")

        # Send the ZIP file and clean up after
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name=f"{shasum}.zip",
            mimetype="application/zip",
        )
    finally:
        # Clean up temp file after sending
        # Note: Flask will handle this after the response is sent
        try:
            os.unlink(temp_zip.name)
        except Exception:
            pass


@app.route("/download/<shasum>/preview")
def download_preview(shasum: str):
    """Preview a downloaded file (text files only)."""
    # Get file info from cache
    file_info = yara_cache.get_result(shasum)

    if not file_info:
        return render_template("404.html", message="File not found in cache"), 404

    if not file_info.get("is_previewable"):
        return render_template("404.html", message="File type not previewable"), 400

    # Check if file exists
    download_path = CONFIG["download_path"]
    file_path = os.path.join(download_path, shasum)

    if not os.path.exists(file_path):
        return render_template("404.html", message="File not found on disk"), 404

    # Check file size
    file_size = os.path.getsize(file_path)
    max_size = 1024 * 1024  # 1MB limit

    if file_size > max_size:
        return render_template(
            "404.html", message=f"File too large for preview ({file_size} bytes, max {max_size})"
        ), 400

    # Read file content
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        # Try to decode as UTF-8, fall back to latin-1
        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            text_content = content.decode("latin-1")

        # Determine language for syntax highlighting based on file type
        file_type = file_info.get("file_type", "").lower()
        file_mime = file_info.get("file_mime", "").lower()

        language = "plaintext"
        if "python" in file_type or "python" in file_mime:
            language = "python"
        elif "shell" in file_type or "bash" in file_type or file_mime == "text/x-shellscript":
            language = "bash"
        elif "perl" in file_type or "perl" in file_mime:
            language = "perl"
        elif "ruby" in file_type or "ruby" in file_mime:
            language = "ruby"
        elif "php" in file_type or "php" in file_mime:
            language = "php"
        elif "javascript" in file_type or "javascript" in file_mime:
            language = "javascript"
        elif "json" in file_type or file_mime == "application/json":
            language = "json"
        elif "xml" in file_type or "xml" in file_mime:
            language = "xml"
        elif "html" in file_type or "html" in file_mime:
            language = "html"
        elif "c source" in file_type or "c++" in file_type:
            language = "c"

        return render_template(
            "preview.html",
            shasum=shasum,
            file_info=file_info,
            content=text_content,
            language=language,
            file_size=file_size,
            config=CONFIG,
        )

    except Exception as e:
        return render_template("404.html", message=f"Error reading file: {e}"), 500


@app.route("/api/download/<shasum>/content")
def api_download_content(shasum: str):
    """API endpoint to get raw file content (text files only)."""
    # Get file info from cache
    file_info = yara_cache.get_result(shasum)

    if not file_info:
        return jsonify({"error": "File not found in cache"}), 404

    if not file_info.get("is_previewable"):
        return jsonify({"error": "File type not previewable"}), 400

    # Check if file exists
    download_path = CONFIG["download_path"]
    file_path = os.path.join(download_path, shasum)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on disk"}), 404

    # Check file size
    file_size = os.path.getsize(file_path)
    max_size = 1024 * 1024  # 1MB limit

    if file_size > max_size:
        return jsonify({"error": f"File too large ({file_size} bytes)"}), 400

    # Read and return content
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            text_content = content.decode("latin-1")

        return Response(text_content, mimetype="text/plain")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/commands")
def commands():
    """Commands listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    unique_only = request.args.get("unique", "")
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "commands.html",
        hours=hours,
        unique=unique_only,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/ips")
def ip_list():
    """IP address listing page.""" - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    asn_filter = request.args.get("asn", "")
    country_filter = request.args.get("country", "")
    city_filter = request.args.get("city", "")

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "ips.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        asn_filter=asn_filter,
        country_filter=country_filter,
        city_filter=city_filter,
        config=CONFIG,
    )


@app.route("/countries")
def countries():
    """All countries listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "countries.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/credentials")
def credentials():
    """All credentials listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "credentials.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/clients")
def clients():
    """All SSH clients listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "clients.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/asns")
def asns():
    """All ASNs listing page - returns HTML immediately, data loaded via AJAX."""
    hours = request.args.get("hours", 168, type=int)
    source_filter = request.args.get("source", "")

    # Get available sources for multi-honeypot mode
    available_sources = []
    if hasattr(session_parser, "sources"):
        available_sources = list(session_parser.sources.keys())

    # Return page immediately with loading state - data loaded via AJAX
    return render_template(
        "asns.html",
        hours=hours,
        source_filter=source_filter,
        available_sources=available_sources,
        config=CONFIG,
    )


@app.route("/webhook/canary", methods=["POST"])
def canary_webhook():
    """Webhook endpoint for Canary Token alerts.

    Security notes:
    - Accessible via public reverse proxy with rate limiting
    - Reverse proxy forwards X-Real-IP header for attacker IP tracking
    """
    try:
        # Get JSON payload
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        payload = request.get_json()

        # Extract Canary Token data
        # Canarytokens.org webhook format:
        # - manage_url: URL to manage the token
        # - memo: User-defined name/description
        # - channel: Token type (HTTP, PDF, AWS, etc.)
        # - src_ip: IP that triggered the token
        # - useragent: User agent string
        # - referer: HTTP referer
        # - location: Geographic location
        # - additional_data: Extra fields

        webhook_data = {
            "token_type": payload.get("channel", "unknown"),
            "token_name": payload.get("memo", "Unnamed Token"),
            "trigger_ip": payload.get("src_ip", request.remote_addr),
            "trigger_user_agent": payload.get("useragent", ""),
            "trigger_location": payload.get("location", ""),
            "trigger_hostname": payload.get("hostname", ""),
            "referer": payload.get("referer", ""),
            "additional_data": {
                "manage_url": payload.get("manage_url", ""),
                "time": payload.get("time", ""),
                "hits": payload.get("hits", 0),
            },
            "raw_payload": payload,
        }

        # Store in database
        webhook_id = canary_webhook_db.add_webhook(webhook_data)

        print(
            f"[+] Canary webhook received: {webhook_data['token_type']} - {webhook_data['token_name']} from {webhook_data['trigger_ip']}"
        )

        # Add to real-time event queue for SSE streaming
        try:
            # Enrich with GeoIP data for the map (use global instance)
            geo = global_geoip.lookup(webhook_data["trigger_ip"]) if webhook_data["trigger_ip"] else {}

            print(f"[+] GeoIP lookup for {webhook_data['trigger_ip']}: {geo}")

            canary_event = {
                "id": webhook_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "geo": geo,
                **webhook_data,
            }

            # Non-blocking put with timeout
            with canary_queue_lock:
                try:
                    canary_event_queue.put_nowait(canary_event)
                    print(f"[+] Canary event added to queue. Queue size: {canary_event_queue.qsize()}")
                except queue.Full:
                    # Queue full, remove oldest and add new
                    try:
                        canary_event_queue.get_nowait()
                        canary_event_queue.put_nowait(canary_event)
                        print("[+] Queue was full, replaced oldest event")
                    except queue.Empty:
                        pass
        except Exception as e:
            print(f"[!] Error adding canary event to queue: {e}")
            import traceback

            traceback.print_exc()

        return jsonify({"success": True, "id": webhook_id}), 200

    except Exception as e:
        print(f"[!] Error processing canary webhook: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/canary-webhooks")
def api_canary_webhooks():
    """API endpoint for recent Canary Token webhook alerts."""
    limit = request.args.get("limit", 100, type=int)
    webhooks = canary_webhook_db.get_recent_webhooks(limit=limit)

    # Enrich with GeoIP data if available (use global instance)
    for webhook in webhooks:
        if webhook.get("trigger_ip"):
            webhook["geo"] = global_geoip.lookup(webhook["trigger_ip"])

    return jsonify({"webhooks": webhooks, "total": len(webhooks)})


@app.route("/canary-alerts")
def canary_alerts():
    """Canary Token alerts page."""
    limit = request.args.get("limit", 100, type=int)
    webhooks = canary_webhook_db.get_recent_webhooks(limit=limit)

    # Enrich with GeoIP data (use global instance)
    for webhook in webhooks:
        if webhook.get("trigger_ip"):
            webhook["geo"] = global_geoip.lookup(webhook["trigger_ip"])

    # Check if user is accessing via proxy (hide manage links if proxied)
    is_proxied = "X-Forwarded-For" in request.headers

    return render_template(
        "canary_alerts.html", webhooks=webhooks, limit=limit, config=CONFIG, now=datetime.now, is_proxied=is_proxied
    )


@app.route("/api/attack-stream")
def attack_stream():
    """Server-Sent Events endpoint for real-time attack feed."""

    def generate():
        """Generate SSE events from Cowrie log file and canary webhooks."""
        import select
        import subprocess

        # Disable SSE in multi-source mode (no local Cowrie instance)
        if hasattr(session_parser, "sources"):
            print("[!] SSE stream disabled in multi-source mode")
            yield f"data: {json.dumps({'event': 'info', 'message': 'Live mode not available in multi-honeypot deployment'})}\n\n"
            return

        log_path = CONFIG["log_path"]

        # Check if log file exists
        if not os.path.exists(log_path):
            print(f"[!] Log file not found: {log_path}")
            yield f"data: {json.dumps({'event': 'error', 'message': 'Log file not found'})}\n\n"
            return

        # Use tail -F to follow the log file
        try:
            proc = subprocess.Popen(
                ["tail", "-F", "-n", "0", log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
        except Exception as e:
            print(f"[!] Failed to start tail process: {e}")
            yield f"data: {json.dumps({'event': 'error', 'message': f'Failed to start log tail: {str(e)}'})}\n\n"
            return

        # Use global GeoIP instance (already loaded at startup)
        active_sessions = {}  # Track active sessions
        last_keepalive = time.time()
        keepalive_interval = 30  # Send keepalive every 30 seconds

        print(f"[+] SSE stream started, monitoring {log_path}")

        # Send initial connected message to establish SSE connection
        yield f"data: {json.dumps({'event': 'connected', 'message': 'Live stream connected'})}\n\n"

        try:
            while True:
                # Send keepalive comment to prevent timeout
                if time.time() - last_keepalive > keepalive_interval:
                    yield ": keepalive\n\n"
                    last_keepalive = time.time()
                # Check for canary token events first (non-blocking)
                try:
                    with canary_queue_lock:
                        canary_event = canary_event_queue.get_nowait()

                    print(f"[+] SSE: Got canary event from queue: {canary_event.get('token_name')}")

                    # Send canary token trigger event
                    if (
                        canary_event.get("geo")
                        and "latitude" in canary_event["geo"]
                        and "longitude" in canary_event["geo"]
                    ):
                        event_data = {
                            "event": "canary_trigger",
                            "id": canary_event.get("id"),
                            "ip": canary_event.get("trigger_ip"),
                            "lat": canary_event["geo"].get("latitude"),
                            "lon": canary_event["geo"].get("longitude"),
                            "city": canary_event["geo"].get("city", "-"),
                            "country": canary_event["geo"].get("country", "-"),
                            "asn": canary_event["geo"].get("asn"),
                            "asn_org": canary_event["geo"].get("asn_org"),
                            "timestamp": canary_event.get("timestamp"),
                            "token_type": canary_event.get("token_type"),
                            "token_name": canary_event.get("token_name"),
                            "trigger_user_agent": canary_event.get("trigger_user_agent"),
                            "trigger_location": canary_event.get("trigger_location"),
                        }
                        print(f"[+] SSE: Sending canary_trigger event: {event_data}")
                        yield f"data: {json.dumps(event_data)}\n\n"
                    else:
                        print(f"[!] SSE: Canary event has no geo coordinates: {canary_event.get('geo')}")
                except queue.Empty:
                    pass  # No canary events, continue
                except Exception as e:
                    print(f"[!] Error processing canary event from queue: {e}")
                    import traceback

                    traceback.print_exc()

                # Check if there's data available from tail process (non-blocking)
                line = None
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)
                if ready:
                    line = proc.stdout.readline()

                if not line:
                    # No data available, sleep briefly to prevent tight loop
                    time.sleep(0.1)
                    continue

                try:
                    entry = json.loads(line.strip())
                    event_id = entry.get("eventid", "")
                    session_id = entry.get("session")

                    # Track session.connect events
                    if event_id == "cowrie.session.connect":
                        src_ip = entry.get("src_ip")
                        if src_ip and session_id:
                            geo = global_geoip.lookup(src_ip)
                            active_sessions[session_id] = {
                                "src_ip": src_ip,
                                "geo": geo,
                                "start_time": entry.get("timestamp"),
                                "login_success": False,
                                "username": None,
                                "password": None,
                            }

                            # Send connect event
                            event_data = {
                                "event": "connect",
                                "session_id": session_id,
                                "ip": src_ip,
                                "lat": geo.get("latitude"),
                                "lon": geo.get("longitude"),
                                "city": geo.get("city", "-"),
                                "country": geo.get("country", "-"),
                                "timestamp": entry.get("timestamp"),
                                "asn": geo.get("asn"),
                                "asn_org": geo.get("asn_org"),
                            }
                            yield f"data: {json.dumps(event_data)}\n\n"

                    # Track successful logins
                    elif event_id == "cowrie.login.success" and session_id in active_sessions:
                        active_sessions[session_id]["login_success"] = True
                        active_sessions[session_id]["username"] = entry.get("username")
                        active_sessions[session_id]["password"] = entry.get("password")

                        # Send login success event
                        session = active_sessions[session_id]
                        event_data = {
                            "event": "login_success",
                            "session_id": session_id,
                            "ip": session["src_ip"],
                            "username": entry.get("username"),
                            "password": entry.get("password"),
                            "timestamp": entry.get("timestamp"),
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"

                    # Track failed logins (only the first one to get credentials)
                    elif event_id == "cowrie.login.failed" and session_id in active_sessions:
                        session = active_sessions[session_id]
                        # Only send if we don't already have credentials
                        if not session.get("username"):
                            session["username"] = entry.get("username")
                            session["password"] = entry.get("password")

                            # Send login failed event with credentials
                            event_data = {
                                "event": "login_failed",
                                "session_id": session_id,
                                "ip": session["src_ip"],
                                "username": entry.get("username"),
                                "password": entry.get("password"),
                                "timestamp": entry.get("timestamp"),
                            }
                            yield f"data: {json.dumps(event_data)}\n\n"

                    # Track command input
                    elif event_id == "cowrie.command.input" and session_id in active_sessions:
                        session = active_sessions[session_id]

                        # Send command event
                        event_data = {
                            "event": "command_input",
                            "session_id": session_id,
                            "ip": session["src_ip"],
                            "command": entry.get("input", ""),
                            "timestamp": entry.get("timestamp"),
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"

                    # Track session closures
                    elif event_id == "cowrie.session.closed" and session_id in active_sessions:
                        session = active_sessions[session_id]

                        # Send close event
                        event_data = {
                            "event": "session_closed",
                            "session_id": session_id,
                            "ip": session["src_ip"],
                            "login_success": session["login_success"],
                            "timestamp": entry.get("timestamp"),
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"

                        # Clean up
                        del active_sessions[session_id]

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        except GeneratorExit:
            proc.terminate()
            proc.wait()

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/api/attack-stream-multi")
def attack_stream_multi():
    """Server-Sent Events endpoint for multi-source real-time attack feed."""

    def generate():
        """Generate SSE events by polling multiple honeypot APIs."""
        # Only enable in multi-source mode
        if not hasattr(session_parser, "sources"):
            yield f"data: {json.dumps({'event': 'error', 'message': 'Multi-source mode not enabled'})}\n\n"
            return

        import requests

        # Track seen sessions per source: {source_name: {session_id: session_data}}
        seen_sessions = {source_name: {} for source_name in session_parser.sources.keys()}
        last_keepalive = time.time()
        keepalive_interval = 30  # Send keepalive every 30 seconds
        poll_interval = 2  # Poll each source every 2 seconds

        print(f"[+] Multi-source SSE stream started for sources: {list(session_parser.sources.keys())}")

        # Send initial connected message
        yield f"data: {json.dumps({'event': 'connected', 'message': 'Multi-source live stream connected'})}\n\n"

        try:
            while True:
                # Send keepalive comment to prevent timeout
                if time.time() - last_keepalive > keepalive_interval:
                    yield ": keepalive\n\n"
                    last_keepalive = time.time()

                # Check for canary token events (shared queue)
                try:
                    with canary_queue_lock:
                        canary_event = canary_event_queue.get_nowait()

                    print(f"[+] Multi-SSE: Got canary event from queue: {canary_event.get('token_name')}")

                    # Send canary token trigger event (no source attribution for canary tokens)
                    if (
                        canary_event.get("geo")
                        and "latitude" in canary_event["geo"]
                        and "longitude" in canary_event["geo"]
                    ):
                        event_data = {
                            "event": "canary_trigger",
                            "id": canary_event.get("id"),
                            "ip": canary_event.get("trigger_ip"),
                            "lat": canary_event["geo"].get("latitude"),
                            "lon": canary_event["geo"].get("longitude"),
                            "city": canary_event["geo"].get("city", "-"),
                            "country": canary_event["geo"].get("country", "-"),
                            "asn": canary_event["geo"].get("asn"),
                            "asn_org": canary_event["geo"].get("asn_org"),
                            "timestamp": canary_event.get("timestamp"),
                            "token_type": canary_event.get("token_type"),
                            "token_name": canary_event.get("token_name"),
                            "trigger_user_agent": canary_event.get("trigger_user_agent"),
                            "trigger_location": canary_event.get("trigger_location"),
                            "_source": "canary",  # Special source for canary tokens
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"
                except queue.Empty:
                    pass  # No canary events, continue
                except Exception as e:
                    print(f"[!] Error processing canary event from queue: {e}")

                # Poll each source for new sessions
                for source_name, source in session_parser.sources.items():
                    try:
                        # Get sessions from last 5 minutes, sorted by start time (newest first)
                        api_url = source.datasource.api_base_url
                        response = requests.get(
                            f"{api_url}/api/v1/sessions",
                            params={"hours": 0.083, "limit": 50},  # Last 5 minutes, max 50 sessions
                            timeout=3,
                        )

                        if not response.ok:
                            continue

                        result = response.json()
                        sessions = result.get("sessions", [])

                        # Process sessions in reverse order (oldest first) to maintain chronological order
                        for session in reversed(sessions):
                            session_id = session.get("session_id") or session.get("id")
                            if not session_id:
                                continue

                            # Check if this is a new session
                            if session_id not in seen_sessions[source_name]:
                                # New session detected - send connect event
                                src_ip = session.get("src_ip")
                                if not src_ip:
                                    continue

                                # Get geo data (should already be enriched by API)
                                geo = session.get("geo", {})
                                if not geo or "latitude" not in geo:
                                    # Fallback to local GeoIP lookup
                                    geo = global_geoip.lookup(src_ip)

                                # Initialize session tracking
                                seen_sessions[source_name][session_id] = {
                                    "src_ip": src_ip,
                                    "geo": geo,
                                    "start_time": session.get("start_time"),
                                    "login_success": session.get("login_success", False),
                                    "username": session.get("username"),
                                    "password": session.get("password"),
                                    "commands_seen": 0,
                                    "end_time": session.get("end_time"),
                                }

                                # Send connect event
                                event_data = {
                                    "event": "connect",
                                    "session_id": session_id,
                                    "ip": src_ip,
                                    "lat": geo.get("latitude"),
                                    "lon": geo.get("longitude"),
                                    "city": geo.get("city", "-"),
                                    "country": geo.get("country", "-"),
                                    "timestamp": session.get("start_time"),
                                    "asn": geo.get("asn"),
                                    "asn_org": geo.get("asn_org"),
                                    "_source": source_name,  # Tag with source
                                }
                                yield f"data: {json.dumps(event_data)}\n\n"

                                # If session already has credentials, send login event
                                if session.get("username"):
                                    login_event = "login_success" if session.get("login_success") else "login_failed"
                                    event_data = {
                                        "event": login_event,
                                        "session_id": session_id,
                                        "ip": src_ip,
                                        "username": session.get("username"),
                                        "password": session.get("password"),
                                        "timestamp": session.get(
                                            "start_time"
                                        ),  # Use session start time as approximation
                                        "_source": source_name,
                                    }
                                    yield f"data: {json.dumps(event_data)}\n\n"

                                # Send command events for any commands
                                commands = session.get("commands", [])
                                for cmd in commands:
                                    event_data = {
                                        "event": "command_input",
                                        "session_id": session_id,
                                        "ip": src_ip,
                                        "command": cmd.get("command", cmd.get("input", "")),
                                        "timestamp": cmd.get("timestamp", session.get("start_time")),
                                        "_source": source_name,
                                    }
                                    yield f"data: {json.dumps(event_data)}\n\n"
                                    seen_sessions[source_name][session_id]["commands_seen"] += 1

                                # Check if session is already closed
                                if session.get("end_time"):
                                    event_data = {
                                        "event": "session_closed",
                                        "session_id": session_id,
                                        "ip": src_ip,
                                        "login_success": session.get("login_success", False),
                                        "timestamp": session.get("end_time"),
                                        "_source": source_name,
                                    }
                                    yield f"data: {json.dumps(event_data)}\n\n"

                            else:
                                # Existing session - check for updates
                                tracked = seen_sessions[source_name][session_id]

                                # Check for new commands
                                commands = session.get("commands", [])
                                if len(commands) > tracked["commands_seen"]:
                                    # Send new commands
                                    for cmd in commands[tracked["commands_seen"] :]:
                                        event_data = {
                                            "event": "command_input",
                                            "session_id": session_id,
                                            "ip": tracked["src_ip"],
                                            "command": cmd.get("command", cmd.get("input", "")),
                                            "timestamp": cmd.get("timestamp", session.get("start_time")),
                                            "_source": source_name,
                                        }
                                        yield f"data: {json.dumps(event_data)}\n\n"
                                    tracked["commands_seen"] = len(commands)

                                # Check for login success (if not already tracked)
                                if session.get("login_success") and not tracked["login_success"]:
                                    tracked["login_success"] = True
                                    tracked["username"] = session.get("username")
                                    tracked["password"] = session.get("password")

                                    event_data = {
                                        "event": "login_success",
                                        "session_id": session_id,
                                        "ip": tracked["src_ip"],
                                        "username": session.get("username"),
                                        "password": session.get("password"),
                                        "timestamp": session.get("start_time"),  # Approximation
                                        "_source": source_name,
                                    }
                                    yield f"data: {json.dumps(event_data)}\n\n"

                                # Check for session closure
                                if session.get("end_time") and not tracked.get("end_time"):
                                    tracked["end_time"] = session.get("end_time")

                                    event_data = {
                                        "event": "session_closed",
                                        "session_id": session_id,
                                        "ip": tracked["src_ip"],
                                        "login_success": tracked["login_success"],
                                        "timestamp": session.get("end_time"),
                                        "_source": source_name,
                                    }
                                    yield f"data: {json.dumps(event_data)}\n\n"

                    except Exception as e:
                        print(f"[!] Error polling source '{source_name}': {e}")
                        # Continue with other sources

                # Sleep before next poll
                time.sleep(poll_interval)

        except GeneratorExit:
            print("[+] Multi-source SSE stream closed")

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.template_filter("format_duration")
def format_duration(seconds):
    """Format duration in seconds to human readable string."""
    if not seconds:
        return "N/A"

    # Convert to float if it's a string
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "N/A"

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


@app.template_filter("format_timestamp")
def format_timestamp(ts_str):
    """Format ISO timestamp to readable string."""
    if not ts_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts_str


@app.template_filter("truncate_hash")
def truncate_hash(hash_str, length=16):
    """Truncate a hash for display."""
    if not hash_str:
        return "N/A"
    if len(hash_str) <= length:
        return hash_str
    return hash_str[:length] + "..."


if __name__ == "__main__":
    # Development server
    app.run(host="0.0.0.0", port=5000, debug=True)
