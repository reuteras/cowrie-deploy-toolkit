#!/usr/bin/env python3
"""
Cowrie SSH Session Playback Web Service

Provides a web interface for viewing and replaying SSH sessions captured by Cowrie.
"""

import json
import os
import sqlite3
import struct
import tempfile
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

app = Flask(__name__)

# Configuration from environment variables
CONFIG = {
    "log_path": os.getenv("COWRIE_LOG_PATH", "/cowrie-data/log/cowrie/cowrie.json"),
    "tty_path": os.getenv("COWRIE_TTY_PATH", "/cowrie-data/lib/cowrie/tty"),
    "download_path": os.getenv("COWRIE_DOWNLOAD_PATH", "/cowrie-data/lib/cowrie/downloads"),
    "honeyfs_path": os.getenv("HONEYFS_PATH", "/cowrie-data/share/cowrie/contents"),
    "identity_path": os.getenv("IDENTITY_PATH", "/cowrie-data/identity"),
    "geoip_db_path": os.getenv("GEOIP_DB_PATH", "/cowrie-data/geoip/GeoLite2-City.mmdb"),
    "geoip_asn_path": os.getenv("GEOIP_ASN_PATH", "/cowrie-data/geoip/GeoLite2-ASN.mmdb"),
    "base_url": os.getenv("BASE_URL", ""),
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "cache_db_path": os.getenv("CACHE_DB_PATH", "/tmp/vt-cache.db"),
    "yara_cache_db_path": os.getenv("YARA_CACHE_DB_PATH", "/cowrie-data/var/yara-cache.db"),
    "metadata_path": os.getenv("COWRIE_METADATA_PATH", "/cowrie-metadata/metadata.json"),
    "server_ip": os.getenv("SERVER_IP", ""),
    "honeypot_hostname": os.getenv("HONEYPOT_HOSTNAME", ""),
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

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.sessions = {}
        self.geoip = GeoIPLookup(CONFIG["geoip_db_path"], CONFIG.get("geoip_asn_path"))

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
                            session["commands"].append({"command": entry.get("input", ""), "timestamp": entry["timestamp"]})

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
                                session["tty_logs"].append({
                                    "ttylog": tty_log,
                                    "timestamp": entry["timestamp"],
                                    "duration": entry.get("duration", "0"),
                                    "size": entry.get("size", 0)
                                })
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
        result = {"greynoise": None}

        if not os.path.exists(self.log_path):
            return result

        with open(self.log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    event_id = entry.get("eventid", "")
                    src_ip = entry.get("src_ip")

                    if src_ip != ip_address:
                        continue

                    if event_id == "cowrie.greynoise.result":
                        # Extract classification from message if available
                        classification = entry.get("classification", "unknown")
                        if not classification or classification == "unknown":
                            message = entry.get("message", "")
                            if "classification is malicious" in message.lower():
                                classification = "malicious"
                            elif "classification is benign" in message.lower():
                                classification = "benign"

                        result["greynoise"] = {
                            "classification": classification,
                            "message": entry.get("message", ""),
                            "timestamp": entry["timestamp"],
                        }

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
                "greynoise_ips": [],
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
        greynoise_results = {}  # IP -> {classification, message, timestamp}
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
                        asn_details[asn_key] = {
                            "asn_number": asn,
                            "asn_org": asn_org or "Unknown Organization"
                        }

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

        # Parse threat intelligence events (GreyNoise)
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        if os.path.exists(self.log_path):
            with open(self.log_path) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))

                        if timestamp < cutoff_time:
                            continue

                        event_id = entry.get("eventid", "")
                        src_ip = entry.get("src_ip")

                        if event_id == "cowrie.greynoise.result" and src_ip:
                            # Extract classification from message if available
                            classification = entry.get("classification", "unknown")
                            if not classification or classification == "unknown":
                                # Try to parse from message
                                message = entry.get("message", "")
                                if "classification is malicious" in message.lower():
                                    classification = "malicious"
                                elif "classification is benign" in message.lower():
                                    classification = "benign"

                            greynoise_results[src_ip] = {
                                "classification": classification,
                                "message": entry.get("message", ""),
                                "timestamp": entry["timestamp"],
                            }

                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue

        # Sort hourly activity
        sorted_hours = sorted(hourly_activity.items())

        # Sort IP details by session count
        sorted_ips = sorted(
            [{"ip": ip, **details} for ip, details in ip_details.items()], key=lambda x: x["count"], reverse=True
        )

        # Convert threat intelligence dicts to sorted lists
        greynoise_list = sorted(
            [{"ip": ip, **data} for ip, data in greynoise_results.items()],
            key=lambda x: x["timestamp"],
            reverse=True,
        )

        # Build top ASNs list with details
        top_asns = []
        for asn_key, count in asn_counter.most_common(10):
            details = asn_details.get(asn_key, {})
            top_asns.append({
                "asn": asn_key,
                "asn_number": details.get("asn_number", 0),
                "asn_org": details.get("asn_org", "Unknown"),
                "count": count
            })

        # Collect malicious downloads with VT scores
        download_path = CONFIG["download_path"]
        all_downloads = []
        for session in sessions.values():
            for download in session["downloads"]:
                all_downloads.append({
                    "session_id": session["id"],
                    "src_ip": session["src_ip"],
                    "shasum": download["shasum"],
                    "url": download.get("url", ""),
                    "timestamp": download["timestamp"],
                })

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
        top_downloads = sorted(
            all_scanned_files.values(),
            key=lambda x: x.get("vt_detections", 0),
            reverse=True
        )[:10]

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
            "greynoise_ips": greynoise_list,
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
                            # Only include TYPE_OUTPUT (2) which contains prompts, echoed commands, and output
                            # TYPE_INPUT (1) is just raw keystrokes and should be excluded
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
                            break

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
        username = session.get("username", "root")

        print(f"[DEBUG] merge_tty_logs: Found {len(tty_logs)} TTY logs and {len(commands)} commands")

        if not tty_logs:
            print("[DEBUG] merge_tty_logs: No TTY logs found, returning None")
            return None

        merged_stdout = []
        total_duration = 0.0
        width = 120
        height = 30

        # Create prompt string (e.g., "root@dmz-web01:~# ")
        prompt = f"{username}@{hostname}:~# "

        # Match TTY logs with commands by timestamp
        # Sort both by timestamp for correlation
        sorted_ttys = sorted(tty_logs, key=lambda x: x.get("timestamp", ""))
        sorted_cmds = sorted(commands, key=lambda x: x.get("timestamp", ""))

        for i, tty_entry in enumerate(sorted_ttys):
            # Add prompt before command
            merged_stdout.append([total_duration, prompt])

            # Get corresponding command if available
            if i < len(sorted_cmds):
                cmd_text = sorted_cmds[i].get("command", "")
                # Echo the command (what user typed) with a newline
                merged_stdout.append([total_duration, cmd_text + "\r\n"])
                total_duration += 0.05

            # Parse and add the TTY log output
            tty_log_name = tty_entry.get("ttylog")
            if tty_log_name:
                asciicast = self.parse_tty_log(tty_log_name)
                if asciicast:
                    # Update dimensions if needed
                    width = max(width, asciicast.get("width", 120))
                    height = max(height, asciicast.get("height", 30))

                    # Add the command output with timing from original TTY file
                    # Scale timing slightly to make it more readable
                    for event in asciicast.get("stdout", []):
                        # Scale the timing by 1.5x to slow down fast output
                        scaled_time = event[0] * 1.5
                        merged_stdout.append([scaled_time, event[1].replace("\n", "\r\n")])
                        total_duration += scaled_time

        print(f"[DEBUG] merge_tty_logs: Created asciicast with {len(merged_stdout)} events, duration={total_duration:.2f}s")

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

# Initialize parsers
session_parser = SessionParser(CONFIG["log_path"])
tty_parser = TTYLogParser(CONFIG["tty_path"])

# Initialize VirusTotal scanner if API key is provided
vt_scanner = None
if CONFIG["virustotal_api_key"]:
    cache_db = CacheDB(CONFIG["cache_db_path"])
    vt_scanner = VirusTotalScanner(CONFIG["virustotal_api_key"], cache_db)

# Initialize YARA cache (reads results from yara-scanner-daemon)
yara_cache = YARACache(CONFIG["yara_cache_db_path"])


@app.route("/")
def index():
    """Dashboard page."""
    hours = request.args.get("hours", 24, type=int)
    stats = session_parser.get_stats(hours=hours)
    return render_template("index.html", stats=stats, hours=hours, config=CONFIG)


@app.route("/attack-map")
def attack_map_page():
    """Attack visualization map page."""
    hours = request.args.get("hours", 24, type=int)
    sessions = session_parser.parse_all(hours=hours)

    # Get honeypot location from server IP
    geoip = GeoIPLookup(CONFIG["geoip_db_path"], CONFIG.get("geoip_asn_path"))
    honeypot_location = None
    if CONFIG["server_ip"]:
        honeypot_geo = geoip.lookup(CONFIG["server_ip"])
        if "latitude" in honeypot_geo and "longitude" in honeypot_geo:
            honeypot_location = {
                "lat": honeypot_geo["latitude"],
                "lon": honeypot_geo["longitude"],
                "city": honeypot_geo.get("city", "-"),
                "country": honeypot_geo.get("country", "-"),
            }

    # Collect attack data with timestamps for animation
    attacks = []
    for session in sessions.values():
        if session.get("src_ip") and session.get("geo"):
            geo = session["geo"]
            if "latitude" in geo and "longitude" in geo:
                attacks.append(
                    {
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
                    }
                )

    # Sort by timestamp
    attacks.sort(key=lambda x: x["timestamp"])

    return render_template(
        "attack_map.html", attacks=attacks, honeypot_location=honeypot_location, hours=hours, config=CONFIG
    )


@app.route("/sessions")
def sessions():
    """Session listing page."""
    hours = request.args.get("hours", 168, type=int)
    page = request.args.get("page", 1, type=int)
    per_page = 50

    all_sessions = session_parser.parse_all(hours=hours)

    # Sort by start time (most recent first)
    sorted_sessions = sorted(all_sessions.values(), key=lambda x: x["start_time"] or "", reverse=True)

    # Filter options
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
        sorted_sessions = [s for s in sorted_sessions if f"{s.get('username', '')}:{s.get('password', '')}" == credentials_filter]
    if client_version_filter:
        sorted_sessions = [s for s in sorted_sessions if s.get("client_version") == client_version_filter]
    if command_filter:
        sorted_sessions = [s for s in sorted_sessions if any(cmd["command"] == command_filter for cmd in s["commands"])]
    if has_commands == "1":
        sorted_sessions = [s for s in sorted_sessions if s["commands"]]
    if has_tty == "1":
        sorted_sessions = [s for s in sorted_sessions if s["tty_log"]]
    if successful_login == "1":
        sorted_sessions = [s for s in sorted_sessions if s.get("login_success")]

    # Paginate
    total = len(sorted_sessions)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = sorted_sessions[start:end]

    return render_template(
        "sessions.html",
        sessions=paginated,
        page=page,
        per_page=per_page,
        total=total,
        hours=hours,
        ip_filter=ip_filter,
        country_filter=country_filter,
        credentials_filter=credentials_filter,
        client_version_filter=client_version_filter,
        command_filter=command_filter,
        has_commands=has_commands,
        has_tty=has_tty,
        successful_login=successful_login,
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

    all_sessions = session_parser.parse_all(hours=hours)
    sorted_sessions = sorted(all_sessions.values(), key=lambda x: x["start_time"] or "", reverse=True)[:limit]

    return jsonify(sorted_sessions)


@app.route("/api/system-info")
def api_system_info():
    """API endpoint for honeypot system information."""
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
    # Paths where Canary Tokens are placed (relative to honeyfs)
    honeyfs_path = CONFIG.get("honeyfs_path", "/cowrie-data/share/cowrie/contents")

    tokens = []

    # Check for MySQL backup token
    mysql_token_path = os.path.join(honeyfs_path, "root/backup/mysql-backup.sql")
    if os.path.exists(mysql_token_path):
        stat_info = os.stat(mysql_token_path)
        tokens.append({
            "type": "MySQL Dump",
            "icon": "🗄️",
            "path": "/root/backup/mysql-backup.sql",
            "size": stat_info.st_size,
            "description": "Database backup file"
        })

    # Check for Excel token
    excel_token_path = os.path.join(honeyfs_path, "root/Q1_Financial_Report.xlsx")
    if os.path.exists(excel_token_path):
        stat_info = os.stat(excel_token_path)
        tokens.append({
            "type": "Excel Document",
            "icon": "📊",
            "path": "/root/Q1_Financial_Report.xlsx",
            "size": stat_info.st_size,
            "description": "Financial report spreadsheet"
        })

    # Check for PDF token
    pdf_token_path = os.path.join(honeyfs_path, "root/Network_Passwords.pdf")
    if os.path.exists(pdf_token_path):
        stat_info = os.stat(pdf_token_path)
        tokens.append({
            "type": "PDF Document",
            "icon": "📄",
            "path": "/root/Network_Passwords.pdf",
            "size": stat_info.st_size,
            "description": "Password documentation"
        })

    return jsonify({
        "tokens": tokens,
        "total": len(tokens)
    })


@app.route("/system-info")
def system_info():
    """Extended system information page with SSH config and canary tokens."""
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
            canary_tokens.append({
                "path": path,
                "icon": icon,
                "description": description,
                "size": stat_info.st_size,
            })

    return render_template("system_info.html", system=system_data, canary_tokens=canary_tokens)


@app.route("/downloads")
def downloads():
    """Downloaded files listing page."""
    hours = request.args.get("hours", 168, type=int)
    all_sessions = session_parser.parse_all(hours=hours)

    # Collect all downloads
    all_downloads = []
    for session in all_sessions.values():
        for download in session["downloads"]:
            download["session_id"] = session["id"]
            download["src_ip"] = session["src_ip"]
            all_downloads.append(download)

    # Deduplicate by shasum
    unique_downloads = {}
    for dl in all_downloads:
        shasum = dl["shasum"]
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

    downloads_list = sorted(unique_downloads.values(), key=lambda x: x["timestamp"], reverse=True)

    return render_template("downloads.html", downloads=downloads_list, hours=hours, config=CONFIG)


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
        with zipfile.ZipFile(
            temp_zip.name,
            "w"
        ) as zipf:
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
    """Commands listing page."""
    hours = request.args.get("hours", 168, type=int)
    unique_only = request.args.get("unique", "")
    all_commands = session_parser.get_all_commands(hours=hours)

    # Filter to unique commands if requested
    if unique_only == "1":
        seen_commands = set()
        unique_commands = []
        for cmd in all_commands:
            if cmd["command"] not in seen_commands:
                seen_commands.add(cmd["command"])
                unique_commands.append(cmd)
        all_commands = unique_commands

    return render_template("commands.html", commands=all_commands, hours=hours, unique=unique_only, config=CONFIG)


@app.route("/ips")
def ip_list():
    """IP address listing page."""
    hours = request.args.get("hours", 168, type=int)
    stats = session_parser.get_stats(hours=hours)

    # Get filter parameters
    asn_filter = request.args.get("asn", "")
    country_filter = request.args.get("country", "")
    city_filter = request.args.get("city", "")

    # Apply filters
    filtered_ips = stats["ip_list"]
    if asn_filter:
        filtered_ips = [ip for ip in filtered_ips if ip.get("geo", {}).get("asn") and f"AS{ip['geo']['asn']}" == asn_filter]
    if country_filter:
        filtered_ips = [ip for ip in filtered_ips if ip.get("geo", {}).get("country") == country_filter]
    if city_filter:
        filtered_ips = [ip for ip in filtered_ips if ip.get("geo", {}).get("city") == city_filter]

    return render_template(
        "ips.html",
        ips=filtered_ips,
        hours=hours,
        asn_filter=asn_filter,
        country_filter=country_filter,
        city_filter=city_filter,
        config=CONFIG
    )


@app.route("/countries")
def countries():
    """All countries listing page."""
    hours = request.args.get("hours", 168, type=int)

    # Get all countries (not just top 10)
    sessions = session_parser.parse_all(hours=hours)
    country_counter = Counter()
    for session in sessions.values():
        if session.get("src_ip"):
            country = session.get("geo", {}).get("country", "Unknown")
            country_counter[country] += 1

    all_countries = country_counter.most_common()

    return render_template("countries.html", countries=all_countries, hours=hours, config=CONFIG)


@app.route("/credentials")
def credentials():
    """All credentials listing page."""
    hours = request.args.get("hours", 168, type=int)

    # Get all credentials (not just top 10)
    sessions = session_parser.parse_all(hours=hours)
    credential_counter = Counter()
    successful_credentials = set()
    for session in sessions.values():
        if session["username"] and session["password"]:
            cred = f"{session['username']}:{session['password']}"
            credential_counter[cred] += 1
            if session.get("login_success"):
                successful_credentials.add(cred)

    all_credentials = credential_counter.most_common()

    return render_template(
        "credentials.html",
        credentials=all_credentials,
        successful_credentials=successful_credentials,
        hours=hours,
        config=CONFIG
    )


@app.route("/clients")
def clients():
    """All SSH clients listing page."""
    hours = request.args.get("hours", 168, type=int)

    # Get all client versions (not just top 10)
    sessions = session_parser.parse_all(hours=hours)
    client_version_counter = Counter()
    for session in sessions.values():
        if session.get("client_version"):
            client_version_counter[session["client_version"]] += 1

    all_clients = client_version_counter.most_common()

    return render_template("clients.html", clients=all_clients, hours=hours, config=CONFIG)


@app.route("/asns")
def asns():
    """All ASNs listing page."""
    hours = request.args.get("hours", 168, type=int)

    # Get all ASNs (not just top 10)
    sessions = session_parser.parse_all(hours=hours)
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
                    asn_details[asn_key] = {
                        "asn_number": asn,
                        "asn_org": asn_org or "Unknown Organization"
                    }

    # Build full ASNs list with details
    all_asns = []
    for asn_key, count in asn_counter.most_common():
        details = asn_details.get(asn_key, {})
        all_asns.append({
            "asn": asn_key,
            "asn_number": details.get("asn_number", 0),
            "asn_org": details.get("asn_org", "Unknown"),
            "count": count
        })

    return render_template("asns.html", asns=all_asns, hours=hours, config=CONFIG)


@app.route("/api/attack-stream")
def attack_stream():
    """Server-Sent Events endpoint for real-time attack feed."""
    def generate():
        """Generate SSE events from Cowrie log file."""
        import subprocess

        log_path = CONFIG["log_path"]

        # Use tail -F to follow the log file
        proc = subprocess.Popen(
            ["tail", "-F", "-n", "0", log_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        geoip = GeoIPLookup(CONFIG["geoip_db_path"], CONFIG.get("geoip_asn_path"))
        active_sessions = {}  # Track active sessions

        try:
            while True:
                line = proc.stdout.readline()
                if not line:
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
                            geo = geoip.lookup(src_ip)
                            active_sessions[session_id] = {
                                "src_ip": src_ip,
                                "geo": geo,
                                "start_time": entry.get("timestamp"),
                                "login_success": False,
                                "username": None,
                                "password": None
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
                                "asn_org": geo.get("asn_org")
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
                            "timestamp": entry.get("timestamp")
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
                                "timestamp": entry.get("timestamp")
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
                            "timestamp": entry.get("timestamp")
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
                            "timestamp": entry.get("timestamp")
                        }
                        yield f"data: {json.dumps(event_data)}\n\n"

                        # Clean up
                        del active_sessions[session_id]

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        except GeneratorExit:
            proc.terminate()
            proc.wait()

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


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
