"""
SQLite-based statistics parser for Cowrie API

Queries Cowrie's SQLite database directly for fast statistics generation.
Falls back to JSON parsing if SQLite is unavailable.
"""

import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone

import geoip2.database
import geoip2.errors

# Database path (container mount path)
DEFAULT_DB_PATH = "/cowrie/cowrie-git/var/lib/cowrie/cowrie.db"
DEFAULT_LOG_PATH = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"


class SQLiteStatsParser:
    """Fast statistics parser using SQLite database"""

    def __init__(self, db_path: str = None, geoip_city_db: str = None, geoip_asn_db: str = None, log_path: str = None):
        """
        Initialize SQLite parser

        Args:
            db_path: Path to cowrie.db (defaults to standard location)
            geoip_city_db: Path to GeoLite2-City.mmdb
            geoip_asn_db: Path to GeoLite2-ASN.mmdb
            log_path: Path to cowrie.json log file (for events)
        """
        self.db_path = db_path or os.getenv("COWRIE_DB_PATH", DEFAULT_DB_PATH)
        self.available = os.path.exists(self.db_path)
        self.log_path = log_path or os.getenv("COWRIE_LOG_PATH", DEFAULT_LOG_PATH)

        # Initialize GeoIP readers
        self.geoip_city_db = geoip_city_db or os.getenv("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
        self.geoip_asn_db = geoip_asn_db or os.getenv("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")

        self.city_reader = None
        self.asn_reader = None

        if os.path.exists(self.geoip_city_db):
            try:
                self.city_reader = geoip2.database.Reader(self.geoip_city_db)
            except Exception as e:
                print(f"[!] Failed to load GeoIP City database: {e}")

        if os.path.exists(self.geoip_asn_db):
            try:
                self.asn_reader = geoip2.database.Reader(self.geoip_asn_db)
            except Exception as e:
                print(f"[!] Failed to load GeoIP ASN database: {e}")

    def _get_session_events_from_db(self, session_id: str) -> list:
        """
        Get all events for a session from the events database table.

        Args:
            session_id: Session ID to search for

        Returns:
            List of event dicts for this session, or empty list if events table doesn't exist
        """
        if not self.available:
            return []

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check if events table exists
            cursor.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='events'
                """
            )
            if not cursor.fetchone():
                conn.close()
                return []

            # Query events for this session
            cursor.execute(
                """
                SELECT data FROM events
                WHERE session = ?
                ORDER BY timestamp
                """,
                (session_id,),
            )

            events = []
            for row in cursor.fetchall():
                try:
                    event = json.loads(row["data"])
                    events.append(event)
                except json.JSONDecodeError:
                    continue

            conn.close()
            return events

        except Exception as e:
            print(f"[!] Error querying events from database: {e}")
            return []

    def _get_session_events(self, session_id: str) -> list:
        """
        Get all events for a session from the database.

        Args:
            session_id: Session ID to search for

        Returns:
            List of event dicts for this session
        """
        # Get events from database (indexed by event-indexer daemon)
        return self._get_session_events_from_db(session_id)

    def _geoip_lookup(self, ip: str) -> dict:
        """Lookup GeoIP information for an IP address"""
        result = {
            "country": "-",
            "country_code": "XX",
            "city": "-",
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": "-",
        }

        if not self.city_reader:
            return result

        try:
            response = self.city_reader.city(ip)
            result["country"] = response.country.name or "-"
            result["country_code"] = response.country.iso_code or "XX"
            result["city"] = response.city.name or "-"
            if response.location.latitude and response.location.longitude:
                result["latitude"] = response.location.latitude
                result["longitude"] = response.location.longitude
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[!] GeoIP City lookup error for {ip}: {e}")

        if self.asn_reader:
            try:
                asn_response = self.asn_reader.asn(ip)
                result["asn"] = asn_response.autonomous_system_number
                result["asn_org"] = asn_response.autonomous_system_organization or "-"
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                print(f"[!] GeoIP ASN lookup error for {ip}: {e}")

        return result

    def get_stats_overview(self, days: int = 7) -> dict:
        """
        Get overview statistics using SQL queries

        Args:
            days: Number of days to include

        Returns:
            Statistics dict with totals, top IPs, credentials, commands
        """
        if not self.available:
            raise FileNotFoundError(f"SQLite database not found at {self.db_path}")

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Total sessions and unique IPs
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total_sessions,
                    COUNT(DISTINCT ip) as unique_ips
                FROM sessions
                WHERE starttime >= ?
                """,
                (cutoff_str,),
            )
            totals = dict(cursor.fetchone())

            # Sessions with commands
            cursor.execute(
                """
                SELECT COUNT(DISTINCT session) as sessions_with_commands
                FROM input
                WHERE timestamp >= ?
                """,
                (cutoff_str,),
            )
            totals["sessions_with_commands"] = cursor.fetchone()["sessions_with_commands"]

            # Total downloads (only successful ones with shasum)
            cursor.execute(
                """
                SELECT COUNT(*) as downloads
                FROM downloads
                WHERE timestamp >= ? AND shasum IS NOT NULL
                """,
                (cutoff_str,),
            )
            totals["downloads"] = cursor.fetchone()["downloads"]

            # Unique downloads (distinct shasum values)
            cursor.execute(
                """
                SELECT COUNT(DISTINCT shasum) as unique_downloads
                FROM downloads
                WHERE timestamp >= ? AND shasum IS NOT NULL
                """,
                (cutoff_str,),
            )
            totals["unique_downloads"] = cursor.fetchone()["unique_downloads"]

            # Get list of unique SHA256 hashes for deduplication across sources
            cursor.execute(
                """
                SELECT DISTINCT shasum
                FROM downloads
                WHERE timestamp >= ? AND shasum IS NOT NULL
                ORDER BY shasum
                """,
                (cutoff_str,),
            )
            totals["unique_download_hashes"] = [row["shasum"] for row in cursor.fetchall()]

            # All IPs with GeoIP enrichment (no limit for /ips page)
            cursor.execute(
                """
                SELECT
                    s.ip,
                    COUNT(*) as count,
                    MAX(s.starttime) as last_seen,
                    COUNT(CASE WHEN a.success = 1 THEN 1 END) as successful_logins,
                    COUNT(CASE WHEN a.success = 0 THEN 1 END) as failed_logins
                FROM sessions s
                LEFT JOIN auth a ON s.id = a.session
                WHERE s.starttime >= ?
                GROUP BY s.ip
                ORDER BY count DESC
                """,
                (cutoff_str,),
            )
            top_ips = []
            for row in cursor.fetchall():
                ip = row["ip"]
                geo = self._geoip_lookup(ip)
                top_ips.append(
                    {
                        "ip": ip,
                        "count": row["count"],
                        "last_seen": row["last_seen"],
                        "successful_logins": row["successful_logins"] or 0,
                        "failed_logins": row["failed_logins"] or 0,
                        "geo": {
                            "country": geo["country"],
                            "city": geo["city"],
                            "latitude": geo["latitude"],
                            "longitude": geo["longitude"],
                        },
                        "asn": geo["asn"],
                        "asn_org": geo["asn_org"],
                    }
                )

            # Top credentials
            cursor.execute(
                """
                SELECT username, password, COUNT(*) as count
                FROM auth
                WHERE timestamp >= ?
                GROUP BY username, password
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_credentials = [
                {"username": row["username"], "password": row["password"], "count": row["count"]}
                for row in cursor.fetchall()
            ]

            # Top commands
            cursor.execute(
                """
                SELECT input as command, COUNT(*) as count
                FROM input
                WHERE timestamp >= ? AND success = 1
                GROUP BY input
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_commands = [{"command": row["command"], "count": row["count"]} for row in cursor.fetchall()]

            # Top SSH clients (join with clients table)
            cursor.execute(
                """
                SELECT c.version as client, COUNT(*) as count
                FROM sessions s
                JOIN clients c ON s.client = c.id
                WHERE s.starttime >= ?
                GROUP BY c.version
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_clients = [{"client": row["client"], "count": row["count"]} for row in cursor.fetchall()]

            # Get IPs with session counts for GeoIP enrichment
            # Count sessions per IP (not just unique IPs) for accurate ASN/country stats
            cursor.execute(
                """
                SELECT ip, COUNT(*) as session_count
                FROM sessions
                WHERE starttime >= ?
                GROUP BY ip
                """,
                (cutoff_str,),
            )
            ip_session_counts = {row["ip"]: row["session_count"] for row in cursor.fetchall()}

            # Enrich with GeoIP data
            country_counter = Counter()
            asn_counter = Counter()
            asn_details = {}
            ip_locations = []

            for ip, session_count in ip_session_counts.items():
                geo = self._geoip_lookup(ip)

                # Count by country (weighted by session count)
                if geo["country"] != "-":
                    country_counter[geo["country"]] += session_count

                # Count by ASN (weighted by session count)
                if geo["asn"]:
                    asn_key = f"AS{geo['asn']}"
                    asn_counter[asn_key] += session_count
                    asn_details[asn_key] = {
                        "asn": asn_key,
                        "organization": geo["asn_org"],
                    }

                # Add to map locations if has coordinates
                if geo["latitude"] and geo["longitude"]:
                    ip_locations.append(
                        {
                            "ip": ip,
                            "lat": geo["latitude"],
                            "lon": geo["longitude"],
                            "city": geo["city"],
                            "country": geo["country"],
                        }
                    )

            # Format top countries
            top_countries = [{"country": country, "count": count} for country, count in country_counter.most_common(10)]

            # Format top ASNs
            top_asns = []
            for asn, count in asn_counter.most_common(10):
                entry = {"asn": asn, "count": count}
                if asn in asn_details:
                    entry["organization"] = asn_details[asn]["organization"]
                top_asns.append(entry)

            return {
                "time_range": {
                    "start": cutoff.isoformat(),
                    "end": datetime.now(timezone.utc).isoformat(),
                    "days": days,
                },
                "totals": totals,
                "top_ips": top_ips,
                "top_credentials": top_credentials,
                "top_commands": top_commands,
                "top_clients": top_clients,
                "top_countries": top_countries,
                "top_asns": top_asns,
                "ip_locations": ip_locations,
            }

        finally:
            conn.close()

    def get_all_asns(self, days: int = 7) -> list[dict]:
        """
        Get ALL ASNs with session counts (not just top 10).

        This is more efficient than fetching all sessions - it queries
        unique IPs from SQLite and enriches with GeoIP, counting sessions per ASN.

        Args:
            days: Number of days to include

        Returns:
            List of ASN dicts with asn, asn_org, and count (sorted by count desc)
        """
        if not self.available:
            raise FileNotFoundError(f"SQLite database not found at {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

            # Get IPs with session counts
            cursor.execute(
                """
                SELECT ip, COUNT(*) as session_count
                FROM sessions
                WHERE starttime >= ?
                GROUP BY ip
                """,
                (cutoff_str,),
            )
            ip_session_counts = {row["ip"]: row["session_count"] for row in cursor.fetchall()}

            # Aggregate by ASN
            asn_counter = Counter()
            asn_details = {}

            for ip, session_count in ip_session_counts.items():
                geo = self._geoip_lookup(ip)
                if geo["asn"]:
                    asn_key = f"AS{geo['asn']}"
                    asn_counter[asn_key] += session_count
                    if asn_key not in asn_details:
                        asn_details[asn_key] = {
                            "asn": asn_key,
                            "asn_number": geo["asn"],
                            "asn_org": geo["asn_org"] or "Unknown",
                        }

            # Build result list sorted by count
            result = []
            for asn_key, count in asn_counter.most_common():
                details = asn_details.get(asn_key, {})
                result.append({
                    "asn": asn_key,
                    "asn_number": details.get("asn_number", 0),
                    "asn_org": details.get("asn_org", "Unknown"),
                    "count": count,
                })

            return result

        finally:
            conn.close()

    def get_attack_map_data(self, days: int = 7) -> dict:
        """
        Get aggregated attack data for the map visualization.

        Returns per-IP data with coordinates, session counts, and success counts.
        Much more efficient than fetching all sessions.

        Args:
            days: Number of days to include

        Returns:
            Dict with 'attacks' list and 'total_sessions' count
        """
        if not self.available:
            raise FileNotFoundError(f"SQLite database not found at {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

            # Get IP stats: session count, success count, latest timestamp
            cursor.execute(
                """
                SELECT
                    s.ip,
                    COUNT(*) as session_count,
                    MAX(s.starttime) as latest_timestamp
                FROM sessions s
                WHERE s.starttime >= ?
                GROUP BY s.ip
                """,
                (cutoff_str,),
            )
            ip_stats = {row["ip"]: {
                "session_count": row["session_count"],
                "latest_timestamp": row["latest_timestamp"],
            } for row in cursor.fetchall()}

            # Get success counts per IP from auth table
            cursor.execute(
                """
                SELECT
                    a.source_ip,
                    COUNT(*) as success_count
                FROM auth a
                WHERE a.timestamp >= ? AND a.success = 1
                GROUP BY a.source_ip
                """,
                (cutoff_str,),
            )
            for row in cursor.fetchall():
                if row["source_ip"] in ip_stats:
                    ip_stats[row["source_ip"]]["success_count"] = row["success_count"]

            # Build attack list with GeoIP enrichment
            attacks = []
            total_sessions = 0

            for ip, stats in ip_stats.items():
                geo = self._geoip_lookup(ip)

                # Skip IPs without coordinates
                if not geo.get("latitude") or not geo.get("longitude"):
                    continue

                session_count = stats["session_count"]
                success_count = stats.get("success_count", 0)
                total_sessions += session_count

                attacks.append({
                    "ip": ip,
                    "lat": geo["latitude"],
                    "lon": geo["longitude"],
                    "city": geo.get("city", "-"),
                    "country": geo.get("country", "-"),
                    "country_code": geo.get("country_code", "XX"),
                    "asn": geo.get("asn"),
                    "asn_org": geo.get("asn_org"),
                    "session_count": session_count,
                    "success_count": success_count,
                    "latest_timestamp": stats["latest_timestamp"],
                })

            # Sort by latest timestamp for animation ordering
            attacks.sort(key=lambda x: x["latest_timestamp"] or "")

            return {
                "attacks": attacks,
                "total_sessions": total_sessions,
                "unique_ips": len(attacks),
            }

        finally:
            conn.close()

    def get_sessions(
        self,
        limit: int = 100,
        offset: int = 0,
        src_ip: str = None,
        username: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> list[dict]:
        """
        Get sessions from SQLite database with TTY logs, commands, and auth data

        Args:
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip
            src_ip: Filter by source IP
            username: Filter by username
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            List of session dictionaries
        """
        if not self.available:
            raise FileNotFoundError(f"SQLite database not found at {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Build WHERE clause
            where_clauses = []
            params = []

            if src_ip:
                where_clauses.append("s.ip = ?")
                params.append(src_ip)

            if username:
                where_clauses.append("EXISTS (SELECT 1 FROM auth a WHERE a.session = s.id AND a.username = ?)")
                params.append(username)

            if start_time:
                where_clauses.append("s.starttime >= ?")
                # Format as ISO8601 to match database format (YYYY-MM-DDTHH:MM:SS.ffffffZ)
                params.append(start_time.strftime("%Y-%m-%dT%H:%M:%S"))

            if end_time:
                where_clauses.append("s.starttime <= ?")
                # Format as ISO8601 to match database format (YYYY-MM-DDTHH:MM:SS.ffffffZ)
                params.append(end_time.strftime("%Y-%m-%dT%H:%M:%S"))

            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

            # Query sessions with basic info
            query = f"""
                SELECT
                    s.id as session_id,
                    s.ip as src_ip,
                    s.starttime as start_time,
                    s.endtime as end_time,
                    c.version as client_version
                FROM sessions s
                LEFT JOIN clients c ON s.client = c.id
                WHERE {where_sql}
                ORDER BY s.starttime DESC
                LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])

            cursor.execute(query, params)
            sessions_rows = cursor.fetchall()

            sessions = []
            for row in sessions_rows:
                session_id = row["session_id"]

                # Build session dict
                session = {
                    "session_id": session_id,
                    "id": session_id,  # Add for compatibility
                    "src_ip": row["src_ip"],
                    "start_time": row["start_time"],
                    "end_time": row["end_time"],
                    "client_version": row["client_version"],
                    "commands": [],
                    "downloads": [],
                    "events": self._get_session_events(session_id),
                }

                # Get ALL TTY logs for this session
                cursor.execute("SELECT id, ttylog, size FROM ttylog WHERE session = ? ORDER BY id", (session_id,))
                tty_rows = cursor.fetchall()
                if tty_rows:
                    # Set tty_logs (plural) as list of dicts with ttylog and timestamp
                    # merge_tty_logs() expects: [{"ttylog": "...", "timestamp": "..."}, ...]
                    session["tty_logs"] = [
                        {"ttylog": row["ttylog"], "timestamp": str(row["id"])} for row in tty_rows if row["size"] > 0
                    ]
                    # Also set tty_log (singular) for backwards compatibility
                    session["tty_log"] = tty_rows[0]["ttylog"] if tty_rows else None
                    session["has_tty"] = len(session["tty_logs"]) > 0
                else:
                    session["tty_log"] = None
                    session["tty_logs"] = []
                    session["has_tty"] = False

                # Get authentication data
                cursor.execute(
                    """
                    SELECT username, password, success
                    FROM auth
                    WHERE session = ?
                    ORDER BY timestamp
                    LIMIT 1
                    """,
                    (session_id,),
                )
                auth_row = cursor.fetchone()
                if auth_row:
                    session["username"] = auth_row["username"]
                    session["password"] = auth_row["password"]
                    session["login_success"] = bool(auth_row["success"])
                    session["authentication_success"] = bool(auth_row["success"])
                else:
                    session["username"] = None
                    session["password"] = None
                    session["login_success"] = False
                    session["authentication_success"] = False

                # Get commands
                cursor.execute(
                    """
                    SELECT timestamp, input, success
                    FROM input
                    WHERE session = ?
                    ORDER BY timestamp
                    """,
                    (session_id,),
                )
                for cmd_row in cursor.fetchall():
                    session["commands"].append(
                        {
                            "timestamp": cmd_row["timestamp"],
                            "input": cmd_row["input"],
                            "command": cmd_row["input"],  # Add for compatibility
                            "success": bool(cmd_row["success"]),
                        }
                    )

                # Get downloads with metadata
                cursor.execute(
                    """
                    SELECT d.timestamp, d.url, d.outfile, d.shasum,
                           m.file_size, m.file_type, m.file_category, m.is_previewable
                    FROM downloads d
                    LEFT JOIN download_meta m ON d.shasum = m.shasum
                    WHERE d.session = ?
                    ORDER BY d.timestamp
                    """,
                    (session_id,),
                )
                for dl_row in cursor.fetchall():
                    download = {
                        "timestamp": dl_row["timestamp"],
                        "url": dl_row["url"],
                        "outfile": dl_row["outfile"],
                        "shasum": dl_row["shasum"],
                        "file_size": dl_row["file_size"],
                        "file_type": dl_row["file_type"],
                        "file_category": dl_row["file_category"] or "unknown",
                        "is_previewable": bool(dl_row["is_previewable"]),
                    }
                    session["downloads"].append(download)

                # Get first and last activity timestamps across all event tables
                cursor.execute(
                    """
                    SELECT MIN(timestamp) as first_ts, MAX(timestamp) as last_ts
                    FROM (
                        SELECT timestamp FROM auth WHERE session = ?
                        UNION ALL
                        SELECT timestamp FROM input WHERE session = ?
                        UNION ALL
                        SELECT timestamp FROM downloads WHERE session = ?
                    )
                    """,
                    (session_id, session_id, session_id),
                )
                ts_row = cursor.fetchone()
                session["first_timestamp"] = ts_row["first_ts"] if ts_row else None
                session["last_timestamp"] = ts_row["last_ts"] if ts_row else None

                # Calculate duration
                if session["start_time"] and session["end_time"]:
                    try:
                        start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
                        end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
                        session["duration"] = int((end - start).total_seconds())
                    except (ValueError, AttributeError):
                        session["duration"] = 0
                else:
                    session["duration"] = 0

                # Add counts
                session["commands_count"] = len(session["commands"])
                session["downloads_count"] = len(session["downloads"])

                sessions.append(session)

            return sessions

        finally:
            conn.close()

    def get_session(self, session_id: str) -> dict:
        """Get a single session by ID"""
        self.get_sessions(limit=1, offset=0)
        # Filter to the specific session by querying with modified WHERE clause
        if not self.available:
            return None

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Query the specific session
            cursor.execute(
                """
                SELECT
                    s.id as session_id,
                    s.ip as src_ip,
                    s.starttime as start_time,
                    s.endtime as end_time,
                    c.version as client_version
                FROM sessions s
                LEFT JOIN clients c ON s.client = c.id
                WHERE s.id = ?
                """,
                (session_id,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            # Build session dict (reuse logic from get_sessions)
            session = {
                "session_id": row["session_id"],
                "id": row["session_id"],
                "src_ip": row["src_ip"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "client_version": row["client_version"],
                "commands": [],
                "downloads": [],
                "events": self._get_session_events(row["session_id"]),
            }

            # Get ALL TTY logs for this session
            cursor.execute("SELECT id, ttylog, size FROM ttylog WHERE session = ? ORDER BY id", (session_id,))
            tty_rows = cursor.fetchall()
            if tty_rows:
                # Set tty_logs (plural) as list of dicts with ttylog and timestamp
                # merge_tty_logs() expects: [{"ttylog": "...", "timestamp": "..."}, ...]
                session["tty_logs"] = [
                    {"ttylog": row["ttylog"], "timestamp": str(row["id"])} for row in tty_rows if row["size"] > 0
                ]
                # Also set tty_log (singular) for backwards compatibility
                session["tty_log"] = tty_rows[0]["ttylog"] if tty_rows else None
                session["has_tty"] = len(session["tty_logs"]) > 0
            else:
                session["tty_log"] = None
                session["tty_logs"] = []
                session["has_tty"] = False

            # Get authentication data
            cursor.execute(
                """
                SELECT username, password, success
                FROM auth
                WHERE session = ?
                ORDER BY timestamp
                LIMIT 1
                """,
                (session_id,),
            )
            auth_row = cursor.fetchone()
            if auth_row:
                session["username"] = auth_row["username"]
                session["password"] = auth_row["password"]
                session["login_success"] = bool(auth_row["success"])
                session["authentication_success"] = bool(auth_row["success"])
            else:
                session["username"] = None
                session["password"] = None
                session["login_success"] = False
                session["authentication_success"] = False

            # Get commands
            cursor.execute(
                """
                SELECT timestamp, input, success
                FROM input
                WHERE session = ?
                ORDER BY timestamp
                """,
                (session_id,),
            )
            for cmd_row in cursor.fetchall():
                session["commands"].append(
                    {
                        "timestamp": cmd_row["timestamp"],
                        "input": cmd_row["input"],
                        "command": cmd_row["input"],
                        "success": bool(cmd_row["success"]),
                    }
                )

            # Get downloads with metadata
            cursor.execute(
                """
                SELECT d.timestamp, d.url, d.outfile, d.shasum,
                       m.file_size, m.file_type, m.file_category, m.is_previewable
                FROM downloads d
                LEFT JOIN download_meta m ON d.shasum = m.shasum
                WHERE d.session = ?
                ORDER BY d.timestamp
                """,
                (session_id,),
            )
            for dl_row in cursor.fetchall():
                download = {
                    "timestamp": dl_row["timestamp"],
                    "url": dl_row["url"],
                    "outfile": dl_row["outfile"],
                    "shasum": dl_row["shasum"],
                    "file_size": dl_row["file_size"],
                    "file_type": dl_row["file_type"],
                    "file_category": dl_row["file_category"] or "unknown",
                    "is_previewable": bool(dl_row["is_previewable"]),
                }
                session["downloads"].append(download)

            # Get first and last activity timestamps across all event tables
            cursor.execute(
                """
                SELECT MIN(timestamp) as first_ts, MAX(timestamp) as last_ts
                FROM (
                    SELECT timestamp FROM auth WHERE session = ?
                    UNION ALL
                    SELECT timestamp FROM input WHERE session = ?
                    UNION ALL
                    SELECT timestamp FROM downloads WHERE session = ?
                )
                """,
                (session_id, session_id, session_id),
            )
            ts_row = cursor.fetchone()
            session["first_timestamp"] = ts_row["first_ts"] if ts_row else None
            session["last_timestamp"] = ts_row["last_ts"] if ts_row else None

            # Calculate duration
            if session["start_time"] and session["end_time"]:
                try:
                    start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
                    session["duration"] = int((end - start).total_seconds())
                except (ValueError, AttributeError):
                    session["duration"] = 0
            else:
                session["duration"] = 0

            # Add counts
            session["commands_count"] = len(session["commands"])
            session["downloads_count"] = len(session["downloads"])

            return session

        finally:
            conn.close()

    def get_vt_results(self, sha256: str) -> dict:
        """
        Get VirusTotal scan results from the database for a specific SHA256.

        Args:
            sha256: SHA256 hash of the file

        Returns:
            Dict with VT results: {"detections": int, "total": int, "threat_label": str, "scan_date": int, "is_new": bool}
            Returns empty dict if no results found
        """
        if not self.available:
            return {}

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Try the new virustotal_scans table first
            cursor.execute(
                """
                SELECT positives, total, scan_date, threat_label, is_new
                FROM virustotal_scans
                WHERE shasum = ?
                """,
                (sha256,),
            )

            row = cursor.fetchone()
            if row:
                return {
                    "detections": row["positives"] or 0,
                    "total": row["total"] or 0,
                    "threat_label": row["threat_label"] or "",
                    "scan_date": row["scan_date"] or 0,
                    "is_new": bool(row["is_new"]) if row["is_new"] is not None else False,
                }

            # Fallback to events table for legacy data
            cursor.execute(
                """
                SELECT json_extract(data, '$.positives') as positives,
                       json_extract(data, '$.total') as total,
                       json_extract(data, '$.scan_date') as scan_date,
                       json_extract(data, '$.threat_label') as threat_label,
                       json_extract(data, '$.is_new') as is_new
                FROM events
                WHERE eventid = 'cowrie.virustotal.scanfile'
                AND json_extract(data, '$.sha256') = ?
                ORDER BY timestamp DESC LIMIT 1
                """,
                (sha256,),
            )

            row = cursor.fetchone()
            if row:
                positives = row["positives"] or 0
                total = row["total"] or 0
                scan_date = row["scan_date"] or 0
                threat_label = row["threat_label"] or ""
                is_new = row["is_new"] == "true" if row["is_new"] else False

                return {
                    "detections": positives,
                    "total": total,
                    "threat_label": threat_label,
                    "scan_date": scan_date,
                    "is_new": is_new,
                }

            return {}

        finally:
            conn.close()


# Global instance
sqlite_parser = SQLiteStatsParser()
