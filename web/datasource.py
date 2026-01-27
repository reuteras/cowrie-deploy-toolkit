#!/usr/bin/env python3
"""
Data Source Abstraction Layer for Cowrie Dashboard

Provides a unified interface for accessing Cowrie data in two modes:
- Local mode: Direct file access (single-host deployment)
- Remote mode: API calls via HTTP (multi-host deployment)
"""

import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class DataSource:
    """Abstract data source that supports both local and remote modes."""

    def __init__(self, mode: str = "local", api_base_url: str = None):
        """
        Initialize data source.

        Args:
            mode: "local" for direct file access, "remote" for API calls
            api_base_url: Base URL for API (required for remote mode)
        """
        self.mode = mode
        self.api_base_url = api_base_url
        self.session = None

        if self.mode == "remote" and not self.api_base_url:
            raise ValueError("api_base_url is required for remote mode")

        # Normalize API URL (remove trailing slash)
        if self.api_base_url:
            self.api_base_url = self.api_base_url.rstrip("/")

        # Create persistent session for remote mode (connection pooling)
        if self.mode == "remote":
            self.session = requests.Session()
            # Configure connection pooling limits
            # IMPORTANT: pool_block=True to prevent file descriptor exhaustion
            # When pool is full, wait for available connection instead of creating new ones
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=2,  # Max number of connection pools (one per host)
                pool_maxsize=5,  # Max connections per pool
                max_retries=0,  # Disable retries - let caching and backoff handle failures
                pool_block=True,  # CRITICAL: Block instead of creating new connections
            )
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

        print(
            f"[DataSource] Initialized in {self.mode} mode"
            + (f" with API: {self.api_base_url}" if self.mode == "remote" else "")
        )

    def get_sessions(
        self,
        hours: int = 168,
        limit: int = 100,
        offset: int = 0,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        has_commands: Optional[bool] = None,
        has_tty: Optional[bool] = None,
        login_success: Optional[bool] = None,
    ) -> dict:
        """
        Get sessions with optional filtering and pagination.

        Args:
            hours: Time range in hours
            limit: Maximum number of sessions to return
            offset: Offset for pagination
            src_ip: Filter by source IP
            username: Filter by username
            start_time: Filter by start time (ISO format)
            end_time: Filter by end time (ISO format)
            has_commands: Filter for sessions with commands
            has_tty: Filter for sessions with TTY recordings
            login_success: Filter for successful logins

        Returns:
            Dict with "total" and "sessions" keys
        """
        if self.mode == "local":
            return self._get_sessions_local(
                hours, limit, offset, src_ip, username, start_time, end_time, has_commands, has_tty, login_success
            )
        else:
            return self._get_sessions_remote(
                hours, limit, offset, src_ip, username, start_time, end_time, has_commands, has_tty, login_success
            )

    def _get_sessions_local(
        self,
        hours,
        limit,
        offset,
        src_ip,
        username,
        start_time,
        end_time,
        has_commands=None,
        has_tty=None,
        login_success=None,
    ) -> dict:
        """Get sessions from local files (uses existing SessionParser)."""
        from app import session_parser

        # For local mode, we need to parse_all to get the full dataset
        # This is unavoidable since we're parsing JSON files
        all_sessions = session_parser.parse_all(hours=hours)
        sessions_list = list(all_sessions.values())

        # Apply filters
        if src_ip:
            sessions_list = [s for s in sessions_list if s.get("src_ip") == src_ip]
        if username:
            sessions_list = [s for s in sessions_list if s.get("username") == username]
        if has_commands is True:
            sessions_list = [s for s in sessions_list if len(s.get("commands", [])) > 0]
        elif has_commands is False:
            sessions_list = [s for s in sessions_list if len(s.get("commands", [])) == 0]
        if has_tty is True:
            sessions_list = [s for s in sessions_list if s.get("tty_log")]
        elif has_tty is False:
            sessions_list = [s for s in sessions_list if not s.get("tty_log")]
        if login_success is True:
            sessions_list = [s for s in sessions_list if s.get("login_success")]
        elif login_success is False:
            sessions_list = [s for s in sessions_list if not s.get("login_success")]

        # Sort by start time (most recent first)
        sessions_list = sorted(sessions_list, key=lambda x: x.get("start_time") or "", reverse=True)

        # Paginate
        total = len(sessions_list)
        paginated = sessions_list[offset : offset + limit]

        return {"total": total, "sessions": paginated}

    def _get_sessions_remote(
        self,
        hours,
        limit,
        offset,
        src_ip,
        username,
        start_time,
        end_time,
        has_commands=None,
        has_tty=None,
        login_success=None,
    ) -> dict:
        """Get sessions from remote API with pagination."""
        from datetime import datetime, timedelta, timezone

        # Convert hours to start_time/end_time if not already provided
        if not start_time and not end_time:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(hours=hours)
            # Remove timezone suffix to avoid URL encoding issues with '+'
            # All times are UTC, so timezone info is redundant
            start_time = start_dt.isoformat().replace("+00:00", "")
            end_time = end_dt.isoformat().replace("+00:00", "")

        params = {
            "limit": limit,
            "offset": offset,
        }
        if src_ip:
            params["src_ip"] = src_ip
        if username:
            params["username"] = username
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        # Server-side filters
        if has_commands is not None:
            params["has_commands"] = str(has_commands).lower()
        if has_tty is not None:
            params["has_tty"] = str(has_tty).lower()
        if login_success is not None:
            params["login_success"] = str(login_success).lower()

        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/sessions",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Error fetching sessions from API: {e}")
            return {"total": 0, "sessions": []}

    def get_all_sessions(self, hours: int = 168, src_ip: Optional[str] = None, username: Optional[str] = None) -> list:
        """
        Get ALL sessions for a time period using pagination.

        Fetches sessions iteratively until all are retrieved.
        No hardcoded limits - keeps fetching until no more results.

        Args:
            hours: Time range in hours
            src_ip: Filter by source IP (optional)
            username: Filter by username (optional)

        Returns:
            List of all sessions (not paginated)
        """
        all_sessions = []
        offset = 0
        page_size = 1000  # Fetch in chunks of 1000

        print(f"[DataSource] Fetching all sessions for {hours} hours using pagination (page_size={page_size})")

        while True:
            result = self.get_sessions(hours=hours, limit=page_size, offset=offset, src_ip=src_ip, username=username)

            sessions = result.get("sessions", [])
            all_sessions.extend(sessions)

            print(f"[DataSource] Fetched {len(sessions)} sessions (offset={offset}, total so far={len(all_sessions)})")

            # If we got fewer results than the page size, we've reached the end
            if len(sessions) < page_size:
                break

            offset += page_size

        print(f"[DataSource] Finished fetching: {len(all_sessions)} total sessions")
        return all_sessions

    def get_session(self, session_id: str) -> Optional[dict]:
        """
        Get a specific session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session dict or None if not found
        """
        if self.mode == "local":
            return self._get_session_local(session_id)
        else:
            return self._get_session_remote(session_id)

    def _get_session_local(self, session_id: str) -> Optional[dict]:
        """Get session from local files."""
        from app import session_parser

        return session_parser.get_session(session_id)

    def _get_session_remote(self, session_id: str) -> Optional[dict]:
        """Get session from remote API."""
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/sessions/{session_id}",
                timeout=10,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Error fetching session {session_id} from API: {e}")
            return None

    def get_session_tty(self, session_id: str) -> Optional[dict]:
        """
        Get TTY recording for a session (asciicast format).

        Args:
            session_id: Session ID

        Returns:
            Asciicast dict or None
        """
        if self.mode == "local":
            return self._get_session_tty_local(session_id)
        else:
            return self._get_session_tty_remote(session_id)

    def _get_session_tty_local(self, session_id: str) -> Optional[dict]:
        """Get TTY recording from local files."""
        from app import CONFIG, session_parser, tty_parser

        session = session_parser.get_session(session_id)
        if not session:
            return None

        # Use merged TTY logs if available, otherwise fall back to single file
        hostname = CONFIG.get("honeypot_hostname", "dmz-web01")
        if session.get("tty_logs") and len(session["tty_logs"]) > 0:
            return tty_parser.merge_tty_logs(session, hostname=hostname)
        elif session.get("tty_log"):
            return tty_parser.parse_tty_log(session["tty_log"])

        return None

    def _get_session_tty_remote(self, session_id: str) -> Optional[dict]:
        """Get TTY recording from remote API."""
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/sessions/{session_id}/tty",
                timeout=30,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Error fetching TTY for session {session_id} from API: {e}")
            return None

    def get_stats(self, hours: int = 24) -> dict:
        """
        Get dashboard statistics.

        Args:
            hours: Time range in hours

        Returns:
            Stats dict with various metrics
        """
        if self.mode == "local":
            return self._get_stats_local(hours)
        else:
            return self._get_stats_remote(hours)

    def _get_stats_local(self, hours: int) -> dict:
        """Get stats from local files."""
        from app import session_parser

        return session_parser.get_stats(hours=hours)

    def _get_stats_remote(self, hours: int) -> dict:
        """Get stats from remote API."""
        # Send hours parameter directly to API
        try:
            logger.info(f"[DataSource] Calling API: {self.api_base_url}/api/v1/stats/overview?hours={hours}")
            response = self.session.get(
                f"{self.api_base_url}/api/v1/stats/overview",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            api_data = response.json()
            logger.info(
                f"[DataSource] API Response: {response.status_code}, sessions: {api_data.get('total_sessions', 0)}, downloads: {len(api_data.get('top_downloads_with_vt', []))}"
            )

            # Normalize API response to match dashboard format
            # The API now includes GeoIP enrichment and additional data
            # NOTE: API returns stats in nested structure: {"stats": {"totals": {...}}}
            stats_data = api_data.get("stats", {})
            totals = stats_data.get("totals", {})

            # Convert top_ips to ip_list format (now enriched with geo, ASN, and login data by API)
            ip_list = []
            for ip_data in api_data.get("top_ips", []):
                ip_list.append(
                    {
                        "ip": ip_data.get("ip", ""),
                        "count": ip_data.get("count", 0),
                        "geo": ip_data.get("geo", {}),
                        "asn": ip_data.get("asn"),
                        "asn_org": ip_data.get("asn_org"),
                        "successful_logins": ip_data.get("successful_logins", 0),
                        "failed_logins": ip_data.get("failed_logins", 0),
                        "last_seen": ip_data.get("last_seen"),
                    }
                )

            return {
                "total_sessions": totals.get("total_sessions", 0),
                "unique_ips": totals.get("unique_ips", 0),
                "sessions_with_commands": totals.get("sessions_with_commands", 0),
                "total_downloads": totals.get("downloads", 0),
                "unique_downloads": totals.get("unique_downloads", 0),
                "unique_download_hashes": totals.get("unique_download_hashes", []),  # NEW: for proper deduplication
                "ip_list": ip_list,
                "ip_locations": api_data.get("ip_locations", []),  # Now enriched by API
                "top_countries": api_data.get("top_countries", []),  # Now enriched by API
                "top_credentials": api_data.get("top_credentials", []),
                "successful_credentials": [],  # Not tracked in SQLite stats
                "top_commands": api_data.get("top_commands", []),
                "top_clients": api_data.get("top_clients", []),  # Now enriched by API
                "top_asns": api_data.get("top_asns", []),  # Now enriched by API
                "hourly_activity": [],  # Not calculated in SQLite stats
                "vt_stats": {
                    "total_scanned": 0,
                    "total_malicious": 0,
                    "avg_detection_rate": 0.0,
                    "total_threat_families": 0,
                },
            }
        except requests.RequestException as e:
            print(f"[!] Error fetching stats from API: {e}")
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

    def get_dashboard_overview(
        self, hours: int = 24, source_filter: Optional[str] = None, force_refresh: bool = False
    ) -> dict:
        """
        Get complete dashboard data in one request.

        Args:
            hours: Number of hours to include in statistics
            source_filter: Not used for single-source mode (for API compatibility)
            force_refresh: Force cache refresh

        Returns:
            Complete dashboard data dict
        """
        # source_filter ignored for single-source datasources
        if self.mode == "local":
            return self._get_dashboard_overview_local(hours, force_refresh)
        else:
            return self._get_dashboard_overview_remote(hours, force_refresh)

    def _get_dashboard_overview_local(self, hours: int, force_refresh: bool) -> dict:
        """Get dashboard overview from local SQLite database."""
        # For local mode, we'd need to implement the aggregation logic here
        # For now, return empty - local mode should use the old method
        return {}

    def _get_dashboard_overview_remote(self, hours: int, force_refresh: bool) -> dict:
        """Get dashboard overview from remote API."""
        params = f"hours={hours}"
        if force_refresh:
            params += "&force_refresh=true"

        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/dashboard/overview?{params}",
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch dashboard overview: {e}") from e

    def get_all_asns(self, hours: int = 168) -> dict:
        """
        Get ALL ASNs with session counts from API.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'asns' list and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/asns",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch ASNs from API: {e}")
            return {"asns": [], "total": 0}

    def get_all_ips(self, hours: int = 168) -> dict:
        """
        Get ALL IPs with session counts and GeoIP data from API.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'ips' list and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/ips",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch IPs from API: {e}")
            return {"ips": [], "total": 0}

    def get_all_countries(self, hours: int = 168) -> dict:
        """
        Get ALL countries with session counts from API.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'countries' list and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/countries",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch countries from API: {e}")
            return {"countries": [], "total": 0}

    def get_all_credentials(self, hours: int = 168) -> dict:
        """
        Get ALL credentials with attempt counts from API.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'credentials' list, 'successful' list, and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/credentials",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch credentials from API: {e}")
            return {"credentials": [], "successful": [], "total": 0}

    def get_all_clients(self, hours: int = 168) -> dict:
        """
        Get ALL SSH client versions with session counts from API.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'clients' list and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/clients",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch clients from API: {e}")
            return {"clients": [], "total": 0}

    def get_all_commands(self, hours: int = 168, unique_only: bool = False) -> dict:
        """
        Get ALL commands with counts and metadata from API.

        Args:
            hours: Time range in hours
            unique_only: If True, return unique commands with counts

        Returns:
            Dict with 'commands' list and 'total' count
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/commands",
                params={"hours": hours, "unique": unique_only},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch commands from API: {e}")
            return {"commands": [], "total": 0}

    def get_attack_map_data(self, hours: int = 24) -> dict:
        """
        Get aggregated attack data for the map visualization.

        Args:
            hours: Time range in hours

        Returns:
            Dict with 'attacks' list, 'total_sessions', and 'unique_ips'
        """
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/attack-map",
                params={"hours": hours},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DataSource] Failed to fetch attack map data from API: {e}")
            return {"attacks": [], "total_sessions": 0, "unique_ips": 0}

    def get_downloads(
        self,
        hours: int = 168,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """
        Get downloaded files with metadata.

        Args:
            hours: Time range in hours
            limit: Maximum number of downloads to return
            offset: Offset for pagination

        Returns:
            Dict with "total" and "downloads" keys
        """
        if self.mode == "local":
            return self._get_downloads_local(hours, limit, offset)
        else:
            return self._get_downloads_remote(hours, limit, offset)

    def _get_downloads_local(self, hours, limit, offset) -> dict:
        """Get downloads from local files."""
        from app import CONFIG, session_parser, vt_scanner, yara_cache

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

        # Check which files exist and get metadata
        download_path = CONFIG["download_path"]
        for shasum, dl in unique_downloads.items():
            file_path = os.path.join(download_path, shasum)
            dl["exists"] = os.path.exists(file_path)
            if dl["exists"]:
                dl["size"] = os.path.getsize(file_path)
            else:
                dl["size"] = 0

            # Get YARA matches
            yara_result = yara_cache.get_result(shasum)
            if yara_result:
                dl["yara_matches"] = yara_result.get("matches", [])
                dl["file_type"] = yara_result.get("file_type")
                dl["file_category"] = yara_result.get("file_category")
                dl["is_previewable"] = yara_result.get("is_previewable", False)

            # Get VirusTotal data
            if vt_scanner and shasum:
                vt_result = vt_scanner.scan_file(shasum)
                if vt_result:
                    dl["vt_detections"] = vt_result["detections"]
                    dl["vt_total"] = vt_result["total_engines"]
                    dl["vt_link"] = vt_result["link"]
                    dl["vt_threat_label"] = vt_result.get("threat_label", "")

        downloads_list = sorted(unique_downloads.values(), key=lambda x: x["timestamp"], reverse=True)

        # Paginate
        total = len(downloads_list)
        paginated = downloads_list[offset : offset + limit]

        return {"total": total, "downloads": paginated}

    def _get_downloads_remote(self, hours, limit, offset) -> dict:
        """Get downloads from remote API."""
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/downloads",
                params={"hours": hours, "limit": limit, "offset": offset},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Error fetching downloads from API: {e}")
            return {"total": 0, "downloads": []}

    def get_download_file(self, sha256: str) -> Optional[bytes]:
        """
        Get raw download file content.

        Args:
            sha256: SHA256 hash of file

        Returns:
            File content as bytes or None
        """
        if self.mode == "local":
            return self._get_download_file_local(sha256)
        else:
            return self._get_download_file_remote(sha256)

    def _get_download_file_local(self, sha256: str) -> Optional[bytes]:
        """Get download file from local storage."""
        from app import CONFIG

        download_path = CONFIG["download_path"]
        file_path = os.path.join(download_path, sha256)

        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception as e:
            print(f"[!] Error reading download file {sha256}: {e}")
            return None

    def _get_download_file_remote(self, sha256: str) -> Optional[bytes]:
        """Get download file from remote API."""
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/downloads/{sha256}/file",
                timeout=30,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.content
        except requests.RequestException as e:
            print(f"[!] Error fetching download file {sha256} from API: {e}")
            return None

    def get_threat_intel(self, ip_address: str) -> dict:
        """
        Get threat intelligence for an IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            Threat intelligence dict with GeoIP and other sources.
        """
        if self.mode == "local":
            return self._get_threat_intel_local(ip_address)
        else:
            return self._get_threat_intel_remote(ip_address)

    def _get_threat_intel_local(self, ip_address: str) -> dict:
        """Get threat intel from local sources."""
        from app import global_geoip

        result = {
            "ip": ip_address,
            "geo": global_geoip.lookup(ip_address),
        }

        # Future threat intelligence sources can be added here

        return result

    def _get_threat_intel_remote(self, ip_address: str) -> dict:
        """Get threat intel from remote API."""
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/v1/threat/ip/{ip_address}",
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Error fetching threat intel for {ip_address} from API: {e}")
            return {
                "ip": ip_address,
                "geo": {"country": "-", "country_code": "XX", "city": "-"},
            }

    def get_health(self) -> dict:
        """
        Get data source health status.

        Returns:
            Health status dict
        """
        if self.mode == "local":
            return {"status": "healthy", "mode": "local"}
        else:
            try:
                response = self.session.get(
                    f"{self.api_base_url}/api/v1/health",
                    timeout=5,
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as e:
                return {
                    "status": "unhealthy",
                    "mode": "remote",
                    "error": str(e),
                }

    def close(self):
        """Close HTTP session and clean up resources."""
        if self.session:
            self.session.close()
            self.session = None

    def __del__(self):
        """Destructor to ensure session is closed."""
        self.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self.close()
        return False
