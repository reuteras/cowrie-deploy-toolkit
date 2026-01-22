#!/usr/bin/env python3
"""
Multi-Source Data Aggregation for Cowrie Dashboard

Enables dashboard to aggregate data from multiple honeypots of different types.
Supports parallel querying with graceful degradation on partial failures.
Includes caching and rate limiting to prevent resource exhaustion.
"""

import concurrent.futures
import os
from datetime import datetime
from typing import Optional

from cache import ExponentialBackoff, ResponseCache
from datasource import DataSource

# Configuration from environment variables
CACHE_TTL_STATS = int(os.getenv("MULTISOURCE_CACHE_TTL_STATS", "300"))  # 5 minutes for stats
CACHE_TTL_SESSIONS = int(os.getenv("MULTISOURCE_CACHE_TTL_SESSIONS", "180"))  # 3 minutes for sessions
MAX_WORKERS = int(os.getenv("MULTISOURCE_MAX_WORKERS", "2"))  # Reduced from 5 to 2
BACKOFF_BASE_DELAY = float(os.getenv("MULTISOURCE_BACKOFF_BASE_DELAY", "2.0"))  # 2 seconds
BACKOFF_MAX_DELAY = float(os.getenv("MULTISOURCE_BACKOFF_MAX_DELAY", "60.0"))  # 60 seconds
BACKOFF_MAX_FAILURES = int(os.getenv("MULTISOURCE_BACKOFF_MAX_FAILURES", "3"))  # 3 consecutive failures


class HoneypotSource:
    """Configuration for a single honeypot data source."""

    def __init__(
        self,
        name: str,
        source_type: str,
        mode: str = "remote",
        api_base_url: Optional[str] = None,
        location: Optional[str] = None,
        enabled: bool = True,
    ):
        """
        Initialize honeypot source configuration.

        Args:
            name: Unique identifier for this source (e.g., "honeypot-ssh-1")
            source_type: Type of honeypot (e.g., "cowrie-ssh", "web", "vpn")
            mode: Access mode - "local" for direct file access, "remote" for API
            api_base_url: API base URL for this honeypot (required if mode="remote")
            location: Hetzner datacenter location code (e.g., "hel1", "fsn1", "nbg1")
            enabled: Whether this source is active
        """
        self.name = name
        self.type = source_type
        self.mode = mode
        self.api_base_url = api_base_url
        self.location = location
        self.enabled = enabled
        self.datasource = None

        if self.enabled:
            try:
                # IMPORTANT: "local" mode now means "use local API" not "parse files directly"
                # This ensures we always benefit from fast SQLite queries via the API
                if mode == "local":
                    # Local source uses the local API endpoint
                    actual_api_url = "http://cowrie-api:8000"
                    actual_mode = "remote"  # Always use API-based access
                    print(
                        f"[MultiSource] Initialized source '{name}' ({source_type}) using local API at {actual_api_url}"
                    )
                elif mode == "remote":
                    if not api_base_url:
                        raise ValueError(f"API base URL required for remote mode (source: {name})")
                    actual_api_url = api_base_url
                    actual_mode = "remote"
                    print(f"[MultiSource] Initialized source '{name}' ({source_type}) at {api_base_url}")
                else:
                    raise ValueError(f"Unknown mode '{mode}' for source '{name}'")

                # Create DataSource instance for this honeypot
                self.datasource = DataSource(mode=actual_mode, api_base_url=actual_api_url)

            except Exception as e:
                print(f"[MultiSource] Failed to initialize source '{name}': {e}")
                self.enabled = False

    def is_available(self) -> bool:
        """Check if this source is enabled and has a valid datasource."""
        return self.enabled and self.datasource is not None


class MultiSourceDataSource:
    """Aggregate data from multiple honeypot sources with caching and rate limiting."""

    def __init__(self, sources: list[HoneypotSource]):
        """
        Initialize multi-source data aggregator.

        Args:
            sources: List of HoneypotSource configurations
        """
        self.sources = {s.name: s for s in sources if s.is_available()}
        self.active_source_count = len(self.sources)

        # Initialize caching and backoff
        self.stats_cache = ResponseCache(default_ttl=CACHE_TTL_STATS)
        self.sessions_cache = ResponseCache(default_ttl=CACHE_TTL_SESSIONS)
        self.backoff = ExponentialBackoff(
            base_delay=BACKOFF_BASE_DELAY, max_delay=BACKOFF_MAX_DELAY, max_failures=BACKOFF_MAX_FAILURES
        )

        print(f"[MultiSource] Initialized with {self.active_source_count} active sources:")
        for name, source in self.sources.items():
            print(f"[MultiSource]   - {name} ({source.type}): {source.api_base_url}")
        print(
            f"[MultiSource] Caching enabled: stats={CACHE_TTL_STATS}s, sessions={CACHE_TTL_SESSIONS}s, workers={MAX_WORKERS}"
        )

    def _tag_data(self, data: dict, source_name: str, source_type: str) -> dict:
        """
        Add source metadata to data objects.

        Args:
            data: Data dict to tag
            source_name: Source identifier
            source_type: Honeypot type

        Returns:
            Tagged data dict
        """
        if isinstance(data, dict):
            data["_source"] = source_name
            data["_source_type"] = source_type
        return data

    def _tag_list(self, items: list, source_name: str, source_type: str) -> list:
        """Tag each item in a list with source metadata."""
        return [self._tag_data(item, source_name, source_type) for item in items]

    def get_sessions(
        self,
        hours: int = 168,
        limit: int = 100,
        offset: int = 0,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        source_filter: Optional[str] = None,
        skip_global_limit: bool = False,
    ) -> dict:
        """
        Get sessions from all sources (or filtered sources) with caching.

        Args:
            hours: Time range in hours
            limit: Maximum sessions per source
            offset: Offset for pagination
            src_ip: Filter by source IP
            username: Filter by username
            start_time: Filter by start time
            end_time: Filter by end time
            source_filter: Filter by specific source name (None = all sources)

        Returns:
            Aggregated sessions dict with source tags
        """
        # Check cache first
        cache_key = f"sessions_{hours}_{limit}_{offset}_{src_ip}_{username}_{source_filter or 'all'}"
        cached = self.sessions_cache.get(cache_key)
        if cached is not None:
            print(f"[MultiSource] Cache hit for sessions (hours={hours}, limit={limit}, filter={source_filter})")
            return cached

        print(f"[MultiSource] get_sessions called: hours={hours}, limit={limit}, source_filter='{source_filter}'")

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            print(f"[MultiSource] Filtering to single source: {source_filter}")
            sources_to_query = {source_filter: self.sources[source_filter]}
        else:
            print(f"[MultiSource] Querying all sources: {list(self.sources.keys())}")

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }
        print(f"[MultiSource] Available sources after backoff filter: {list(available_sources.keys())}")

        if len(available_sources) < len(sources_to_query):
            skipped = set(sources_to_query.keys()) - set(available_sources.keys())
            print(f"[MultiSource] Skipping sources in backoff: {skipped}")

        all_sessions = []
        total_count = 0
        source_errors = {}

        if not available_sources:
            print("[MultiSource] No sources available (all in backoff)")
            result = {"total": 0, "sessions": [], "sources_queried": [], "source_errors": {}}
            self.sessions_cache.set(cache_key, result, ttl=5)
            return result

        # Query sources in parallel with reduced concurrency
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(
                    source.datasource.get_sessions,
                    hours=hours,
                    limit=limit,
                    offset=offset,
                    src_ip=src_ip,
                    username=username,
                    start_time=start_time,
                    end_time=end_time,
                ): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)  # Reset backoff on success
                    # Tag sessions with source info
                    tagged_sessions = self._tag_list(result.get("sessions", []), source.name, source.type)
                    session_count = len(tagged_sessions)
                    print(f"[MultiSource] Fetched {session_count} sessions from '{source.name}'")
                    all_sessions.extend(tagged_sessions)
                    total_count += result.get("total", 0)
                except Exception as e:
                    print(f"[MultiSource] Error fetching sessions from '{source.name}': {e}")
                    import traceback

                    traceback.print_exc()
                    source_errors[source.name] = str(e)
                    self.backoff.record_failure(source.name)  # Record failure for backoff

        # Sort combined sessions by start_time (most recent first)
        all_sessions.sort(key=lambda x: x.get("start_time") or "", reverse=True)

        # Apply global limit (skip if requested, e.g., for parse_all)
        if not skip_global_limit and len(all_sessions) > limit:
            print(f"[MultiSource] Truncating {len(all_sessions)} sessions to global limit of {limit}")
            all_sessions = all_sessions[:limit]
        elif skip_global_limit:
            print(f"[MultiSource] Skipping global limit, returning all {len(all_sessions)} sessions")

        result = {
            "total": total_count,
            "sessions": all_sessions,
            "sources_queried": list(sources_to_query.keys()),
            "source_errors": source_errors,
        }

        # Cache the result
        self.sessions_cache.set(cache_key, result)

        return result

    def get_all_sessions_from_source(self, source, hours: int, max_sessions: Optional[int] = None) -> list:
        """
        Get ALL sessions from a single source using pagination.

        Args:
            source: HoneypotSource instance
            hours: Time range in hours
            max_sessions: Maximum number of sessions to fetch (None = unlimited)

        Returns:
            List of all sessions from this source (up to max_sessions)
        """
        all_sessions = []
        offset = 0
        page_size = 1000

        limit_str = f"max={max_sessions}" if max_sessions else "unlimited"
        print(f"[MultiSource] Fetching sessions from '{source.name}' (hours={hours}, {limit_str})")

        while True:
            try:
                result = source.datasource.get_sessions(hours=hours, limit=page_size, offset=offset)

                sessions = result.get("sessions", [])

                # Tag sessions with source info
                for session in sessions:
                    session["_source"] = source.name
                    session["_source_type"] = source.type

                all_sessions.extend(sessions)
                print(
                    f"[MultiSource] '{source.name}': fetched {len(sessions)} sessions (offset={offset}, total={len(all_sessions)})"
                )

                # Check if we've reached the limit
                if max_sessions and len(all_sessions) >= max_sessions:
                    all_sessions = all_sessions[:max_sessions]  # Trim to exact limit
                    print(f"[MultiSource] '{source.name}': reached max_sessions limit ({max_sessions})")
                    break

                # If we got fewer results than page size, we're done
                if len(sessions) < page_size:
                    break

                offset += page_size

            except Exception as e:
                print(f"[MultiSource] Error fetching from '{source.name}' at offset {offset}: {e}")
                break

        print(f"[MultiSource] '{source.name}': finished with {len(all_sessions)} total sessions")
        return all_sessions

    def parse_all(
        self, hours: int = 168, source_filter: Optional[str] = None, max_sessions: Optional[int] = None
    ) -> dict:
        """
        Get all sessions as a dict keyed by session ID (compatibility method).

        Uses pagination to fetch sessions from the time period.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source name (None = all sources)
            max_sessions: Maximum number of sessions to fetch per source (None = unlimited)

        Returns:
            Dict of sessions keyed by session ID
        """
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        all_sessions_list = []

        # Fetch sessions from each source using pagination
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(self.get_all_sessions_from_source, source, hours, max_sessions): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    sessions = future.result(timeout=120)  # Longer timeout for pagination
                    self.backoff.record_success(source.name)
                    all_sessions_list.extend(sessions)
                except Exception as e:
                    print(f"[MultiSource] Error fetching all sessions from '{source.name}': {e}")
                    import traceback

                    traceback.print_exc()
                    self.backoff.record_failure(source.name)

        print(f"[MultiSource] parse_all: got {len(all_sessions_list)} total sessions from all sources")

        # Convert list to dict keyed by session ID
        sessions_dict = {}
        skipped = 0
        for session in all_sessions_list:
            # Handle both 'id' and 'session_id' field names
            session_id = session.get("id") or session.get("session_id")
            if session_id:
                # Normalize: ensure 'id' field exists for compatibility
                if "id" not in session and "session_id" in session:
                    session["id"] = session["session_id"]
                sessions_dict[session_id] = session
            else:
                skipped += 1

        if skipped > 0:
            print(f"[MultiSource] WARNING: Skipped {skipped} sessions without 'id' or 'session_id' field")

        # Enrich sessions with GeoIP data if missing
        # Import here to avoid circular imports
        from app import global_geoip

        enriched_count = 0
        for _session_id, session in sessions_dict.items():
            if not session.get("geo") and session.get("src_ip"):
                geo_data = global_geoip.lookup(session["src_ip"])
                if geo_data:
                    session["geo"] = geo_data
                    enriched_count += 1

        if enriched_count > 0:
            print(f"[MultiSource] Enriched {enriched_count} sessions with GeoIP data")

        print(f"[MultiSource] parse_all: returning {len(sessions_dict)} sessions")
        return sessions_dict

    def get_session(self, session_id: str, source_name: Optional[str] = None) -> Optional[dict]:
        """
        Get a specific session by ID.

        Args:
            session_id: Session ID
            source_name: Source to query (if known), otherwise tries all sources

        Returns:
            Session dict with source tag or None
        """
        # If source is known, query it directly
        if source_name and source_name in self.sources:
            source = self.sources[source_name]
            session = source.datasource.get_session(session_id)
            if session:
                return self._tag_data(session, source.name, source.type)
            return None

        # Otherwise, try all sources until we find it
        for source in self.sources.values():
            try:
                session = source.datasource.get_session(session_id)
                if session:
                    return self._tag_data(session, source.name, source.type)
            except Exception as e:
                print(f"[MultiSource] Error fetching session from '{source.name}': {e}")

        return None

    def get_stats(self, hours: int = 24, source_filter: Optional[str] = None, force_refresh: bool = False) -> dict:
        """
        Get aggregated statistics from all sources using pre-aggregated API endpoints.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Aggregated stats dict
        """
        # Check cache first
        cache_key = f"stats_v3_{hours}_{source_filter or 'all'}"
        cached = self.stats_cache.get(cache_key)
        if cached is not None:
            return cached

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        if len(available_sources) < len(sources_to_query):
            skipped = set(sources_to_query.keys()) - set(available_sources.keys())
            print(f"[MultiSource] Skipping sources in backoff: {skipped}")

        # Initialize result
        aggregated = {
            "total_sessions": 0,
            "unique_ips": 0,
            "sessions_with_commands": 0,
            "total_downloads": 0,
            "unique_downloads": 0,
            "ip_list": [],
            "top_countries": [],
            "top_credentials": [],
            "successful_credentials": [],
            "top_commands": [],
            "top_clients": [],
            "top_asns": [],
            "ip_locations": [],
            "hourly_activity": [],
            "vt_stats": {
                "total_scanned": 0,
                "total_malicious": 0,
                "avg_detection_rate": 0.0,
                "total_threat_families": 0,
            },
            "top_downloads_with_vt": [],
            "source_stats": {},
            "source_errors": {},
            "failed_sources": [],
        }

        # Set to collect all unique download hashes for cross-honeypot deduplication
        all_unique_hashes: set[str] = set()

        if not available_sources:
            print("[MultiSource] No sources available (all in backoff)")
            self.stats_cache.set(cache_key, aggregated, ttl=5)
            return aggregated

        # Query each source's aggregated dashboard endpoint
        for source_name, source in available_sources.items():
            try:
                # Call the new aggregated endpoint
                data = source.datasource.get_dashboard_overview(hours=hours, force_refresh=force_refresh)
                self.backoff.record_success(source.name)

                # Debug logging
                stats = data.get("stats", {})
                stats_totals = stats.get("totals", {})
                print(
                    f"[MultiSource] Source '{source_name}' returned: sessions={stats_totals.get('total_sessions', 0)}, downloads={len(data.get('top_downloads_with_vt', []))}"
                )

                # Merge the pre-aggregated data
                # Stats are nested inside "totals" from the API
                totals = data.get("stats", {}).get("totals", {})
                aggregated["total_sessions"] += totals.get("total_sessions", 0)
                aggregated["unique_ips"] += totals.get("unique_ips", 0)
                aggregated["sessions_with_commands"] += totals.get("sessions_with_commands", 0)
                downloads_count = totals.get("downloads", 0)
                unique_downloads_count = totals.get("unique_downloads", 0)
                aggregated["total_downloads"] += downloads_count
                # Note: unique_downloads will be recalculated after deduplication across all sources

                # Collect unique download hashes for cross-honeypot deduplication
                source_hashes = totals.get("unique_download_hashes", [])
                all_unique_hashes.update(source_hashes)

                print(
                    f"[MultiSource] Source '{source_name}' downloads: {downloads_count} total, {unique_downloads_count} unique, {len(source_hashes)} hashes"
                )

                # Merge lists (extend for multi-source)
                # Note: API returns "top_ips" but we store as "ip_list" for consistency
                aggregated["ip_list"].extend(data.get("stats", {}).get("top_ips", []))
                aggregated["ip_locations"].extend(data.get("stats", {}).get("ip_locations", []))

                # Collect raw data for later aggregation (don't extend directly)
                # These will be properly merged after all sources are fetched
                for item in data.get("stats", {}).get("top_countries", []):
                    aggregated["top_countries"].append(item)
                for item in data.get("stats", {}).get("top_credentials", []):
                    aggregated["top_credentials"].append(item)
                for item in data.get("stats", {}).get("top_commands", []):
                    aggregated["top_commands"].append(item)
                for item in data.get("stats", {}).get("top_clients", []):
                    aggregated["top_clients"].append(item)
                for item in data.get("stats", {}).get("top_asns", []):
                    aggregated["top_asns"].append(item)

                # Merge VT stats
                vt_stats = data.get("stats", {}).get("vt_stats", {})
                aggregated["vt_stats"]["total_scanned"] += vt_stats.get("total_scanned", 0)
                aggregated["vt_stats"]["total_malicious"] += vt_stats.get("total_malicious", 0)

                # Merge top downloads with VT data
                downloads = data.get("top_downloads_with_vt", [])
                for dl in downloads:
                    # Add source tag
                    dl_copy = dl.copy()
                    dl_copy["_source"] = source_name
                    aggregated["top_downloads_with_vt"].append(dl_copy)

                # Store per-source stats
                aggregated["source_stats"][source_name] = {
                    "type": source.type,
                    "status": "success",
                    "sessions": totals.get("total_sessions", 0),
                    "downloads": len(downloads),
                }

                print(
                    f"[MultiSource] Merged data from '{source_name}': {totals.get('total_sessions', 0)} sessions, {len(downloads)} downloads"
                )

            except Exception as e:
                print(f"[MultiSource] Error fetching dashboard data from '{source_name}': {e}")
                aggregated["source_errors"][source_name] = str(e)
                aggregated["failed_sources"].append(source_name)
                self.backoff.record_failure(source.name)

        # Final processing: deduplicate and sort
        aggregated["top_downloads_with_vt"] = self._deduplicate_and_sort_downloads(aggregated["top_downloads_with_vt"])

        # Update unique_downloads to reflect cross-honeypot deduplication
        aggregated["unique_downloads"] = len(all_unique_hashes)

        # Calculate VT averages
        if aggregated["vt_stats"]["total_scanned"] > 0:
            aggregated["vt_stats"]["avg_detection_rate"] = (
                aggregated["vt_stats"]["total_malicious"] / aggregated["vt_stats"]["total_scanned"]
            ) * 100

        # Properly aggregate counts for items from multiple sources
        # ASNs: merge by ASN key and sum counts
        asn_merged = {}
        for item in aggregated["top_asns"]:
            if isinstance(item, dict):
                key = item.get("asn")
                if key:
                    if key not in asn_merged:
                        asn_merged[key] = {"asn": key, "count": 0, "organization": item.get("organization", "Unknown")}
                    asn_merged[key]["count"] += item.get("count", 0)
        aggregated["top_asns"] = sorted(asn_merged.values(), key=lambda x: x.get("count", 0), reverse=True)[:10]

        # Countries: merge by country name and sum counts
        # Output format: list of {"country": ..., "count": ...} dicts for template
        country_merged = {}
        for item in aggregated["top_countries"]:
            if isinstance(item, dict):
                key = item.get("country")
                count = item.get("count", 0)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                key, count = item[0], item[1]
            else:
                continue
            if key:
                country_merged[key] = country_merged.get(key, 0) + count
        aggregated["top_countries"] = [
            {"country": k, "count": v}
            for k, v in sorted(country_merged.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Credentials: merge by credential and sum counts
        # API returns {"username": "...", "password": "...", "count": ...}
        # Output format: list of {"username": ..., "password": ..., "count": ...} dicts for template
        cred_merged = {}
        cred_details = {}
        for item in aggregated["top_credentials"]:
            if isinstance(item, dict):
                username = item.get("username", "")
                password = item.get("password", "")
                key = f"{username}:{password}"
                count = item.get("count", 0)
                cred_details[key] = {"username": username, "password": password}
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                key, count = item[0], item[1]
                parts = key.split(":", 1) if ":" in key else [key, ""]
                cred_details[key] = {"username": parts[0], "password": parts[1] if len(parts) > 1 else ""}
            else:
                continue
            if key:
                cred_merged[key] = cred_merged.get(key, 0) + count
        aggregated["top_credentials"] = [
            {"username": cred_details[k]["username"], "password": cred_details[k]["password"], "count": v}
            for k, v in sorted(cred_merged.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Commands: merge by command and sum counts
        # Output format: list of {"command": ..., "count": ...} dicts for template
        cmd_merged = {}
        for item in aggregated["top_commands"]:
            if isinstance(item, dict):
                key = item.get("command")
                count = item.get("count", 0)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                key, count = item[0], item[1]
            else:
                continue
            if key:
                cmd_merged[key] = cmd_merged.get(key, 0) + count
        aggregated["top_commands"] = [
            {"command": k, "count": v}
            for k, v in sorted(cmd_merged.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Clients: merge by client and sum counts
        # Output format: list of {"client": ..., "count": ...} dicts for template
        client_merged = {}
        for item in aggregated["top_clients"]:
            if isinstance(item, dict):
                key = item.get("client")
                count = item.get("count", 0)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                key, count = item[0], item[1]
            else:
                continue
            if key:
                client_merged[key] = client_merged.get(key, 0) + count
        aggregated["top_clients"] = [
            {"client": k, "count": v}
            for k, v in sorted(client_merged.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Count how many downloads actually have VT scan results (vt_total > 0)
        vt_scanned_count = sum(1 for dl in aggregated["top_downloads_with_vt"] if (dl.get("vt_total") or 0) > 0)
        print(
            f"[MultiSource] Final aggregation: {aggregated['total_downloads']} total downloads, "
            f"{aggregated['unique_downloads']} unique downloads (cross-honeypot deduplicated from {len(all_unique_hashes)} hashes), "
            f"{len(aggregated['top_downloads_with_vt'])} in top list ({vt_scanned_count} VT-scanned)"
        )

        # Cache the result
        self.stats_cache.set(cache_key, aggregated, ttl=300)  # 5 minutes

        return aggregated

    def get_dashboard_overview(
        self, hours: int = 24, source_filter: Optional[str] = None, force_refresh: bool = False
    ) -> dict:
        """
        Get complete dashboard data in one request (multi-source compatible).

        This aggregates data from all sources into the dashboard overview format.

        Args:
            hours: Number of hours to include in statistics
            source_filter: Filter by specific source (None = all sources)
            force_refresh: Force cache refresh

        Returns:
            Complete dashboard data dict with stats and downloads
        """
        # Get aggregated stats
        aggregated_stats = self.get_stats(hours=hours, source_filter=source_filter, force_refresh=force_refresh)

        # Return in dashboard overview format
        return {
            "stats": aggregated_stats,
            "top_downloads_with_vt": aggregated_stats.get("top_downloads_with_vt", []),
            "generated_at": datetime.now().isoformat(),
            "hours": hours,
            "sources": list(self.sources.keys()),
            "status": "complete",
        }

    def _deduplicate_and_sort_downloads(self, downloads_list):
        """Deduplicate downloads by SHA256 and sort by VT detections."""
        dl_dict = {}
        for dl in downloads_list:
            if dl is None or not isinstance(dl, dict):
                continue
            shasum = dl.get("sha256") or dl.get("shasum")
            if shasum:
                if shasum not in dl_dict:
                    dl_dict[shasum] = dl
                else:
                    # Keep the one with higher VT detections (treat None as 0)
                    existing = dl_dict[shasum].get("vt_detections") or 0
                    current = dl.get("vt_detections") or 0
                    if current > existing:
                        dl_dict[shasum] = dl

        # Include all downloads (VT-scanned and unscanned), sorted by detections (high to low)
        # Treat None/missing vt_detections as 0
        return sorted(dl_dict.values(), key=lambda x: x.get("vt_detections") or 0, reverse=True)[:10]

    def get_attack_map_data(self, hours: int = 24, source_filter: Optional[str] = None) -> dict:
        """
        Get aggregated attack data for the map visualization from all sources.

        Aggregates attack data from each source's /api/v1/attack-map endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'attacks' list, 'total_sessions', and 'unique_ips'
        """
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate attack data across all sources
        # Key by IP to merge data from multiple sources
        ip_attacks = {}
        total_sessions = 0

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_attack_map_data, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for attack in result.get("attacks", []):
                        ip = attack.get("ip")
                        if not ip:
                            continue

                        # Add source attribution
                        attack["_source"] = source.name

                        if ip not in ip_attacks:
                            ip_attacks[ip] = attack
                        else:
                            # Merge: sum session counts, keep latest timestamp
                            existing = ip_attacks[ip]
                            existing["session_count"] += attack.get("session_count", 0)
                            existing["success_count"] = existing.get("success_count", 0) + attack.get("success_count", 0)
                            if attack.get("latest_timestamp", "") > existing.get("latest_timestamp", ""):
                                existing["latest_timestamp"] = attack["latest_timestamp"]
                            # Keep first source for attribution
                            if "_sources" not in existing:
                                existing["_sources"] = [existing["_source"]]
                            existing["_sources"].append(source.name)

                    total_sessions += result.get("total_sessions", 0)
                    print(f"[MultiSource] Fetched {len(result.get('attacks', []))} attack locations from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching attack map data from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Convert to list and sort by latest timestamp
        attacks = list(ip_attacks.values())
        attacks.sort(key=lambda x: x.get("latest_timestamp") or "")

        return {
            "attacks": attacks,
            "total_sessions": total_sessions,
            "unique_ips": len(attacks),
        }

    def get_all_asns(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL ASNs with session counts from all sources via API.

        Aggregates ASN data from each source's /api/v1/asns endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'asns' list and 'total' count
        """
        from collections import Counter

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate ASN counts across all sources
        asn_counter = Counter()
        asn_details = {}

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_all_asns, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for asn_data in result.get("asns", []):
                        asn_key = asn_data.get("asn")
                        if asn_key:
                            asn_counter[asn_key] += asn_data.get("count", 0)
                            if asn_key not in asn_details:
                                asn_details[asn_key] = {
                                    "asn_number": asn_data.get("asn_number", 0),
                                    "asn_org": asn_data.get("asn_org", "Unknown"),
                                }

                    print(f"[MultiSource] Fetched {len(result.get('asns', []))} ASNs from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching ASNs from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Build result list sorted by count
        all_asns = []
        for asn_key, count in asn_counter.most_common():
            details = asn_details.get(asn_key, {})
            all_asns.append({
                "asn": asn_key,
                "asn_number": details.get("asn_number", 0),
                "asn_org": details.get("asn_org", "Unknown"),
                "count": count,
            })

        return {"asns": all_asns, "total": len(all_asns)}

    def get_all_ips(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL IPs with session counts and GeoIP data from all sources via API.

        Aggregates IP data from each source's /api/v1/ips endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'ips' list and 'total' count
        """
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate IP stats across all sources
        ip_stats = {}

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_all_ips, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for ip_data in result.get("ips", []):
                        ip = ip_data.get("ip")
                        if not ip:
                            continue

                        if ip not in ip_stats:
                            ip_stats[ip] = {
                                "ip": ip,
                                "count": 0,
                                "successful_logins": 0,
                                "failed_logins": 0,
                                "last_seen": ip_data.get("last_seen"),
                                "geo": ip_data.get("geo", {}),
                                "sources": [],
                            }

                        # Aggregate counts
                        ip_stats[ip]["count"] += ip_data.get("count", 0)
                        ip_stats[ip]["successful_logins"] += ip_data.get("successful_logins", 0)
                        ip_stats[ip]["failed_logins"] += ip_data.get("failed_logins", 0)
                        ip_stats[ip]["sources"].append(source.name)

                        # Update last_seen if newer
                        new_last_seen = ip_data.get("last_seen")
                        if new_last_seen:
                            old_last_seen = ip_stats[ip]["last_seen"]
                            if not old_last_seen or new_last_seen > old_last_seen:
                                ip_stats[ip]["last_seen"] = new_last_seen

                    print(f"[MultiSource] Fetched {len(result.get('ips', []))} IPs from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching IPs from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Build result list sorted by count
        all_ips = sorted(ip_stats.values(), key=lambda x: x["count"], reverse=True)

        return {"ips": all_ips, "total": len(all_ips)}

    def get_all_countries(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL countries with session counts from all sources via API.

        Aggregates country data from each source's /api/v1/countries endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'countries' list and 'total' count
        """
        from collections import Counter

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate country counts across all sources
        country_counter = Counter()
        country_details = {}

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_all_countries, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for country_data in result.get("countries", []):
                        country = country_data.get("country")
                        if country:
                            country_counter[country] += country_data.get("count", 0)
                            if country not in country_details:
                                country_details[country] = {
                                    "country_code": country_data.get("country_code", "XX"),
                                }

                    print(f"[MultiSource] Fetched {len(result.get('countries', []))} countries from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching countries from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Build result list sorted by count
        all_countries = []
        for country, count in country_counter.most_common():
            details = country_details.get(country, {})
            all_countries.append({
                "country": country,
                "country_code": details.get("country_code", "XX"),
                "count": count,
            })

        return {"countries": all_countries, "total": len(all_countries)}

    def get_all_credentials(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL credentials with attempt counts from all sources via API.

        Aggregates credential data from each source's /api/v1/credentials endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'credentials' list, 'successful' list, and 'total' count
        """
        from collections import Counter

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate credential counts across all sources
        cred_counter = Counter()
        cred_details = {}
        successful_creds = set()

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_all_credentials, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for cred_data in result.get("credentials", []):
                        cred = cred_data.get("credential")
                        if cred:
                            cred_counter[cred] += cred_data.get("count", 0)
                            if cred not in cred_details:
                                cred_details[cred] = {
                                    "username": cred_data.get("username", ""),
                                    "password": cred_data.get("password", ""),
                                }
                            if cred_data.get("successful"):
                                successful_creds.add(cred)

                    # Also track successful credentials from the successful list
                    for cred in result.get("successful", []):
                        successful_creds.add(cred)

                    print(f"[MultiSource] Fetched {len(result.get('credentials', []))} credentials from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching credentials from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Build result list sorted by count
        all_credentials = []
        for cred, count in cred_counter.most_common():
            details = cred_details.get(cred, {})
            all_credentials.append({
                "credential": cred,
                "username": details.get("username", ""),
                "password": details.get("password", ""),
                "count": count,
                "successful": cred in successful_creds,
            })

        return {
            "credentials": all_credentials,
            "successful": list(successful_creds),
            "total": len(all_credentials),
        }

    def get_all_clients(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL SSH client versions with session counts from all sources via API.

        Aggregates client data from each source's /api/v1/clients endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'clients' list and 'total' count
        """
        from collections import Counter

        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # Aggregate client counts across all sources
        client_counter = Counter()

        # Query sources in parallel
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_all_clients, hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    self.backoff.record_success(source.name)

                    for client_data in result.get("clients", []):
                        client = client_data.get("client")
                        if client:
                            client_counter[client] += client_data.get("count", 0)

                    print(f"[MultiSource] Fetched {len(result.get('clients', []))} clients from '{source.name}'")

                except Exception as e:
                    print(f"[MultiSource] Error fetching clients from '{source.name}': {e}")
                    self.backoff.record_failure(source.name)

        # Build result list sorted by count
        all_clients = []
        for client, count in client_counter.most_common():
            all_clients.append({
                "client": client,
                "count": count,
            })

        return {"clients": all_clients, "total": len(all_clients)}

    def get_all_commands(self, hours: int = 168, unique_only: bool = False, source_filter: Optional[str] = None) -> dict:
        """
        Get ALL commands with counts from all sources via API.

        Aggregates command data from each source's /api/v1/commands endpoint,
        much more efficient than fetching all sessions.

        Args:
            hours: Time range in hours
            unique_only: If True, return unique commands with counts
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Dict with 'commands' list and 'total' count
        """
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Filter out sources in backoff
        available_sources = {
            name: source for name, source in sources_to_query.items() if self.backoff.should_retry(name)
        }

        # For unique_only, we need to aggregate counts across sources
        if unique_only:
            command_stats = {}

            # Query sources in parallel
            max_workers = min(len(available_sources), MAX_WORKERS)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_source = {
                    executor.submit(source.datasource.get_all_commands, hours, unique_only): source
                    for source in available_sources.values()
                }

                for future in concurrent.futures.as_completed(future_to_source):
                    source = future_to_source[future]
                    try:
                        result = future.result(timeout=30)
                        self.backoff.record_success(source.name)

                        for cmd_data in result.get("commands", []):
                            cmd_text = cmd_data.get("command", "")
                            if not cmd_text:
                                continue

                            if cmd_text not in command_stats:
                                command_stats[cmd_text] = {
                                    "command": cmd_text,
                                    "count": 0,
                                    "timestamp": cmd_data.get("timestamp"),
                                    "src_ip": cmd_data.get("src_ip"),
                                    "session_id": cmd_data.get("session_id"),
                                    "sources": [],
                                }

                            # Aggregate counts
                            command_stats[cmd_text]["count"] += cmd_data.get("count", 1)
                            command_stats[cmd_text]["sources"].append(source.name)

                            # Update timestamp if newer
                            new_ts = cmd_data.get("timestamp")
                            if new_ts:
                                old_ts = command_stats[cmd_text]["timestamp"]
                                if not old_ts or new_ts > old_ts:
                                    command_stats[cmd_text]["timestamp"] = new_ts
                                    command_stats[cmd_text]["src_ip"] = cmd_data.get("src_ip")
                                    command_stats[cmd_text]["session_id"] = cmd_data.get("session_id")

                        print(f"[MultiSource] Fetched {len(result.get('commands', []))} commands from '{source.name}'")

                    except Exception as e:
                        print(f"[MultiSource] Error fetching commands from '{source.name}': {e}")
                        self.backoff.record_failure(source.name)

            # Sort by count
            all_commands = sorted(command_stats.values(), key=lambda x: x["count"], reverse=True)
        else:
            # For non-unique, just collect all commands from all sources
            all_commands = []

            max_workers = min(len(available_sources), MAX_WORKERS)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_source = {
                    executor.submit(source.datasource.get_all_commands, hours, unique_only): source
                    for source in available_sources.values()
                }

                for future in concurrent.futures.as_completed(future_to_source):
                    source = future_to_source[future]
                    try:
                        result = future.result(timeout=30)
                        self.backoff.record_success(source.name)

                        for cmd_data in result.get("commands", []):
                            cmd_data["source"] = source.name
                            all_commands.append(cmd_data)

                        print(f"[MultiSource] Fetched {len(result.get('commands', []))} commands from '{source.name}'")

                    except Exception as e:
                        print(f"[MultiSource] Error fetching commands from '{source.name}': {e}")
                        self.backoff.record_failure(source.name)

            # Sort by timestamp (most recent first)
            all_commands.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        return {"commands": all_commands, "total": len(all_commands)}

    def get_available_sources(self) -> list[dict]:
        """
        Get list of available data sources.

        Returns:
            List of source info dicts
        """
        return [
            {"name": source.name, "type": source.type, "api_base_url": source.api_base_url}
            for source in self.sources.values()
        ]

    def get_health(self) -> dict:
        """
        Get health status of all sources.

        Returns:
            Health status dict with per-source info
        """
        health_status = {
            "status": "healthy" if self.active_source_count > 0 else "degraded",
            "mode": "multi",
            "total_sources": len(self.sources),
            "active_sources": self.active_source_count,
            "sources": {},
        }

        # Check health of each source in parallel
        # Limit max workers to prevent thread exhaustion (max 5 concurrent queries)
        max_workers = min(len(self.sources), 5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_health): source for source in self.sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    health = future.result(timeout=5)
                    health_status["sources"][source.name] = {
                        "status": health.get("status", "unknown"),
                        "type": source.type,
                    }
                except Exception as e:
                    health_status["sources"][source.name] = {
                        "status": "unhealthy",
                        "error": str(e),
                        "type": source.type,
                    }

        return health_status

    def get_session_events(self, session_id: str) -> list:
        """
        Get all events for a specific session.

        For multi-source mode, events are included in the session data
        returned by get_session().

        Args:
            session_id: The session ID to get events for

        Returns:
            List of event dicts sorted by timestamp
        """
        session = self.get_session(session_id)
        if not session:
            return []

        events = session.get("events", [])
        # Sort by timestamp
        events.sort(key=lambda x: x.get("timestamp", ""))
        return events

    def get_threat_intel_for_ip(self, ip_address: str) -> dict:
        """
        Get threat intelligence data for a specific IP address.

        For multi-source mode, this would require querying all sources
        for threat intel events. For now, return empty result.

        Args:
            ip_address: The IP address to look up

        Returns:
            Threat intel dict (currently empty for multi-source)
        """
        # TODO: Query sources for threat intel events
        # For now, return empty to avoid errors
        return {}


def create_multisource_from_config(config_sources: list) -> Optional[MultiSourceDataSource]:
    """
    Create MultiSourceDataSource from configuration.

    Supports mixed local/remote sources for aggregating data from
    the local honeypot and remote honeypots via API.

    Args:
        config_sources: List of source dicts from configuration.
                       Each dict should have: name, type, mode, api_base_url (if remote), enabled

    Returns:
        MultiSourceDataSource instance or None if no valid sources
    """
    sources = []

    for source_config in config_sources:
        name = source_config.get("name")
        source_type = source_config.get("type", "cowrie-ssh")
        mode = source_config.get("mode", "remote")
        api_base_url = source_config.get("api_base_url")
        enabled = source_config.get("enabled", True)

        # Validate required fields based on mode
        if not name:
            print(f"[MultiSource] Skipping source without name: {source_config}")
            continue

        if mode == "remote" and not api_base_url:
            print(f"[MultiSource] Skipping remote source '{name}' without api_base_url")
            continue

        sources.append(
            HoneypotSource(
                name=name,
                source_type=source_type,
                mode=mode,
                api_base_url=api_base_url,
                enabled=enabled,
            )
        )

    if not sources:
        print("[MultiSource] No valid sources configured")
        return None

    return MultiSourceDataSource(sources)
