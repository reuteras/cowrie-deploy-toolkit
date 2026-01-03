#!/usr/bin/env python3
"""
Multi-Source Data Aggregation for Cowrie Dashboard

Enables dashboard to aggregate data from multiple honeypots of different types.
Supports parallel querying with graceful degradation on partial failures.
Includes caching and rate limiting to prevent resource exhaustion.
"""

import concurrent.futures
import os
from typing import Optional

from cache import ExponentialBackoff, ResponseCache
from datasource import DataSource

# Configuration from environment variables
CACHE_TTL_STATS = int(os.getenv("MULTISOURCE_CACHE_TTL_STATS", "30"))  # 30 seconds for stats
CACHE_TTL_SESSIONS = int(os.getenv("MULTISOURCE_CACHE_TTL_SESSIONS", "15"))  # 15 seconds for sessions
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

    def parse_all(self, hours: int = 168, source_filter: Optional[str] = None) -> dict:
        """
        Get all sessions as a dict keyed by session ID (compatibility method).

        This method maintains compatibility with routes that expect the old
        SessionParser.parse_all() format (dict keyed by session ID).

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source name (None = all sources)

        Returns:
            Dict of sessions keyed by session ID
        """
        # Use 1000 per source (API max limit)
        # For multi-source, we'll get up to 1000 from each source
        # and NOT apply the global limit truncation
        per_source_limit = 1000

        result = self.get_sessions(
            hours=hours, limit=per_source_limit, offset=0, source_filter=source_filter, skip_global_limit=True
        )

        print(f"[MultiSource] parse_all: got {len(result.get('sessions', []))} sessions from get_sessions")

        # Convert list to dict keyed by session ID
        sessions_dict = {}
        skipped = 0
        for session in result.get("sessions", []):
            # Debug: Check what fields are in the first session
            if len(sessions_dict) == 0 and session:
                print(f"[MultiSource] Sample session keys: {list(session.keys())[:10]}")

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

    def get_all_commands(self, hours: int = 168, source_filter: Optional[str] = None) -> list:
        """
        Get a flat list of all commands from all sessions.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            List of command dicts with timestamp, command, src_ip, session_id, and _source
        """
        sessions = self.parse_all(hours=hours, source_filter=source_filter)
        all_commands = []

        for session in sessions.values():
            if session.get("commands"):
                for cmd in session["commands"]:
                    all_commands.append(
                        {
                            "timestamp": cmd.get("timestamp"),
                            "command": cmd.get("command"),
                            "src_ip": session.get("src_ip"),
                            "session_id": session.get("id"),
                            "_source": session.get("_source", "local"),
                        }
                    )

        # Sort by timestamp, most recent first
        return sorted(all_commands, key=lambda x: x.get("timestamp", ""), reverse=True)

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

    def get_stats(self, hours: int = 24, source_filter: Optional[str] = None) -> dict:
        """
        Get aggregated statistics from all sources with caching.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Aggregated stats dict
        """
        # Check cache first
        cache_key = f"stats_{hours}_{source_filter or 'all'}"
        cached = self.stats_cache.get(cache_key)
        if cached is not None:
            print(f"[MultiSource] Cache hit for stats (hours={hours}, filter={source_filter})")
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

        # Initialize aggregated stats
        aggregated = {
            "total_sessions": 0,
            "unique_ips": set(),
            "sessions_with_commands": 0,
            "total_downloads": 0,
            "unique_downloads": set(),
            "ip_list": [],  # List of IP details with geo, counts, etc.
            "top_countries": {},
            "top_credentials": {},
            "successful_credentials": set(),
            "top_commands": {},
            "top_clients": {},
            "top_asns": {},
            "ip_locations": [],
            "hourly_activity": {},
            "vt_stats": {
                "total_scanned": 0,
                "total_malicious": 0,
                "avg_detection_rate": 0.0,
                "total_threat_families": set(),
            },
            "source_stats": {},  # Per-source breakdown
            "source_errors": {},
        }

        if not available_sources:
            print("[MultiSource] No sources available (all in backoff)")
            self.stats_cache.set(cache_key, aggregated, ttl=5)  # Short cache for empty results
            return aggregated

        # Query sources in parallel with reduced concurrency
        max_workers = min(len(available_sources), MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_stats, hours=hours): source
                for source in available_sources.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    stats = future.result(timeout=30)
                    self.backoff.record_success(source.name)  # Reset backoff on success

                    # Store per-source stats
                    aggregated["source_stats"][source.name] = {
                        "type": source.type,
                        "total_sessions": stats.get("total_sessions", 0),
                        "unique_ips": stats.get("unique_ips", 0),
                    }

                    # Aggregate metrics
                    aggregated["total_sessions"] += stats.get("total_sessions", 0)
                    aggregated["sessions_with_commands"] += stats.get("sessions_with_commands", 0)
                    aggregated["total_downloads"] += stats.get("total_downloads", 0)

                    # Merge IP list details and unique IPs
                    for ip_info in stats.get("ip_list", []):
                        aggregated["unique_ips"].add(ip_info["ip"])
                        # Add source tag to IP info for multi-source tracking
                        ip_info_copy = ip_info.copy()
                        ip_info_copy["source"] = source.name
                        aggregated["ip_list"].append(ip_info_copy)

                    # Merge unique downloads (handle both set and int formats)
                    unique_dl = stats.get("unique_downloads", 0)
                    if isinstance(unique_dl, set):
                        aggregated["unique_downloads"].update(unique_dl)
                    elif isinstance(unique_dl, int):
                        # Add to the set as a counter (can't get actual hashes from count)
                        # This is a limitation - we track total count, not actual unique hashes
                        for i in range(unique_dl):
                            aggregated["unique_downloads"].add(f"{source.name}_{i}")

                    # Merge top lists - handle both dict format from API and tuple format from local
                    for item in stats.get("top_countries", []):
                        if isinstance(item, dict):
                            # New API format: {"country": "USA", "count": 5}
                            country = item.get("country", "-")
                            count = item.get("count", 0)
                            aggregated["top_countries"][country] = aggregated["top_countries"].get(country, 0) + count
                        elif isinstance(item, (tuple, list)) and len(item) >= 2:
                            # Old tuple format: ("USA", 5)
                            country, count = item[0], item[1]
                            aggregated["top_countries"][country] = aggregated["top_countries"].get(country, 0) + count

                    for item in stats.get("top_credentials", []):
                        if isinstance(item, dict):
                            # New API format: {"username": "root", "password": "admin", "count": 5}
                            username = item.get("username", "")
                            password = item.get("password", "")
                            cred = f"{username}:{password}"
                            count = item.get("count", 0)
                            aggregated["top_credentials"][cred] = aggregated["top_credentials"].get(cred, 0) + count
                        elif isinstance(item, (tuple, list)) and len(item) >= 2:
                            # Old tuple format: ("root:admin", 5)
                            cred, count = item[0], item[1]
                            aggregated["top_credentials"][cred] = aggregated["top_credentials"].get(cred, 0) + count

                    for item in stats.get("top_commands", []):
                        if isinstance(item, dict):
                            # New API format: {"command": "ls", "count": 10}
                            cmd = item.get("command", "")
                            count = item.get("count", 0)
                            aggregated["top_commands"][cmd] = aggregated["top_commands"].get(cmd, 0) + count
                        elif isinstance(item, (tuple, list)) and len(item) >= 2:
                            # Old tuple format: ("ls", 10)
                            cmd, count = item[0], item[1]
                            aggregated["top_commands"][cmd] = aggregated["top_commands"].get(cmd, 0) + count

                    # Merge top SSH clients (new field from enriched API)
                    for item in stats.get("top_clients", []):
                        if isinstance(item, dict):
                            client = item.get("client", "")
                            count = item.get("count", 0)
                            aggregated["top_clients"][client] = aggregated["top_clients"].get(client, 0) + count
                        elif isinstance(item, (tuple, list)) and len(item) >= 2:
                            client, count = item[0], item[1]
                            aggregated["top_clients"][client] = aggregated["top_clients"].get(client, 0) + count

                    # Merge top ASNs (new field from enriched API)
                    for item in stats.get("top_asns", []):
                        if isinstance(item, dict):
                            asn = item.get("asn", "")
                            count = item.get("count", 0)
                            org = item.get("organization", "-")
                            # Store ASN with its organization
                            if asn not in aggregated["top_asns"]:
                                aggregated["top_asns"][asn] = {"count": 0, "organization": org}
                            aggregated["top_asns"][asn]["count"] += count
                        elif isinstance(item, (tuple, list)) and len(item) >= 2:
                            asn, count = item[0], item[1]
                            if asn not in aggregated["top_asns"]:
                                aggregated["top_asns"][asn] = {"count": 0, "organization": "-"}
                            aggregated["top_asns"][asn]["count"] += count

                    # Merge IP locations for map
                    aggregated["ip_locations"].extend(stats.get("ip_locations", []))

                    # Merge VirusTotal stats
                    vt = stats.get("vt_stats", {})
                    aggregated["vt_stats"]["total_scanned"] += vt.get("total_scanned", 0)
                    aggregated["vt_stats"]["total_malicious"] += vt.get("total_malicious", 0)

                except Exception as e:
                    print(f"[MultiSource] Error fetching stats from '{source.name}': {e}")
                    aggregated["source_errors"][source.name] = str(e)
                    self.backoff.record_failure(source.name)  # Record failure for backoff

        # Convert sets to lists and sort
        aggregated["unique_ips"] = len(aggregated["unique_ips"])
        aggregated["unique_downloads"] = len(aggregated["unique_downloads"])

        # Sort and deduplicate IP list by session count
        ip_dict = {}
        for ip_info in aggregated["ip_list"]:
            ip = ip_info["ip"]
            if ip not in ip_dict:
                # Ensure all necessary keys exist with defaults
                ip_dict[ip] = ip_info.copy()
                ip_dict[ip]["count"] = ip_info.get("count", 0)
                ip_dict[ip]["successful_logins"] = ip_info.get("successful_logins", 0)
                ip_dict[ip]["failed_logins"] = ip_info.get("failed_logins", 0)
            else:
                # Merge counts from multiple sources
                ip_dict[ip]["count"] += ip_info.get("count", 0)
                ip_dict[ip]["successful_logins"] += ip_info.get("successful_logins", 0)
                ip_dict[ip]["failed_logins"] += ip_info.get("failed_logins", 0)
                # Keep the most recent last_seen
                if ip_info.get("last_seen") and (
                    not ip_dict[ip].get("last_seen") or ip_info["last_seen"] > ip_dict[ip]["last_seen"]
                ):
                    ip_dict[ip]["last_seen"] = ip_info["last_seen"]
                    ip_dict[ip]["geo"] = ip_info.get("geo", {})

        aggregated["ip_list"] = sorted(ip_dict.values(), key=lambda x: x.get("count", 0), reverse=True)

        aggregated["top_countries"] = sorted(aggregated["top_countries"].items(), key=lambda x: x[1], reverse=True)[:10]
        aggregated["top_credentials"] = sorted(aggregated["top_credentials"].items(), key=lambda x: x[1], reverse=True)[
            :10
        ]
        aggregated["top_commands"] = sorted(aggregated["top_commands"].items(), key=lambda x: x[1], reverse=True)[:20]
        aggregated["top_clients"] = sorted(aggregated["top_clients"].items(), key=lambda x: x[1], reverse=True)[:10]

        # Format top_asns to include organization names
        aggregated["top_asns"] = [
            {"asn": asn, "count": data["count"], "organization": data["organization"]}
            for asn, data in sorted(aggregated["top_asns"].items(), key=lambda x: x[1]["count"], reverse=True)[:10]
        ]

        # Calculate average VT detection rate
        vt_total = aggregated["vt_stats"]["total_scanned"]
        if vt_total > 0:
            aggregated["vt_stats"]["avg_detection_rate"] = aggregated["vt_stats"]["total_malicious"] / vt_total * 100
        aggregated["vt_stats"]["total_threat_families"] = len(aggregated["vt_stats"]["total_threat_families"])

        aggregated["sources_queried"] = list(sources_to_query.keys())

        # Cache the result
        self.stats_cache.set(cache_key, aggregated)

        return aggregated

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
