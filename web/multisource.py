#!/usr/bin/env python3
"""
Multi-Source Data Aggregation for Cowrie Dashboard

Enables dashboard to aggregate data from multiple honeypots of different types.
Supports parallel querying with graceful degradation on partial failures.
"""

import concurrent.futures
import os
from typing import List, Optional

from datasource import DataSource


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
                # Validate configuration based on mode
                if mode == "remote" and not api_base_url:
                    raise ValueError(f"API base URL required for remote mode (source: {name})")

                # Create DataSource instance for this honeypot
                self.datasource = DataSource(mode=mode, api_base_url=api_base_url)

                if mode == "local":
                    print(f"[MultiSource] Initialized source '{name}' ({source_type}) in LOCAL mode")
                else:
                    print(f"[MultiSource] Initialized source '{name}' ({source_type}) at {api_base_url}")
            except Exception as e:
                print(f"[MultiSource] Failed to initialize source '{name}': {e}")
                self.enabled = False

    def is_available(self) -> bool:
        """Check if this source is enabled and has a valid datasource."""
        return self.enabled and self.datasource is not None


class MultiSourceDataSource:
    """Aggregate data from multiple honeypot sources."""

    def __init__(self, sources: List[HoneypotSource]):
        """
        Initialize multi-source data aggregator.

        Args:
            sources: List of HoneypotSource configurations
        """
        self.sources = {s.name: s for s in sources if s.is_available()}
        self.active_source_count = len(self.sources)

        print(f"[MultiSource] Initialized with {self.active_source_count} active sources:")
        for name, source in self.sources.items():
            print(f"[MultiSource]   - {name} ({source.type}): {source.api_base_url}")

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
    ) -> dict:
        """
        Get sessions from all sources (or filtered sources).

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
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        all_sessions = []
        total_count = 0
        source_errors = {}

        # Query sources in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources_to_query)) as executor:
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
                for source in sources_to_query.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=30)
                    # Tag sessions with source info
                    tagged_sessions = self._tag_list(result.get("sessions", []), source.name, source.type)
                    all_sessions.extend(tagged_sessions)
                    total_count += result.get("total", 0)
                except Exception as e:
                    print(f"[MultiSource] Error fetching sessions from '{source.name}': {e}")
                    source_errors[source.name] = str(e)

        # Sort combined sessions by start_time (most recent first)
        all_sessions.sort(key=lambda x: x.get("start_time") or "", reverse=True)

        # Apply global limit
        if len(all_sessions) > limit:
            all_sessions = all_sessions[:limit]

        return {
            "total": total_count,
            "sessions": all_sessions,
            "sources_queried": list(sources_to_query.keys()),
            "source_errors": source_errors,
        }

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
        Get aggregated statistics from all sources.

        Args:
            hours: Time range in hours
            source_filter: Filter by specific source (None = all sources)

        Returns:
            Aggregated stats dict
        """
        # Determine which sources to query
        sources_to_query = self.sources
        if source_filter and source_filter in self.sources:
            sources_to_query = {source_filter: self.sources[source_filter]}

        # Initialize aggregated stats
        aggregated = {
            "total_sessions": 0,
            "unique_ips": set(),
            "sessions_with_commands": 0,
            "total_downloads": 0,
            "unique_downloads": set(),
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

        # Query sources in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources_to_query)) as executor:
            future_to_source = {
                executor.submit(source.datasource.get_stats, hours=hours): source
                for source in sources_to_query.values()
            }

            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    stats = future.result(timeout=30)

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

                    # Merge unique IPs
                    for ip_info in stats.get("ip_list", []):
                        aggregated["unique_ips"].add(ip_info["ip"])

                    # Merge unique downloads (handle both set and int formats)
                    unique_dl = stats.get("unique_downloads", set())
                    if isinstance(unique_dl, set):
                        aggregated["unique_downloads"].update(unique_dl)
                    elif isinstance(unique_dl, int):
                        # If it's an int (count), we can't merge properly, so just track we saw downloads
                        # This is a limitation when aggregating from sources that only provide counts
                        pass  # We'll use total_downloads as the metric instead

                    # Merge top lists (countries, credentials, commands, etc.)
                    for country, count in stats.get("top_countries", []):
                        aggregated["top_countries"][country] = aggregated["top_countries"].get(country, 0) + count

                    for cred, count in stats.get("top_credentials", []):
                        aggregated["top_credentials"][cred] = aggregated["top_credentials"].get(cred, 0) + count

                    for cmd, count in stats.get("top_commands", []):
                        aggregated["top_commands"][cmd] = aggregated["top_commands"].get(cmd, 0) + count

                    # Merge IP locations for map
                    aggregated["ip_locations"].extend(stats.get("ip_locations", []))

                    # Merge VirusTotal stats
                    vt = stats.get("vt_stats", {})
                    aggregated["vt_stats"]["total_scanned"] += vt.get("total_scanned", 0)
                    aggregated["vt_stats"]["total_malicious"] += vt.get("total_malicious", 0)

                except Exception as e:
                    print(f"[MultiSource] Error fetching stats from '{source.name}': {e}")
                    aggregated["source_errors"][source.name] = str(e)

        # Convert sets to lists and sort
        aggregated["unique_ips"] = len(aggregated["unique_ips"])
        aggregated["unique_downloads"] = len(aggregated["unique_downloads"])
        aggregated["top_countries"] = sorted(aggregated["top_countries"].items(), key=lambda x: x[1], reverse=True)[:10]
        aggregated["top_credentials"] = sorted(aggregated["top_credentials"].items(), key=lambda x: x[1], reverse=True)[
            :10
        ]
        aggregated["top_commands"] = sorted(aggregated["top_commands"].items(), key=lambda x: x[1], reverse=True)[:20]

        # Calculate average VT detection rate
        vt_total = aggregated["vt_stats"]["total_scanned"]
        if vt_total > 0:
            aggregated["vt_stats"]["avg_detection_rate"] = (
                aggregated["vt_stats"]["total_malicious"] / vt_total * 100
            )
        aggregated["vt_stats"]["total_threat_families"] = len(aggregated["vt_stats"]["total_threat_families"])

        aggregated["sources_queried"] = list(sources_to_query.keys())

        return aggregated

    def get_available_sources(self) -> List[dict]:
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
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
                    health_status["sources"][source.name] = {"status": "unhealthy", "error": str(e), "type": source.type}

        return health_status


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
