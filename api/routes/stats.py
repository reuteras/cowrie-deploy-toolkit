"""
Statistics endpoints

Provides aggregated statistics from Cowrie data
"""

import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from services.sqlite_parser import sqlite_parser

logger = logging.getLogger(__name__)


# Simple in-memory cache for aggregated data
class SimpleCache:
    def __init__(self):
        self.cache = {}
        self.timestamps = {}

    def get(self, key):
        if key in self.cache:
            if time.time() - self.timestamps.get(key, 0) < 300:  # 5 minutes
                return self.cache[key]
            else:
                # Expired, remove
                del self.cache[key]
                del self.timestamps[key]
        return None

    def set(self, key, value, ttl=300):
        self.cache[key] = value
        self.timestamps[key] = time.time()


cache = SimpleCache()

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/stats/overview")
async def get_stats_overview(hours: int = Query(168, ge=1, le=8760)):  # Default 1 week, max ~1 year
    """
    Get overview statistics for the dashboard

    Args:
        hours: Number of hours to include in statistics

    Returns:
        Comprehensive statistics including:
        - Total connections and sessions
        - Unique IPs
        - Top countries, credentials, commands
        - Downloads count
    """
    # SQLite is now mandatory - no JSON fallback
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    # Convert hours to days for the SQLite parser (which expects days)
    days = max(1, hours // 24)
    logger.info(f"Using SQLite parser for stats (hours={hours}, converted to days={days})")
    return sqlite_parser.get_stats_overview(days=days)


@router.get("/asns")
async def get_all_asns(hours: int = Query(168, ge=1, le=8760)):
    """
    Get ALL ASNs with session counts (not just top 10).

    This endpoint returns all ASNs seen in the time period, sorted by session count.
    Much more efficient than fetching all sessions - uses SQLite + GeoIP lookup.

    Args:
        hours: Number of hours to include in statistics

    Returns:
        List of ASN dicts with asn, asn_number, asn_org, and count
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all ASNs (hours={hours}, converted to days={days})")

    asns = sqlite_parser.get_all_asns(days=days)

    return {
        "asns": asns,
        "total": len(asns),
        "hours": hours,
    }


@router.get("/countries")
async def get_all_countries(hours: int = Query(168, ge=1, le=8760)):
    """
    Get ALL countries with session counts (not just top 10).

    This endpoint returns all countries seen in the time period, sorted by session count.
    Much more efficient than fetching all sessions - uses SQLite + GeoIP lookup.

    Args:
        hours: Number of hours to include in statistics

    Returns:
        List of country dicts with country, country_code, and count
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all countries (hours={hours}, converted to days={days})")

    countries = sqlite_parser.get_all_countries(days=days)

    return {
        "countries": countries,
        "total": len(countries),
        "hours": hours,
    }


@router.get("/credentials")
async def get_all_credentials(hours: int = Query(168, ge=1, le=8760)):
    """
    Get ALL credentials with attempt counts (not just top 10).

    This endpoint returns all credentials seen in the time period, sorted by attempt count.
    Much more efficient than fetching all sessions - queries auth table directly.

    Args:
        hours: Number of hours to include in statistics

    Returns:
        Dict with 'credentials' list and 'successful' list of successful credentials
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all credentials (hours={hours}, converted to days={days})")

    result = sqlite_parser.get_all_credentials(days=days)

    return {
        "credentials": result["credentials"],
        "successful": result["successful"],
        "total": len(result["credentials"]),
        "hours": hours,
    }


@router.get("/clients")
async def get_all_clients(hours: int = Query(168, ge=1, le=8760)):
    """
    Get ALL SSH client versions with session counts (not just top 10).

    This endpoint returns all SSH clients seen in the time period, sorted by session count.
    Much more efficient than fetching all sessions - queries clients table directly.

    Args:
        hours: Number of hours to include in statistics

    Returns:
        List of client dicts with client and count
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all SSH clients (hours={hours}, converted to days={days})")

    clients = sqlite_parser.get_all_clients(days=days)

    return {
        "clients": clients,
        "total": len(clients),
        "hours": hours,
    }


@router.get("/ips")
async def get_all_ips(hours: int = Query(168, ge=1, le=8760)):
    """
    Get ALL IPs with session counts and GeoIP data.

    This endpoint returns all IPs seen in the time period with aggregated stats.
    Much more efficient than fetching all sessions - uses SQLite + GeoIP lookup.

    Args:
        hours: Number of hours to include in statistics

    Returns:
        List of IP dicts with ip, count, geo data, successful/failed logins, last_seen
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all IPs (hours={hours}, converted to days={days})")

    ips = sqlite_parser.get_all_ips(days=days)

    return {
        "ips": ips,
        "total": len(ips),
        "hours": hours,
    }


@router.get("/commands")
async def get_all_commands(
    hours: int = Query(168, ge=1, le=8760),
    unique: bool = Query(False, description="Return unique commands with counts"),
):
    """
    Get ALL commands with counts and metadata.

    This endpoint returns all commands seen in the time period.
    Much more efficient than fetching all sessions - queries input table directly.

    Args:
        hours: Number of hours to include in statistics
        unique: If True, return unique commands with counts; if False, return all commands

    Returns:
        List of command dicts with command, count, timestamp, src_ip, session_id
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting all commands (hours={hours}, converted to days={days}, unique={unique})")

    commands = sqlite_parser.get_all_commands(days=days, unique_only=unique)

    return {
        "commands": commands,
        "total": len(commands),
        "hours": hours,
        "unique": unique,
    }


@router.get("/attack-map")
async def get_attack_map_data(hours: int = Query(24, ge=1, le=8760)):
    """
    Get aggregated attack data for the map visualization.

    Returns per-IP data with coordinates, session counts, and success counts.
    Much more efficient than fetching all sessions.

    Args:
        hours: Number of hours to include

    Returns:
        Dict with attacks list, total_sessions, and unique_ips
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    days = max(1, hours // 24)
    logger.info(f"Getting attack map data (hours={hours}, converted to days={days})")

    return sqlite_parser.get_attack_map_data(days=days)


@router.get("/dashboard/overview")
async def get_dashboard_overview(hours: int = Query(24, ge=1), force_refresh: bool = Query(False)):
    """
    Get complete aggregated dashboard data in one request

    This endpoint provides all data needed for the dashboard in a single call,
    including pre-aggregated statistics and top downloads with VT data.

    Args:
        hours: Number of hours to include in statistics
        force_refresh: Force cache refresh (ignore cached data)

    Returns:
        Complete dashboard data with stats, downloads, IPs, etc.
    """
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    # Check cache unless force refresh
    cache_key = f"dashboard_{hours}"
    if not force_refresh:
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Returning cached dashboard data for {hours} hours")
            return cached_data

    logger.info(f"Generating dashboard overview for {hours} hours")

    # Get base stats
    stats = sqlite_parser.get_stats_overview(days=max(1, hours // 24))

    # Add aggregated download data with VT and metadata
    top_downloads = get_top_downloads_with_vt(hours)

    # Add source identification (for multi-source compatibility)
    result = {
        "stats": stats,
        "top_downloads_with_vt": top_downloads,
        "generated_at": datetime.now().isoformat(),
        "hours": hours,
        "sources": ["local"],  # For multi-source identification
        "status": "complete",
    }

    # Cache for 5 minutes
    cache.set(cache_key, result, ttl=300)

    return result


def _table_exists(cursor, table_name: str) -> bool:
    """Check if a table exists in the database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None


def get_top_downloads_with_vt(hours: int) -> list:
    """Get top downloads with VT data and metadata from database"""
    if not sqlite_parser.available:
        return []

    # Create direct database connection
    import sqlite3

    db_path = sqlite_parser.db_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Check if download_meta table exists
        has_download_meta = _table_exists(cursor, "download_meta")

        if has_download_meta:
            # Full query with metadata
            query = """
                SELECT
                    d.shasum,
                    COUNT(d.id) as download_count,
                    MAX(d.timestamp) as latest_download,
                    m.file_size,
                    m.file_type,
                    COALESCE(m.file_category, 'unknown') as file_category,
                    m.is_previewable,
                    COALESCE(vt.positives, 0) as vt_detections,
                    COALESCE(vt.total, 0) as vt_total,
                    vt.threat_label as vt_threat_label,
                    vt.is_new as vt_is_new
                FROM downloads d
                LEFT JOIN download_meta m ON d.shasum = m.shasum
                LEFT JOIN virustotal_scans vt ON vt.shasum = d.shasum
                WHERE d.timestamp >= ? AND d.shasum IS NOT NULL
                GROUP BY d.shasum
                ORDER BY vt_detections DESC, download_count DESC
                LIMIT 10
            """
        else:
            # Simplified query without download_meta
            logger.info("download_meta table not found, using simplified query")
            query = """
                SELECT
                    d.shasum,
                    COUNT(d.id) as download_count,
                    MAX(d.timestamp) as latest_download,
                    NULL as file_size,
                    NULL as file_type,
                    'unknown' as file_category,
                    0 as is_previewable,
                    COALESCE(vt.positives, 0) as vt_detections,
                    COALESCE(vt.total, 0) as vt_total,
                    vt.threat_label as vt_threat_label,
                    vt.is_new as vt_is_new
                FROM downloads d
                LEFT JOIN virustotal_scans vt ON vt.shasum = d.shasum
                WHERE d.timestamp >= ? AND d.shasum IS NOT NULL
                GROUP BY d.shasum
                ORDER BY vt_detections DESC, download_count DESC
                LIMIT 10
            """

        cursor.execute(query, (cutoff_str,))

        downloads = []
        for row in cursor.fetchall():
            downloads.append(
                {
                    "shasum": row["shasum"],
                    "download_count": row["download_count"],
                    "latest_download": row["latest_download"],
                    "file_size": row["file_size"],
                    "file_type": row["file_type"],
                    "file_category": row["file_category"],
                    "is_previewable": bool(row["is_previewable"]) if row["is_previewable"] else False,
                    "vt_detections": row["vt_detections"],
                    "vt_total": row["vt_total"],
                    "vt_threat_label": row["vt_threat_label"],
                    "vt_is_new": bool(row["vt_is_new"]) if row["vt_is_new"] is not None else None,
                }
            )

        return downloads

    finally:
        conn.close()
