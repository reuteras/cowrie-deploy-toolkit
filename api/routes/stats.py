"""
Statistics endpoints

Provides aggregated statistics from Cowrie data
"""

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from services.log_parser import parser
from services.sqlite_parser import sqlite_parser

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/stats/overview")
async def get_stats_overview(days: int = Query(7, ge=1, le=365)):
    """
    Get overview statistics for the dashboard

    Args:
        days: Number of days to include in statistics

    Returns:
        Comprehensive statistics including:
        - Total connections and sessions
        - Unique IPs
        - Top countries, credentials, commands
        - Downloads count
    """
    # Try SQLite first (FAST), fall back to JSON parsing (SLOW)
    if sqlite_parser.available:
        logger.info(f"Using SQLite parser for stats (days={days})")
        try:
            return sqlite_parser.get_stats_overview(days=days)
        except Exception as e:
            logger.error(f"SQLite parser failed: {e}, falling back to JSON parser")

    # Fallback to JSON parsing (original implementation)
    logger.warning("Using slow JSON parser - consider enabling SQLite output in Cowrie")

    # Get all sessions
    all_sessions = parser.get_sessions(limit=10000)  # Get a large number

    # Filter by time range
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    recent_sessions = []
    for session in all_sessions:
        if session.get("start_time"):
            try:
                dt = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
                if dt >= cutoff:
                    recent_sessions.append(session)
            except (ValueError, AttributeError):
                continue

    # Calculate statistics
    total_sessions = len(recent_sessions)
    unique_ips = len({s.get("src_ip") for s in recent_sessions if s.get("src_ip")})
    sessions_with_commands = sum(1 for s in recent_sessions if s.get("commands_count", 0) > 0)
    total_downloads = sum(s.get("downloads_count", 0) for s in recent_sessions)

    # Top IPs
    ip_counter = Counter(s.get("src_ip") for s in recent_sessions if s.get("src_ip"))
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(10)]

    # Top credentials
    cred_counter = Counter()
    for s in recent_sessions:
        if s.get("username") and s.get("password"):
            cred_counter[f"{s['username']}:{s['password']}"] += 1
    top_credentials = [
        {"username": cred.split(":")[0], "password": cred.split(":")[1], "count": count}
        for cred, count in cred_counter.most_common(10)
    ]

    # Top commands
    command_counter = Counter()
    for s in recent_sessions:
        for cmd in s.get("commands", []):
            command_counter[cmd.get("input", "")] += 1
    top_commands = [{"command": cmd, "count": count} for cmd, count in command_counter.most_common(10)]

    return {
        "time_range": {"start": cutoff.isoformat(), "end": datetime.now(timezone.utc).isoformat(), "days": days},
        "totals": {
            "sessions": total_sessions,
            "unique_ips": unique_ips,
            "sessions_with_commands": sessions_with_commands,
            "downloads": total_downloads,
        },
        "top_ips": top_ips,
        "top_credentials": top_credentials,
        "top_commands": top_commands,
    }
