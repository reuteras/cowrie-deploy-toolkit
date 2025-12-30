"""
Statistics endpoints

Provides aggregated statistics from Cowrie data
"""

import logging

from fastapi import APIRouter, Query
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
    # SQLite is now mandatory - no JSON fallback
    if not sqlite_parser.available:
        logger.error(f"SQLite database not found at {sqlite_parser.db_path}")
        raise FileNotFoundError(
            f"SQLite database required but not found at {sqlite_parser.db_path}. "
            "Please enable SQLite output in Cowrie configuration."
        )

    logger.info(f"Using SQLite parser for stats (days={days})")
    return sqlite_parser.get_stats_overview(days=days)
