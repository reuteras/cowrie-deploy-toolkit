"""
SQLite-based statistics parser for Cowrie API

Queries Cowrie's SQLite database directly for fast statistics generation.
Falls back to JSON parsing if SQLite is unavailable.
"""

import os
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

# Database path (same as configured in Cowrie)
DEFAULT_DB_PATH = "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db"


class SQLiteStatsParser:
    """Fast statistics parser using SQLite database"""

    def __init__(self, db_path: str = None):
        """
        Initialize SQLite parser

        Args:
            db_path: Path to cowrie.db (defaults to standard location)
        """
        self.db_path = db_path or os.getenv("COWRIE_DB_PATH", DEFAULT_DB_PATH)
        self.available = os.path.exists(self.db_path)

    def get_stats_overview(self, days: int = 7) -> Dict:
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

            # Total downloads
            cursor.execute(
                """
                SELECT COUNT(*) as downloads
                FROM downloads
                WHERE timestamp >= ?
                """,
                (cutoff_str,),
            )
            totals["downloads"] = cursor.fetchone()["downloads"]

            # Top IPs
            cursor.execute(
                """
                SELECT ip, COUNT(*) as count
                FROM sessions
                WHERE starttime >= ?
                GROUP BY ip
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_ips = [{"ip": row["ip"], "count": row["count"]} for row in cursor.fetchall()]

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
            }

        finally:
            conn.close()


# Global instance
sqlite_parser = SQLiteStatsParser()
