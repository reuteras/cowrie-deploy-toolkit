"""
Cache services for API
"""

import json
import os
import sqlite3
from typing import Optional


class CacheDB:
    """Simple SQLite cache for VirusTotal results."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_vt_result(self, sha256: str) -> Optional[dict]:
        """Get cached VT result."""
        if not os.path.exists(self.db_path):
            return None

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT result FROM vt_cache WHERE sha256 = ?", (sha256,))
            row = cursor.fetchone()
            conn.close()

            if row and row[0]:
                return json.loads(row[0])
        except Exception:
            pass
        return None


class YARACache:
    """SQLite cache for YARA scan results and file type info."""

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
