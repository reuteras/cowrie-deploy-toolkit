"""
Downloads endpoints

Provides access to downloaded files (malware samples)
"""

import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import config
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from services.cache import YARACache
from services.sqlite_parser import sqlite_parser

logger = logging.getLogger(__name__)
router = APIRouter()

# SECURITY: SHA256 validation regex (exactly 64 hexadecimal characters)
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def validate_sha256(sha256: str) -> str:
    """
    Validate and sanitize SHA256 hash parameter.

    SECURITY: Prevents path traversal attacks by ensuring the parameter
    is a valid SHA256 hash and cannot escape the downloads directory.

    Args:
        sha256: User-provided SHA256 hash parameter

    Returns:
        Validated SHA256 hash

    Raises:
        HTTPException: If the SHA256 is invalid or contains path traversal attempts
    """
    # Check for path traversal attempts
    if ".." in sha256 or "/" in sha256 or "\\" in sha256:
        raise HTTPException(status_code=400, detail="Invalid SHA256: path traversal detected")

    # Validate SHA256 format (exactly 64 hex characters)
    if not SHA256_REGEX.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256: must be 64 hexadecimal characters")

    return sha256.lower()  # Normalize to lowercase


def get_safe_download_path(sha256: str) -> Path:
    """
    Get a safe, validated path to a download file.

    SECURITY: Double-checks that the resolved path is within the downloads directory
    to prevent path traversal even if validation is bypassed.

    Args:
        sha256: Validated SHA256 hash

    Returns:
        Absolute, resolved path to the download file

    Raises:
        HTTPException: If the path escapes the downloads directory
    """
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH).resolve()
    filepath = (downloads_path / sha256).resolve()

    # SECURITY: Verify the resolved path is still within downloads directory
    # This prevents path traversal even with symlinks or other tricks
    try:
        filepath.relative_to(downloads_path)
    except ValueError as err:
        # Path is outside downloads directory - potential attack
        raise HTTPException(status_code=403, detail="Access denied: path traversal attempt detected") from err

    return filepath


def _table_exists(cursor, table_name: str) -> bool:
    """Check if a table exists in the database."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None


@router.get("/downloads")
async def get_downloads(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), hours: int = Query(24, ge=1)
):
    """
    Get list of downloaded files with VT and YARA metadata

    Returns list of files with SHA256 hashes and enriched metadata
    """
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH)

    if not downloads_path.exists():
        return {"total": 0, "downloads": []}

    # Query downloads with metadata directly from database
    if not sqlite_parser.available:
        return {"total": 0, "downloads": []}

    # Create database connection
    db_path = sqlite_parser.db_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Get downloads with metadata in the time range
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Check which optional tables exist
        has_download_meta = _table_exists(cursor, "download_meta")

        # Build query based on available tables
        if has_download_meta:
            # Full query with metadata
            query = """
                SELECT
                    d.shasum,
                    d.session,
                    d.timestamp,
                    d.url,
                    d.outfile,
                    COUNT(d.id) as download_count,
                    MAX(d.timestamp) as latest_download,
                    MIN(d.timestamp) as first_seen,
                    m.file_size,
                    m.file_type,
                    COALESCE(m.file_category, 'unknown') as file_category,
                    m.is_previewable,
                    COALESCE(json_extract(vt.data, '$.positives'), 0) as vt_detections,
                    COALESCE(json_extract(vt.data, '$.total'), 0) as vt_total,
                    json_extract(vt.data, '$.threat_label') as vt_threat_label,
                    s.src_ip
                FROM downloads d
                LEFT JOIN download_meta m ON d.shasum = m.shasum
                LEFT JOIN (
                    SELECT
                        json_extract(data, '$.sha256') as sha256,
                        data,
                        timestamp,
                        ROW_NUMBER() OVER (PARTITION BY json_extract(data, '$.sha256') ORDER BY timestamp DESC) as rn
                    FROM events
                    WHERE eventid = 'cowrie.virustotal.scanfile'
                ) vt ON vt.sha256 = d.shasum AND vt.rn = 1
                LEFT JOIN (
                    SELECT session, json_extract(data, '$.src_ip') as src_ip
                    FROM events
                    WHERE eventid = 'cowrie.session.connect'
                    GROUP BY session
                ) s ON s.session = d.session
                WHERE d.timestamp >= ? AND d.shasum IS NOT NULL
                GROUP BY d.shasum
                ORDER BY latest_download DESC
            """
        else:
            # Simplified query without download_meta table
            logger.info("download_meta table not found, using simplified query")
            query = """
                SELECT
                    d.shasum,
                    d.session,
                    d.timestamp,
                    d.url,
                    d.outfile,
                    COUNT(d.id) as download_count,
                    MAX(d.timestamp) as latest_download,
                    MIN(d.timestamp) as first_seen,
                    NULL as file_size,
                    NULL as file_type,
                    'unknown' as file_category,
                    0 as is_previewable,
                    COALESCE(json_extract(vt.data, '$.positives'), 0) as vt_detections,
                    COALESCE(json_extract(vt.data, '$.total'), 0) as vt_total,
                    json_extract(vt.data, '$.threat_label') as vt_threat_label,
                    s.src_ip
                FROM downloads d
                LEFT JOIN (
                    SELECT
                        json_extract(data, '$.sha256') as sha256,
                        data,
                        timestamp,
                        ROW_NUMBER() OVER (PARTITION BY json_extract(data, '$.sha256') ORDER BY timestamp DESC) as rn
                    FROM events
                    WHERE eventid = 'cowrie.virustotal.scanfile'
                ) vt ON vt.sha256 = d.shasum AND vt.rn = 1
                LEFT JOIN (
                    SELECT session, json_extract(data, '$.src_ip') as src_ip
                    FROM events
                    WHERE eventid = 'cowrie.session.connect'
                    GROUP BY session
                ) s ON s.session = d.session
                WHERE d.timestamp >= ? AND d.shasum IS NOT NULL
                GROUP BY d.shasum
                ORDER BY latest_download DESC
            """

        cursor.execute(query, (cutoff_str,))

        # Convert rows to list of dicts
        files = []
        for row in cursor.fetchall():
            file_info = {
                "shasum": row["shasum"],
                "sha256": row["shasum"],  # Alias for compatibility
                "session_id": row["session"],
                "src_ip": row["src_ip"],
                "timestamp": row["latest_download"],
                "first_seen": row["first_seen"],
                "count": row["download_count"],
                "url": row["url"],
                "outfile": row["outfile"],
                "size": row["file_size"],
                "file_type": row["file_type"],
                "file_category": row["file_category"],
                "is_previewable": bool(row["is_previewable"]),
                "vt_detections": row["vt_detections"],
                "vt_total": row["vt_total"],
                "vt_threat_label": row["vt_threat_label"],
                "exists": True,  # Will be updated below
                "yara_matches": [],  # Will be populated from YARA cache
            }
            files.append(file_info)

    finally:
        conn.close()

    # Add YARA matches and check file existence
    yara_cache = YARACache(config.YARA_CACHE_DB)
    for file_info in files:
        shasum = file_info["shasum"]

        # Get YARA matches from cache
        yara_data = yara_cache.get_result(shasum)
        if yara_data:
            file_info["yara_matches"] = yara_data.get("matches", [])
            # Update file metadata if not already set
            if not file_info["file_type"]:
                file_info["file_type"] = yara_data.get("file_type")
            if file_info["file_category"] == "unknown":
                file_info["file_category"] = yara_data.get("file_category", "unknown")
            if file_info["is_previewable"] is None:
                file_info["is_previewable"] = yara_data.get("is_previewable", False)

        # Check if file actually exists on disk
        file_path = downloads_path / shasum
        file_info["exists"] = file_path.exists()
        if not file_info["exists"] and file_info["size"] is None:
            file_info["size"] = 0

    # Sort by timestamp (newest first) - already sorted by query
    # files.sort(key=lambda x: x["timestamp"], reverse=True)

    # Paginate
    total = len(files)
    paginated = files[offset : offset + limit]

    result = {"total": total, "limit": limit, "offset": offset, "downloads": paginated}
    return result


@router.get("/downloads/{sha256}")
async def get_download_metadata(sha256: str):
    """Get metadata for a specific downloaded file"""
    # SECURITY: Validate SHA256 and get safe path
    validated_sha256 = validate_sha256(sha256)
    filepath = get_safe_download_path(validated_sha256)

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")

    stat = filepath.stat()

    return {
        "sha256": validated_sha256,
        "size": stat.st_size,
        "first_seen": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


@router.get("/downloads/{sha256}/content")
async def download_file(sha256: str):
    """Download the actual file content"""
    # SECURITY: Validate SHA256 and get safe path
    validated_sha256 = validate_sha256(sha256)
    filepath = get_safe_download_path(validated_sha256)

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")

    # SECURITY: Use validated filename to prevent header injection
    return FileResponse(filepath, media_type="application/octet-stream", filename=f"{validated_sha256}.bin")
