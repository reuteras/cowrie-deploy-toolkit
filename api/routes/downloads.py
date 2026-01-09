"""
Downloads endpoints

Provides access to downloaded files (malware samples)
"""

import re
from datetime import datetime
from pathlib import Path

from config import config
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from services.cache import CacheDB, YARACache
from services.sqlite_parser import sqlite_parser

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


@router.get("/downloads")
async def get_downloads(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """
    Get list of downloaded files with VT and YARA metadata

    Returns list of files with SHA256 hashes and enriched metadata
    """
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH)

    if not downloads_path.exists():
        return {"total": 0, "downloads": []}

    # Initialize cache readers (for YARA data only)
    yara_cache = YARACache(config.YARA_CACHE_DB)

    # Get all files
    files = []
    for filepath in downloads_path.iterdir():
        if filepath.is_file():
            sha256 = filepath.name
            stat = filepath.stat()

            file_info = {
                "sha256": sha256,
                "size": stat.st_size,
                "first_seen": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "exists": True,
            }

            # Add VT data from database
            vt_data = sqlite_parser.get_vt_results(sha256)
            if vt_data:
                file_info["vt_detections"] = vt_data.get("detections", 0)
                file_info["vt_total"] = vt_data.get("total", 0)
                file_info["vt_threat_label"] = vt_data.get("threat_label", "")
                print(f"[DEBUG] API: Found VT data for {sha256}: {vt_data}")
            else:
                print(f"[DEBUG] API: No VT data for {sha256}")

            # Add YARA data
            yara_data = yara_cache.get_result(sha256)
            if yara_data:
                file_info["yara_matches"] = yara_data.get("matches", [])
                file_info["file_type"] = yara_data.get("file_type")
                file_info["file_category"] = yara_data.get("file_category")
                file_info["is_previewable"] = yara_data.get("is_previewable", False)

            files.append(file_info)

    # Sort by first seen (newest first)
    files.sort(key=lambda x: x["first_seen"], reverse=True)

    # Paginate
    total = len(files)
    paginated = files[offset : offset + limit]

    return {"total": total, "limit": limit, "offset": offset, "downloads": paginated}


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
