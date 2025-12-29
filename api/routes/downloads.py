"""
Downloads endpoints

Provides access to downloaded files (malware samples)
"""

from datetime import datetime
from pathlib import Path

from config import config
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/downloads")
async def get_downloads(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """
    Get list of downloaded files

    Returns list of files with SHA256 hashes and metadata
    """
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH)

    if not downloads_path.exists():
        return {"total": 0, "downloads": []}

    # Get all files
    files = []
    for filepath in downloads_path.iterdir():
        if filepath.is_file():
            stat = filepath.stat()
            files.append(
                {
                    "sha256": filepath.name,
                    "size": stat.st_size,
                    "first_seen": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            )

    # Sort by first seen (newest first)
    files.sort(key=lambda x: x["first_seen"], reverse=True)

    # Pagination
    total = len(files)
    paginated = files[offset : offset + limit]

    return {"total": total, "limit": limit, "offset": offset, "downloads": paginated}


@router.get("/downloads/{sha256}")
async def get_download_metadata(sha256: str):
    """Get metadata for a specific downloaded file"""
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH)
    filepath = downloads_path / sha256

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")

    stat = filepath.stat()

    return {
        "sha256": sha256,
        "size": stat.st_size,
        "first_seen": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


@router.get("/downloads/{sha256}/content")
async def download_file(sha256: str):
    """Download the actual file content"""
    downloads_path = Path(config.COWRIE_DOWNLOADS_PATH)
    filepath = downloads_path / sha256

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(filepath, media_type="application/octet-stream", filename=sha256)

