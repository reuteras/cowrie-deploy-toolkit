"""
Health check endpoints
"""

import json
import os
import time
from pathlib import Path

from config import config
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint
    Returns API status and data availability
    """
    return {
        "status": "healthy",
        "version": "2.1.0",
        "data_sources": {
            "cowrie_log": Path(config.COWRIE_LOG_PATH).exists() or Path(config.COWRIE_LOG_PATH).parent.exists(),
            "tty_recordings": Path(config.COWRIE_TTY_PATH).exists(),
            "downloads": Path(config.COWRIE_DOWNLOADS_PATH).exists(),
        },
    }


@router.get("/api/v1/info")
async def get_info():
    """
    Get API information and configuration
    """
    return {
        "name": "Cowrie API",
        "version": "2.1.0",
        "description": "REST API for Cowrie honeypot data",
        "endpoints": {
            "health": "/health",
            "sessions": "/api/v1/sessions",
            "downloads": "/api/v1/downloads",
            "stats": "/api/v1/stats/overview",
            "threat_intel": "/api/v1/threat/ip/{ip}",
            "system_info": "/api/v1/system-info",
        },
    }


@router.get("/api/v1/system-info")
async def get_system_info():
    """
    Get honeypot system information (metadata, version, etc.)
    """
    info = {
        "server_ip": os.getenv("SERVER_IP", ""),
        "honeypot_hostname": os.getenv("HONEYPOT_HOSTNAME", ""),
        "cowrie_version": "unknown",
        "git_commit": None,
        "build_date": None,
        "uptime_seconds": None,
    }

    # Try to read metadata from Cowrie container
    metadata_path = os.getenv("COWRIE_METADATA_PATH", "/cowrie-metadata/metadata.json")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                metadata = json.load(f)
                info["cowrie_version"] = metadata.get("cowrie_version", "unknown")
                info["git_commit"] = metadata.get("git_commit")
                info["build_date"] = metadata.get("build_date")

                # Calculate uptime from build timestamp
                build_ts = metadata.get("build_timestamp")
                if build_ts:
                    info["uptime_seconds"] = int(time.time() - build_ts)
        except Exception as e:
            print(f"[!] Failed to read metadata: {e}")

    return info
