"""System information route for Cowrie API"""

import json
import os
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/system-info")
async def get_system_info():
    """Get honeypot system information"""
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
        except Exception:
            pass

    return JSONResponse(content=info)
