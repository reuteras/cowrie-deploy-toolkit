"""System information route for Cowrie API"""

import json
import os
import re
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


def get_cowrie_version_from_log():
    """
    Extract Cowrie version from log file.

    Parses cowrie.log for the version line that appears at startup:
    2026-01-11T09:12:37+0000 [-] Cowrie Version 2.9.6.dev6+ge73958d3e

    Returns:
        Version string or None if not found
    """
    # Try cowrie.log (text format, contains version line)
    # First try env var, then fallback paths
    log_paths = [
        os.getenv("COWRIE_LOG_PATH", ""),
        "/remote-cowrie-data/log/cowrie/cowrie.log",
        "/cowrie/cowrie-git/var/log/cowrie/cowrie.log",
        "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log",
    ]
    log_paths = [p for p in log_paths if p]  # Remove empty strings

    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue

        try:
            # Read last 200 lines (version is logged at startup)
            with open(log_path, "rb") as f:
                # Seek to near end of file
                f.seek(0, 2)  # Go to end
                file_size = f.tell()

                # Read last ~50KB (should contain recent startup)
                read_size = min(50000, file_size)
                f.seek(file_size - read_size)

                # Decode and search for version
                content = f.read().decode("utf-8", errors="ignore")

                # Look for "Cowrie Version X.Y.Z" pattern
                match = re.search(r"Cowrie Version ([\d\.]+(\.dev\d+)?(\+g[a-f0-9]+)?)", content)
                if match:
                    return match.group(1)

        except Exception as e:
            print(f"[!] Failed to read {log_path}: {e}")
            continue

    return None


@router.get("/system-info")
@router.get("/api/v1/system-info")  # Also register with full path for internal API calls
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

    # Try to get Cowrie version from log file first (most reliable)
    version_from_log = get_cowrie_version_from_log()
    if version_from_log:
        info["cowrie_version"] = version_from_log
        print(f"[+] Found Cowrie version from log: {version_from_log}")

    # Try to read metadata from Cowrie container (fallback)
    metadata_path = os.getenv("COWRIE_METADATA_PATH", "/cowrie-metadata/metadata.json")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                metadata = json.load(f)
                # Only use metadata version if we didn't find it in log
                if info["cowrie_version"] == "unknown":
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
