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


def get_cowrie_version_from_log():
    """
    Extract Cowrie version from log file.

    Parses cowrie.log for the version line that appears at startup:
    2026-01-11T09:12:37+0000 [-] Cowrie Version 2.9.6.dev6+ge73958d3e

    Returns:
        Version string or None if not found
    """
    # Try cowrie.log (text format, contains version line)
    log_paths = [
        "/cowrie/cowrie-git/var/log/cowrie/cowrie.log",
        "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.log",
    ]

    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue

        try:
            # Read last 200 lines (version is logged at startup)
            with open(log_path, 'rb') as f:
                # Seek to near end of file
                f.seek(0, 2)  # Go to end
                file_size = f.tell()

                # Read last ~50KB (should contain recent startup)
                read_size = min(50000, file_size)
                f.seek(file_size - read_size)

                # Decode and search for version
                content = f.read().decode('utf-8', errors='ignore')

                # Look for "Cowrie Version X.Y.Z" pattern
                import re
                match = re.search(r'Cowrie Version ([\d\.]+(\.dev\d+)?(\+g[a-f0-9]+)?)', content)
                if match:
                    return match.group(1)

        except Exception as e:
            print(f"[!] Failed to read {log_path}: {e}")
            continue

    return None


@router.get("/api/v1/system-info")
async def get_system_info():
    """
    Get honeypot system information (metadata, version, identity, SSH config, etc.)
    """
    info = {
        "server_ip": os.getenv("SERVER_IP", ""),
        "honeypot_hostname": os.getenv("HONEYPOT_HOSTNAME", ""),
        "cowrie_version": "unknown",
        "git_commit": None,
        "build_date": None,
        "uptime_seconds": None,
        "kernel": None,
        "arch": None,
        "os_release": None,
        "debian_version": None,
        "ssh_banner": None,
        "ssh_ciphers": [],
        "ssh_macs": [],
        "ssh_kex": [],
        "ssh_keys": [],
        "userdb_entries": [],
        "userdb_path": None,
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
        except Exception as e:
            print(f"[!] Failed to read metadata: {e}")

    # Read identity data
    identity_path = os.getenv("IDENTITY_PATH", "/identity")

    def read_identity_file(filename):
        """Read single-line identity file"""
        path = Path(identity_path) / filename
        if path.exists():
            try:
                return path.read_text().strip()
            except Exception as e:
                print(f"[!] Failed to read {filename}: {e}")
        return None

    def read_identity_lines(filename):
        """Read multi-line identity file"""
        path = Path(identity_path) / filename
        if path.exists():
            try:
                return [line.strip() for line in path.read_text().splitlines() if line.strip()]
            except Exception as e:
                print(f"[!] Failed to read {filename}: {e}")
        return []

    # Read basic identity
    info["kernel"] = read_identity_file("kernel.txt")
    info["ssh_banner"] = read_identity_file("ssh-banner.txt")
    info["debian_version"] = read_identity_file("debian_version")

    # Read OS release
    os_release_content = read_identity_file("os-release")
    if os_release_content:
        for line in os_release_content.split("\n"):
            if line.startswith("PRETTY_NAME="):
                info["os_release"] = line.split("=", 1)[1].strip('"')
                break

    # Extract architecture from kernel
    if info["kernel"]:
        parts = info["kernel"].split()
        if len(parts) >= 3:
            info["arch"] = parts[-1]

    # Read SSH configuration
    info["ssh_ciphers"] = read_identity_lines("ssh-ciphers.txt")
    info["ssh_macs"] = read_identity_lines("ssh-mac.txt")
    info["ssh_kex"] = read_identity_lines("ssh-kex.txt")
    info["ssh_keys"] = read_identity_lines("ssh-key.txt")

    # Read userdb.txt (authentication database)
    userdb_locations = [
        "/cowrie-etc/userdb.txt",
        "/cowrie-data/etc/userdb.txt",
        Path(identity_path) / "userdb.txt",
    ]

    for userdb_path in userdb_locations:
        userdb_path_obj = Path(userdb_path) if not isinstance(userdb_path, Path) else userdb_path
        if userdb_path_obj.exists():
            try:
                userdb_lines = [
                    line.strip()
                    for line in userdb_path_obj.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                info["userdb_entries"] = userdb_lines
                info["userdb_path"] = str(userdb_path_obj)
                break
            except Exception as e:
                print(f"[!] Failed to read {userdb_path}: {e}")

    return info
