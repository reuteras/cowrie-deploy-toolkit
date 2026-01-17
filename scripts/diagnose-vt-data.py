#!/usr/bin/env python3
"""
Diagnostic script to check VirusTotal data and file type issues in Cowrie honeypot.

This script checks:
1. Event indexer service status
2. SQLite database state (events, downloads, download_meta)
3. VirusTotal configuration in Cowrie
4. Data consistency issues

Usage:
    uv run scripts/diagnose-vt-data.py
"""

import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta


def print_header(title):
    """Print a formatted section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def check_event_indexer():
    """Check if event indexer systemd service is running."""
    print_header("1. Event Indexer Service Status")

    try:
        result = subprocess.run(
            ["systemctl", "status", "cowrie-event-indexer"], capture_output=True, text=True, timeout=5
        )

        if "active (running)" in result.stdout:
            print("✅ Event indexer is RUNNING")
        elif "inactive (dead)" in result.stdout:
            print("❌ Event indexer is NOT running")
            print("\nTo start it:")
            print("  sudo systemctl start cowrie-event-indexer")
            print("  sudo systemctl enable cowrie-event-indexer")
        else:
            print("⚠️  Event indexer status unclear:")
            print(result.stdout[:500])

        # Check recent logs
        print("\nRecent logs (last 10 lines):")
        log_result = subprocess.run(
            ["journalctl", "-u", "cowrie-event-indexer", "-n", "10", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        print(log_result.stdout)

    except subprocess.TimeoutExpired:
        print("⚠️  Command timed out")
    except FileNotFoundError:
        print("⚠️  systemctl not found (not running on systemd?)")
    except Exception as e:
        print(f"❌ Error checking service: {e}")


def check_database(db_path):
    """Check SQLite database state."""
    print_header("2. SQLite Database State")

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    print(f"✅ Database exists: {db_path}")
    print(f"   Size: {os.path.getsize(db_path) / 1024 / 1024:.2f} MB")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check downloads table
        cursor.execute("SELECT COUNT(*) FROM downloads")
        download_count = cursor.fetchone()[0]
        print(f"\n📊 Downloads table: {download_count:,} total downloads")

        # Check unique downloads
        cursor.execute("SELECT COUNT(DISTINCT shasum) FROM downloads")
        unique_downloads = cursor.fetchone()[0]
        print(f"   Unique files: {unique_downloads:,}")

        # Check download_meta table
        cursor.execute("SELECT COUNT(*) FROM download_meta")
        meta_count = cursor.fetchone()[0]
        print(f"\n📋 Download metadata table: {meta_count:,} files with metadata")

        if meta_count < unique_downloads:
            print(f"   ⚠️  Missing metadata for {unique_downloads - meta_count} files")
            print("   Run event indexer to backfill")

        # Show sample metadata
        cursor.execute("""
            SELECT shasum, file_type, file_category, file_size
            FROM download_meta
            LIMIT 5
        """)
        print("\n   Sample metadata:")
        for row in cursor.fetchall():
            print(f"     {row[0][:16]}... | {row[2]:12} | {row[1][:40]}")

        # Check events table for VT scans
        cursor.execute("""
            SELECT COUNT(*)
            FROM events
            WHERE eventid = 'cowrie.virustotal.scanfile'
        """)
        vt_events = cursor.fetchone()[0]
        print(f"\n🔍 VirusTotal scan events: {vt_events:,}")

        if vt_events == 0:
            print("   ❌ NO VirusTotal scan events found!")
            print("   This means Cowrie is not scanning files with VirusTotal")
        else:
            # Show sample VT events
            cursor.execute("""
                SELECT data
                FROM events
                WHERE eventid = 'cowrie.virustotal.scanfile'
                LIMIT 3
            """)
            print("\n   Sample VT scan results:")
            for (data_json,) in cursor.fetchall():
                data = json.loads(data_json)
                sha = data.get("sha256", "unknown")[:16]
                pos = data.get("positives", 0)
                tot = data.get("total", 0)
                print(f"     {sha}... | {pos}/{tot} detections")

        # Check recent downloads (last 24h)
        cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM downloads
            WHERE timestamp >= ?
        """,
            (cutoff,),
        )
        recent_downloads = cursor.fetchone()[0]
        print(f"\n📅 Downloads in last 24 hours: {recent_downloads:,}")

        # Check if recent downloads have VT data
        cursor.execute(
            """
            SELECT d.shasum,
                   m.file_category,
                   m.file_type,
                   json_extract(vt.data, '$.positives') as vt_detections,
                   json_extract(vt.data, '$.total') as vt_total
            FROM downloads d
            LEFT JOIN download_meta m ON d.shasum = m.shasum
            LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
                AND json_extract(vt.data, '$.sha256') = d.shasum
            WHERE d.timestamp >= ?
            GROUP BY d.shasum
            LIMIT 10
        """,
            (cutoff,),
        )

        print("\n   Recent downloads with metadata:")
        print("   SHA256           | Category     | VT Score | File Type")
        print("   " + "-" * 70)
        for row in cursor.fetchall():
            sha = row[0][:16] if row[0] else "unknown"
            cat = row[1] or "unknown"
            ftype = row[2][:30] if row[2] else "unknown"
            vt_d = row[3] or 0
            vt_t = row[4] or 0
            print(f"   {sha}... | {cat:12} | {vt_d}/{vt_t}    | {ftype}")

        conn.close()

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")


def check_cowrie_config():
    """Check Cowrie VirusTotal configuration."""
    print_header("3. Cowrie VirusTotal Configuration")

    config_paths = [
        "/opt/cowrie/etc/cowrie.cfg",
        "/var/lib/docker/volumes/cowrie-etc/_data/cowrie.cfg",
    ]

    config_path = None
    for path in config_paths:
        if os.path.exists(path):
            config_path = path
            break

    if not config_path:
        print("❌ Could not find cowrie.cfg")
        return

    print(f"✅ Found config: {config_path}")

    try:
        with open(config_path) as f:
            content = f.read()

        # Check for VirusTotal section
        if "[output_virustotal]" in content:
            print("\n✅ VirusTotal output plugin section found")

            # Extract key settings
            lines = content.split("\n")
            in_vt_section = False
            for line in lines:
                if "[output_virustotal]" in line:
                    in_vt_section = True
                elif line.startswith("["):
                    in_vt_section = False
                elif in_vt_section and "=" in line and not line.strip().startswith("#"):
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    if key == "enabled":
                        if value.lower() == "true":
                            print(f"   ✅ enabled = {value}")
                        else:
                            print(f"   ❌ enabled = {value} (should be 'true')")
                    elif key == "api_key":
                        if value and value != "YOUR_API_KEY_HERE":
                            print(f"   ✅ api_key = {value[:8]}... (configured)")
                        else:
                            print(f"   ❌ api_key = {value} (not configured!)")
                    elif key in ["upload", "debug", "scan_file", "scan_url"]:
                        print(f"   {key} = {value}")
        else:
            print("\n❌ No [output_virustotal] section found in config")
            print("   VirusTotal scanning is not configured!")

    except Exception as e:
        print(f"❌ Error reading config: {e}")


def check_cowrie_logs():
    """Check recent Cowrie logs for VT activity."""
    print_header("4. Recent Cowrie Log Activity")

    log_paths = [
        "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json",
        "/opt/cowrie/var/log/cowrie/cowrie.json",
    ]

    log_path = None
    for path in log_paths:
        if os.path.exists(path):
            log_path = path
            break

    if not log_path:
        print("❌ Could not find cowrie.json log")
        return

    print(f"✅ Found log: {log_path}")

    try:
        # Read last 100 lines
        with open(log_path, "rb") as f:
            # Seek to end and read backwards
            f.seek(0, 2)  # End of file
            file_size = f.tell()

            # Read last 50KB (should contain many events)
            read_size = min(50000, file_size)
            f.seek(file_size - read_size)
            lines = f.read().decode("utf-8", errors="ignore").split("\n")

        # Count event types
        event_counts = {}
        vt_events = []
        download_events = []

        for line in lines[-1000:]:  # Last 1000 lines
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                eventid = event.get("eventid", "unknown")
                event_counts[eventid] = event_counts.get(eventid, 0) + 1

                if eventid == "cowrie.virustotal.scanfile":
                    vt_events.append(event)
                elif eventid == "cowrie.session.file_download":
                    download_events.append(event)
            except json.JSONDecodeError:
                continue

        print("\n📊 Event types in last 1000 log lines:")
        for eventid, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"   {eventid:40} | {count:,}")

        print(f"\n📥 Download events: {len(download_events)}")
        print(f"🔍 VirusTotal scan events: {len(vt_events)}")

        if download_events and not vt_events:
            print("\n⚠️  FILES ARE BEING DOWNLOADED but NOT scanned by VirusTotal!")
            print("   Check Cowrie VirusTotal configuration")

        if vt_events:
            print("\n   Recent VT scans:")
            for event in vt_events[-5:]:
                sha = event.get("sha256", "unknown")[:16]
                pos = event.get("positives", 0)
                tot = event.get("total", 0)
                print(f"     {sha}... | {pos}/{tot} detections")

    except Exception as e:
        print(f"❌ Error reading logs: {e}")


def main():
    """Main diagnostic routine."""
    print("\n" + "=" * 80)
    print("  COWRIE VIRUSTOTAL DATA DIAGNOSTIC TOOL")
    print("=" * 80)

    # Detect database path
    db_paths = [
        "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db",
        "/opt/cowrie/var/lib/cowrie/cowrie.db",
    ]

    db_path = None
    for path in db_paths:
        if os.path.exists(path):
            db_path = path
            break

    if not db_path:
        print("\n❌ Could not find cowrie.db database!")
        print("   Searched:")
        for path in db_paths:
            print(f"     - {path}")
        sys.exit(1)

    # Run diagnostics
    check_event_indexer()
    check_database(db_path)
    check_cowrie_config()
    check_cowrie_logs()

    # Summary
    print_header("Summary & Recommendations")
    print("""
If you see VT scores as 0/0:
  1. Check if VirusTotal is enabled in cowrie.cfg
  2. Verify API key is configured correctly
  3. Ensure event indexer is running
  4. Check if Cowrie logs show VT scan events
  5. Restart Cowrie container if config was changed

If file types show generic "script", "data":
  1. This is expected - front page shows file_category (generic)
  2. Downloads page shows detailed file_type
  3. Fix: Update front page template to show detailed types

To fix immediately:
  1. SSH to honeypot: ssh -p 2222 root@<HONEYPOT_IP>
  2. Run this diagnostic: cd /opt/cowrie && uv run scripts/diagnose-vt-data.py
  3. Fix issues based on output above
  4. Restart services:
     - systemctl restart cowrie-event-indexer
     - cd /opt/cowrie && docker compose restart
""")


if __name__ == "__main__":
    main()
