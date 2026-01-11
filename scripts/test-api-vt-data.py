#!/usr/bin/env python3
"""
Test script to check what VT data the API is returning.

Run this on the honeypot to see what data the API returns vs what's in the database.
"""

import json
import requests
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db"
API_URL = "http://cowrie-api:8000"

def check_api_response():
    """Check what the API returns for dashboard overview."""
    print("=" * 80)
    print("Testing API /api/v1/dashboard/overview endpoint")
    print("=" * 80)

    try:
        response = requests.get(f"{API_URL}/api/v1/dashboard/overview?hours=24", timeout=10)
        response.raise_for_status()
        data = response.json()

        print(f"\n✅ API responded with status {response.status_code}")
        print(f"\nTop downloads with VT data ({len(data.get('top_downloads_with_vt', []))} items):")
        print("-" * 80)

        for dl in data.get('top_downloads_with_vt', []):
            shasum = dl.get('shasum', 'unknown')[:16]
            file_cat = dl.get('file_category', 'unknown')
            file_type = dl.get('file_type', 'unknown')[:40]
            vt_det = dl.get('vt_detections', 0)
            vt_tot = dl.get('vt_total', 0)

            print(f"SHA: {shasum}... | {file_cat:12} | VT: {vt_det}/{vt_tot:2} | {file_type}")

        print("\n" + "=" * 80)
        return data

    except requests.RequestException as e:
        print(f"❌ API request failed: {e}")
        return None

def check_database_direct():
    """Check what's actually in the database using the same SQL query as the API."""
    print("\n" + "=" * 80)
    print("Querying database directly (same SQL as API uses)")
    print("=" * 80)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")

        # This is the EXACT query from api/routes/stats.py:143-167
        cursor.execute(
            """
            SELECT
                d.shasum,
                COUNT(d.id) as download_count,
                MAX(d.timestamp) as latest_download,
                m.file_size,
                m.file_type,
                COALESCE(m.file_category, 'unknown') as file_category,
                m.is_previewable,
                COALESCE(json_extract(vt.data, '$.positives'), 0) as vt_detections,
                COALESCE(json_extract(vt.data, '$.total'), 0) as vt_total,
                json_extract(vt.data, '$.threat_label') as vt_threat_label
            FROM downloads d
            LEFT JOIN download_meta m ON d.shasum = m.shasum
            LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
                AND json_extract(vt.data, '$.sha256') = d.shasum
                AND vt.timestamp >= ?
            WHERE d.timestamp >= ?
            GROUP BY d.shasum
            ORDER BY vt_detections DESC, download_count DESC
            LIMIT 10
            """,
            (cutoff, cutoff),
        )

        print(f"\nDirect SQL query results:")
        print("-" * 80)

        rows = cursor.fetchall()
        for row in rows:
            shasum = row['shasum'][:16] if row['shasum'] else 'unknown'
            file_cat = row['file_category']
            file_type = (row['file_type'] or 'unknown')[:40]
            vt_det = row['vt_detections']
            vt_tot = row['vt_total']

            print(f"SHA: {shasum}... | {file_cat:12} | VT: {vt_det}/{vt_tot:2} | {file_type}")

        conn.close()
        print("\n" + "=" * 80)

    except sqlite3.Error as e:
        print(f"❌ Database query failed: {e}")

def check_vt_events_for_hash(shasum):
    """Check if a specific hash has VT events."""
    print(f"\n" + "=" * 80)
    print(f"Checking VT events for hash: {shasum}")
    print("=" * 80)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Find all VT events for this hash
        cursor.execute(
            """
            SELECT timestamp, data
            FROM events
            WHERE eventid = 'cowrie.virustotal.scanfile'
            AND json_extract(data, '$.sha256') = ?
            ORDER BY timestamp DESC
            """,
            (shasum,)
        )

        rows = cursor.fetchall()
        print(f"\nFound {len(rows)} VT scan event(s) for this hash:")

        for timestamp, data_json in rows:
            data = json.loads(data_json)
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            scan_date = data.get('scan_date', 'unknown')

            print(f"  Timestamp: {timestamp}")
            print(f"  VT Score: {positives}/{total}")
            print(f"  Scan Date: {scan_date}")
            print(f"  Data: {json.dumps(data, indent=2)[:500]}...")
            print()

        if not rows:
            print("  ❌ No VT events found for this hash!")
            print("  This explains why it shows 0/0 on the dashboard")

        conn.close()

    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("\n" + "=" * 80)
    print("  API VT DATA TEST SCRIPT")
    print("=" * 80)

    # Test 1: Check API response
    api_data = check_api_response()

    # Test 2: Check database directly
    check_database_direct()

    # Test 3: Check specific hashes that show 0/0
    print("\n" + "=" * 80)
    print("Detailed investigation of specific hashes")
    print("=" * 80)

    problem_hashes = [
        "a8460f446be54041000439c44823c5f3a0d5ef77996471f6c85dd5d0e60649d1",
        "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        "1fdd5aec31db9c85e820c5e1d17c0a7e470c2c7f51c1c4c8c6b177d8c7d3e8f0",
        "51dbe032d7ef8d143e46b079e9d8a4d7e8c7b0e9c5f0e9d8c7b6e5f4d3c2b1a0",
    ]

    for shasum in problem_hashes:
        check_vt_events_for_hash(shasum)

    # Summary
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    print("""
If API and database queries match:
  → Problem is in dashboard rendering (template or data aggregation)

If they differ:
  → Problem is in API query logic

If database shows VT data but API returns 0/0:
  → Check API query WHERE clause (timestamp filtering?)
  → Check VT event timestamps vs download timestamps

If no VT events exist for certain hashes:
  → Those files were never scanned by VirusTotal
  → Check Cowrie logs for why VT scan didn't happen
""")

if __name__ == "__main__":
    main()
