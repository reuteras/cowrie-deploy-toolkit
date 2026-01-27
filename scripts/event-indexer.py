#!/usr/bin/env python3
"""
Cowrie Event Indexer Daemon

Continuously monitors Cowrie JSON logs and indexes events into SQLite database
for fast querying. Handles log rotation and backfills from rotated logs.

This daemon runs as a systemd service and provides:
- Real-time event indexing from JSON logs
- Automatic handling of log rotation
- Backfill from rotated/archived logs on startup
- Gap detection and recovery
"""

import argparse
import glob
import gzip
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# Optional: requests for VT API
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Paths (container mount paths)
DEFAULT_DB_PATH = "/cowrie-data/lib/cowrie/cowrie.db"
DEFAULT_LOG_PATH = "/cowrie-data/log/cowrie/cowrie.json"
DEFAULT_LOG_DIR = "/cowrie-data/log/cowrie"

# VT retry configuration
VT_RETRY_DELAYS = [60, 300, 900, 3600, 7200]  # 1min, 5min, 15min, 1hr, 2hr
VT_MAX_RETRIES = len(VT_RETRY_DELAYS)
VT_RATE_LIMIT_DELAY = 15.5  # VT free tier: 4 requests/minute


class VirusTotalScanner:
    """
    VirusTotal scanner for downloaded files.

    Handles VT API queries with rate limiting, caching, and retry logic for
    files that are new to VT's database.
    """

    def __init__(self, api_key: str, conn: sqlite3.Connection):
        """
        Initialize VT scanner.

        Args:
            api_key: VirusTotal API key
            conn: SQLite database connection
        """
        self.api_key = api_key
        self.conn = conn
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = 0
        self._lock = threading.Lock()

    def _rate_limit(self):
        """Enforce VT API rate limiting (4 requests/minute for free tier)."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < VT_RATE_LIMIT_DELAY:
                sleep_time = VT_RATE_LIMIT_DELAY - elapsed
                print(f"[VT] Rate limiting: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
            self.last_request_time = time.time()

    def is_already_scanned(self, shasum: str) -> bool:
        """Check if file has already been scanned."""
        cursor = self.conn.execute("SELECT 1 FROM virustotal_scans WHERE shasum = ?", (shasum,))
        return cursor.fetchone() is not None

    def is_pending(self, shasum: str) -> bool:
        """Check if file is in pending queue."""
        cursor = self.conn.execute("SELECT 1 FROM virustotal_pending WHERE shasum = ?", (shasum,))
        return cursor.fetchone() is not None

    def scan_file(self, shasum: str, session: str = None, src_ip: str = None) -> Optional[dict]:
        """
        Scan a file hash with VirusTotal.

        Args:
            shasum: SHA256 hash of file
            session: Cowrie session ID (for context)
            src_ip: Source IP (for context)

        Returns:
            Scan result dict, or None if failed/rate-limited
        """
        if not self.api_key or not REQUESTS_AVAILABLE:
            return None

        # Skip if already scanned
        if self.is_already_scanned(shasum):
            print(f"[VT] {shasum[:16]}... already scanned, skipping")
            return None

        # Apply rate limiting
        self._rate_limit()

        headers = {"x-apikey": self.api_key}

        try:
            print(f"[VT] Querying {shasum[:16]}...")
            response = requests.get(
                f"{self.base_url}/files/{shasum}",
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                # File found in VT database
                data = response.json()
                attributes = data["data"]["attributes"]

                result = self._parse_vt_response(shasum, attributes)
                self._store_scan_result(result)

                # Remove from pending if it was there
                self._remove_from_pending(shasum)

                print(f"[VT] {shasum[:16]}... detected: {result['positives']}/{result['total']}")
                return result

            elif response.status_code == 404:
                # File not found - new to VT
                print(f"[VT] {shasum[:16]}... not found in VT (new file)")
                self._add_to_pending(shasum, session, src_ip, "File not found in VT")
                return {"is_new": True, "shasum": shasum}

            elif response.status_code == 429:
                # Rate limited
                print("[VT] Rate limited by VT API, will retry later")
                self._add_to_pending(shasum, session, src_ip, "Rate limited")
                return None

            else:
                print(f"[VT] API error: HTTP {response.status_code}")
                self._add_to_pending(shasum, session, src_ip, f"HTTP {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[VT] Request timeout for {shasum[:16]}...")
            self._add_to_pending(shasum, session, src_ip, "Timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[VT] Request error: {e}")
            self._add_to_pending(shasum, session, src_ip, str(e))
            return None

    def _parse_vt_response(self, shasum: str, attributes: dict) -> dict:
        """Parse VT API response into our schema."""
        stats = attributes.get("last_analysis_stats", {})

        result = {
            "shasum": shasum,
            "positives": stats.get("malicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "scan_date": attributes.get("last_analysis_date"),
            "permalink": f"https://www.virustotal.com/gui/file/{shasum}",
            "is_new": False,
        }

        # Extract threat classification
        threat_class = attributes.get("popular_threat_classification", {})
        if threat_class:
            if "suggested_threat_label" in threat_class:
                result["threat_label"] = threat_class["suggested_threat_label"]

            if "popular_threat_category" in threat_class:
                categories = threat_class["popular_threat_category"]
                if categories:
                    result["threat_categories"] = json.dumps(
                        [{"name": c["value"], "count": c["count"]} for c in categories]
                    )

        # Extract family labels from tags
        if "tags" in attributes and attributes["tags"]:
            result["family_labels"] = json.dumps(attributes["tags"])

        return result

    def _store_scan_result(self, result: dict):
        """Store VT scan result in database."""
        self.conn.execute(
            """
            INSERT OR REPLACE INTO virustotal_scans
            (shasum, positives, total, scan_date, threat_label, threat_categories,
             family_labels, permalink, is_new, scanned_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                result["shasum"],
                result.get("positives", 0),
                result.get("total", 0),
                result.get("scan_date"),
                result.get("threat_label"),
                result.get("threat_categories"),
                result.get("family_labels"),
                result.get("permalink"),
                result.get("is_new", False),
            ),
        )
        self.conn.commit()

    def _add_to_pending(self, shasum: str, session: str, src_ip: str, error: str):
        """Add file to pending scan queue."""
        # Check if already pending
        cursor = self.conn.execute("SELECT retry_count FROM virustotal_pending WHERE shasum = ?", (shasum,))
        row = cursor.fetchone()

        if row:
            # Already pending, update retry info
            retry_count = row[0]
            if retry_count >= VT_MAX_RETRIES:
                print(f"[VT] {shasum[:16]}... max retries reached, marking as new")
                # Store as "new to VT" result
                self._store_scan_result(
                    {
                        "shasum": shasum,
                        "positives": 0,
                        "total": 0,
                        "is_new": True,
                    }
                )
                self._remove_from_pending(shasum)
                return

            # Calculate next retry time
            delay = VT_RETRY_DELAYS[min(retry_count, len(VT_RETRY_DELAYS) - 1)]
            next_retry = datetime.now() + timedelta(seconds=delay)

            self.conn.execute(
                """
                UPDATE virustotal_pending
                SET retry_count = retry_count + 1,
                    next_retry_at = ?,
                    last_error = ?
                WHERE shasum = ?
                """,
                (next_retry.isoformat(), error, shasum),
            )
        else:
            # New pending entry
            next_retry = datetime.now() + timedelta(seconds=VT_RETRY_DELAYS[0])
            self.conn.execute(
                """
                INSERT INTO virustotal_pending
                (shasum, first_seen, retry_count, next_retry_at, last_error, session, src_ip)
                VALUES (?, CURRENT_TIMESTAMP, 0, ?, ?, ?, ?)
                """,
                (shasum, next_retry.isoformat(), error, session, src_ip),
            )

        self.conn.commit()
        print(f"[VT] {shasum[:16]}... added to pending queue")

    def _remove_from_pending(self, shasum: str):
        """Remove file from pending queue."""
        self.conn.execute("DELETE FROM virustotal_pending WHERE shasum = ?", (shasum,))
        self.conn.commit()

    def process_pending_scans(self) -> int:
        """
        Process pending VT scans that are due for retry.

        Returns:
            Number of scans processed
        """
        now = datetime.now().isoformat()
        cursor = self.conn.execute(
            """
            SELECT shasum, session, src_ip, retry_count
            FROM virustotal_pending
            WHERE next_retry_at <= ?
            ORDER BY next_retry_at ASC
            LIMIT 10
            """,
            (now,),
        )

        pending = cursor.fetchall()
        if not pending:
            return 0

        processed = 0
        for shasum, session, src_ip, retry_count in pending:
            print(f"[VT] Retrying {shasum[:16]}... (attempt {retry_count + 1})")
            result = self.scan_file(shasum, session, src_ip)
            if result and not result.get("is_new"):
                processed += 1

        return processed


class EventIndexer:
    """Indexes Cowrie JSON events into SQLite for fast queries."""

    def __init__(
        self, db_path: str = DEFAULT_DB_PATH, log_path: str = DEFAULT_LOG_PATH, log_dir: str = DEFAULT_LOG_DIR
    ):
        """
        Initialize event indexer.

        Args:
            db_path: Path to cowrie.db SQLite database
            log_path: Path to current cowrie.json log file
            log_dir: Directory containing log files (for rotation)
        """
        self.db_path = db_path
        self.log_path = log_path
        self.log_dir = log_dir
        self.running = True
        self.conn = None

        # VT scanner (initialized after DB connection)
        self.vt_scanner: Optional[VirusTotalScanner] = None
        self.vt_api_key = self._load_vt_api_key()
        self.vt_enabled = bool(self.vt_api_key) and REQUESTS_AVAILABLE
        self._vt_thread: Optional[threading.Thread] = None

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _load_vt_api_key(self) -> str:
        """
        Load VT API key from environment or report.env file.

        Checks in order:
        1. VT_API_KEY environment variable
        2. /opt/cowrie/etc/report.env file

        Returns:
            VT API key string, or empty string if not found
        """
        # First check environment variable
        api_key = os.environ.get("VT_API_KEY", "")
        if api_key:
            return api_key

        # Try to read from report.env file
        report_env_path = Path("/opt/cowrie/etc/report.env")
        if report_env_path.exists():
            try:
                with open(report_env_path) as f:
                    for line in f:
                        line = line.strip()
                        # Parse lines like: export VT_API_KEY="value"
                        if line.startswith("export VT_API_KEY="):
                            # Remove 'export ' prefix and parse the value
                            assignment = line[7:]  # Remove 'export '
                            if "=" in assignment:
                                key, value = assignment.split("=", 1)
                                # Remove quotes if present
                                value = value.strip().strip('"').strip("'")
                                if value:
                                    print(f"[EventIndexer] Loaded VT_API_KEY from {report_env_path}")
                                    return value
            except Exception as e:
                print(f"[!] Error reading {report_env_path}: {e}")

        return ""

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"[EventIndexer] Received signal {signum}, shutting down...")
        self.running = False

    def _init_db(self):
        """Initialize database schema if not exists."""
        print(f"[EventIndexer] Initializing database at {self.db_path}")

        # Read schema file
        schema_path = Path(__file__).parent.parent / "api" / "sql" / "events_schema.sql"
        if not schema_path.exists():
            print(f"[!] Schema file not found: {schema_path}")
            sys.exit(1)

        with open(schema_path) as f:
            schema = f.read()

        # Execute schema
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.executescript(schema)
        self.conn.commit()
        print("[EventIndexer] Database schema initialized")

        # Initialize VT scanner if enabled
        if self.vt_enabled:
            self.vt_scanner = VirusTotalScanner(self.vt_api_key, self.conn)
            print("[EventIndexer] VirusTotal scanning enabled")
        else:
            if not REQUESTS_AVAILABLE:
                print("[EventIndexer] VT scanning disabled (requests module not available)")
            elif not self.vt_api_key:
                print("[EventIndexer] VT scanning disabled (VT_API_KEY not set)")

    def _index_event(self, event: dict) -> bool:
        """
        Index a single event into the database.

        Args:
            event: Event dictionary from JSON log

        Returns:
            True if indexed successfully, False otherwise
        """
        session = event.get("session")
        timestamp = event.get("timestamp")
        eventid = event.get("eventid")
        src_ip = event.get("src_ip")

        if not session or not timestamp or not eventid:
            return False

        try:
            self.conn.execute(
                """
                INSERT INTO events (session, timestamp, eventid, src_ip, data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session, timestamp, eventid, src_ip, json.dumps(event)),
            )

            # Check for download events and detect file metadata
            if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                self._detect_file_metadata(event)

            return True
        except sqlite3.IntegrityError:
            # Duplicate event, skip
            return False
        except Exception as e:
            print(f"[!] Error indexing event: {e}")
            return False

    def _detect_file_metadata(self, event: dict) -> None:
        """
        Detect and store file metadata for download/upload events.

        Also ensures the file is in the downloads table (Cowrie's SQLite plugin
        doesn't always populate this for file_upload events).

        Args:
            event: Download/upload event dictionary
        """
        try:
            # Get file path from event
            shasum = event.get("shasum")
            if not shasum:
                return

            # Ensure file is in downloads table (Cowrie may not add file_upload events)
            session = event.get("session", "")
            timestamp = event.get("timestamp", "")
            url = event.get("url", "")  # file_download has url
            filename = event.get("filename", "")  # file_upload has filename
            outfile = event.get("outfile", "")

            # Use filename as url for uploads if url is empty
            if not url and filename:
                url = f"upload://{filename}"

            try:
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO downloads (session, timestamp, url, outfile, shasum)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (session, timestamp, url, outfile, shasum),
                )
            except sqlite3.Error as e:
                print(f"[!] Error inserting into downloads table: {e}")

            # Construct file path (assuming downloads are in lib/cowrie/downloads/)
            downloads_dir = Path(self.db_path).parent / "downloads"
            file_path = downloads_dir / shasum

            if not file_path.exists():
                print(f"[!] File not found for metadata detection: {file_path}")
                return

            # Get file size
            file_size = file_path.stat().st_size

            # Detect MIME type using file command
            try:
                result = subprocess.run(
                    ["file", "--mime-type", "-b", str(file_path)], capture_output=True, text=True, timeout=10
                )

                if result.returncode == 0:
                    mime_type = result.stdout.strip()
                else:
                    mime_type = "application/octet-stream"  # Default
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                mime_type = "application/octet-stream"

            # Map MIME type to category
            file_category, is_previewable = self._map_mime_to_category(mime_type)

            # Store metadata in database
            self.conn.execute(
                """
                INSERT OR REPLACE INTO download_meta
                (shasum, file_size, file_type, file_category, is_previewable, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (shasum, file_size, mime_type, file_category, is_previewable),
            )

            print(f"[EventIndexer] Stored metadata for {shasum}: {file_category} ({mime_type})")

            # Trigger VT scan if enabled
            if self.vt_scanner:
                session = event.get("session")
                src_ip = event.get("src_ip")
                self.vt_scanner.scan_file(shasum, session, src_ip)

        except Exception as e:
            print(f"[!] Error detecting file metadata: {e}")

    def _map_mime_to_category(self, mime_type: str) -> tuple[str, bool]:
        """
        Map MIME type to file category and previewability.

        Args:
            mime_type: MIME type string

        Returns:
            Tuple of (category, is_previewable)
        """
        if mime_type.startswith("application/"):
            if any(
                exe in mime_type
                for exe in [
                    "executable",
                    "x-dosexec",
                    "x-elf",
                    "x-mach-binary",
                    "x-sharedlib",
                    "x-object",
                    "x-pie-executable",
                ]
            ):
                return "executable", False
            elif any(fmt in mime_type for fmt in ["zip", "gzip", "tar", "x-tar", "x-gzip"]):
                return "archive", False
            elif any(doc in mime_type for doc in ["pdf", "document", "word", "excel"]):
                return "document", True
            else:
                return "data", False
        elif mime_type.startswith("text/"):
            return "script", True
        elif mime_type.startswith("image/"):
            return "image", False
        else:
            return "unknown", False

    def _get_rotated_logs(self) -> list:
        """
        Get list of rotated log files in chronological order.

        Returns:
            List of log file paths (oldest first)
        """
        log_files = []

        # Find all cowrie.json* files (including .gz)
        pattern = os.path.join(self.log_dir, "cowrie.json*")
        all_logs = glob.glob(pattern)

        # Sort by modification time (oldest first)
        all_logs.sort(key=lambda x: os.path.getmtime(x))

        # Filter out the current log file
        for log in all_logs:
            if log != self.log_path:
                log_files.append(log)

        return log_files

    def _backfill_from_file(self, filepath: str) -> int:
        """
        Backfill events from a log file.

        Args:
            filepath: Path to log file (can be .gz)

        Returns:
            Number of events indexed
        """
        print(f"[EventIndexer] Backfilling from {filepath}")
        count = 0
        errors = 0

        # Determine if file is gzipped
        open_func = gzip.open if filepath.endswith(".gz") else open
        mode = "rt" if filepath.endswith(".gz") else "r"

        try:
            with open_func(filepath, mode) as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if self._index_event(event):
                            count += 1

                            # Commit every 1000 events for performance
                            if count % 1000 == 0:
                                self.conn.commit()
                                print(f"[EventIndexer] Indexed {count} events from {os.path.basename(filepath)}...")

                    except json.JSONDecodeError:
                        errors += 1
                        continue

            # Final commit
            self.conn.commit()

        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

        if errors > 0:
            print(f"[EventIndexer] Skipped {errors} invalid lines in {filepath}")

        return count

    def backfill(self):
        """Backfill events from rotated logs if needed."""
        print("[EventIndexer] Checking for rotated logs to backfill...")

        rotated_logs = self._get_rotated_logs()
        if not rotated_logs:
            print("[EventIndexer] No rotated logs found")
            return

        print(f"[EventIndexer] Found {len(rotated_logs)} rotated log files")

        total_indexed = 0
        for log_file in rotated_logs:
            count = self._backfill_from_file(log_file)
            total_indexed += count

        print(f"[EventIndexer] Backfill complete: {total_indexed} events indexed")

        # Backfill downloads table from file events (Cowrie may not populate for uploads)
        self._backfill_downloads_table()

        # Backfill missing download metadata
        self._backfill_download_metadata()

    def _backfill_downloads_table(self):
        """Backfill downloads table from file events in events table."""
        print("[EventIndexer] Checking for file events not in downloads table...")

        try:
            # Find file events that aren't in downloads table
            cursor = self.conn.execute(
                """
                SELECT DISTINCT
                    e.session,
                    e.timestamp,
                    json_extract(e.data, '$.url') as url,
                    json_extract(e.data, '$.filename') as filename,
                    json_extract(e.data, '$.outfile') as outfile,
                    json_extract(e.data, '$.shasum') as shasum
                FROM events e
                LEFT JOIN downloads d ON json_extract(e.data, '$.shasum') = d.shasum
                WHERE e.eventid IN ('cowrie.session.file_download', 'cowrie.session.file_upload')
                AND json_extract(e.data, '$.shasum') IS NOT NULL
                AND d.shasum IS NULL
                """
            )

            missing = cursor.fetchall()

            if not missing:
                print("[EventIndexer] All file events are in downloads table")
                return

            print(f"[EventIndexer] Found {len(missing)} file events not in downloads table")

            for session, timestamp, url, filename, outfile, shasum in missing:
                # Use filename as url for uploads if url is empty
                if not url and filename:
                    url = f"upload://{filename}"

                try:
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO downloads (session, timestamp, url, outfile, shasum)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (session, timestamp, url or "", outfile or "", shasum),
                    )
                except sqlite3.Error as e:
                    print(f"[!] Error inserting into downloads: {e}")

            self.conn.commit()
            print(f"[EventIndexer] Backfilled {len(missing)} entries to downloads table")

        except Exception as e:
            print(f"[!] Error during downloads table backfill: {e}")

    def _backfill_download_metadata(self):
        """Backfill metadata for downloads that don't have it."""
        print("[EventIndexer] Checking for downloads missing metadata...")

        try:
            # Find downloads without metadata
            cursor = self.conn.execute(
                """
                SELECT d.shasum FROM downloads d
                LEFT JOIN download_meta m ON d.shasum = m.shasum
                WHERE m.shasum IS NULL
                """
            )

            missing_shasums = [row[0] for row in cursor.fetchall()]

            if not missing_shasums:
                print("[EventIndexer] All downloads have metadata")
                return

            print(f"[EventIndexer] Found {len(missing_shasums)} downloads missing metadata")

            # Process in batches to avoid overwhelming the system
            batch_size = 50
            processed = 0

            for i in range(0, len(missing_shasums), batch_size):
                batch = missing_shasums[i : i + batch_size]

                for shasum in batch:
                    # Create a mock event for metadata detection
                    mock_event = {
                        "eventid": "cowrie.session.file_download",
                        "shasum": shasum,
                        "timestamp": "2026-01-01T00:00:00.000000Z",  # Placeholder
                        "session": "backfill",
                        "src_ip": "127.0.0.1",
                    }
                    self._detect_file_metadata(mock_event)
                    processed += 1

                print(f"[EventIndexer] Processed {processed}/{len(missing_shasums)} missing metadata entries")
                self.conn.commit()  # Commit batch

            print(f"[EventIndexer] Metadata backfill complete: {processed} entries processed")

        except Exception as e:
            print(f"[!] Error during metadata backfill: {e}")

    def _vt_pending_worker(self):
        """
        Background worker to process pending VT scans.

        Runs every 30 seconds to check for pending scans that are due for retry.
        """
        print("[VT] Starting pending scan worker thread")

        while self.running:
            try:
                if self.vt_scanner:
                    processed = self.vt_scanner.process_pending_scans()
                    if processed > 0:
                        print(f"[VT] Processed {processed} pending scans")
            except Exception as e:
                print(f"[VT] Error processing pending scans: {e}")

            # Sleep for 30 seconds, but check running flag frequently
            for _ in range(30):
                if not self.running:
                    break
                time.sleep(1)

        print("[VT] Pending scan worker thread stopped")

    def _backfill_vt_scans(self):
        """Backfill VT scans for downloads that don't have scan results."""
        if not self.vt_scanner:
            return

        print("[VT] Checking for downloads missing VT scans...")

        try:
            # Find downloads without VT scans (excluding those in pending queue)
            cursor = self.conn.execute(
                """
                SELECT DISTINCT d.shasum, d.session, e.src_ip
                FROM downloads d
                LEFT JOIN events e ON d.session = e.session
                    AND e.eventid = 'cowrie.session.connect'
                LEFT JOIN virustotal_scans v ON d.shasum = v.shasum
                LEFT JOIN virustotal_pending p ON d.shasum = p.shasum
                WHERE v.shasum IS NULL AND p.shasum IS NULL
                LIMIT 100
                """
            )

            missing = cursor.fetchall()

            if not missing:
                print("[VT] All downloads have VT scan results or are pending")
                return

            print(f"[VT] Found {len(missing)} downloads missing VT scans")

            for shasum, session, src_ip in missing:
                if not self.running:
                    break
                self.vt_scanner.scan_file(shasum, session, src_ip)

            print("[VT] VT scan backfill complete")

        except Exception as e:
            print(f"[!] Error during VT scan backfill: {e}")

    def _tail_file(self, filepath: str):
        """
        Tail a file and index new events in real-time.

        Args:
            filepath: Path to log file to tail
        """
        print(f"[EventIndexer] Tailing {filepath}")

        # Seek to end of file
        with open(filepath) as f:
            # Go to end of file
            f.seek(0, 2)
            file_size = f.tell()
            print(f"[EventIndexer] Starting from position {file_size}")

            while self.running:
                line = f.readline()

                if line:
                    # Process new line
                    try:
                        event = json.loads(line.strip())
                        if self._index_event(event):
                            self.conn.commit()
                    except json.JSONDecodeError:
                        continue
                else:
                    # No new data, check if file was rotated
                    current_size = os.path.getsize(filepath)
                    if current_size < file_size:
                        # File was rotated/truncated, reopen
                        print("[EventIndexer] Log rotation detected, reopening file...")
                        break

                    file_size = current_size
                    time.sleep(0.1)  # Brief sleep to avoid tight loop

    def run(self):
        """Main daemon loop."""
        print("[EventIndexer] Starting Cowrie Event Indexer Daemon")
        print(f"[EventIndexer] Database: {self.db_path}")
        print(f"[EventIndexer] Log file: {self.log_path}")

        # Initialize database
        self._init_db()

        # Check if backfill is needed
        cursor = self.conn.execute("SELECT COUNT(*) FROM events")
        event_count = cursor.fetchone()[0]
        print(f"[EventIndexer] Current events in database: {event_count}")

        if event_count == 0:
            print("[EventIndexer] Database is empty, performing initial backfill...")
            self.backfill()

        # Start VT pending scan worker thread if VT is enabled
        if self.vt_enabled and self.vt_scanner:
            self._vt_thread = threading.Thread(target=self._vt_pending_worker, name="vt-pending-worker", daemon=True)
            self._vt_thread.start()

            # Check for pending VT scans from previous runs
            cursor = self.conn.execute("SELECT COUNT(*) FROM virustotal_pending")
            pending_count = cursor.fetchone()[0]
            if pending_count > 0:
                print(f"[VT] Found {pending_count} pending scans from previous run")

            # Backfill VT scans for existing downloads
            self._backfill_vt_scans()

        # Start tailing current log file
        while self.running:
            if not os.path.exists(self.log_path):
                print(f"[!] Log file not found: {self.log_path}, waiting...")
                time.sleep(5)
                continue

            try:
                self._tail_file(self.log_path)
            except Exception as e:
                print(f"[!] Error tailing file: {e}")
                time.sleep(5)

        # Cleanup
        print("[EventIndexer] Shutting down...")

        # Wait for VT thread to finish
        if self._vt_thread and self._vt_thread.is_alive():
            print("[EventIndexer] Waiting for VT worker thread...")
            self._vt_thread.join(timeout=5)

        if self.conn:
            self.conn.close()
        print("[EventIndexer] Shutdown complete")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Cowrie Event Indexer Daemon")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to cowrie.db SQLite database")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH, help="Path to cowrie.json log file")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR, help="Directory containing log files")
    parser.add_argument("--backfill-only", action="store_true", help="Only backfill and exit")

    args = parser.parse_args()

    indexer = EventIndexer(db_path=args.db, log_path=args.log, log_dir=args.log_dir)

    if args.backfill_only:
        indexer._init_db()
        indexer.backfill()
    else:
        indexer.run()


if __name__ == "__main__":
    main()
