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
import time
from pathlib import Path

# Paths (container mount paths)
DEFAULT_DB_PATH = "/cowrie-data/lib/cowrie/cowrie.db"
DEFAULT_LOG_PATH = "/cowrie-data/log/cowrie/cowrie.json"
DEFAULT_LOG_DIR = "/cowrie-data/log/cowrie"


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

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

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
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(schema)
        self.conn.commit()
        print("[EventIndexer] Database schema initialized")

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

        Args:
            event: Download/upload event dictionary
        """
        try:
            # Get file path from event
            shasum = event.get("shasum")
            if not shasum:
                return

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
            if "executable" in mime_type or "x-dosexec" in mime_type or "x-elf" in mime_type:
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

        # Backfill missing download metadata
        self._backfill_download_metadata()

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
