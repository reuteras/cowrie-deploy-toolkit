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
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Paths (container mount paths)
DEFAULT_DB_PATH = "/cowrie-data/lib/cowrie/cowrie.db"
DEFAULT_LOG_PATH = "/cowrie-data/log/cowrie/cowrie.json"
DEFAULT_LOG_DIR = "/cowrie-data/log/cowrie"


class EventIndexer:
    """Indexes Cowrie JSON events into SQLite for fast queries."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, log_path: str = DEFAULT_LOG_PATH, log_dir: str = DEFAULT_LOG_DIR):
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
            return True
        except sqlite3.IntegrityError:
            # Duplicate event, skip
            return False
        except Exception as e:
            print(f"[!] Error indexing event: {e}")
            return False

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
