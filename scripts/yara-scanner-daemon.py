#!/usr/bin/env python3
"""
Cowrie YARA Scanner Daemon

Real-time YARA scanning for downloaded malware using inotify.
Watches the downloads directory and scans new files immediately.
Results are cached in SQLite for fast lookups by other tools.

Usage:
    ./yara-scanner-daemon.py                    # Run in foreground
    ./yara-scanner-daemon.py --daemon           # Run as daemon
    ./yara-scanner-daemon.py --scan-existing    # Scan all existing files
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    import yara
    from inotify_simple import INotify, flags
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install dependencies with: cd /opt/cowrie && uv sync")
    sys.exit(1)


# Configuration from environment variables
CONFIG = {
    'download_path': os.getenv('COWRIE_DOWNLOAD_PATH', '/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads'),
    'yara_rules_path': os.getenv('YARA_RULES_PATH', '/opt/cowrie/yara-rules'),
    'cache_db_path': os.getenv('YARA_CACHE_DB_PATH', '/opt/cowrie/var/yara-cache.db'),
}


class YARACache:
    """SQLite cache for YARA scan results."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS yara_cache (
                sha256 TEXT PRIMARY KEY,
                matches TEXT NOT NULL,
                scan_timestamp INTEGER NOT NULL,
                rules_version TEXT
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_yara_timestamp
            ON yara_cache(scan_timestamp)
        ''')
        conn.commit()
        conn.close()

    def get_result(self, sha256: str) -> Optional[dict]:
        """Get cached YARA scan result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            'SELECT matches, scan_timestamp, rules_version FROM yara_cache WHERE sha256 = ?',
            (sha256,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                'sha256': sha256,
                'matches': json.loads(row[0]),
                'scan_timestamp': row[1],
                'rules_version': row[2]
            }
        return None

    def set_result(self, sha256: str, matches: List[str], rules_version: str = None):
        """Cache YARA scan result."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            '''INSERT OR REPLACE INTO yara_cache
               (sha256, matches, scan_timestamp, rules_version)
               VALUES (?, ?, ?, ?)''',
            (sha256, json.dumps(matches), int(time.time()), rules_version)
        )
        conn.commit()
        conn.close()

    def has_result(self, sha256: str) -> bool:
        """Check if we have a cached result for this hash."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            'SELECT 1 FROM yara_cache WHERE sha256 = ?',
            (sha256,)
        )
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def get_stats(self) -> dict:
        """Get cache statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('SELECT COUNT(*) FROM yara_cache')
        total = cursor.fetchone()[0]

        cursor = conn.execute(
            "SELECT COUNT(*) FROM yara_cache WHERE matches != '[]'"
        )
        with_matches = cursor.fetchone()[0]

        conn.close()
        return {
            'total_scanned': total,
            'with_matches': with_matches,
            'clean': total - with_matches
        }


class YARAScanner:
    """YARA rule scanner with caching."""

    def __init__(self, rules_path: str, cache: YARACache):
        self.rules_path = rules_path
        self.cache = cache
        self.rules = None
        self.rules_version = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from directory."""
        if not os.path.exists(self.rules_path):
            print(f"[!] Warning: YARA rules directory not found: {self.rules_path}")
            return

        rule_files = {}
        for root, dirs, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    rule_path = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = rule_path

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                # Use modification time of rules directory as version
                self.rules_version = str(int(os.path.getmtime(self.rules_path)))
                print(f"[*] Loaded {len(rule_files)} YARA rule files")
            except Exception as e:
                print(f"[!] Error loading YARA rules: {e}")

    def reload_rules(self):
        """Reload YARA rules (useful after rule updates)."""
        print("[*] Reloading YARA rules...")
        self._load_rules()

    def scan_file(self, file_path: str, use_cache: bool = True) -> List[str]:
        """Scan a file and return matched rule names."""
        if not self.rules:
            return []

        # Get SHA256 from filename (Cowrie stores files by their hash)
        sha256 = os.path.basename(file_path)

        # Check cache first
        if use_cache:
            cached = self.cache.get_result(sha256)
            if cached:
                return cached['matches']

        if not os.path.exists(file_path):
            return []

        try:
            matches = self.rules.match(file_path)
            match_names = [match.rule for match in matches]

            # Cache the result
            self.cache.set_result(sha256, match_names, self.rules_version)

            return match_names
        except Exception as e:
            print(f"[!] YARA scan error for {file_path}: {e}")
            return []


class DownloadWatcher:
    """Watch downloads directory for new files using inotify."""

    def __init__(self, download_path: str, scanner: YARAScanner):
        self.download_path = download_path
        self.scanner = scanner
        self.inotify = None

    def setup(self):
        """Set up inotify watch."""
        if not os.path.exists(self.download_path):
            print(f"[!] Creating downloads directory: {self.download_path}")
            os.makedirs(self.download_path, exist_ok=True)

        self.inotify = INotify()
        # Watch for new files being created and closed (finished writing)
        watch_flags = flags.CLOSE_WRITE | flags.MOVED_TO
        self.inotify.add_watch(self.download_path, watch_flags)
        print(f"[*] Watching directory: {self.download_path}")

    def run(self):
        """Main event loop."""
        print("[*] YARA Scanner Daemon started")
        print("[*] Waiting for new downloads...")

        while True:
            try:
                # Wait for events (1 second timeout for graceful shutdown)
                events = self.inotify.read(timeout=1000)

                for event in events:
                    if event.name:
                        file_path = os.path.join(self.download_path, event.name)

                        # Skip if not a regular file
                        if not os.path.isfile(file_path):
                            continue

                        # Skip very small files (likely incomplete)
                        if os.path.getsize(file_path) < 1:
                            continue

                        print(f"[*] New file detected: {event.name}")
                        self._scan_file(file_path)

            except KeyboardInterrupt:
                print("\n[*] Shutting down...")
                break
            except Exception as e:
                print(f"[!] Error in event loop: {e}")
                time.sleep(1)

    def _scan_file(self, file_path: str):
        """Scan a single file and report results."""
        start_time = time.time()
        matches = self.scanner.scan_file(file_path, use_cache=False)
        scan_time = time.time() - start_time

        sha256 = os.path.basename(file_path)

        if matches:
            print(f"[!] YARA MATCH: {sha256[:16]}... -> {', '.join(matches[:5])}")
            if len(matches) > 5:
                print(f"    ... and {len(matches) - 5} more matches")
        else:
            print(f"[*] Clean: {sha256[:16]}... ({scan_time:.2f}s)")

    def scan_existing(self):
        """Scan all existing files in the downloads directory."""
        if not os.path.exists(self.download_path):
            print(f"[!] Downloads directory not found: {self.download_path}")
            return

        files = os.listdir(self.download_path)
        total = len(files)

        if total == 0:
            print("[*] No files to scan")
            return

        print(f"[*] Scanning {total} existing files...")

        scanned = 0
        matched = 0

        for filename in files:
            file_path = os.path.join(self.download_path, filename)

            if not os.path.isfile(file_path):
                continue

            # Check if already cached
            if self.scanner.cache.has_result(filename):
                scanned += 1
                continue

            matches = self.scanner.scan_file(file_path, use_cache=False)
            scanned += 1

            if matches:
                matched += 1
                print(f"[!] MATCH: {filename[:16]}... -> {', '.join(matches[:3])}")

            # Progress update every 100 files
            if scanned % 100 == 0:
                print(f"[*] Progress: {scanned}/{total} files scanned...")

        print(f"[*] Scan complete: {scanned} files, {matched} with YARA matches")


def main():
    parser = argparse.ArgumentParser(
        description='Cowrie YARA Scanner Daemon - Real-time malware scanning'
    )
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run as daemon (background)'
    )
    parser.add_argument(
        '--scan-existing', '-s',
        action='store_true',
        help='Scan all existing files before watching'
    )
    parser.add_argument(
        '--download-path',
        default=CONFIG['download_path'],
        help='Path to downloads directory'
    )
    parser.add_argument(
        '--rules-path',
        default=CONFIG['yara_rules_path'],
        help='Path to YARA rules directory'
    )
    parser.add_argument(
        '--cache-db',
        default=CONFIG['cache_db_path'],
        help='Path to SQLite cache database'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show cache statistics and exit'
    )

    args = parser.parse_args()

    # Initialize cache
    cache = YARACache(args.cache_db)

    # Stats mode
    if args.stats:
        stats = cache.get_stats()
        print(f"YARA Cache Statistics:")
        print(f"  Total scanned: {stats['total_scanned']}")
        print(f"  With matches:  {stats['with_matches']}")
        print(f"  Clean:         {stats['clean']}")
        return

    # Initialize scanner
    scanner = YARAScanner(args.rules_path, cache)

    if not scanner.rules:
        print("[!] No YARA rules loaded. Exiting.")
        sys.exit(1)

    # Initialize watcher
    watcher = DownloadWatcher(args.download_path, scanner)

    # Scan existing files if requested
    if args.scan_existing:
        watcher.scan_existing()
        if not args.daemon:
            return

    # Set up and run watcher
    watcher.setup()

    if args.daemon:
        # Daemonize
        pid = os.fork()
        if pid > 0:
            print(f"[*] Daemon started with PID {pid}")
            sys.exit(0)

        # Child process
        os.setsid()
        os.chdir('/')

        # Redirect stdout/stderr to log file
        log_path = '/var/log/yara-scanner.log'
        sys.stdout = open(log_path, 'a', buffering=1)
        sys.stderr = sys.stdout
        print(f"\n[*] YARA Scanner Daemon started at {datetime.now().isoformat()}")

    watcher.run()


if __name__ == '__main__':
    main()
