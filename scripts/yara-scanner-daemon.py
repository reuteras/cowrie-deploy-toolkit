#!/usr/bin/env python3
"""
Cowrie YARA Scanner Daemon

Real-time YARA scanning and file type detection for downloaded malware using inotify.
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
from typing import Optional

try:
    import magic
    import yara
    from inotify_simple import INotify, flags
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install dependencies with: cd /opt/cowrie && uv sync")
    sys.exit(1)


# Configuration from environment variables
CONFIG = {
    "download_path": os.getenv("COWRIE_DOWNLOAD_PATH", "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/downloads"),
    "yara_rules_path": os.getenv("YARA_RULES_PATH", "/opt/cowrie/yara-rules"),
    "cache_db_path": os.getenv("YARA_CACHE_DB_PATH", "/opt/cowrie/var/yara-cache.db"),
}


class FileAnalysisCache:
    """SQLite cache for YARA scan results and file type detection."""

    # File categories for quick filtering
    CATEGORY_EXECUTABLE = "executable"
    CATEGORY_SCRIPT = "script"
    CATEGORY_DOCUMENT = "document"
    CATEGORY_ARCHIVE = "archive"
    CATEGORY_DATA = "data"
    CATEGORY_UNKNOWN = "unknown"

    # MIME types that are safe to preview (text-based)
    PREVIEWABLE_MIMES = {
        "text/plain",
        "text/x-shellscript",
        "text/x-python",
        "text/x-perl",
        "text/x-ruby",
        "text/x-php",
        "text/x-c",
        "text/x-c++",
        "text/html",
        "text/xml",
        "text/css",
        "text/javascript",
        "text/x-ssh-public-key",
        "application/json",
        "application/xml",
        "application/x-sh",
        "application/x-csh",
        "application/javascript",
        "application/x-perl",
        "application/x-python",
    }

    # File type descriptions that indicate text/script content
    TEXT_INDICATORS = [
        "text",
        "script",
        "ASCII",
        "UTF-8",
        "Unicode",
        "JSON",
        "XML",
        "HTML",
        "shell",
        "Python",
        "Perl",
        "Ruby",
        "PHP",
        "source",
        "program text",
        "OpenSSH",
        "SSH",
        "RSA public key",
        "DSA public key",
        "ECDSA public key",
        "Ed25519 public key",
        "public key",
        "PEM certificate",
    ]

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)

        # Check if we need to migrate the schema
        cursor = conn.execute("PRAGMA table_info(yara_cache)")
        columns = {row[1] for row in cursor.fetchall()}

        if "file_type" not in columns:
            # Add new columns for file type info
            if "yara_cache" in [
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            ]:
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_type TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_mime TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN file_category TEXT")
                conn.execute("ALTER TABLE yara_cache ADD COLUMN is_previewable INTEGER DEFAULT 0")
                print("[*] Migrated database schema to include file type columns")
            else:
                # Create new table with all columns
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS yara_cache (
                        sha256 TEXT PRIMARY KEY,
                        matches TEXT NOT NULL,
                        scan_timestamp INTEGER NOT NULL,
                        rules_version TEXT,
                        file_type TEXT,
                        file_mime TEXT,
                        file_category TEXT,
                        is_previewable INTEGER DEFAULT 0
                    )
                """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_yara_timestamp
            ON yara_cache(scan_timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_category
            ON yara_cache(file_category)
        """)
        conn.commit()
        conn.close()

    def get_result(self, sha256: str) -> Optional[dict]:
        """Get cached scan result including file type."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            """SELECT matches, scan_timestamp, rules_version,
                      file_type, file_mime, file_category, is_previewable
               FROM yara_cache WHERE sha256 = ?""",
            (sha256,),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "sha256": sha256,
                "matches": json.loads(row[0]) if row[0] else [],
                "scan_timestamp": row[1],
                "rules_version": row[2],
                "file_type": row[3],
                "file_mime": row[4],
                "file_category": row[5],
                "is_previewable": bool(row[6]) if row[6] is not None else False,
            }
        return None

    def set_result(
        self, sha256: str, matches: list[str], rules_version: str = None, file_type: str = None, file_mime: str = None
    ):
        """Cache scan result with file type information."""
        # Determine category and previewability
        file_category = self._categorize_file(file_type, file_mime)
        is_previewable = self._is_previewable(file_type, file_mime)

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """INSERT OR REPLACE INTO yara_cache
               (sha256, matches, scan_timestamp, rules_version,
                file_type, file_mime, file_category, is_previewable)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sha256,
                json.dumps(matches),
                int(time.time()),
                rules_version,
                file_type,
                file_mime,
                file_category,
                int(is_previewable),
            ),
        )
        conn.commit()
        conn.close()

    def _categorize_file(self, file_type: str, file_mime: str) -> str:
        """Categorize file based on type and MIME."""
        if not file_type and not file_mime:
            return self.CATEGORY_UNKNOWN

        file_type_lower = (file_type or "").lower()
        file_mime_lower = (file_mime or "").lower()

        # Executables
        if any(x in file_type_lower for x in ["elf", "executable", "mach-o", "pe32"]):
            return self.CATEGORY_EXECUTABLE
        if file_mime_lower in [
            "application/x-executable",
            "application/x-mach-binary",
            "application/x-dosexec",
            "application/x-elf",
        ]:
            return self.CATEGORY_EXECUTABLE

        # Scripts
        if any(x in file_type_lower for x in ["script", "python", "perl", "ruby", "php", "shell"]):
            return self.CATEGORY_SCRIPT
        if "script" in file_mime_lower or file_mime_lower.startswith("text/x-"):
            return self.CATEGORY_SCRIPT

        # Archives
        if any(x in file_type_lower for x in ["archive", "compressed", "zip", "tar", "gzip", "bzip"]):
            return self.CATEGORY_ARCHIVE
        if any(x in file_mime_lower for x in ["zip", "tar", "gzip", "compress", "archive"]):
            return self.CATEGORY_ARCHIVE

        # Documents
        if any(x in file_type_lower for x in ["document", "pdf", "word", "office"]):
            return self.CATEGORY_DOCUMENT

        # Data/text files
        if "text" in file_type_lower or "ascii" in file_type_lower:
            return self.CATEGORY_DATA
        if file_mime_lower.startswith("text/"):
            return self.CATEGORY_DATA

        return self.CATEGORY_DATA

    def _is_previewable(self, file_type: str, file_mime: str) -> bool:
        """Determine if file content can be safely previewed as text."""
        if file_mime and file_mime.lower() in self.PREVIEWABLE_MIMES:
            return True

        if file_type:
            return any(indicator.lower() in file_type.lower() for indicator in self.TEXT_INDICATORS)

        return False

    def has_result(self, sha256: str) -> bool:
        """Check if we have a cached result for this hash."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT 1 FROM yara_cache WHERE sha256 = ?", (sha256,))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def get_stats(self) -> dict:
        """Get cache statistics including file type breakdown."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM yara_cache")
        total = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) FROM yara_cache WHERE matches != '[]'")
        with_matches = cursor.fetchone()[0]

        # File category breakdown
        cursor = conn.execute(
            """SELECT file_category, COUNT(*) FROM yara_cache
               GROUP BY file_category ORDER BY COUNT(*) DESC"""
        )
        categories = {row[0] or "unknown": row[1] for row in cursor.fetchall()}

        # Previewable count
        cursor = conn.execute("SELECT COUNT(*) FROM yara_cache WHERE is_previewable = 1")
        previewable = cursor.fetchone()[0]

        conn.close()
        return {
            "total_scanned": total,
            "with_matches": with_matches,
            "clean": total - with_matches,
            "categories": categories,
            "previewable": previewable,
        }


# Alias for backward compatibility
YARACache = FileAnalysisCache


class FileTypeDetector:
    """Detect file types using libmagic."""

    def __init__(self):
        self.magic_mime = magic.Magic(mime=True)
        self.magic_desc = magic.Magic(mime=False)

    def detect(self, file_path: str) -> tuple[str, str]:
        """Detect file type and MIME type.

        Returns:
            Tuple of (file_type_description, mime_type)
        """
        try:
            file_type = self.magic_desc.from_file(file_path)
            mime_type = self.magic_mime.from_file(file_path)
            return file_type, mime_type
        except Exception as e:
            print(f"[!] File type detection error: {e}")
            return None, None


class FileAnalyzer:
    """Combined YARA scanning and file type detection."""

    def __init__(self, rules_path: str, cache: FileAnalysisCache):
        self.rules_path = rules_path
        self.cache = cache
        self.rules = None
        self.rules_version = None
        self.file_detector = FileTypeDetector()
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from directory."""
        if not os.path.exists(self.rules_path):
            print(f"[!] Warning: YARA rules directory not found: {self.rules_path}")
            return

        rule_files = {}
        for root, _, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
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

    def analyze_file(self, file_path: str, use_cache: bool = True) -> dict:
        """Analyze a file: YARA scan and file type detection.

        Returns:
            Dict with matches, file_type, file_mime, file_category, is_previewable
        """
        # Get SHA256 from filename (Cowrie stores files by their hash)
        sha256 = os.path.basename(file_path)

        # Check cache first
        if use_cache:
            cached = self.cache.get_result(sha256)
            if cached and cached.get("file_type"):
                return cached

        if not os.path.exists(file_path):
            return {"matches": [], "file_type": None, "file_mime": None}

        # Detect file type
        file_type, file_mime = self.file_detector.detect(file_path)

        # YARA scan
        match_names = []
        if self.rules:
            try:
                matches = self.rules.match(file_path)
                match_names = [match.rule for match in matches]
            except Exception as e:
                print(f"[!] YARA scan error for {file_path}: {e}")

        # Cache the result
        self.cache.set_result(sha256, match_names, self.rules_version, file_type, file_mime)

        # Return full result
        return self.cache.get_result(sha256)

    def scan_file(self, file_path: str, use_cache: bool = True) -> list[str]:
        """Scan a file and return matched rule names (backward compatible)."""
        result = self.analyze_file(file_path, use_cache)
        return result.get("matches", [])


# Alias for backward compatibility
YARAScanner = FileAnalyzer


class DownloadWatcher:
    """Watch downloads directory for new files using inotify."""

    def __init__(self, download_path: str, analyzer: FileAnalyzer):
        self.download_path = download_path
        self.analyzer = analyzer
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
        print("[*] File Analyzer Daemon started")
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
                        self._analyze_file(file_path)

            except KeyboardInterrupt:
                print("\n[*] Shutting down...")
                break
            except Exception as e:
                print(f"[!] Error in event loop: {e}")
                time.sleep(1)

    def _analyze_file(self, file_path: str):
        """Analyze a single file and report results."""
        start_time = time.time()
        result = self.analyzer.analyze_file(file_path, use_cache=False)
        scan_time = time.time() - start_time

        sha256 = os.path.basename(file_path)
        matches = result.get("matches", [])
        file_type = result.get("file_type", "unknown")
        file_category = result.get("file_category", "unknown")

        # Truncate file type for display
        if file_type and len(file_type) > 50:
            file_type_display = file_type[:50] + "..."
        else:
            file_type_display = file_type or "unknown"

        if matches:
            print(f"[!] YARA MATCH: {sha256[:16]}...")
            print(f"    Type: {file_type_display}")
            print(f"    Category: {file_category}")
            print(f"    Rules: {', '.join(matches[:5])}")
            if len(matches) > 5:
                print(f"    ... and {len(matches) - 5} more matches")
        else:
            print(f"[*] Analyzed: {sha256[:16]}... [{file_category}] ({scan_time:.2f}s)")
            print(f"    Type: {file_type_display}")

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

        print(f"[*] Analyzing {total} existing files...")

        analyzed = 0
        matched = 0
        categories = {}

        for filename in files:
            file_path = os.path.join(self.download_path, filename)

            if not os.path.isfile(file_path):
                continue

            # Check if already cached with file type info
            cached = self.analyzer.cache.get_result(filename)
            if cached and cached.get("file_type"):
                analyzed += 1
                cat = cached.get("file_category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1
                if cached.get("matches"):
                    matched += 1
                continue

            result = self.analyzer.analyze_file(file_path, use_cache=False)
            analyzed += 1

            cat = result.get("file_category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1

            if result.get("matches"):
                matched += 1
                print(f"[!] MATCH: {filename[:16]}... [{cat}] -> {', '.join(result['matches'][:3])}")

            # Progress update every 100 files
            if analyzed % 100 == 0:
                print(f"[*] Progress: {analyzed}/{total} files analyzed...")

        print(f"[*] Analysis complete: {analyzed} files, {matched} with YARA matches")
        print(f"[*] File categories: {', '.join(f'{k}={v}' for k, v in sorted(categories.items()))}")


def main():
    parser = argparse.ArgumentParser(description="Cowrie YARA Scanner Daemon - Real-time malware scanning")
    parser.add_argument("--daemon", "-d", action="store_true", help="Run as daemon (background)")
    parser.add_argument("--scan-existing", "-s", action="store_true", help="Scan all existing files before watching")
    parser.add_argument("--download-path", default=CONFIG["download_path"], help="Path to downloads directory")
    parser.add_argument("--rules-path", default=CONFIG["yara_rules_path"], help="Path to YARA rules directory")
    parser.add_argument("--cache-db", default=CONFIG["cache_db_path"], help="Path to SQLite cache database")
    parser.add_argument("--stats", action="store_true", help="Show cache statistics and exit")

    args = parser.parse_args()

    # Initialize cache
    cache = YARACache(args.cache_db)

    # Stats mode
    if args.stats:
        stats = cache.get_stats()
        print("File Analysis Cache Statistics:")
        print(f"  Total scanned:  {stats['total_scanned']}")
        print(f"  With matches:   {stats['with_matches']}")
        print(f"  Clean:          {stats['clean']}")
        print(f"  Previewable:    {stats.get('previewable', 0)}")
        if stats.get("categories"):
            print("\nFile Categories:")
            for cat, count in sorted(stats["categories"].items(), key=lambda x: -x[1]):
                print(f"  {cat:12s}  {count}")
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
        os.chdir("/")

        # Redirect stdout/stderr to log file
        log_path = "/var/log/yara-scanner.log"
        sys.stdout = open(log_path, "a", buffering=1)
        sys.stderr = sys.stdout
        print(f"\n[*] YARA Scanner Daemon started at {datetime.now().isoformat()}")

    watcher.run()


if __name__ == "__main__":
    main()
