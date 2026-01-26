"""
Attack Clustering Service

Provides clustering algorithms for identifying coordinated attacks:
- Command sequence fingerprinting
- HASSH (SSH client) fingerprinting
- Payload-based clustering
- Temporal proximity clustering
"""

import hashlib
import json
import logging
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

logger = logging.getLogger(__name__)


class ClusteringService:
    """Service for clustering attack sessions by various attributes."""

    def __init__(self, source_db_path: str, clustering_db_path: Optional[str] = None):
        """
        Initialize clustering service.

        Args:
            source_db_path: Path to the Cowrie SQLite database (read-only source data)
            clustering_db_path: Path to clustering database (writable, for storing results)
                              If None, defaults to source_db_path + "_clustering.db"
        """
        self.source_db_path = source_db_path
        self.clustering_db_path = clustering_db_path or source_db_path.replace(".db", "_clustering.db")
        logger.info(f"Clustering service: source={self.source_db_path}, clustering={self.clustering_db_path}")
        self._ensure_tables()

    def _get_source_connection(self) -> sqlite3.Connection:
        """Get a read-only connection to the source Cowrie database."""
        # Open in read-only mode using URI
        conn = sqlite3.connect(f"file:{self.source_db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_clustering_connection(self) -> sqlite3.Connection:
        """Get a writable connection to the clustering database."""
        conn = sqlite3.connect(self.clustering_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_connection(self) -> sqlite3.Connection:
        """Get a connection to the clustering database (for backward compatibility)."""
        return self._get_clustering_connection()

    def _ensure_tables(self):
        """Ensure clustering tables exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create command_fingerprints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS command_fingerprints (
                session TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                normalized_commands TEXT,
                command_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cmd_fingerprint ON command_fingerprints(fingerprint)")

        # Create hassh_fingerprints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hassh_fingerprints (
                session TEXT PRIMARY KEY,
                hassh TEXT NOT NULL,
                hassh_server TEXT,
                kex_algorithms TEXT,
                encryption_algorithms TEXT,
                mac_algorithms TEXT,
                src_ip TEXT,
                timestamp DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hassh ON hassh_fingerprints(hassh)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hassh_ip ON hassh_fingerprints(src_ip)")

        # Create attack_clusters table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_clusters (
                cluster_id TEXT PRIMARY KEY,
                cluster_type TEXT NOT NULL,
                fingerprint TEXT,
                name TEXT,
                description TEXT,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                session_count INTEGER NOT NULL DEFAULT 0,
                score INTEGER DEFAULT 0,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_clusters_type ON attack_clusters(cluster_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_clusters_fingerprint ON attack_clusters(fingerprint)")

        # Create cluster_members table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cluster_members (
                cluster_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                session_count INTEGER DEFAULT 1,
                metadata TEXT,
                PRIMARY KEY (cluster_id, src_ip)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cluster_members_ip ON cluster_members(src_ip)")

        # Create cluster_enrichment table for threat intel data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cluster_enrichment (
                cluster_id TEXT PRIMARY KEY,
                threat_families TEXT,
                top_asns TEXT,
                countries TEXT,
                threat_score INTEGER DEFAULT 0,
                tags TEXT,
                enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create TTP fingerprinting tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ttp_fingerprints (
                session TEXT PRIMARY KEY,
                ttp_sequence TEXT,  -- JSON array of TTP matches
                technique_count INTEGER DEFAULT 0,
                dominant_techniques TEXT,  -- JSON array of top techniques
                confidence_score REAL DEFAULT 0.0,
                tactics TEXT,  -- JSON array of ATT&CK tactics
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ttp_sessions ON ttp_fingerprints(session)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ttp_techniques ON ttp_fingerprints(dominant_techniques)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ttp_tactics ON ttp_fingerprints(tactics)")

        # Create TTP cluster table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ttp_clusters (
                cluster_id TEXT PRIMARY KEY,
                dominant_technique TEXT,
                dominant_tactic TEXT,
                member_count INTEGER DEFAULT 0,
                confidence_score REAL DEFAULT 0.0,
                first_seen DATETIME,
                last_seen DATETIME,
                metadata TEXT,  -- JSON with additional cluster info
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ttp_clusters_technique ON ttp_clusters(dominant_technique)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ttp_clusters_tactic ON ttp_clusters(dominant_tactic)")

        conn.commit()
        conn.close()
        logger.info("Clustering tables ensured (including TTP tables)")

    # =========================================================================
    # Command Fingerprinting
    # =========================================================================

    # Common reconnaissance commands that are not interesting for clustering
    COMMON_RECON_COMMANDS = {
        "uname", "uname -a", "uname -r", "uname -m", "uname -s",
        "id", "whoami", "pwd", "hostname", "w", "who",
        "cat /etc/passwd", "cat /etc/issue", "cat /proc/cpuinfo",
        "cat /proc/meminfo", "cat /proc/version",
        "ls", "ls -la", "ls -l", "ls -a", "dir",
        "ps", "ps aux", "ps -ef", "top",
        "ifconfig", "ip addr", "ip a", "netstat", "ss",
        "free", "free -m", "df", "df -h", "uptime",
        "env", "export", "echo $PATH", "echo $HOME",
        "exit", "logout", "quit", "q",
        "help", "?", "man",
        "history", "last",
        "nproc", "lscpu", "arch",
    }

    # High-interest commands indicating malicious activity
    HIGH_INTEREST_PATTERNS = [
        # User/account manipulation
        (r"\buseradd\b", 30),
        (r"\badduser\b", 30),
        (r"\busermod\b", 25),
        (r"\bpasswd\b", 25),
        (r"\bchpasswd\b", 30),
        (r"\bgroupadd\b", 20),
        # Persistence mechanisms
        (r"\bcrontab\b", 25),
        (r"/etc/cron", 25),
        (r"\.bashrc", 20),
        (r"\.profile", 20),
        (r"/etc/rc\.local", 30),
        (r"systemctl\s+enable", 30),
        (r"chmod\s+\+x", 15),
        # Download/execution
        (r"\bwget\b", 20),
        (r"\bcurl\b", 20),
        (r"\btftp\b", 25),
        (r"\bftp\b", 15),
        (r"\bscp\b", 20),
        (r"python\s+-c", 25),
        (r"perl\s+-e", 25),
        (r"base64\s+-d", 30),
        (r"\beval\b", 20),
        # Crypto mining indicators
        (r"xmrig", 40),
        (r"minerd", 40),
        (r"cryptonight", 40),
        (r"stratum\+tcp", 40),
        # Lateral movement
        (r"\bssh\b.*@", 25),
        (r"\bsshpass\b", 30),
        (r"\.ssh/authorized_keys", 35),
        (r"\.ssh/id_rsa", 30),
        # Evasion/cleanup
        (r"\brm\s+-rf\s+/", 25),
        (r"history\s+-c", 20),
        (r"unset\s+HISTFILE", 25),
        (r"/dev/null\s+2>&1", 15),
        # Network tools
        (r"\bnmap\b", 25),
        (r"\bnetcat\b|\bnc\b", 20),
        (r"\bsocat\b", 25),
        # Process hiding
        (r"\bnohup\b", 15),
        (r"&\s*$", 10),
        (r"disown", 15),
    ]

    def calculate_command_interest_score(self, commands: list[str]) -> tuple[int, list[str]]:
        """
        Calculate an interest score for a command sequence.

        High scores indicate sophisticated/malicious activity.
        Low scores indicate common reconnaissance that's not interesting to cluster.

        Args:
            commands: List of raw command strings

        Returns:
            Tuple of (score, list of reasons for the score)
        """
        if not commands:
            return 0, ["empty"]

        score = 0
        reasons = []

        # Normalize commands for comparison
        normalized = [self.normalize_command(cmd) for cmd in commands if cmd]
        raw_lower = [cmd.lower().strip() for cmd in commands if cmd]

        # Check if ALL commands are common recon (boring cluster)
        non_recon_count = 0
        for cmd in raw_lower:
            cmd_base = cmd.split()[0] if cmd.split() else cmd
            if cmd not in self.COMMON_RECON_COMMANDS and cmd_base not in self.COMMON_RECON_COMMANDS:
                non_recon_count += 1

        if non_recon_count == 0:
            return 5, ["only_common_recon"]

        # Base score from command count and diversity
        unique_commands = len(set(normalized))
        if unique_commands >= 10:
            score += 20
            reasons.append(f"diverse_commands:{unique_commands}")
        elif unique_commands >= 5:
            score += 10
            reasons.append(f"moderate_diversity:{unique_commands}")

        # Check for high-interest patterns
        full_sequence = " ; ".join(raw_lower)
        for pattern, pattern_score in self.HIGH_INTEREST_PATTERNS:
            if re.search(pattern, full_sequence, re.IGNORECASE):
                score += pattern_score
                # Extract pattern name for reason
                pattern_name = pattern.replace(r"\b", "").replace("\\", "").split()[0]
                reasons.append(f"pattern:{pattern_name}")

        # Bonus for multi-stage attacks (download + execute)
        has_download = any(re.search(r"\b(wget|curl|tftp)\b", cmd, re.I) for cmd in raw_lower)
        has_execute = any(re.search(r"\b(chmod|sh|bash|python|perl)\b", cmd, re.I) for cmd in raw_lower)
        if has_download and has_execute:
            score += 25
            reasons.append("download_and_execute")

        # Bonus for unique strings (passwords, keys, specific paths)
        for cmd in commands:
            # Long random-looking strings (potential passwords/keys)
            if re.search(r"[a-zA-Z0-9]{16,}", cmd):
                score += 15
                reasons.append("long_random_string")
                break

        # Cap at 100
        score = min(100, score)

        return score, reasons

    def normalize_command(self, cmd: str) -> str:
        """
        Normalize a command for fingerprinting.

        Replaces variable parts (IPs, hashes, paths, ports, URLs) with placeholders.
        """
        if not cmd:
            return ""

        # Strip leading/trailing whitespace
        cmd = cmd.strip()

        # Replace IP addresses
        cmd = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", cmd)

        # Replace hex hashes (32+ chars)
        cmd = re.sub(r"\b[a-fA-F0-9]{32,}\b", "<HASH>", cmd)

        # Replace /tmp paths
        cmd = re.sub(r"/tmp/[^\s;|&]+", "/tmp/<TMP>", cmd)

        # Replace ports
        cmd = re.sub(r":\d{2,5}\b", ":<PORT>", cmd)

        # Replace URLs
        cmd = re.sub(r"https?://[^\s;|&]+", "<URL>", cmd)

        # Replace numeric arguments that look like PIDs or counts
        cmd = re.sub(r"\b\d{4,}\b", "<NUM>", cmd)

        # Lowercase for consistency
        cmd = cmd.lower()

        return cmd

    def fingerprint_commands(self, commands: list[str]) -> str:
        """
        Create a fingerprint from a sequence of commands.

        Args:
            commands: List of command strings

        Returns:
            16-character hex fingerprint
        """
        if not commands:
            return "empty"

        normalized = [self.normalize_command(cmd) for cmd in commands if cmd]
        if not normalized:
            return "empty"

        # Create fingerprint from normalized command sequence
        content = "\n".join(normalized)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def extract_command_fingerprints(self, days: int = 7) -> dict:
        """
        Extract and store command fingerprints for recent sessions.

        Args:
            days: Number of days to look back

        Returns:
            Dict with statistics about fingerprints found
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Read from source database
        source_conn = self._get_source_connection()
        source_cursor = source_conn.cursor()

        # Get sessions with commands
        source_cursor.execute(
            """
            SELECT session, GROUP_CONCAT(input, '|||') as commands
            FROM input
            WHERE timestamp >= ?
            GROUP BY session
            HAVING COUNT(*) > 0
            """,
            (cutoff_str,),
        )

        rows = source_cursor.fetchall()
        source_conn.close()

        # Write to clustering database
        cluster_conn = self._get_clustering_connection()
        cluster_cursor = cluster_conn.cursor()

        fingerprints = {}
        for row in rows:
            session_id = row["session"]
            commands = row["commands"].split("|||") if row["commands"] else []

            if commands:
                fp = self.fingerprint_commands(commands)
                normalized = [self.normalize_command(c) for c in commands]

                # Store fingerprint in clustering database
                cluster_cursor.execute(
                    """
                    INSERT OR REPLACE INTO command_fingerprints
                    (session, fingerprint, normalized_commands, command_count, created_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (session_id, fp, json.dumps(normalized), len(commands)),
                )

                fingerprints[session_id] = fp

        cluster_conn.commit()
        cluster_conn.close()

        # Count unique fingerprints
        fp_counts = Counter(fingerprints.values())
        return {
            "sessions_processed": len(fingerprints),
            "unique_fingerprints": len(fp_counts),
            "top_fingerprints": fp_counts.most_common(10),
        }

    # =========================================================================
    # HASSH Fingerprinting
    # =========================================================================

    def extract_hassh_from_events(self, days: int = 7) -> dict:
        """
        Extract HASSH fingerprints from Cowrie events.

        HASSH is derived from SSH key exchange (KEX) algorithms.

        Args:
            days: Number of days to look back

        Returns:
            Dict with statistics about HASSH fingerprints found
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Read from source database
        source_conn = self._get_source_connection()
        source_cursor = source_conn.cursor()

        # Check if events table exists
        source_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not source_cursor.fetchone():
            source_conn.close()
            return {"error": "Events table not found", "sessions_processed": 0}

        # Get KEX events (cowrie.client.kex contains HASSH data) with session IPs
        source_cursor.execute(
            """
            SELECT e.session, s.ip as src_ip, e.timestamp, e.data
            FROM events e
            JOIN sessions s ON e.session = s.id
            WHERE e.eventid = 'cowrie.client.kex'
            AND e.timestamp >= ?
            """,
            (cutoff_str,),
        )

        rows = source_cursor.fetchall()
        source_conn.close()

        # Write to clustering database
        cluster_conn = self._get_clustering_connection()
        cluster_cursor = cluster_conn.cursor()

        hassh_data = {}
        for row in rows:
            try:
                event = json.loads(row["data"])
                session_id = row["session"]

                # HASSH is typically in the 'hassh' field, or we compute it
                hassh = event.get("hassh")

                if not hassh:
                    # Compute HASSH from KEX algorithms if not present
                    kex_algs = event.get("kexAlgs", [])
                    enc_algs = event.get("encCS", [])  # Encryption client->server
                    mac_algs = event.get("macCS", [])  # MAC client->server

                    if kex_algs or enc_algs or mac_algs:
                        hassh_input = ";".join(
                            [
                                ",".join(kex_algs) if kex_algs else "",
                                ",".join(enc_algs) if enc_algs else "",
                                ",".join(mac_algs) if mac_algs else "",
                            ]
                        )
                        hassh = hashlib.md5(hassh_input.encode()).hexdigest()

                if hassh:
                    # Store HASSH fingerprint in clustering database
                    cluster_cursor.execute(
                        """
                        INSERT OR REPLACE INTO hassh_fingerprints
                        (session, hassh, kex_algorithms, encryption_algorithms,
                         mac_algorithms, src_ip, timestamp, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (
                            session_id,
                            hassh,
                            json.dumps(event.get("kexAlgs", [])),
                            json.dumps(event.get("encCS", [])),
                            json.dumps(event.get("macCS", [])),
                            row["src_ip"],
                            row["timestamp"],
                        ),
                    )

                    hassh_data[session_id] = {
                        "hassh": hassh,
                        "src_ip": row["src_ip"],
                    }

            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"Failed to parse KEX event: {e}")
                continue

        cluster_conn.commit()
        cluster_conn.close()

        # Count unique HASSH values
        hassh_counts = Counter(d["hassh"] for d in hassh_data.values())
        return {
            "sessions_processed": len(hassh_data),
            "unique_hassh": len(hassh_counts),
            "top_hassh": hassh_counts.most_common(10),
        }

    # =========================================================================
    # Cluster Building
    # =========================================================================

    def build_command_clusters(self, days: int = 7, min_interest_score: int = 20) -> list[dict]:
        """
        Build clusters based on command fingerprints and interest scoring.

        Clusters are filtered by command interest/complexity rather than IP count.
        Common reconnaissance commands (uname, id, ls, etc.) are deprioritized.
        Sophisticated attack patterns (useradd, wget+chmod, persistence) are prioritized.

        Args:
            days: Number of days to analyze
            min_interest_score: Minimum interest score (0-100) to include cluster

        Returns:
            List of cluster dicts sorted by interest score
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        # First, ensure fingerprints are extracted
        self.extract_command_fingerprints(days)

        # Get fingerprints from clustering DB
        cluster_conn = self._get_clustering_connection()
        cluster_cursor = cluster_conn.cursor()

        cluster_cursor.execute(
            """
            SELECT session, fingerprint, normalized_commands, command_count
            FROM command_fingerprints
            WHERE fingerprint != 'empty'
            """
        )
        fingerprint_data = {row["session"]: dict(row) for row in cluster_cursor.fetchall()}

        # Get session info from source DB
        source_conn = self._get_source_connection()
        source_cursor = source_conn.cursor()

        # Get sessions with their IPs and raw commands
        if fingerprint_data:
            placeholders = ",".join("?" * len(fingerprint_data))
            source_cursor.execute(
                f"""
                SELECT id, ip, starttime
                FROM sessions
                WHERE id IN ({placeholders})
                AND starttime >= ?
                """,
                list(fingerprint_data.keys()) + [cutoff_str],
            )
        else:
            source_cursor.execute("SELECT id, ip, starttime FROM sessions WHERE 1=0")

        session_info = {row["id"]: dict(row) for row in source_cursor.fetchall()}

        # Get raw commands for interest scoring
        raw_commands_by_session = {}
        if fingerprint_data:
            placeholders = ",".join("?" * len(fingerprint_data))
            source_cursor.execute(
                f"""
                SELECT session, GROUP_CONCAT(input, '|||') as commands
                FROM input
                WHERE session IN ({placeholders})
                GROUP BY session
                """,
                list(fingerprint_data.keys()),
            )
            for row in source_cursor.fetchall():
                raw_commands_by_session[row["session"]] = row["commands"].split("|||") if row["commands"] else []

        # Get payload downloads per session (if available)
        payloads_by_session = defaultdict(list)
        if fingerprint_data:
            source_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
            if source_cursor.fetchone():
                placeholders = ",".join("?" * len(fingerprint_data))
                source_cursor.execute(
                    f"""
                    SELECT
                        d.session,
                        s.ip as src_ip,
                        d.shasum,
                        d.url,
                        v.threat_label,
                        v.positives as vt_detections
                    FROM downloads d
                    JOIN sessions s ON d.session = s.id
                    LEFT JOIN virustotal_scans v ON d.shasum = v.shasum
                    WHERE d.session IN ({placeholders})
                    AND d.shasum IS NOT NULL
                    AND d.shasum != ''
                    """,
                    list(fingerprint_data.keys()),
                )
                for row in source_cursor.fetchall():
                    payloads_by_session[row["session"]].append(
                        {
                            "session": row["session"],
                            "src_ip": row["src_ip"],
                            "shasum": row["shasum"],
                            "url": row["url"],
                            "threat_label": row["threat_label"],
                            "vt_detections": row["vt_detections"],
                        }
                    )

        source_conn.close()

        # Get HASSH fingerprints for sessions (if available)
        hassh_by_session = {}
        if fingerprint_data:
            self.extract_hassh_from_events(days)
            placeholders = ",".join("?" * len(fingerprint_data))
            cluster_cursor.execute(
                f"""
                SELECT session, hassh
                FROM hassh_fingerprints
                WHERE session IN ({placeholders})
                """,
                list(fingerprint_data.keys()),
            )
            for row in cluster_cursor.fetchall():
                if row["hassh"]:
                    hassh_by_session[row["session"]] = row["hassh"]

        # Merge fingerprint data with session info and group by fingerprint
        clusters = defaultdict(list)
        for session_id, fp_data in fingerprint_data.items():
            if session_id in session_info:
                sess = session_info[session_id]
                clusters[fp_data["fingerprint"]].append(
                    {
                        "session": session_id,
                        "src_ip": sess["ip"],
                        "timestamp": sess["starttime"],
                        "commands": fp_data["normalized_commands"],
                        "raw_commands": raw_commands_by_session.get(session_id, []),
                        "command_count": fp_data["command_count"],
                    }
                )

        # Filter by interest score and create cluster records
        result_clusters = []
        for fingerprint, sessions in clusters.items():
            unique_ips = set(s["src_ip"] for s in sessions if s["src_ip"])

            # Get raw commands from first session for interest scoring
            raw_cmds = sessions[0].get("raw_commands", []) if sessions else []
            interest_score, score_reasons = self.calculate_command_interest_score(raw_cmds)

            # Skip low-interest clusters (common recon)
            if interest_score < min_interest_score:
                continue

            # Calculate cluster metadata
            timestamps = [s["timestamp"] for s in sessions if s["timestamp"]]
            first_seen = min(timestamps) if timestamps else datetime.now().isoformat()
            last_seen = max(timestamps) if timestamps else datetime.now().isoformat()

            # Get sample commands for description
            sample_commands = []
            for s in sessions[:1]:
                if s["commands"]:
                    try:
                        sample_commands = json.loads(s["commands"])[:5]
                    except json.JSONDecodeError:
                        pass

            cluster_id = f"cmd-{fingerprint}"

            # Summarize shared payloads within this command cluster
            payload_summary = {}
            payload_files = defaultdict(set)
            for s in sessions:
                for payload in payloads_by_session.get(s["session"], []):
                    shasum = payload.get("shasum")
                    if not shasum:
                        continue
                    entry = payload_summary.setdefault(
                        shasum,
                        {
                            "shasum": shasum,
                            "sessions": set(),
                            "ips": set(),
                            "urls": set(),
                            "threat_label": None,
                            "vt_detections": 0,
                        },
                    )
                    entry["sessions"].add(payload.get("session"))
                    if payload.get("src_ip"):
                        entry["ips"].add(payload["src_ip"])
                    if payload.get("url"):
                        entry["urls"].add(payload["url"])
                        parsed = urlparse(payload["url"])
                        filename = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
                        if filename:
                            payload_files[shasum].add(filename.lower())
                    if payload.get("threat_label") and not entry["threat_label"]:
                        entry["threat_label"] = payload["threat_label"]
                    if payload.get("vt_detections") is not None:
                        entry["vt_detections"] = max(entry["vt_detections"], payload["vt_detections"] or 0)

            # Detect payload execution attempts from raw commands
            execution_sessions_by_payload = defaultdict(set)
            execution_samples_by_payload = defaultdict(list)
            pipe_exec_pattern = re.compile(r"\|\s*(/bin/)?(sh|bash|dash)\b")

            def is_execution_cmd(cmd: str, filename: str, urls: set[str]) -> bool:
                if not cmd or not filename:
                    return False
                cmd_lower = cmd.lower()
                filename_lower = filename.lower()
                filename_variants = {
                    filename_lower,
                    f"/tmp/{filename_lower}",
                    f"./{filename_lower}",
                }
                filename_present = any(var in cmd_lower for var in filename_variants)
                escaped = re.escape(filename_lower)
                patterns = [
                    rf"\bchmod\s+\+x\b.*{escaped}",
                    rf"\bchmod\s+(?:7[0-7]5|7[0-7]7|755|777)\b.*{escaped}",
                    rf"\b(sh|bash|perl|python)\b.*{escaped}",
                    rf"\b(\/tmp\/|\.\/)?{escaped}\b",
                    rf"\bnohup\b.*{escaped}",
                    rf"\bsetsid\b.*{escaped}",
                    rf"\b(bash|sh|dash)\b\s+-c\b.*{escaped}",
                    rf"\b(php|ruby|node)\b.*{escaped}",
                ]
                if filename_present and any(re.search(pat, cmd_lower) for pat in patterns):
                    return True
                if urls and re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash|dash)\b", cmd_lower):
                    return any(url in cmd_lower for url in urls)
                return False

            for s in sessions:
                raw_cmds_for_session = s.get("raw_commands") or []
                if not raw_cmds_for_session:
                    continue
                aggressive_cmds = [cmd for cmd in raw_cmds_for_session if pipe_exec_pattern.search(cmd.lower())]
                session_payloads = payloads_by_session.get(s["session"], [])
                if aggressive_cmds and session_payloads:
                    for payload in session_payloads:
                        shasum = payload.get("shasum")
                        if not shasum:
                            continue
                        execution_sessions_by_payload[shasum].add(s["session"])
                        for cmd in aggressive_cmds:
                            if len(execution_samples_by_payload[shasum]) < 3:
                                execution_samples_by_payload[shasum].append(cmd)
                for shasum, filenames in payload_files.items():
                    urls_lower = {url.lower() for url in payload_summary.get(shasum, {}).get("urls", [])}
                    for filename in filenames:
                        for cmd in raw_cmds_for_session:
                            if is_execution_cmd(cmd, filename, urls_lower):
                                execution_sessions_by_payload[shasum].add(s["session"])
                                if len(execution_samples_by_payload[shasum]) < 3:
                                    execution_samples_by_payload[shasum].append(cmd)
                                break
                        if s["session"] in execution_sessions_by_payload[shasum]:
                            break

            shared_payloads = []
            for shasum, entry in payload_summary.items():
                if len(entry["sessions"]) > 1:
                    exec_sessions = execution_sessions_by_payload.get(shasum, set())
                    shared_payloads.append(
                        {
                            "shasum": shasum,
                            "session_count": len(entry["sessions"]),
                            "unique_ips": len(entry["ips"]),
                            "sample_urls": list(entry["urls"])[:5],
                            "threat_label": entry["threat_label"],
                            "vt_detections": entry["vt_detections"],
                            "execution_attempts": len(exec_sessions),
                            "execution_samples": execution_samples_by_payload.get(shasum, [])[:3],
                        }
                    )
            shared_payloads.sort(key=lambda p: (p["session_count"], p["vt_detections"]), reverse=True)
            payload_execution_payloads = sum(1 for p in shared_payloads if p.get("execution_attempts", 0) > 0)
            payload_execution_sessions = len(
                {sess for p in execution_sessions_by_payload.values() for sess in p}
            )

            # Summarize shared HASSH values within this command cluster
            hassh_counts = Counter()
            hassh_ip_sets = defaultdict(set)
            for s in sessions:
                hassh = hassh_by_session.get(s["session"])
                if not hassh:
                    continue
                hassh_counts[hassh] += 1
                if s.get("src_ip"):
                    hassh_ip_sets[hassh].add(s["src_ip"])

            shared_hassh = []
            for hassh, count in hassh_counts.most_common():
                if count > 1:
                    shared_hassh.append(
                        {
                            "hassh": hassh,
                            "session_count": count,
                            "unique_ips": len(hassh_ip_sets[hassh]),
                        }
                    )
            shared_hassh = shared_hassh[:5]

            extra_description = []
            if shared_payloads:
                extra_description.append(f"shared payloads: {len(shared_payloads)}")
            if payload_execution_payloads:
                extra_description.append(f"execution attempts: {payload_execution_payloads}")
            if shared_hassh:
                extra_description.append(f"shared HASSH: {len(shared_hassh)}")

            # Store cluster in clustering database
            cluster_cursor.execute(
                """
                INSERT OR REPLACE INTO attack_clusters
                (cluster_id, cluster_type, fingerprint, name, description,
                 first_seen, last_seen, size, session_count, score, metadata, updated_at)
                VALUES (?, 'command', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    cluster_id,
                    fingerprint,
                    f"Command Cluster {fingerprint[:8]}",
                    (
                        f"Sessions sharing command pattern: {', '.join(sample_commands[:3])}"
                        + (f" ({'; '.join(extra_description)})" if extra_description else "")
                    ),
                    first_seen,
                    last_seen,
                    len(unique_ips),
                    len(sessions),
                    interest_score,
                    json.dumps({
                        "sample_commands": sample_commands,
                        "interest_reasons": score_reasons,
                        "raw_sample": raw_cmds[:10],  # First 10 raw commands
                        "shared_payloads": shared_payloads[:5],
                        "shared_payloads_count": len(shared_payloads),
                        "shared_payloads_execution_count": payload_execution_payloads,
                        "shared_payloads_execution_sessions": payload_execution_sessions,
                        "shared_hassh": shared_hassh,
                        "shared_hassh_count": len(shared_hassh),
                        "unique_hassh": len(hassh_counts),
                    }),
                ),
            )

            # Store cluster members
            ip_sessions = defaultdict(list)
            for s in sessions:
                if s["src_ip"]:
                    ip_sessions[s["src_ip"]].append(s)

            for ip, ip_sess in ip_sessions.items():
                ip_timestamps = [s["timestamp"] for s in ip_sess if s["timestamp"]]
                cluster_cursor.execute(
                    """
                    INSERT OR REPLACE INTO cluster_members
                    (cluster_id, src_ip, first_seen, last_seen, session_count, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cluster_id,
                        ip,
                        min(ip_timestamps) if ip_timestamps else first_seen,
                        max(ip_timestamps) if ip_timestamps else last_seen,
                        len(ip_sess),
                        json.dumps({"sessions": [s["session"] for s in ip_sess]}),
                    ),
                )

            result_clusters.append(
                {
                    "cluster_id": cluster_id,
                    "cluster_type": "command",
                    "fingerprint": fingerprint,
                    "size": len(unique_ips),
                    "session_count": len(sessions),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "score": interest_score,
                    "interest_reasons": score_reasons,
                    "sample_commands": sample_commands,
                }
            )

        cluster_conn.commit()
        cluster_conn.close()

        # Sort by interest score (most interesting first)
        return sorted(result_clusters, key=lambda x: x["score"], reverse=True)

    def build_hassh_clusters(self, days: int = 7, min_size: int = 2) -> list[dict]:
        """
        Build clusters based on HASSH fingerprints.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size (unique IPs)

        Returns:
            List of cluster dicts
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        # First, ensure HASSH fingerprints are extracted
        self.extract_hassh_from_events(days)

        # Get HASSH fingerprints from clustering DB (already contains src_ip from extraction)
        cluster_conn = self._get_clustering_connection()
        cluster_cursor = cluster_conn.cursor()

        cluster_cursor.execute(
            """
            SELECT
                hassh,
                src_ip,
                session,
                timestamp,
                kex_algorithms
            FROM hassh_fingerprints
            WHERE timestamp >= ?
            """,
            (cutoff_str,),
        )

        clusters = defaultdict(list)
        for row in cluster_cursor.fetchall():
            clusters[row["hassh"]].append(
                {
                    "session": row["session"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "kex_algorithms": row["kex_algorithms"],
                }
            )

        # Filter and create cluster records
        result_clusters = []
        for hassh, sessions in clusters.items():
            unique_ips = set(s["src_ip"] for s in sessions if s["src_ip"])
            if len(unique_ips) < min_size:
                continue

            timestamps = [s["timestamp"] for s in sessions if s["timestamp"]]
            first_seen = min(timestamps) if timestamps else datetime.now().isoformat()
            last_seen = max(timestamps) if timestamps else datetime.now().isoformat()

            cluster_id = f"hassh-{hassh[:16]}"

            # Store cluster in clustering database
            cluster_cursor.execute(
                """
                INSERT OR REPLACE INTO attack_clusters
                (cluster_id, cluster_type, fingerprint, name, description,
                 first_seen, last_seen, size, session_count, score, metadata, updated_at)
                VALUES (?, 'hassh', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    cluster_id,
                    hassh,
                    f"HASSH Cluster {hassh[:8]}",
                    f"Sessions from SSH clients with fingerprint {hassh[:16]}",
                    first_seen,
                    last_seen,
                    len(unique_ips),
                    len(sessions),
                    min(100, len(unique_ips) * 10),
                    json.dumps({"hassh": hassh}),
                ),
            )

            # Store cluster members
            ip_sessions = defaultdict(list)
            for s in sessions:
                if s["src_ip"]:
                    ip_sessions[s["src_ip"]].append(s)

            for ip, ip_sess in ip_sessions.items():
                ip_timestamps = [s["timestamp"] for s in ip_sess if s["timestamp"]]
                cluster_cursor.execute(
                    """
                    INSERT OR REPLACE INTO cluster_members
                    (cluster_id, src_ip, first_seen, last_seen, session_count, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cluster_id,
                        ip,
                        min(ip_timestamps) if ip_timestamps else first_seen,
                        max(ip_timestamps) if ip_timestamps else last_seen,
                        len(ip_sess),
                        json.dumps({"sessions": [s["session"] for s in ip_sess]}),
                    ),
                )

            result_clusters.append(
                {
                    "cluster_id": cluster_id,
                    "cluster_type": "hassh",
                    "fingerprint": hassh,
                    "size": len(unique_ips),
                    "session_count": len(sessions),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                }
            )

        cluster_conn.commit()
        cluster_conn.close()

        return sorted(result_clusters, key=lambda x: x["size"], reverse=True)

    def build_payload_clusters(self, days: int = 7, min_size: int = 1) -> list[dict]:
        """
        Build clusters based on downloaded malware payloads.

        Any download of the same malware is interesting regardless of IP count.
        Score is based on VT detections and unique URL count.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size (default 1 - all payloads are interesting)

        Returns:
            List of cluster dicts sorted by score
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Read from source database
        source_conn = self._get_source_connection()
        source_cursor = source_conn.cursor()

        # Check if downloads table exists
        source_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
        if not source_cursor.fetchone():
            source_conn.close()
            return []

        # Group downloads by SHA256 (reading from source DB)
        source_cursor.execute(
            """
            SELECT
                d.shasum,
                d.session,
                s.ip as src_ip,
                d.timestamp,
                d.url,
                v.threat_label,
                v.positives as vt_detections
            FROM downloads d
            JOIN sessions s ON d.session = s.id
            LEFT JOIN virustotal_scans v ON d.shasum = v.shasum
            WHERE d.timestamp >= ?
            AND d.shasum IS NOT NULL
            AND d.shasum != ''
            """,
            (cutoff_str,),
        )

        clusters = defaultdict(list)
        for row in source_cursor.fetchall():
            clusters[row["shasum"]].append(
                {
                    "session": row["session"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "url": row["url"],
                    "threat_label": row["threat_label"],
                    "vt_detections": row["vt_detections"],
                }
            )

        source_conn.close()

        # Write results to clustering database
        cluster_conn = self._get_clustering_connection()
        cluster_cursor = cluster_conn.cursor()

        # Build payload execution signal map from command clusters (if available)
        payload_exec_info: dict[str, dict] = defaultdict(lambda: {"attempts": 0, "samples": []})
        cluster_cursor.execute(
            """
            SELECT metadata
            FROM attack_clusters
            WHERE cluster_type = 'command'
            AND metadata IS NOT NULL
            """
        )
        for row in cluster_cursor.fetchall():
            try:
                metadata = json.loads(row["metadata"]) if row["metadata"] else {}
            except json.JSONDecodeError:
                continue
            for payload in metadata.get("shared_payloads", []):
                shasum = payload.get("shasum")
                attempts = payload.get("execution_attempts") or 0
                if not shasum or attempts <= 0:
                    continue
                entry = payload_exec_info[shasum]
                entry["attempts"] += attempts
                for cmd in payload.get("execution_samples", []) or []:
                    if cmd not in entry["samples"] and len(entry["samples"]) < 3:
                        entry["samples"].append(cmd)

        # Create cluster records for all payloads (no min_size filter for payloads)
        result_clusters = []
        for shasum, downloads in clusters.items():
            unique_ips = set(d["src_ip"] for d in downloads if d["src_ip"])
            unique_urls = set(d["url"] for d in downloads if d["url"])

            # Skip if below min_size (default is 1, so effectively no filter)
            if len(unique_ips) < min_size:
                continue

            timestamps = [d["timestamp"] for d in downloads if d["timestamp"]]
            first_seen = min(timestamps) if timestamps else datetime.now().isoformat()
            last_seen = max(timestamps) if timestamps else datetime.now().isoformat()

            # Get threat info
            threat_label = next((d["threat_label"] for d in downloads if d["threat_label"]), None)
            vt_detections = max((d["vt_detections"] or 0 for d in downloads), default=0)

            cluster_id = f"payload-{shasum[:16]}"

            # Calculate score based on VT detections, unique IPs, and unique URLs
            # VT detections are strongest signal, then distribution breadth
            score = min(100, (vt_detections * 3) + (len(unique_ips) * 5) + (len(unique_urls) * 3))

            exec_info = payload_exec_info.get(shasum, {})
            exec_attempts = exec_info.get("attempts", 0)
            exec_samples = exec_info.get("samples", [])

            cluster_cursor.execute(
                """
                INSERT OR REPLACE INTO attack_clusters
                (cluster_id, cluster_type, fingerprint, name, description,
                 first_seen, last_seen, size, session_count, score, metadata, updated_at)
                VALUES (?, 'payload', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    cluster_id,
                    shasum,
                    f"Payload Cluster {shasum[:8]}",
                    f"Sessions downloading {threat_label or 'malware'} ({shasum[:16]}...)",
                    first_seen,
                    last_seen,
                    len(unique_ips),
                    len(downloads),
                    score,
                    json.dumps(
                        {
                            "shasum": shasum,
                            "threat_label": threat_label,
                            "vt_detections": vt_detections,
                            "sample_urls": list(set(d["url"] for d in downloads if d["url"]))[:5],
                            "exec_attempts": exec_attempts,
                            "exec_samples": exec_samples,
                        }
                    ),
                ),
            )

            # Store cluster members
            ip_downloads = defaultdict(list)
            for d in downloads:
                if d["src_ip"]:
                    ip_downloads[d["src_ip"]].append(d)

            for ip, ip_dls in ip_downloads.items():
                ip_timestamps = [d["timestamp"] for d in ip_dls if d["timestamp"]]
                cluster_cursor.execute(
                    """
                    INSERT OR REPLACE INTO cluster_members
                    (cluster_id, src_ip, first_seen, last_seen, session_count, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cluster_id,
                        ip,
                        min(ip_timestamps) if ip_timestamps else first_seen,
                        max(ip_timestamps) if ip_timestamps else last_seen,
                        len(ip_dls),
                        json.dumps({"downloads": len(ip_dls)}),
                    ),
                )

            result_clusters.append(
                {
                    "cluster_id": cluster_id,
                    "cluster_type": "payload",
                    "fingerprint": shasum,
                    "size": len(unique_ips),
                    "session_count": len(downloads),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "threat_label": threat_label,
                    "vt_detections": vt_detections,
                    "score": score,
                }
            )

        cluster_conn.commit()
        cluster_conn.close()

        return sorted(result_clusters, key=lambda x: x["score"], reverse=True)

    # =========================================================================
    # Cluster Queries
    # =========================================================================

    def get_clusters(
        self,
        cluster_type: Optional[str] = None,
        min_size: int = 2,
        min_score: int = 0,
        days: int = 7,
        limit: int = 100,
    ) -> list[dict]:
        """
        Get clusters with optional filtering.

        Args:
            cluster_type: Filter by type ('command', 'hassh', 'payload')
            min_size: Minimum number of unique IPs
            min_score: Minimum threat score
            days: Look back period
            limit: Maximum results

        Returns:
            List of cluster dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = """
            SELECT
                cluster_id, cluster_type, fingerprint, name, description,
                first_seen, last_seen, size, session_count, score, metadata
            FROM attack_clusters
            WHERE last_seen >= ?
            AND size >= ?
            AND score >= ?
        """
        params = [cutoff_str, min_size, min_score]

        if cluster_type:
            query += " AND cluster_type = ?"
            params.append(cluster_type)

        query += " ORDER BY score DESC, size DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        clusters = []
        for row in cursor.fetchall():
            cluster = dict(row)
            if cluster["metadata"]:
                try:
                    cluster["metadata"] = json.loads(cluster["metadata"])
                except json.JSONDecodeError:
                    pass
            clusters.append(cluster)

        conn.close()
        return clusters

    def get_cluster_detail(self, cluster_id: str) -> Optional[dict]:
        """
        Get detailed information about a cluster.

        Args:
            cluster_id: Cluster ID

        Returns:
            Cluster dict with members, or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get cluster info
        cursor.execute(
            """
            SELECT
                cluster_id, cluster_type, fingerprint, name, description,
                first_seen, last_seen, size, session_count, score, metadata
            FROM attack_clusters
            WHERE cluster_id = ?
            """,
            (cluster_id,),
        )

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        cluster = dict(row)
        if cluster["metadata"]:
            try:
                cluster["metadata"] = json.loads(cluster["metadata"])
            except json.JSONDecodeError:
                pass

        # Get members
        cursor.execute(
            """
            SELECT src_ip, first_seen, last_seen, session_count, metadata
            FROM cluster_members
            WHERE cluster_id = ?
            ORDER BY session_count DESC
            """,
            (cluster_id,),
        )

        cluster["members"] = []
        for member_row in cursor.fetchall():
            member = dict(member_row)
            if member["metadata"]:
                try:
                    member["metadata"] = json.loads(member["metadata"])
                except json.JSONDecodeError:
                    pass
            cluster["members"].append(member)

        # Get enrichment if available
        cursor.execute(
            """
            SELECT threat_families, top_asns, countries, threat_score, tags
            FROM cluster_enrichment
            WHERE cluster_id = ?
            """,
            (cluster_id,),
        )

        enrichment_row = cursor.fetchone()
        if enrichment_row:
            cluster["enrichment"] = {
                "threat_families": json.loads(enrichment_row["threat_families"] or "[]"),
                "top_asns": json.loads(enrichment_row["top_asns"] or "[]"),
                "countries": json.loads(enrichment_row["countries"] or "[]"),
                "threat_score": enrichment_row["threat_score"],
                "tags": json.loads(enrichment_row["tags"] or "[]"),
            }

        conn.close()
        return cluster

    def get_ip_clusters(self, ip: str) -> list[dict]:
        """
        Get all clusters containing a specific IP.

        Args:
            ip: IP address

        Returns:
            List of cluster dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                c.cluster_id, c.cluster_type, c.fingerprint, c.name,
                c.size, c.session_count, c.score,
                m.first_seen, m.last_seen, m.session_count as ip_sessions
            FROM attack_clusters c
            JOIN cluster_members m ON c.cluster_id = m.cluster_id
            WHERE m.src_ip = ?
            ORDER BY c.score DESC
            """,
            (ip,),
        )

        clusters = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return clusters

    def run_all_clustering(self, days: int = 7, min_size: int = 2) -> dict:
        """
        Run all clustering algorithms.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size

        Returns:
            Summary of all clusters found
        """
        results = {
            "command_clusters": self.build_command_clusters(days, min_size),
            "hassh_clusters": self.build_hassh_clusters(days, min_size),
            "payload_clusters": self.build_payload_clusters(days, min_size),
        }

        results["summary"] = {  # type: ignore
            "total_clusters": sum(len(v) for v in results.values() if isinstance(v, list)),
            "command_clusters_count": len(results["command_clusters"]),
            "hassh_clusters_count": len(results["hassh_clusters"]),
            "payload_clusters_count": len(results["payload_clusters"]),
        }

        return results

    def diagnose(self, days: int = 7) -> dict:
        """
        Diagnose clustering issues by checking database state.

        Returns detailed info about what data is available for clustering.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        result = {
            "db_path": self.source_db_path,
            "clustering_db_path": self.clustering_db_path,
            "cutoff": cutoff_str,
            "tables": {},
            "data_counts": {},
            "sample_timestamps": {},
            "issues": [],
        }

        # First check if source database exists and is accessible
        try:
            conn = self._get_source_connection()
            cursor = conn.cursor()
        except Exception as e:
            result["issues"].append(f"Cannot connect to source database: {e}")
        return result

    # =========================================================================
    # TTP Clustering Methods
    # =========================================================================

    def build_ttp_clusters(self, days: int = 7, min_size: int = 2) -> list[dict]:
        """
        Build clusters based on TTP (Tactics, Techniques, and Procedures) patterns.

        Args:
            days: Number of days to look back
            min_size: Minimum cluster size (unique IPs)

        Returns:
            List of TTP cluster dictionaries
        """
        from services.ttp_extraction import TTPExtractionService

        logger.info(f"Building TTP clusters for last {days} days (min_size={min_size})")

        # Initialize TTP extraction service
        mitre_db_path = (
            self.clustering_db_path.replace("_clustering.db", "_mitre.db")
            if self.clustering_db_path
            else self.source_db_path.replace(".db", "_mitre.db")
        )
        ttp_service = TTPExtractionService(self.source_db_path, mitre_db_path)

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        # Get sessions with TTP fingerprints
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT session, ttp_sequence, dominant_techniques, confidence_score, tactics
            FROM ttp_fingerprints
            WHERE created_at >= ?
            ORDER BY confidence_score DESC
        """,
            (cutoff_date.isoformat(),),
        )

        session_ttps = {}
        for row in cursor.fetchall():
            try:
                session_ttps[row["session"]] = {
                    "ttp_sequence": json.loads(row["ttp_sequence"]),
                    "dominant_techniques": json.loads(row["dominant_techniques"]),
                    "confidence_score": row["confidence_score"],
                    "tactics": json.loads(row["tactics"]),
                }
            except (json.JSONDecodeError, TypeError):
                continue

        conn.close()

        if not session_ttps:
            logger.info("No TTP fingerprints found - running batch analysis first")
            # Auto-analyze sessions to populate fingerprints
            batch_result = self.batch_analyze_ttps(days=days)
            logger.info(
                f"Batch analysis complete: {batch_result.get('analyzed', 0)} sessions analyzed, "
                f"{batch_result.get('ttps_found', 0)} TTPs found"
            )

            # Re-query fingerprints after batch analysis
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT session, ttp_sequence, dominant_techniques, confidence_score, tactics
                FROM ttp_fingerprints
                WHERE created_at >= ?
                ORDER BY confidence_score DESC
            """,
                (cutoff_date.isoformat(),),
            )

            for row in cursor.fetchall():
                try:
                    session_ttps[row["session"]] = {
                        "ttp_sequence": json.loads(row["ttp_sequence"]),
                        "dominant_techniques": json.loads(row["dominant_techniques"]),
                        "confidence_score": row["confidence_score"],
                        "tactics": json.loads(row["tactics"]),
                    }
                except (json.JSONDecodeError, TypeError):
                    continue

            conn.close()

            if not session_ttps:
                logger.info("No TTP fingerprints found even after batch analysis")
                return []

        # Group sessions by dominant technique
        technique_clusters = defaultdict(list)

        for session_id, ttp_data in session_ttps.items():
            if ttp_data["dominant_techniques"]:
                dominant_technique = ttp_data["dominant_techniques"][0]  # Use top technique
                technique_clusters[dominant_technique].append((session_id, ttp_data))

        # Create TTP clusters
        ttp_clusters = []

        for technique_id, sessions_data in technique_clusters.items():
            if len(sessions_data) < min_size:
                continue

            # Get unique IPs for this cluster
            session_ids = [s[0] for s in sessions_data]
            unique_ips = self._get_unique_ips_for_sessions(session_ids)

            if len(unique_ips) < min_size:
                continue

            # Calculate cluster metrics
            confidence_scores = [
                float(s[1]["confidence_score"]) for s in sessions_data if s[1]["confidence_score"] is not None
            ]
            avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0

            # Get technique details
            technique_info = ttp_service.get_technique_details(technique_id)

            cluster_id = f"ttp_{technique_id}_{len(unique_ips)}_{int(avg_confidence * 100)}"

            # Get timestamps safely
            timestamps = [self._get_session_timestamp(s[0]) for s in sessions_data]
            valid_timestamps = [ts for ts in timestamps if ts]

            cluster = {
                "cluster_id": cluster_id,
                "cluster_type": "ttp",
                "dominant_technique": technique_id,
                "technique_name": technique_info.get("name", technique_id) if technique_info else technique_id,
                "dominant_tactic": technique_info.get("tactic_id", "unknown") if technique_info else "unknown",
                "size": len(unique_ips),
                "session_count": len(session_ids),
                "score": int(avg_confidence * 100),
                "first_seen": min(valid_timestamps) if valid_timestamps else datetime.now(timezone.utc).isoformat(),
                "last_seen": max(valid_timestamps) if valid_timestamps else datetime.now(timezone.utc).isoformat(),
                "metadata": json.dumps(
                    {
                        "technique_details": technique_info,
                        "avg_confidence": avg_confidence,
                        "member_sessions": session_ids[:10],  # Sample of sessions
                        "unique_ips": list(unique_ips)[:20],  # Sample of IPs
                    }
                ),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            ttp_clusters.append(cluster)

            # Store cluster in database
            self._store_ttp_cluster(cluster)

        logger.info(f"Created {len(ttp_clusters)} TTP clusters")
        return ttp_clusters

    def _store_ttp_cluster(self, cluster: dict):
        """Store a TTP cluster in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO ttp_clusters
            (cluster_id, dominant_technique, dominant_tactic, member_count, confidence_score,
             first_seen, last_seen, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                cluster["cluster_id"],
                cluster["dominant_technique"],
                cluster["dominant_tactic"],
                cluster["size"],
                cluster.get("avg_confidence", cluster["score"] / 100.0),
                cluster["first_seen"],
                cluster["last_seen"],
                cluster["metadata"],
                cluster["created_at"],
            ),
        )

        conn.commit()
        conn.close()

    def get_ttp_clusters(self, technique_filter: Optional[str] = None, min_score: int = 0) -> list[dict]:
        """
        Get TTP clusters from database.

        Args:
            technique_filter: Filter by specific technique ID
            min_score: Minimum confidence score (0-100)

        Returns:
            List of TTP cluster dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT cluster_id, dominant_technique, dominant_tactic, member_count,
                   confidence_score, first_seen, last_seen, metadata, created_at
            FROM ttp_clusters
            WHERE confidence_score >= ?
        """

        params = [min_score / 100.0]  # type: ignore

        if technique_filter:
            query += " AND dominant_technique = ?"
            params.append(technique_filter)  # type: ignore

        query += " ORDER BY confidence_score DESC, member_count DESC"

        cursor.execute(query, params)

        clusters = []
        for row in cursor.fetchall():
            try:
                metadata = json.loads(row["metadata"]) if row["metadata"] else {}
                cluster = {
                    "cluster_id": row["cluster_id"],
                    "cluster_type": "ttp",
                    "dominant_technique": row["dominant_technique"],
                    "dominant_tactic": row["dominant_tactic"],
                    "size": row["member_count"],
                    "score": int(row["confidence_score"] * 100),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "metadata": metadata,
                    "created_at": row["created_at"],
                }
                clusters.append(cluster)
            except (json.JSONDecodeError, TypeError):
                continue

        conn.close()
        return clusters

    def _get_unique_ips_for_sessions(self, session_ids: list[str]) -> set[str]:
        """Get unique IPs for a list of session IDs."""
        conn = self._get_source_connection()
        cursor = conn.cursor()

        placeholders = ",".join("?" * len(session_ids))
        cursor.execute(
            f"""
            SELECT DISTINCT ip
            FROM sessions
            WHERE id IN ({placeholders})
        """,
            session_ids,
        )

        ips = {row["ip"] for row in cursor.fetchall()}
        conn.close()

        return ips

    def _get_session_timestamp(self, session_id: str) -> str:
        """Get the start timestamp for a session."""
        conn = self._get_source_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT starttime FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        conn.close()

        return row["starttime"] if row else datetime.now(timezone.utc).isoformat()

    def analyze_session_ttps(self, session_id: str) -> dict:
        """
        Analyze TTPs for a specific session.

        Args:
            session_id: Session ID to analyze

        Returns:
            TTP analysis results
        """
        from services.ttp_extraction import TTPExtractionService

        mitre_db_path = (
            self.clustering_db_path.replace("_clustering.db", "_mitre.db")
            if self.clustering_db_path
            else self.source_db_path.replace(".db", "_mitre.db")
        )
        ttp_service = TTPExtractionService(self.source_db_path, mitre_db_path)

        # Extract TTPs
        ttps = ttp_service.extract_session_ttps(session_id)

        # Create fingerprint
        fingerprint = ttp_service.create_ttp_fingerprint(session_id)

        # Store fingerprint if TTPs found
        if fingerprint:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO ttp_fingerprints
                (session, ttp_sequence, technique_count, dominant_techniques,
                 confidence_score, tactics, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (
                    fingerprint["session"],
                    fingerprint["ttp_sequence"],
                    fingerprint["technique_count"],
                    fingerprint["dominant_techniques"],
                    fingerprint["confidence_score"],
                    fingerprint["tactics"],
                ),
            )

            conn.commit()
            conn.close()

        return {"session_id": session_id, "ttps_found": len(ttps), "ttp_details": ttps, "fingerprint": fingerprint}

    def batch_analyze_ttps(self, days: int = 7, batch_size: int = 100) -> dict:
        """
        Analyze TTPs for all sessions in the given time period that haven't been analyzed yet.

        This method should be called periodically (e.g., via scheduled task) to ensure
        TTP fingerprints are populated for clustering.

        Args:
            days: Number of days to look back
            batch_size: Number of sessions to process per batch

        Returns:
            Summary of analysis results
        """
        from services.ttp_extraction import TTPExtractionService

        logger.info(f"Starting batch TTP analysis for last {days} days")

        # Initialize TTP extraction service
        mitre_db_path = (
            self.clustering_db_path.replace("_clustering.db", "_mitre.db")
            if self.clustering_db_path
            else self.source_db_path.replace(".db", "_mitre.db")
        )

        try:
            ttp_service = TTPExtractionService(self.source_db_path, mitre_db_path)
        except Exception as e:
            logger.error(f"Failed to initialize TTP service: {e}")
            return {"error": str(e), "analyzed": 0, "skipped": 0, "failed": 0}

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        # Get existing fingerprints to skip
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT session FROM ttp_fingerprints")
        existing_sessions = {row["session"] for row in cursor.fetchall()}
        conn.close()

        # Get sessions with commands that need analysis
        source_conn = self._get_source_connection()
        source_cursor = source_conn.cursor()

        source_cursor.execute(
            """
            SELECT DISTINCT s.id
            FROM sessions s
            INNER JOIN input i ON s.id = i.session
            WHERE s.starttime >= ?
            ORDER BY s.starttime DESC
        """,
            (cutoff_date.isoformat(),),
        )

        all_sessions = [row["id"] for row in source_cursor.fetchall()]
        source_conn.close()

        # Filter out already analyzed sessions
        sessions_to_analyze = [s for s in all_sessions if s not in existing_sessions]

        logger.info(
            f"Found {len(all_sessions)} sessions with commands, "
            f"{len(existing_sessions)} already analyzed, "
            f"{len(sessions_to_analyze)} to analyze"
        )

        results = {
            "total_sessions": len(all_sessions),
            "already_analyzed": len(existing_sessions),
            "to_analyze": len(sessions_to_analyze),
            "analyzed": 0,
            "ttps_found": 0,
            "skipped": 0,
            "failed": 0,
            "errors": [],
        }

        # Process in batches
        for i in range(0, len(sessions_to_analyze), batch_size):
            batch = sessions_to_analyze[i : i + batch_size]
            logger.info(f"Processing batch {i // batch_size + 1}: sessions {i + 1} to {i + len(batch)}")

            for session_id in batch:
                try:
                    result = self.analyze_session_ttps(session_id)
                    if result.get("ttps_found", 0) > 0:
                        results["analyzed"] += 1
                        results["ttps_found"] += result["ttps_found"]
                    else:
                        results["skipped"] += 1
                except Exception as e:
                    logger.error(f"Failed to analyze session {session_id}: {e}")
                    results["failed"] += 1
                    if len(results["errors"]) < 10:  # Keep first 10 errors
                        results["errors"].append({"session": session_id, "error": str(e)})

        logger.info(
            f"Batch TTP analysis complete: {results['analyzed']} analyzed, "
            f"{results['skipped']} skipped (no TTPs), {results['failed']} failed"
        )

        return results

        # Check which tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]
        result["tables"]["existing"] = tables

        # Check sessions table
        if "sessions" in tables:
            cursor.execute("SELECT COUNT(*) as cnt FROM sessions")
            result["data_counts"]["total_sessions"] = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM sessions WHERE starttime >= ?", (cutoff_str,))
            result["data_counts"]["recent_sessions"] = cursor.fetchone()["cnt"]

            cursor.execute("SELECT starttime FROM sessions ORDER BY starttime DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                result["sample_timestamps"]["latest_session"] = row["starttime"]

            cursor.execute("SELECT COUNT(*) as cnt FROM sessions WHERE ip IS NULL")
            null_ips = cursor.fetchone()["cnt"]
            if null_ips > 0:
                result["issues"].append(f"{null_ips} sessions have NULL ip")
        else:
            result["issues"].append("sessions table not found")

        # Check input table (commands)
        if "input" in tables:
            cursor.execute("SELECT COUNT(*) as cnt FROM input")
            result["data_counts"]["total_commands"] = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM input WHERE timestamp >= ?", (cutoff_str,))
            result["data_counts"]["recent_commands"] = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(DISTINCT session) as cnt FROM input WHERE timestamp >= ?", (cutoff_str,))
            result["data_counts"]["sessions_with_commands"] = cursor.fetchone()["cnt"]

            cursor.execute("SELECT timestamp FROM input ORDER BY timestamp DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                result["sample_timestamps"]["latest_command"] = row["timestamp"]
        else:
            result["issues"].append("input table not found")

        # Check downloads table
        if "downloads" in tables:
            cursor.execute("SELECT COUNT(*) as cnt FROM downloads WHERE shasum IS NOT NULL")
            result["data_counts"]["total_downloads"] = cursor.fetchone()["cnt"]

            cursor.execute(
                "SELECT COUNT(*) as cnt FROM downloads WHERE timestamp >= ? AND shasum IS NOT NULL", (cutoff_str,)
            )
            result["data_counts"]["recent_downloads"] = cursor.fetchone()["cnt"]

            cursor.execute(
                "SELECT COUNT(DISTINCT shasum) as cnt FROM downloads WHERE timestamp >= ? AND shasum IS NOT NULL",
                (cutoff_str,),
            )
            result["data_counts"]["unique_payloads"] = cursor.fetchone()["cnt"]
        else:
            result["issues"].append("downloads table not found")

        # Check for potential timestamp format issues
        if "sessions" in tables:
            cursor.execute("SELECT starttime FROM sessions LIMIT 1")
            row = cursor.fetchone()
            if row and row["starttime"]:
                sample_ts = row["starttime"]
                result["sample_timestamps"]["session_format_example"] = sample_ts
                # Check if format has 'T' separator (ISO8601)
                if "T" in str(sample_ts):
                    result["issues"].append(f"Timestamps use ISO8601 format with 'T' separator: {sample_ts}")

        # Check events table for HASSH
        if "events" in tables:
            cursor.execute("SELECT COUNT(*) as cnt FROM events WHERE eventid = 'cowrie.client.kex'")
            result["data_counts"]["kex_events"] = cursor.fetchone()["cnt"]
        else:
            result["issues"].append("events table not found - HASSH clustering will not work")

        # Summary
        if result["data_counts"].get("recent_commands", 0) == 0:
            result["issues"].append("No commands found in time range - check timestamp format")

        if result["data_counts"].get("sessions_with_commands", 0) < 2:
            result["issues"].append("Less than 2 sessions with commands - minimum for clustering")

        conn.close()

        # Check clustering database
        result["clustering_tables"] = {}
        try:
            cluster_conn = self._get_clustering_connection()
            cluster_cursor = cluster_conn.cursor()

            # Check which tables exist in clustering DB
            cluster_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            cluster_tables = [row["name"] for row in cluster_cursor.fetchall()]
            result["clustering_tables"]["existing"] = cluster_tables

            # Check command_fingerprints table
            if "command_fingerprints" in cluster_tables:
                cluster_cursor.execute("SELECT COUNT(*) as cnt FROM command_fingerprints")
                result["data_counts"]["fingerprints_stored"] = cluster_cursor.fetchone()["cnt"]

                cluster_cursor.execute(
                    "SELECT COUNT(DISTINCT fingerprint) as cnt FROM command_fingerprints WHERE fingerprint != 'empty'"
                )
                result["data_counts"]["unique_fingerprints"] = cluster_cursor.fetchone()["cnt"]

            # Check attack_clusters table
            if "attack_clusters" in cluster_tables:
                cluster_cursor.execute("SELECT COUNT(*) as cnt FROM attack_clusters")
                result["data_counts"]["stored_clusters"] = cluster_cursor.fetchone()["cnt"]

            cluster_conn.close()
        except Exception as e:
            result["issues"].append(f"Cannot connect to clustering database: {e}")

        return result

    # =========================================================================
    # OpenCTI Enrichment
    # =========================================================================

    def enrich_cluster_with_opencti(self, cluster_id: str) -> dict:
        """
        Enrich a cluster with threat intelligence from OpenCTI.

        Queries OpenCTI for related threat actors, campaigns, and malware
        based on the cluster's IOCs (IPs, hashes, techniques).

        Args:
            cluster_id: Cluster ID to enrich

        Returns:
            Enrichment results including matched entities
        """
        import os
        from config import config

        result = {
            "cluster_id": cluster_id,
            "enriched": False,
            "opencti_available": False,
            "threat_actors": [],
            "campaigns": [],
            "malware_families": [],
            "vulnerabilities": [],
            "tags": [],
            "threat_score": 0,
            "errors": [],
        }

        # Check if OpenCTI is configured
        opencti_url = os.getenv("OPENCTI_URL", config.OPENCTI_URL)
        opencti_key = os.getenv("OPENCTI_API_KEY", config.OPENCTI_API_KEY)

        if not opencti_url or not opencti_key:
            result["errors"].append("OpenCTI not configured (missing URL or API key)")
            return result

        try:
            from services.opencti_client import OpenCTIClientService, OPENCTI_AVAILABLE

            if not OPENCTI_AVAILABLE:
                result["errors"].append("OpenCTI client library (pycti) not available")
                return result

            result["opencti_available"] = True

            # Get cluster details
            cluster = self.get_cluster_detail(cluster_id)
            if not cluster:
                result["errors"].append(f"Cluster {cluster_id} not found")
                return result

            # Get cached OpenCTI client (avoids slow init on every request)
            from services.opencti_client import get_opencti_client

            opencti = get_opencti_client(
                url=opencti_url,
                api_key=opencti_key,
                ssl_verify=config.OPENCTI_SSL_VERIFY,
            )

            if not opencti:
                result["errors"].append("Failed to initialize OpenCTI client")
                return result

            # Build search queries based on cluster type
            cluster_type = cluster.get("cluster_type", "unknown")
            search_queries = []

            if cluster_type == "payload":
                # Search by file hash
                fingerprint = cluster.get("fingerprint", "")
                if fingerprint and len(fingerprint) == 64:
                    search_queries.append(("hash", fingerprint))
                # Search by threat label
                metadata = cluster.get("metadata", {})
                threat_label = metadata.get("threat_label") if isinstance(metadata, dict) else None
                if threat_label:
                    search_queries.append(("malware", threat_label))

            elif cluster_type == "ttp":
                # Search by MITRE technique
                technique = cluster.get("dominant_technique") or cluster.get("fingerprint", "")
                if technique and technique.startswith("T"):
                    search_queries.append(("technique", technique))

            elif cluster_type == "command":
                # Search by notable patterns in commands
                metadata = cluster.get("metadata", {})
                interest_reasons = metadata.get("interest_reasons", []) if isinstance(metadata, dict) else []
                for reason in interest_reasons:
                    if reason.startswith("pattern:"):
                        pattern = reason.replace("pattern:", "")
                        search_queries.append(("keyword", pattern))

            # Search for cluster member IPs
            members = cluster.get("members", [])
            for member in members[:10]:  # Limit to first 10 IPs
                ip = member.get("src_ip")
                if ip:
                    search_queries.append(("ip", ip))

            # Execute searches
            all_results = {"threat_actors": [], "campaigns": [], "malware": [], "vulnerabilities": []}

            for query_type, query_value in search_queries:
                try:
                    if query_type == "ip":
                        # Search for IP in indicators
                        search_result = opencti.search_threat_intelligence(
                            query=query_value,
                            entity_types=["Indicator", "Infrastructure"]
                        )
                    elif query_type == "hash":
                        search_result = opencti.search_threat_intelligence(
                            query=query_value,
                            entity_types=["Indicator", "Malware"]
                        )
                    elif query_type == "technique":
                        search_result = opencti.search_threat_intelligence(
                            query=query_value,
                            entity_types=["Attack-Pattern"]
                        )
                    else:
                        search_result = opencti.search_threat_intelligence(
                            query=query_value,
                            entity_types=["Malware", "Threat-Actor", "Campaign"]
                        )

                    if search_result.get("success"):
                        for entity_type, entities in search_result.get("results", {}).items():
                            if entities:
                                if "threat" in entity_type or "actor" in entity_type:
                                    all_results["threat_actors"].extend(entities)
                                elif "campaign" in entity_type:
                                    all_results["campaigns"].extend(entities)
                                elif "malware" in entity_type:
                                    all_results["malware"].extend(entities)
                                elif "vulnerability" in entity_type:
                                    all_results["vulnerabilities"].extend(entities)

                except Exception as e:
                    logger.warning(f"OpenCTI search failed for {query_type}={query_value}: {e}")

            # Deduplicate and format results
            seen_ids = set()
            for actor in all_results["threat_actors"]:
                actor_id = actor.get("id") or actor.get("standard_id")
                if actor_id and actor_id not in seen_ids:
                    seen_ids.add(actor_id)
                    result["threat_actors"].append({
                        "id": actor_id,
                        "name": actor.get("name", "Unknown"),
                        "description": actor.get("description", "")[:200] if actor.get("description") else "",
                    })

            for campaign in all_results["campaigns"]:
                campaign_id = campaign.get("id") or campaign.get("standard_id")
                if campaign_id and campaign_id not in seen_ids:
                    seen_ids.add(campaign_id)
                    result["campaigns"].append({
                        "id": campaign_id,
                        "name": campaign.get("name", "Unknown"),
                        "description": campaign.get("description", "")[:200] if campaign.get("description") else "",
                    })

            for malware in all_results["malware"]:
                malware_id = malware.get("id") or malware.get("standard_id")
                if malware_id and malware_id not in seen_ids:
                    seen_ids.add(malware_id)
                    result["malware_families"].append({
                        "id": malware_id,
                        "name": malware.get("name", "Unknown"),
                        "description": malware.get("description", "")[:200] if malware.get("description") else "",
                    })

            # Calculate threat score based on matches
            threat_score = cluster.get("score", 0)
            if result["threat_actors"]:
                threat_score = min(100, threat_score + 20)
            if result["campaigns"]:
                threat_score = min(100, threat_score + 15)
            if result["malware_families"]:
                threat_score = min(100, threat_score + 10)
            result["threat_score"] = threat_score

            # Generate tags from matches
            tags = []
            for actor in result["threat_actors"][:3]:
                tags.append(f"threat-actor:{actor['name']}")
            for campaign in result["campaigns"][:3]:
                tags.append(f"campaign:{campaign['name']}")
            for malware in result["malware_families"][:3]:
                tags.append(f"malware:{malware['name']}")
            result["tags"] = tags

            # Store enrichment in database
            if result["threat_actors"] or result["campaigns"] or result["malware_families"]:
                result["enriched"] = True
                self._store_cluster_enrichment(cluster_id, result)

            return result

        except Exception as e:
            logger.error(f"OpenCTI enrichment failed for cluster {cluster_id}: {e}")
            result["errors"].append(str(e))
            return result

    def _store_cluster_enrichment(self, cluster_id: str, enrichment: dict):
        """Store cluster enrichment data in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO cluster_enrichment
            (cluster_id, threat_families, top_asns, countries, threat_score, tags, enriched_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                cluster_id,
                json.dumps([m["name"] for m in enrichment.get("malware_families", [])]),
                json.dumps([]),  # ASNs would need GeoIP lookup
                json.dumps([]),  # Countries would need GeoIP lookup
                enrichment.get("threat_score", 0),
                json.dumps(enrichment.get("tags", [])),
            ),
        )

        conn.commit()
        conn.close()

    def enrich_all_clusters(self, min_score: int = 50, days: int = 7, limit: int = 50) -> dict:
        """
        Enrich multiple clusters with OpenCTI threat intelligence.

        Args:
            min_score: Minimum cluster score to enrich
            days: Look back period
            limit: Maximum clusters to enrich

        Returns:
            Summary of enrichment results
        """
        clusters = self.get_clusters(min_score=min_score, days=days, limit=limit, min_size=1)

        results = {
            "total_clusters": len(clusters),
            "enriched": 0,
            "failed": 0,
            "skipped": 0,
            "details": [],
        }

        for cluster in clusters:
            cluster_id = cluster.get("cluster_id")
            if not cluster_id:
                results["skipped"] += 1
                continue

            enrichment = self.enrich_cluster_with_opencti(cluster_id)

            if enrichment.get("enriched"):
                results["enriched"] += 1
                results["details"].append({
                    "cluster_id": cluster_id,
                    "status": "enriched",
                    "threat_actors": len(enrichment.get("threat_actors", [])),
                    "campaigns": len(enrichment.get("campaigns", [])),
                    "malware_families": len(enrichment.get("malware_families", [])),
                })
            elif enrichment.get("errors"):
                results["failed"] += 1
                results["details"].append({
                    "cluster_id": cluster_id,
                    "status": "failed",
                    "error": enrichment["errors"][0] if enrichment["errors"] else "Unknown",
                })
            else:
                results["skipped"] += 1
                results["details"].append({
                    "cluster_id": cluster_id,
                    "status": "no_matches",
                })

        return results
