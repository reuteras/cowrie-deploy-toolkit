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
from uuid import uuid4

logger = logging.getLogger(__name__)


class ClusteringService:
    """Service for clustering attack sessions by various attributes."""

    def __init__(self, db_path: str):
        """
        Initialize clustering service.

        Args:
            db_path: Path to the Cowrie SQLite database
        """
        self.db_path = db_path
        self._ensure_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self):
        """Ensure clustering tables exist."""
        schema_path = "/app/api/sql/events_schema.sql"
        try:
            with open(schema_path) as f:
                schema = f.read()

            conn = self._get_connection()
            conn.executescript(schema)
            conn.commit()
            conn.close()
            logger.info("Clustering tables ensured")
        except FileNotFoundError:
            logger.warning(f"Schema file not found: {schema_path}")
        except Exception as e:
            logger.error(f"Failed to ensure tables: {e}")

    # =========================================================================
    # Command Fingerprinting
    # =========================================================================

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
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get sessions with commands
        cursor.execute(
            """
            SELECT session, GROUP_CONCAT(input, '|||') as commands
            FROM input
            WHERE timestamp >= ?
            GROUP BY session
            HAVING COUNT(*) > 0
            """,
            (cutoff_str,),
        )

        fingerprints = {}
        for row in cursor.fetchall():
            session_id = row["session"]
            commands = row["commands"].split("|||") if row["commands"] else []

            if commands:
                fp = self.fingerprint_commands(commands)
                normalized = [self.normalize_command(c) for c in commands]

                # Store fingerprint
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO command_fingerprints
                    (session, fingerprint, normalized_commands, command_count, created_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (session_id, fp, json.dumps(normalized), len(commands)),
                )

                fingerprints[session_id] = fp

        conn.commit()
        conn.close()

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
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Check if events table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        )
        if not cursor.fetchone():
            conn.close()
            return {"error": "Events table not found", "sessions_processed": 0}

        # Get KEX events (cowrie.client.kex contains HASSH data)
        cursor.execute(
            """
            SELECT session, src_ip, timestamp, data
            FROM events
            WHERE eventid = 'cowrie.client.kex'
            AND timestamp >= ?
            """,
            (cutoff_str,),
        )

        hassh_data = {}
        for row in cursor.fetchall():
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
                    # Store HASSH fingerprint
                    cursor.execute(
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

        conn.commit()
        conn.close()

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

    def build_command_clusters(self, days: int = 7, min_size: int = 2) -> list[dict]:
        """
        Build clusters based on command fingerprints.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size (unique IPs)

        Returns:
            List of cluster dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # First, ensure fingerprints are extracted
        self.extract_command_fingerprints(days)

        # Group sessions by fingerprint with IP info
        cursor.execute(
            """
            SELECT
                cf.fingerprint,
                cf.session,
                cf.normalized_commands,
                cf.command_count,
                s.ip as src_ip,
                s.starttime as timestamp
            FROM command_fingerprints cf
            JOIN sessions s ON cf.session = s.id
            WHERE s.starttime >= ?
            AND cf.fingerprint != 'empty'
            """,
            (cutoff_str,),
        )

        # Group by fingerprint
        clusters = defaultdict(list)
        for row in cursor.fetchall():
            clusters[row["fingerprint"]].append(
                {
                    "session": row["session"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "commands": row["normalized_commands"],
                    "command_count": row["command_count"],
                }
            )

        # Filter to minimum size and create cluster records
        result_clusters = []
        for fingerprint, sessions in clusters.items():
            unique_ips = set(s["src_ip"] for s in sessions if s["src_ip"])
            if len(unique_ips) < min_size:
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

            # Store cluster
            cursor.execute(
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
                    f"Sessions sharing command pattern: {', '.join(sample_commands[:3])}",
                    first_seen,
                    last_seen,
                    len(unique_ips),
                    len(sessions),
                    min(100, len(unique_ips) * 10),  # Simple scoring
                    json.dumps({"sample_commands": sample_commands}),
                ),
            )

            # Store cluster members
            ip_sessions = defaultdict(list)
            for s in sessions:
                if s["src_ip"]:
                    ip_sessions[s["src_ip"]].append(s)

            for ip, ip_sess in ip_sessions.items():
                ip_timestamps = [s["timestamp"] for s in ip_sess if s["timestamp"]]
                cursor.execute(
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
                    "sample_commands": sample_commands,
                }
            )

        conn.commit()
        conn.close()

        return sorted(result_clusters, key=lambda x: x["size"], reverse=True)

    def build_hassh_clusters(self, days: int = 7, min_size: int = 2) -> list[dict]:
        """
        Build clusters based on HASSH fingerprints.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size (unique IPs)

        Returns:
            List of cluster dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # First, ensure HASSH fingerprints are extracted
        self.extract_hassh_from_events(days)

        # Group by HASSH
        cursor.execute(
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
        for row in cursor.fetchall():
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

            # Store cluster
            cursor.execute(
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
                cursor.execute(
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

        conn.commit()
        conn.close()

        return sorted(result_clusters, key=lambda x: x["size"], reverse=True)

    def build_payload_clusters(self, days: int = 7, min_size: int = 2) -> list[dict]:
        """
        Build clusters based on downloaded malware payloads.

        Args:
            days: Number of days to analyze
            min_size: Minimum cluster size (unique IPs)

        Returns:
            List of cluster dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Group downloads by SHA256
        cursor.execute(
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
        for row in cursor.fetchall():
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

        # Filter and create cluster records
        result_clusters = []
        for shasum, downloads in clusters.items():
            unique_ips = set(d["src_ip"] for d in downloads if d["src_ip"])
            if len(unique_ips) < min_size:
                continue

            timestamps = [d["timestamp"] for d in downloads if d["timestamp"]]
            first_seen = min(timestamps) if timestamps else datetime.now().isoformat()
            last_seen = max(timestamps) if timestamps else datetime.now().isoformat()

            # Get threat info
            threat_label = next(
                (d["threat_label"] for d in downloads if d["threat_label"]), None
            )
            vt_detections = max(
                (d["vt_detections"] or 0 for d in downloads), default=0
            )

            cluster_id = f"payload-{shasum[:16]}"

            # Calculate score based on VT detections and cluster size
            score = min(100, (vt_detections * 2) + (len(unique_ips) * 5))

            cursor.execute(
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
                cursor.execute(
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
                }
            )

        conn.commit()
        conn.close()

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
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

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

        results["summary"] = {
            "total_clusters": sum(len(v) for v in results.values() if isinstance(v, list)),
            "command_clusters_count": len(results["command_clusters"]),
            "hassh_clusters_count": len(results["hassh_clusters"]),
            "payload_clusters_count": len(results["payload_clusters"]),
        }

        return results
