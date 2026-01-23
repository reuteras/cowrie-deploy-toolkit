"""
MITRE ATT&CK Database Service

Manages MITRE ATT&CK framework data for TTP clustering and analysis.
"""

import json
import logging
import sqlite3
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class MITREAttackService:
    """Service for managing MITRE ATT&CK framework data."""

    def __init__(self, db_path: str):
        """
        Initialize MITRE ATT&CK service.

        Args:
            db_path: Path to the MITRE ATT&CK database
        """
        self.db_path = db_path
        self._ensure_database()

    def _ensure_database(self):
        """Ensure MITRE ATT&CK database exists and is populated."""
        if not Path(self.db_path).exists():
            logger.info(f"Creating MITRE ATT&CK database at {self.db_path}")
            self._create_schema()
            self._populate_database()
        else:
            logger.info(f"MITRE ATT&CK database already exists at {self.db_path}")

    def _create_schema(self):
        """Create the MITRE ATT&CK database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main techniques table
        cursor.execute("""
            CREATE TABLE techniques (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                tactic_id TEXT,
                tactic_name TEXT,
                platforms TEXT,  -- JSON array
                detection TEXT,
                data_sources TEXT,  -- JSON array
                version TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # TTP pattern mappings
        cursor.execute("""
            CREATE TABLE ttp_patterns (
                pattern_id TEXT PRIMARY KEY,
                technique_id TEXT,
                pattern_type TEXT,  -- 'command', 'behavior', 'sequence', 'regex'
                pattern_data TEXT,  -- JSON: regex pattern or behavior description
                confidence_weight REAL DEFAULT 0.5,  -- 0.0-1.0
                evidence_required TEXT,  -- JSON: required indicators
                platforms TEXT,  -- JSON array of applicable platforms
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (technique_id) REFERENCES techniques(technique_id)
            )
        """)

        # Tactics reference table
        cursor.execute("""
            CREATE TABLE tactics (
                tactic_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                short_name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Indexes for performance
        cursor.execute("CREATE INDEX idx_technique_tactic ON techniques(tactic_id)")
        cursor.execute("CREATE INDEX idx_patterns_technique ON ttp_patterns(technique_id)")
        cursor.execute("CREATE INDEX idx_patterns_type ON ttp_patterns(pattern_type)")

        conn.commit()
        conn.close()

    def _populate_database(self):
        """Download and populate MITRE ATT&CK data."""
        try:
            # Download latest ATT&CK STIX data
            stix_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
            logger.info("Downloading MITRE ATT&CK STIX data...")

            with urllib.request.urlopen(stix_url) as response:
                stix_data = json.loads(response.read().decode())

            # Parse and store the data
            self._parse_stix_data(stix_data)
            logger.info("MITRE ATT&CK database populated successfully")

        except Exception as e:
            logger.error(f"Failed to populate MITRE ATT&CK database: {e}")
            # Fallback: create basic mapping for common techniques
            self._create_fallback_data()

    def _parse_stix_data(self, stix_data: dict):
        """Parse STIX bundle and store ATT&CK data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        objects = stix_data.get("objects", [])

        for obj in objects:
            obj_type = obj.get("type")

            if obj_type == "attack-pattern":
                # Store technique
                technique_id = obj.get("external_references", [{}])[0].get("external_id", "")
                if technique_id.startswith("T"):
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO techniques
                        (technique_id, name, description, platforms, detection, data_sources, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            technique_id,
                            obj.get("name", ""),
                            obj.get("description", ""),
                            json.dumps(obj.get("x_mitre_platforms", [])),
                            obj.get("x_mitre_detection", ""),
                            json.dumps(obj.get("x_mitre_data_sources", [])),
                            stix_data.get("spec_version", "unknown"),
                        ),
                    )

                    # Link to tactics via kill_chain_phases
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactic_id = phase.get("phase_name")
                            # Map tactic ID to technique
                            cursor.execute(
                                """
                                UPDATE techniques SET tactic_id = ? WHERE technique_id = ?
                            """,
                                (tactic_id, technique_id),
                            )

            elif obj_type == "x-mitre-tactic":
                # Store tactic
                tactic_id = obj.get("external_references", [{}])[0].get("external_id", "")
                if tactic_id.startswith("TA"):
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO tactics
                        (tactic_id, name, description, short_name)
                        VALUES (?, ?, ?, ?)
                    """,
                        (tactic_id, obj.get("name", ""), obj.get("description", ""), obj.get("x_mitre_shortname", "")),
                    )

        # Create initial TTP patterns for common techniques
        self._create_initial_patterns(cursor)

        conn.commit()
        conn.close()

    def _create_initial_patterns(self, cursor):
        """Create initial TTP pattern mappings for common techniques."""
        patterns = [
            # T1110 - Brute Force
            ("T1110", "command", r".*(ssh|login|su).*", 0.8, ["authentication_failure"]),
            ("T1110", "behavior", "multiple_failed_logins", 0.9, ["authentication_failure", "temporal_burst"]),
            # T1078 - Valid Accounts
            ("T1078", "behavior", "successful_login", 0.7, ["authentication_success"]),
            # T1083 - File and Directory Discovery
            ("T1083", "command", r".*\b(ls|dir|find|locate)\b.*", 0.8, ["file_system_enumeration"]),
            ("T1083", "command", r".*\b(cat|more|less)\s+/etc/passwd\b.*", 0.9, ["credential_file_access"]),
            # T1003 - OS Credential Dumping
            ("T1003", "command", r".*\b(cat|grep|awk)\s+/etc/shadow\b.*", 0.9, ["credential_file_access"]),
            ("T1003", "command", r".*\bgetent\s+passwd\b.*", 0.8, ["credential_enumeration"]),
            # T1572 - Protocol Tunneling
            ("T1572", "command", r".*ssh.*-R.*", 0.9, ["reverse_tunnel"]),
            ("T1572", "command", r".*ssh.*-L.*", 0.9, ["local_tunnel"]),
            # T1020 - Automated Exfiltration
            ("T1020", "behavior", "large_data_transfer", 0.7, ["data_exfiltration"]),
        ]

        for technique_id, pattern_type, pattern_data, confidence, evidence in patterns:
            pattern_id = f"{technique_id}_{pattern_type}_{hash(pattern_data) % 10000}"
            cursor.execute(
                """
                INSERT OR IGNORE INTO ttp_patterns
                (pattern_id, technique_id, pattern_type, pattern_data, confidence_weight, evidence_required)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (pattern_id, technique_id, pattern_type, pattern_data, confidence, json.dumps(evidence)),
            )

    def _create_fallback_data(self):
        """Create fallback ATT&CK data if STIX download fails."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Basic tactics
        tactics = [
            ("TA0001", "Initial Access", "initial-access"),
            ("TA0002", "Execution", "execution"),
            ("TA0003", "Persistence", "persistence"),
            ("TA0004", "Privilege Escalation", "privilege-escalation"),
            ("TA0005", "Defense Evasion", "defense-evasion"),
            ("TA0006", "Credential Access", "credential-access"),
            ("TA0007", "Discovery", "discovery"),
            ("TA0008", "Lateral Movement", "lateral-movement"),
            ("TA0009", "Collection", "collection"),
            ("TA0010", "Exfiltration", "exfiltration"),
            ("TA0011", "Command and Control", "command-and-control"),
            ("TA0040", "Impact", "impact"),
        ]

        for tactic_id, name, short_name in tactics:
            cursor.execute(
                """
                INSERT OR IGNORE INTO tactics (tactic_id, name, short_name)
                VALUES (?, ?, ?)
            """,
                (tactic_id, name, short_name),
            )

        # Common techniques
        techniques = [
            ("T1110", "Brute Force", "TA0006"),
            ("T1078", "Valid Accounts", "TA0001"),
            ("T1083", "File and Directory Discovery", "TA0007"),
            ("T1003", "OS Credential Dumping", "TA0006"),
            ("T1572", "Protocol Tunneling", "TA0011"),
            ("T1020", "Automated Exfiltration", "TA0010"),
        ]

        for technique_id, name, tactic_id in techniques:
            cursor.execute(
                """
                INSERT OR IGNORE INTO techniques (technique_id, name, tactic_id)
                VALUES (?, ?, ?)
            """,
                (technique_id, name, tactic_id),
            )

        self._create_initial_patterns(cursor)

        conn.commit()
        conn.close()

    def get_technique(self, technique_id: str) -> Optional[dict]:
        """Get technique details by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.*, tac.name as tactic_name, tac.short_name as tactic_short_name
            FROM techniques t
            LEFT JOIN tactics tac ON t.tactic_id = tac.tactic_id
            WHERE t.technique_id = ?
        """,
            (technique_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "technique_id": row[0],
                "name": row[1],
                "description": row[2],
                "tactic_id": row[3],
                "tactic_name": row[4],
                "platforms": json.loads(row[5]) if row[5] else [],
                "detection": row[6],
                "data_sources": json.loads(row[7]) if row[7] else [],
                "version": row[8],
            }
        return None

    def get_ttp_patterns(self, technique_id: Optional[str] = None) -> List[dict]:
        """Get TTP patterns, optionally filtered by technique."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if technique_id:
            cursor.execute("SELECT * FROM ttp_patterns WHERE technique_id = ?", (technique_id,))
        else:
            cursor.execute("SELECT * FROM ttp_patterns")

        patterns = []
        for row in cursor.fetchall():
            patterns.append(
                {
                    "pattern_id": row[0],
                    "technique_id": row[1],
                    "pattern_type": row[2],
                    "pattern_data": row[3],
                    "confidence_weight": row[4],
                    "evidence_required": json.loads(row[5]) if row[5] else [],
                    "platforms": json.loads(row[6]) if row[6] else [],
                }
            )

        conn.close()
        return patterns

    def get_tactics(self) -> List[dict]:
        """Get all tactics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tactics")
        tactics = []
        for row in cursor.fetchall():
            tactics.append({"tactic_id": row[0], "name": row[1], "description": row[2], "short_name": row[3]})

        conn.close()
        return tactics
