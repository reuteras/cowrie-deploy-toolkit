"""
TTP Extraction Service

Analyzes SSH session data to extract Tactics, Techniques, and Procedures (TTPs)
based on MITRE ATT&CK framework patterns.
"""

import json
import logging
import re
import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Optional

from services.mitre_attack import MITREAttackService

logger = logging.getLogger(__name__)


class TTPExtractionService:
    """Service for extracting TTPs from SSH session data."""

    def __init__(self, source_db_path: str, mitre_db_path: str):
        """
        Initialize TTP extraction service.

        Args:
            source_db_path: Path to Cowrie SQLite database (read-only)
            mitre_db_path: Path to MITRE ATT&CK database
        """
        self.source_db_path = source_db_path
        self.mitre_db_path = mitre_db_path

        try:
            self.mitre_service = MITREAttackService(mitre_db_path)
            # Load TTP patterns into memory for performance
            self.ttp_patterns = self._load_ttp_patterns()
            self.initialized = True
            logger.info(f"TTP Extraction Service initialized with {len(self.ttp_patterns)} patterns")
        except Exception as e:
            logger.error(f"Failed to initialize MITRE ATT&CK service: {e}")
            self.mitre_service = None
            self.ttp_patterns = {}
            self.initialized = False

    def _load_ttp_patterns(self) -> dict[str, list[dict]]:
        """Load TTP patterns from MITRE database into memory."""
        if not self.initialized or not self.mitre_service:
            logger.warning("MITRE service not available, loading fallback patterns")
            return self._get_fallback_patterns()

        try:
            patterns = defaultdict(list)
            for pattern in self.mitre_service.get_ttp_patterns():
                technique_id = pattern["technique_id"]
                patterns[technique_id].append(pattern)
            return dict(patterns)
        except Exception as e:
            logger.error(f"Failed to load TTP patterns: {e}")
            return self._get_fallback_patterns()

    def _get_fallback_patterns(self) -> dict[str, list[dict]]:
        """Provide basic fallback TTP patterns when MITRE DB is unavailable."""
        return {
            "T1110": [{"pattern_type": "command", "pattern_data": ".*ssh.*", "confidence_weight": 0.5}],
            "T1003": [{"pattern_type": "command", "pattern_data": ".*shadow.*", "confidence_weight": 0.7}],
            "T1083": [{"pattern_type": "command", "pattern_data": ".*ls.*", "confidence_weight": 0.4}],
        }

    def _get_source_connection(self) -> sqlite3.Connection:
        """Get read-only connection to Cowrie database."""
        return sqlite3.connect(f"file:{self.source_db_path}?mode=ro", uri=True)

    def extract_session_ttps(self, session_id: str) -> list[dict]:
        """
        Extract TTPs from a single session.

        Args:
            session_id: Cowrie session ID

        Returns:
            List of TTP matches with confidence scores
        """
        conn = self._get_source_connection()
        cursor = conn.cursor()

        # Get all commands for this session
        cursor.execute(
            """
            SELECT timestamp, input
            FROM input
            WHERE session = ?
            ORDER BY timestamp
        """,
            (session_id,),
        )

        commands = []
        for row in cursor.fetchall():
            commands.append({"timestamp": row[0], "command": row[1], "session": session_id})

        # Get session metadata
        cursor.execute(
            """
            SELECT starttime, endtime, ip
            FROM sessions
            WHERE id = ?
        """,
            (session_id,),
        )

        session_data = cursor.fetchone()
        session_metadata = {
            "start_time": session_data[0] if session_data else None,
            "end_time": session_data[1] if session_data else None,
            "src_ip": session_data[2] if session_data else None,
        }

        conn.close()

        # Extract TTPs from commands and behavior
        ttps = []
        ttps.extend(self.extract_command_ttps(commands))
        ttps.extend(self.extract_behavioral_ttps(commands, session_metadata))

        return self._consolidate_ttps(ttps)

    def extract_command_ttps(self, commands: list[dict]) -> list[dict]:
        """
        Extract TTPs from command sequences.

        Args:
            commands: List of command dictionaries with 'command' key

        Returns:
            List of TTP matches
        """
        ttps = []

        for cmd_data in commands:
            command = cmd_data.get("command", "").strip()

            for technique_id, patterns in self.ttp_patterns.items():
                for pattern in patterns:
                    if pattern["pattern_type"] == "command":
                        confidence = self._match_command_pattern(command, pattern)
                        if confidence > 0:
                            ttps.append(
                                {
                                    "technique_id": technique_id,
                                    "confidence": confidence,
                                    "evidence": {
                                        "type": "command_match",
                                        "command": command,
                                        "pattern": pattern["pattern_data"],
                                        "pattern_type": pattern["pattern_type"],
                                    },
                                    "timestamp": cmd_data.get("timestamp"),
                                    "session": cmd_data.get("session"),
                                }
                            )

        return ttps

    def extract_behavioral_ttps(self, commands: list[dict], session_metadata: dict) -> list[dict]:
        """
        Extract TTPs from session behavior patterns.

        Args:
            commands: List of command dictionaries
            session_metadata: Session metadata (start_time, end_time, src_ip)

        Returns:
            List of behavioral TTP matches
        """
        ttps = []

        # Analyze command patterns and sequences
        command_texts = [cmd.get("command", "").strip() for cmd in commands]

        # Check for brute force patterns (T1110)
        if self._detect_brute_force_pattern(commands, session_metadata):
            ttps.append(
                {
                    "technique_id": "T1110",
                    "confidence": 0.8,
                    "evidence": {
                        "type": "behavioral",
                        "pattern": "multiple_failed_logins",
                        "commands_analyzed": len(commands),
                    },
                    "timestamp": session_metadata.get("start_time"),
                    "session": commands[0].get("session") if commands else None,
                }
            )

        # Check for credential access patterns (T1003)
        if self._detect_credential_dump_pattern(command_texts):
            ttps.append(
                {
                    "technique_id": "T1003",
                    "confidence": 0.9,
                    "evidence": {
                        "type": "behavioral",
                        "pattern": "credential_file_access",
                        "commands": [
                            cmd
                            for cmd in command_texts
                            if any(x in cmd.lower() for x in ["/etc/shadow", "/etc/passwd", "getent passwd"])
                        ],
                    },
                    "timestamp": session_metadata.get("start_time"),
                    "session": commands[0].get("session") if commands else None,
                }
            )

        # Check for discovery patterns (T1083)
        if self._detect_discovery_pattern(command_texts):
            ttps.append(
                {
                    "technique_id": "T1083",
                    "confidence": 0.7,
                    "evidence": {
                        "type": "behavioral",
                        "pattern": "file_system_enumeration",
                        "commands": [
                            cmd
                            for cmd in command_texts
                            if any(x in cmd.lower() for x in ["ls", "dir", "find", "locate"])
                        ],
                    },
                    "timestamp": session_metadata.get("start_time"),
                    "session": commands[0].get("session") if commands else None,
                }
            )

        # Check for tunneling patterns (T1572)
        if self._detect_tunneling_pattern(command_texts):
            ttps.append(
                {
                    "technique_id": "T1572",
                    "confidence": 0.9,
                    "evidence": {
                        "type": "behavioral",
                        "pattern": "reverse_tunnel",
                        "commands": [cmd for cmd in command_texts if "-R" in cmd or "-L" in cmd],
                    },
                    "timestamp": session_metadata.get("start_time"),
                    "session": commands[0].get("session") if commands else None,
                }
            )

        return ttps

    def _match_command_pattern(self, command: str, pattern: dict) -> float:
        """
        Match a command against a TTP pattern.

        Args:
            command: The command string to match
            pattern: Pattern dictionary with regex and confidence

        Returns:
            Confidence score (0.0-1.0)
        """
        try:
            regex_pattern = pattern["pattern_data"]
            if re.search(regex_pattern, command, re.IGNORECASE):
                # Apply pattern confidence weight and evidence requirements
                base_confidence = pattern["confidence_weight"]

                # Check evidence requirements
                evidence_required = pattern.get("evidence_required", [])
                evidence_score = self._calculate_evidence_score(command, evidence_required)

                return min(1.0, base_confidence * evidence_score)

        except re.error as e:
            logger.warning(f"Invalid regex pattern {pattern['pattern_data']}: {e}")

        return 0.0

    def _calculate_evidence_score(self, command: str, evidence_required: list[str]) -> float:
        """
        Calculate evidence score based on required indicators.

        Args:
            command: The command string
            evidence_required: List of required evidence types

        Returns:
            Evidence multiplier (0.0-1.0)
        """
        if not evidence_required:
            return 1.0

        evidence_found = 0

        for evidence in evidence_required:
            if evidence == "authentication_failure":
                if any(x in command.lower() for x in ["login", "ssh", "su", "sudo"]):
                    evidence_found += 1
            elif evidence == "credential_file_access":
                if any(x in command.lower() for x in ["/etc/shadow", "/etc/passwd", "getent passwd"]):
                    evidence_found += 1
            elif evidence == "file_system_enumeration":
                if any(x in command.lower() for x in ["ls", "dir", "find", "locate"]):
                    evidence_found += 1
            elif evidence == "reverse_tunnel":
                if "-R" in command or "-L" in command:
                    evidence_found += 1

        return evidence_found / len(evidence_required) if evidence_required else 1.0

    def _detect_brute_force_pattern(self, commands: list[dict], session_metadata: dict) -> bool:
        """Detect brute force patterns in session."""
        # Look for rapid succession of authentication attempts
        if len(commands) < 5:
            return False

        # Check timestamps for rapid attempts
        timestamps = [cmd.get("timestamp") for cmd in commands if cmd.get("timestamp")]
        if len(timestamps) < 5:
            return False

        # Calculate time spans
        try:
            start_ts = str(timestamps[0]) if timestamps[0] is not None else ""
            end_ts = str(timestamps[-1]) if timestamps[-1] is not None else ""
            if start_ts and end_ts:
                start_time = datetime.fromisoformat(start_ts.replace("Z", "+00:00"))
                end_time = datetime.fromisoformat(end_ts.replace("Z", "+00:00"))
                duration = (end_time - start_time).total_seconds()
            else:
                return False

            # High frequency of commands in short time = potential brute force
            if duration < 300 and len(commands) > 10:  # 5 minutes, 10+ commands
                return True
        except (ValueError, AttributeError):
            pass

        return False

    def _detect_credential_dump_pattern(self, commands: list[str]) -> bool:
        """Detect credential dumping patterns."""
        credential_commands = [
            "/etc/shadow",
            "/etc/passwd",
            "getent passwd",
            "getent shadow",
            "cat.*shadow",
            "cat.*passwd",
        ]

        return any(any(pattern in cmd.lower() for pattern in credential_commands) for cmd in commands)

    def _detect_discovery_pattern(self, commands: list[str]) -> bool:
        """Detect discovery patterns."""
        discovery_commands = ["ls", "dir", "find", "locate", "pwd", "whoami", "id", "uname"]

        discovery_count = sum(1 for cmd in commands if any(pattern in cmd.lower() for pattern in discovery_commands))

        return discovery_count >= 3  # Multiple discovery commands

    def _detect_tunneling_pattern(self, commands: list[str]) -> bool:
        """Detect tunneling patterns."""
        tunnel_commands = ["ssh -R", "ssh -L", "nc -e", "ncat -e"]

        return any(any(pattern in cmd.lower() for pattern in tunnel_commands) for cmd in commands)

    def _consolidate_ttps(self, ttps: list[dict]) -> list[dict]:
        """
        Consolidate multiple TTP matches for the same technique.

        Args:
            ttps: List of TTP matches

        Returns:
            Consolidated list with highest confidence per technique
        """
        consolidated = {}

        for ttp in ttps:
            technique_id = ttp["technique_id"]

            if technique_id not in consolidated:
                consolidated[technique_id] = ttp
            else:
                # Keep the highest confidence match
                if ttp["confidence"] > consolidated[technique_id]["confidence"]:
                    consolidated[technique_id] = ttp

        return list(consolidated.values())

    def create_ttp_fingerprint(self, session_id: str) -> Optional[dict]:
        """
        Create a TTP fingerprint for a session.

        Args:
            session_id: Session ID to fingerprint

        Returns:
            Fingerprint dictionary or None if no TTPs found
        """
        ttps = self.extract_session_ttps(session_id)

        if not ttps:
            return None

        # Create fingerprint
        fingerprint = {
            "session": session_id,
            "ttp_sequence": json.dumps(
                [
                    {
                        "technique_id": ttp["technique_id"],
                        "confidence": ttp["confidence"],
                        "evidence_type": ttp["evidence"]["type"],
                    }
                    for ttp in ttps
                ]
            ),
            "technique_count": len(ttps),
            "dominant_techniques": json.dumps(
                [ttp["technique_id"] for ttp in sorted(ttps, key=lambda x: x["confidence"], reverse=True)][:3]
            ),
            "confidence_score": sum(ttp["confidence"] for ttp in ttps) / len(ttps),
            "tactics": json.dumps(list({self._get_tactic_for_technique(ttp["technique_id"]) for ttp in ttps})),
        }

        return fingerprint

    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Get the tactic ID for a technique."""
        if not self.initialized or not self.mitre_service:
            return "unknown"
        try:
            if self.mitre_service:
                technique = self.mitre_service.get_technique(technique_id)
                return technique["tactic_id"] if technique else "unknown"
            else:
                return "unknown"
        except Exception:
            return "unknown"

    def get_technique_details(self, technique_id: str) -> Optional[dict]:
        """Get detailed information about a technique."""
        if not self.initialized or not self.mitre_service:
            return None
        try:
            return self.mitre_service.get_technique(technique_id)
        except Exception as e:
            logger.error(f"Failed to get technique details for {technique_id}: {e}")
            return None
