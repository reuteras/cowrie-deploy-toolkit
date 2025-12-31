"""
Cowrie log parser service

Parses cowrie.json log file and extracts session information
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import config

logger = logging.getLogger(__name__)


class CowrieLogParser:
    """Parser for Cowrie JSON logs"""

    def __init__(self, log_path: str = None):
        self.log_path = Path(log_path or config.COWRIE_LOG_PATH)

    def get_sessions(
        self,
        limit: int = 100,
        offset: int = 0,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[dict]:
        """
        Parse log file and return sessions with filters

        Args:
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip
            src_ip: Filter by source IP
            username: Filter by username
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            List of session dictionaries
        """
        sessions = self._build_sessions()

        # Apply filters
        filtered = []
        for _session_id, session in sessions.items():
            # Filter by IP
            if src_ip and session.get("src_ip") != src_ip:
                continue

            # Filter by username
            if username and session.get("username") != username:
                continue

            # Filter by time range
            if start_time or end_time:
                session_time = session.get("start_time")
                if session_time:
                    try:
                        dt = datetime.fromisoformat(session_time.replace("Z", "+00:00"))
                        if start_time and dt < start_time:
                            continue
                        if end_time and dt > end_time:
                            continue
                    except (ValueError, AttributeError):
                        continue

            filtered.append(session)

        # Sort by start time (newest first)
        filtered.sort(key=lambda x: x.get("start_time", ""), reverse=True)

        # Apply pagination
        return filtered[offset : offset + limit]

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a single session by ID"""
        sessions = self._build_sessions()
        return sessions.get(session_id)

    def _build_sessions(self) -> dict[str, dict]:
        """
        Build sessions from log file
        Returns dict of session_id -> session data
        """
        if not self.log_path.exists():
            logger.warning(f"Log file not found: {self.log_path}")
            return {}

        sessions = defaultdict(lambda: {"commands": [], "downloads": [], "events": []})

        try:
            with open(self.log_path) as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        session_id = event.get("session")

                        if not session_id:
                            continue

                        # Initialize session if first event
                        if "session_id" not in sessions[session_id]:
                            sessions[session_id]["session_id"] = session_id
                            sessions[session_id]["src_ip"] = event.get("src_ip")
                            sessions[session_id]["src_port"] = event.get("src_port")
                            sessions[session_id]["dst_ip"] = event.get("dst_ip", event.get("sensor"))
                            sessions[session_id]["dst_port"] = event.get("dst_port", 22)
                            sessions[session_id]["start_time"] = event.get("timestamp")

                        # Track session end time
                        sessions[session_id]["end_time"] = event.get("timestamp")

                        # Handle login events
                        if event.get("eventid") == "cowrie.login.success":
                            sessions[session_id]["username"] = event.get("username")
                            sessions[session_id]["password"] = event.get("password")
                            sessions[session_id]["authentication_success"] = True
                            sessions[session_id]["login_success"] = True  # Add for dashboard compatibility

                        elif event.get("eventid") == "cowrie.login.failed":
                            if "authentication_success" not in sessions[session_id]:
                                sessions[session_id]["authentication_success"] = False
                                sessions[session_id]["login_success"] = False  # Add for dashboard compatibility

                        # Handle commands
                        elif event.get("eventid") == "cowrie.command.input":
                            cmd_input = event.get("input")
                            sessions[session_id]["commands"].append(
                                {
                                    "timestamp": event.get("timestamp"),
                                    "input": cmd_input,
                                    "command": cmd_input,  # Add for dashboard compatibility
                                }
                            )

                        # Handle downloads
                        elif event.get("eventid") == "cowrie.session.file_download":
                            sessions[session_id]["downloads"].append(
                                {
                                    "timestamp": event.get("timestamp"),
                                    "url": event.get("url"),
                                    "shasum": event.get("shasum"),
                                    "outfile": event.get("outfile"),
                                }
                            )

                        # Store all events for detailed view
                        sessions[session_id]["events"].append(event)

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"Error parsing log file: {e}", exc_info=True)
            return {}

        # Calculate session metadata
        for _session_id, session in sessions.items():
            session["commands_count"] = len(session["commands"])
            session["downloads_count"] = len(session["downloads"])

            # Check for TTY recordings and extract filename
            tty_events = [e for e in session["events"] if e.get("eventid") == "cowrie.log.open"]
            session["has_tty"] = len(tty_events) > 0
            if tty_events:
                # Get the TTY log filename from the first tty event
                session["tty_log"] = tty_events[0].get("ttylog")
            else:
                session["tty_log"] = None

            # Calculate duration
            if session.get("start_time") and session.get("end_time"):
                try:
                    start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
                    session["duration"] = int((end - start).total_seconds())
                except (ValueError, AttributeError):
                    session["duration"] = 0

        return dict(sessions)


# Global parser instance
parser = CowrieLogParser()
