"""
Session endpoints

Provides access to Cowrie session data
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from services.log_parser import parser

router = APIRouter()


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of sessions to return"),
    offset: int = Query(0, ge=0, description="Number of sessions to skip"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    start_time: Optional[str] = Query(None, description="Filter by start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="Filter by end time (ISO format)"),
):
    """
    Get list of sessions with filtering and pagination

    Returns sessions sorted by start time (newest first)
    """
    # Parse datetime filters
    start_dt = None
    end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_time format")

    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_time format")

    # Get sessions from parser
    sessions = parser.get_sessions(
        limit=limit, offset=offset, src_ip=src_ip, username=username, start_time=start_dt, end_time=end_dt
    )

    return {"total": len(sessions), "limit": limit, "offset": offset, "sessions": sessions}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """
    Get detailed information about a specific session

    Returns:
        - Session metadata
        - All commands executed
        - Files downloaded
        - Full event log
    """
    session = parser.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.get("/sessions/{session_id}/commands")
async def get_session_commands(session_id: str):
    """Get all commands from a session"""
    session = parser.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": session_id,
        "commands_count": len(session.get("commands", [])),
        "commands": session.get("commands", []),
    }
