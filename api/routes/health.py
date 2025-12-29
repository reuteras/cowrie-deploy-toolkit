"""
Health check endpoints
"""

from pathlib import Path

from config import config
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint
    Returns API status and data availability
    """
    return {
        "status": "healthy",
        "version": "2.1.0",
        "data_sources": {
            "cowrie_log": Path(config.COWRIE_LOG_PATH).exists() or Path(config.COWRIE_LOG_PATH).parent.exists(),
            "tty_recordings": Path(config.COWRIE_TTY_PATH).exists(),
            "downloads": Path(config.COWRIE_DOWNLOADS_PATH).exists(),
        },
    }


@router.get("/api/v1/info")
async def get_info():
    """
    Get API information and configuration
    """
    return {
        "name": "Cowrie API",
        "version": "2.1.0",
        "description": "REST API for Cowrie honeypot data",
        "endpoints": {
            "health": "/health",
            "sessions": "/api/v1/sessions",
            "downloads": "/api/v1/downloads",
            "stats": "/api/v1/stats/overview",
            "threat_intel": "/api/v1/threat/ip/{ip}",
        },
    }
