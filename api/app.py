"""
Cowrie API - FastAPI application for multi-host dashboard deployment

Provides REST API endpoints for Cowrie honeypot data:
- Sessions and commands
- Downloaded files (malware)
- Statistics and analytics
- Threat intelligence (GeoIP, VirusTotal, AbuseIPDB)
- Live event streaming (SSE)
"""

import logging
from contextlib import asynccontextmanager

from config import config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from routes import canary, downloads, health, sessions, stats, system, threat

# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL), format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("Starting Cowrie API...")
    logger.info(f"Cowrie log path: {config.COWRIE_LOG_PATH}")
    logger.info(f"TTY path: {config.COWRIE_TTY_PATH}")
    logger.info(f"Downloads path: {config.COWRIE_DOWNLOADS_PATH}")

    # Validate paths
    missing = config.validate_paths()
    if missing:
        logger.warning(f"Some paths are missing (will be created by Cowrie): {missing}")

    yield

    # Shutdown
    logger.info("Shutting down Cowrie API...")


# Create FastAPI app
app = FastAPI(title="Cowrie API", description="REST API for Cowrie honeypot data", version="2.1.0", lifespan=lifespan)

# CORS middleware (for development and multi-host scenarios)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(health.router, tags=["health"])
app.include_router(sessions.router, prefix="/api/v1", tags=["sessions"])
app.include_router(downloads.router, prefix="/api/v1", tags=["downloads"])
app.include_router(stats.router, prefix="/api/v1", tags=["statistics"])
app.include_router(system.router, tags=["system"])  # No prefix - Tailscale strips /api
app.include_router(threat.router, prefix="/api/v1", tags=["threat-intel"])
app.include_router(canary.router, tags=["canary"])  # No prefix - handles both direct and /api/v1 paths


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
