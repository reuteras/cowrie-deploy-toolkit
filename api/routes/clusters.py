"""
Cluster management endpoints

Provides API endpoints for attack cluster analysis:
- List clusters with filtering
- Get cluster details with members
- Get clusters for specific IP
- Trigger cluster analysis
- Get threat intelligence for IPs and hashes
"""

import logging
from typing import Optional

from config import config
from fastapi import APIRouter, HTTPException, Query
from services.clustering import ClusteringService
from services.threat_intel import ThreatIntelService

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize services lazily
_clustering_service: Optional[ClusteringService] = None
_threat_intel_service: Optional[ThreatIntelService] = None


def get_clustering_service() -> ClusteringService:
    """Get or create clustering service instance."""
    global _clustering_service
    if _clustering_service is None:
        _clustering_service = ClusteringService(
            source_db_path=config.COWRIE_DB_PATH,
            clustering_db_path=config.CLUSTERING_DB_PATH,
        )
    return _clustering_service


def get_threat_intel_service() -> ThreatIntelService:
    """Get or create threat intel service instance."""
    global _threat_intel_service
    if _threat_intel_service is None:
        _threat_intel_service = ThreatIntelService(
            config.COWRIE_DB_PATH,
            abuseipdb_key=config.ABUSEIPDB_API_KEY,
        )
    return _threat_intel_service


# =============================================================================
# Cluster Endpoints
# =============================================================================


@router.get("/clusters")
async def list_clusters(
    cluster_type: Optional[str] = Query(None, description="Filter by type: command, hassh, payload"),
    min_size: int = Query(2, ge=1, description="Minimum number of unique IPs"),
    min_score: int = Query(0, ge=0, le=100, description="Minimum threat score"),
    days: int = Query(7, ge=1, le=365, description="Look back period in days"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
):
    """
    List attack clusters with optional filtering.

    Clusters group related attack sessions by:
    - **command**: Same command sequence fingerprint
    - **hassh**: Same SSH client fingerprint
    - **payload**: Same downloaded malware

    Returns clusters sorted by threat score and size.
    """
    try:
        service = get_clustering_service()
        clusters = service.get_clusters(
            cluster_type=cluster_type,
            min_size=min_size,
            min_score=min_score,
            days=days,
            limit=limit,
        )
        return {
            "clusters": clusters,
            "total": len(clusters),
            "filters": {
                "cluster_type": cluster_type,
                "min_size": min_size,
                "min_score": min_score,
                "days": days,
            },
        }
    except Exception as e:
        logger.error(f"Failed to list clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clusters/{cluster_id}")
async def get_cluster_detail(cluster_id: str):
    """
    Get detailed information about a specific cluster.

    Returns:
    - Cluster metadata (type, fingerprint, score, etc.)
    - Member IPs with per-IP session counts
    - Enrichment data if available (threat families, ASNs, countries)
    """
    try:
        service = get_clustering_service()
        cluster = service.get_cluster_detail(cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail="Cluster not found")
        return cluster
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clusters/{cluster_id}/members")
async def get_cluster_members(
    cluster_id: str,
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
):
    """
    Get members (IPs) of a cluster with threat intelligence.
    """
    try:
        service = get_clustering_service()
        cluster = service.get_cluster_detail(cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail="Cluster not found")

        members = cluster.get("members", [])[:limit]
        return {
            "cluster_id": cluster_id,
            "members": members,
            "total": len(cluster.get("members", [])),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster members: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ip/{ip}/clusters")
async def get_ip_clusters(ip: str):
    """
    Get all clusters containing a specific IP address.

    Useful for understanding the attack profile of a particular IP.
    """
    try:
        service = get_clustering_service()
        clusters = service.get_ip_clusters(ip)
        return {
            "ip": ip,
            "clusters": clusters,
            "total": len(clusters),
        }
    except Exception as e:
        logger.error(f"Failed to get IP clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clusters/diagnose")
async def diagnose_clustering(
    days: int = Query(7, ge=1, le=365, description="Days to check"),
):
    """
    Diagnose clustering issues.

    Returns detailed information about the database state and
    what data is available for clustering. Useful for debugging
    when clusters aren't being found.
    """
    try:
        service = get_clustering_service()
        return service.diagnose(days)
    except Exception as e:
        logger.error(f"Failed to diagnose clustering: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/clusters/analyze")
async def trigger_cluster_analysis(
    days: int = Query(7, ge=1, le=365, description="Days to analyze"),
    min_size: int = Query(2, ge=1, description="Minimum cluster size"),
    cluster_types: Optional[str] = Query(
        None, description="Comma-separated types: command,hassh,payload"
    ),
):
    """
    Trigger manual cluster analysis.

    This runs all clustering algorithms and updates the database.
    Note: This can be CPU-intensive for large datasets.
    """
    try:
        service = get_clustering_service()

        # Parse cluster types if provided
        types_to_run = None
        if cluster_types:
            types_to_run = [t.strip() for t in cluster_types.split(",")]

        results = {"days": days, "min_size": min_size}

        if types_to_run is None or "command" in types_to_run:
            results["command_clusters"] = service.build_command_clusters(days, min_size)

        if types_to_run is None or "hassh" in types_to_run:
            results["hassh_clusters"] = service.build_hassh_clusters(days, min_size)

        if types_to_run is None or "payload" in types_to_run:
            results["payload_clusters"] = service.build_payload_clusters(days, min_size)

        # Summary
        results["summary"] = {
            "command_clusters_count": len(results.get("command_clusters", [])),
            "hassh_clusters_count": len(results.get("hassh_clusters", [])),
            "payload_clusters_count": len(results.get("payload_clusters", [])),
            "total_clusters": sum(
                len(results.get(k, []))
                for k in ["command_clusters", "hassh_clusters", "payload_clusters"]
            ),
        }

        return results

    except Exception as e:
        logger.error(f"Failed to run cluster analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Threat Intelligence Endpoints
# =============================================================================


@router.get("/intel/ip/{ip}")
async def get_ip_threat_intel(
    ip: str,
    sources: Optional[str] = Query(
        None, description="Comma-separated sources: shodan,threatfox,urlhaus"
    ),
):
    """
    Get aggregated threat intelligence for an IP address.

    Queries multiple free threat intelligence sources:
    - **Shodan InternetDB**: Open ports, vulnerabilities, tags
    - **ThreatFox**: Malware C2, botnet infrastructure
    - **URLhaus**: Malware distribution URLs

    Results are cached for 24 hours.
    """
    try:
        service = get_threat_intel_service()

        source_list = None
        if sources:
            source_list = [s.strip() for s in sources.split(",")]

        return service.get_ip_intel(ip, source_list)

    except Exception as e:
        logger.error(f"Failed to get IP threat intel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/intel/hash/{file_hash}")
async def get_hash_threat_intel(
    file_hash: str,
    sources: Optional[str] = Query(
        None, description="Comma-separated sources: threatfox,malwarebazaar"
    ),
):
    """
    Get aggregated threat intelligence for a file hash.

    Queries multiple free threat intelligence sources:
    - **ThreatFox**: Malware IOCs and attribution
    - **MalwareBazaar**: Malware sample database

    Supports SHA256, MD5, and SHA1 hashes.
    Results are cached for 24 hours.
    """
    try:
        service = get_threat_intel_service()

        source_list = None
        if sources:
            source_list = [s.strip() for s in sources.split(",")]

        return service.get_hash_intel(file_hash, source_list)

    except Exception as e:
        logger.error(f"Failed to get hash threat intel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/intel/url")
async def get_url_threat_intel(url: str = Query(..., description="URL to check")):
    """
    Get threat intelligence for a URL.

    Queries URLhaus for known malware distribution URLs.
    """
    try:
        service = get_threat_intel_service()
        return service.query_urlhaus_url(url)

    except Exception as e:
        logger.error(f"Failed to get URL threat intel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/intel/sources")
async def get_threat_intel_sources():
    """
    List available threat intelligence sources with their status.
    """
    sources = [
        {
            "name": "shodan",
            "display_name": "Shodan InternetDB",
            "description": "Open ports, vulnerabilities, and tags",
            "query_types": ["ip"],
            "rate_limit": "Unlimited",
            "requires_api_key": False,
        },
        {
            "name": "threatfox",
            "display_name": "ThreatFox (abuse.ch)",
            "description": "Malware IOCs, C2 servers, botnet infrastructure",
            "query_types": ["ip", "hash"],
            "rate_limit": "Unlimited",
            "requires_api_key": False,
        },
        {
            "name": "malwarebazaar",
            "display_name": "MalwareBazaar (abuse.ch)",
            "description": "Malware sample database with YARA matches",
            "query_types": ["hash"],
            "rate_limit": "Unlimited",
            "requires_api_key": False,
        },
        {
            "name": "urlhaus",
            "display_name": "URLhaus (abuse.ch)",
            "description": "Malware distribution URLs",
            "query_types": ["url", "host"],
            "rate_limit": "Unlimited",
            "requires_api_key": False,
        },
    ]

    # Get cache stats
    try:
        service = get_threat_intel_service()
        cache_stats = service.get_cache_stats()
    except Exception:
        cache_stats = None

    return {
        "sources": sources,
        "cache_stats": cache_stats,
    }


@router.post("/intel/cache/cleanup")
async def cleanup_threat_intel_cache():
    """
    Clean up expired cache entries.
    """
    try:
        service = get_threat_intel_service()
        deleted = service.cleanup_expired_cache()
        return {"deleted_entries": deleted}

    except Exception as e:
        logger.error(f"Failed to cleanup cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))
