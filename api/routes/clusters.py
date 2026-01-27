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
import os
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
            config.THREAT_INTEL_CACHE_DB,
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
        raise HTTPException(status_code=500, detail=str(e)) from e


# NOTE: Static paths (/clusters/diagnose, /clusters/analyze) MUST come before
# dynamic paths (/clusters/{cluster_id}) to prevent route matching issues


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
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clusters/analyze")
async def trigger_cluster_analysis(
    days: int = Query(7, ge=1, le=365, description="Days to analyze"),
    min_size: int = Query(2, ge=1, description="Minimum cluster size (for HASSH/TTP clusters)"),
    min_interest_score: int = Query(20, ge=0, le=100, description="Minimum interest score for command clusters"),
    cluster_types: Optional[str] = Query(None, description="Comma-separated types: command,payload,ttp,hassh"),
):
    """
    Trigger manual cluster analysis.

    Default behavior excludes HASSH clusters unless explicitly requested.

    Clustering logic:
    - **Command clusters**: Filtered by interest score (not IP count). Common recon
      commands (uname, id, ls) are deprioritized. Sophisticated attacks (useradd,
      wget+chmod, persistence) are prioritized.
    - **Payload clusters**: No minimum - any shared malware download is interesting.
    - **TTP clusters**: Grouped by MITRE ATT&CK technique patterns.
    - **HASSH clusters**: Optional; filtered by min_size (unique IPs with same SSH fingerprint).

    Note: This can be CPU-intensive for large datasets.
    """
    try:
        service = get_clustering_service()

        # Parse cluster types if provided
        types_to_run = ["command", "payload", "ttp"]
        if cluster_types:
            types_to_run = [t.strip() for t in cluster_types.split(",")]

        results = {
            "days": days,
            "min_size": min_size,
            "min_interest_score": min_interest_score,
        }

        if "command" in types_to_run:
            try:
                # Command clusters use interest score, not min_size
                results["command_clusters"] = service.build_command_clusters(days, min_interest_score)
            except Exception as e:
                logger.warning(f"Command clustering failed: {e}")
                results["command_clusters"] = []

        if "payload" in types_to_run:
            try:
                # Payload clusters: min_size=1 (all payloads interesting)
                results["payload_clusters"] = service.build_payload_clusters(days, min_size=1)
            except Exception as e:
                logger.warning(f"Payload clustering failed: {e}")
                results["payload_clusters"] = []

        if "ttp" in types_to_run:
            try:
                results["ttp_clusters"] = service.build_ttp_clusters(days, min_size=min_size)
            except Exception as e:
                logger.warning(f"TTP clustering failed: {e}")
                results["ttp_clusters"] = []

        if "hassh" in types_to_run:
            try:
                # HASSH clusters still use min_size
                results["hassh_clusters"] = service.build_hassh_clusters(days, min_size)
            except Exception as e:
                logger.warning(f"HASSH clustering failed: {e}")
                results["hassh_clusters"] = []

        # Summary
        results["summary"] = {
            "command_clusters_count": len(results.get("command_clusters", [])),
            "hassh_clusters_count": len(results.get("hassh_clusters", [])),
            "payload_clusters_count": len(results.get("payload_clusters", [])),
            "ttp_clusters_count": len(results.get("ttp_clusters", [])),
            "total_clusters": sum(
                len(results.get(k, []))
                for k in ["command_clusters", "hassh_clusters", "payload_clusters", "ttp_clusters"]
            ),
        }

        return results

    except Exception as e:
        logger.error(f"Failed to run cluster analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


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
        raise HTTPException(status_code=500, detail=str(e)) from e


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
        raise HTTPException(status_code=500, detail=str(e)) from e


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
        raise HTTPException(status_code=500, detail=str(e)) from e


# =============================================================================
# Threat Intelligence Endpoints
# =============================================================================


@router.get("/intel/ip/{ip}")
async def get_ip_threat_intel(
    ip: str,
    sources: Optional[str] = Query(None, description="Comma-separated sources: shodan,threatfox,urlhaus"),
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
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/intel/hash/{file_hash}")
async def get_hash_threat_intel(
    file_hash: str,
    sources: Optional[str] = Query(None, description="Comma-separated sources: threatfox,malwarebazaar"),
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
        raise HTTPException(status_code=500, detail=str(e)) from e


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
        raise HTTPException(status_code=500, detail=str(e)) from e


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
        raise HTTPException(status_code=500, detail=str(e)) from e


# =============================================================================
# TTP Clustering Endpoints
# =============================================================================


@router.post("/clusters/ttp/analyze")
async def analyze_session_ttp(request: dict):
    """
    Analyze TTPs for a specific session and store fingerprint.

    Request body should contain: {"session_id": "session-id-here"}

    Returns TTP analysis results including extracted techniques and confidence scores.
    """
    session_id = request.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required in request body")
    try:
        service = get_clustering_service()
        result = service.analyze_session_ttps(session_id)

        # Check if TTP service is properly initialized
        if not result.get("ttps_found", 0) > 0 and "MITRE" in str(result):
            raise HTTPException(
                status_code=503,
                detail="TTP analysis service not fully initialized. MITRE ATT&CK database may still be loading.",
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to analyze session TTPs: {e}")
        if "no such table" in str(e):
            raise HTTPException(
                status_code=503, detail="TTP analysis database not ready. Please try again in a few moments."
            ) from e
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/clusters/ttp")
async def get_ttp_clusters(
    technique: str = Query(None, description="Filter by MITRE technique ID (e.g., T1110)"),
    min_score: int = Query(0, description="Minimum confidence score (0-100)", ge=0, le=100),
):
    """
    Get TTP clusters with optional filtering.

    Returns clusters grouped by dominant MITRE ATT&CK techniques.
    """
    try:
        service = get_clustering_service()
        clusters = service.get_ttp_clusters(technique_filter=technique, min_score=min_score)
        return {"clusters": clusters, "count": len(clusters)}

    except Exception as e:
        logger.error(f"Failed to get TTP clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clusters/ttp/build")
async def build_ttp_clusters(
    days: int = Query(7, description="Number of days to analyze", ge=1, le=365),
    min_size: int = Query(2, description="Minimum cluster size", ge=1),
):
    """
    Build TTP clusters from recent session data.

    Analyzes sessions for MITRE ATT&CK technique patterns and groups them into clusters.
    """
    try:
        service = get_clustering_service()
        clusters = service.build_ttp_clusters(days=days, min_size=min_size)

        return {
            "message": f"Built {len(clusters)} TTP clusters",
            "clusters": clusters,
            "parameters": {"days": days, "min_size": min_size},
        }

    except Exception as e:
        logger.error(f"Failed to build TTP clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clusters/ttp/batch-analyze")
async def batch_analyze_ttps(
    days: int = Query(7, description="Number of days to analyze", ge=1, le=365),
    batch_size: int = Query(100, description="Sessions per batch", ge=10, le=1000),
):
    """
    Batch analyze TTP fingerprints for all sessions in the time period.

    This endpoint populates the TTP fingerprints table by analyzing all sessions
    that haven't been analyzed yet. Should be called periodically or before
    building clusters for the first time.

    Returns:
        Summary of analysis including sessions analyzed, TTPs found, and errors.
    """
    try:
        service = get_clustering_service()
        result = service.batch_analyze_ttps(days=days, batch_size=batch_size)

        return {
            "message": f"Batch analysis complete: {result.get('analyzed', 0)} sessions analyzed",
            "result": result,
            "parameters": {"days": days, "batch_size": batch_size},
        }

    except Exception as e:
        logger.error(f"Failed to batch analyze TTPs: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/clusters/ttp/{technique_id}")
async def get_clusters_by_technique(technique_id: str):
    """
    Get all clusters associated with a specific MITRE ATT&CK technique.

    Returns both IOC clusters and TTP clusters that match the technique.
    """
    try:
        service = get_clustering_service()

        # Get TTP clusters for this technique
        ttp_clusters = service.get_ttp_clusters(technique_filter=technique_id)

        # Also get IOC clusters that might be related (this would need enhancement)
        # For now, just return TTP clusters
        all_clusters = ttp_clusters

        return {"technique_id": technique_id, "clusters": all_clusters, "count": len(all_clusters)}

    except Exception as e:
        logger.error(f"Failed to get clusters for technique {technique_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/intel/ttp/{technique_id}")
async def get_technique_details(technique_id: str):
    """
    Get detailed information about a MITRE ATT&CK technique.

    Includes technique metadata, associated tactics, and detection guidance.
    """
    try:
        from services.ttp_extraction import TTPExtractionService

        # Initialize TTP service to access MITRE data
        clustering_db = config.CLUSTERING_DB_PATH or config.COWRIE_DB_PATH.replace(".db", "_clustering.db")
        mitre_db = clustering_db.replace("_clustering.db", "_mitre.db")

        ttp_service = TTPExtractionService(config.COWRIE_DB_PATH, mitre_db)
        technique_info = ttp_service.get_technique_details(technique_id)

        if not technique_info:
            raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

        return technique_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get technique details for {technique_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


# =============================================================================
# STIX Export Endpoints
# =============================================================================


@router.get("/stix/clusters/{cluster_id}")
async def export_cluster_stix(
    cluster_id: str, format: str = Query("json", description="Output format: 'json' or 'dict'", pattern="^(json|dict)$")
):
    """
    Export a single cluster as a STIX bundle.

    Returns STIX 2.1 bundle containing indicators, attack patterns, and relationships
    for the specified cluster.
    """
    try:
        # Check if STIX is available
        from services.stix_export import STIX_AVAILABLE

        if not STIX_AVAILABLE:
            raise HTTPException(status_code=503, detail="STIX export not available. Please install 'stix2' package.")

        # Get cluster data
        service = get_clustering_service()
        clusters = service.get_clusters(days=30)  # Get recent clusters
        cluster_data = next((c for c in clusters if c["cluster_id"] == cluster_id), None)

        if not cluster_data:
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found")

        # Create STIX bundle
        from services.stix_export import STIXExportService

        stix_service = STIXExportService()

        bundle = stix_service.create_cluster_bundle(cluster_data)

        if format == "dict":
            result = stix_service.bundle_to_dict(bundle)
        else:
            result = stix_service.bundle_to_json(bundle)

        return {"cluster_id": cluster_id, "stix_bundle": result, "format": format, "spec_version": "2.1"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export cluster {cluster_id} to STIX: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/stix/export")
async def bulk_stix_export(
    cluster_type: str = Query(None, description="Filter by cluster type: 'command', 'hassh', 'payload', 'ttp'"),
    min_score: int = Query(0, description="Minimum cluster score", ge=0, le=100),
    days: int = Query(7, description="Days to look back", ge=1, le=365),
    format: str = Query("json", description="Output format: 'json' or 'dict'", pattern="^(json|dict)$"),
    validate: bool = Query(True, description="Validate STIX bundle"),
):
    """
    Export multiple clusters as a STIX bundle.

    Allows filtering by cluster type, score, and time range.
    Returns consolidated STIX 2.1 bundle.
    """
    try:
        # Check if STIX is available
        from services.stix_export import STIX_AVAILABLE

        if not STIX_AVAILABLE:
            raise HTTPException(status_code=503, detail="STIX export not available. Please install 'stix2' package.")

        # Get clusters with filtering
        service = get_clustering_service()
        clusters = service.get_clusters(days=days, min_size=1)

        # Apply filters
        if cluster_type:
            clusters = [c for c in clusters if c.get("cluster_type") == cluster_type]

        clusters = [c for c in clusters if c.get("score", 0) >= min_score]

        if not clusters:
            return {"message": "No clusters match the specified criteria", "clusters_found": 0, "stix_bundle": None}

        # Create STIX bundle
        from services.stix_export import STIXExportService

        stix_service = STIXExportService()

        export_result = stix_service.export_clusters_to_stix(clusters=clusters, output_format=format, validate=validate)

        return {
            "message": f"Exported {len(clusters)} clusters to STIX",
            "clusters_exported": len(clusters),
            "stix_bundle": export_result["bundle"],
            "validation": export_result["validation"],
            "metadata": export_result["metadata"],
            "format": format,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export clusters to STIX: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/stix/validate/{cluster_id}")
async def validate_cluster_stix(cluster_id: str):
    """
    Validate STIX bundle for a cluster without exporting.

    Returns validation results including any errors or warnings.
    """
    try:
        # Get cluster data
        service = get_clustering_service()
        clusters = service.get_clusters(days=30)
        cluster_data = next((c for c in clusters if c["cluster_id"] == cluster_id), None)

        if not cluster_data:
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found")

        # Create and validate STIX bundle
        from services.stix_export import STIXExportService

        stix_service = STIXExportService()

        bundle = stix_service.create_cluster_bundle(cluster_data)
        validation = stix_service.validate_bundle(bundle)

        return {
            "cluster_id": cluster_id,
            "validation": validation,
            "cluster_type": cluster_data.get("cluster_type"),
            "cluster_score": cluster_data.get("score"),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to validate STIX for cluster {cluster_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/stix/info")
async def get_stix_info():
    """
    Get information about STIX export capabilities.

    Returns supported formats, STIX version, and available object types.
    """
    try:
        from services.opencti_client import OPENCTI_AVAILABLE
        from services.stix_export import STIX_AVAILABLE

        info = {
            "stix_available": STIX_AVAILABLE,
            "opencti_available": OPENCTI_AVAILABLE,
            "stix_version": "2.1" if STIX_AVAILABLE else None,
            "supported_formats": ["json", "dict"] if STIX_AVAILABLE else [],
            "supported_cluster_types": ["command", "hassh", "payload", "ttp"],
            "object_types": ["identity", "indicator", "attack-pattern", "malware", "relationship", "intrusion-set"]
            if STIX_AVAILABLE
            else [],
            "integrations": {
                "opencti_enabled": bool(os.getenv("OPENCTI_URL") and OPENCTI_AVAILABLE),
                "auto_push": os.getenv("OPENCTI_AUTO_PUSH", "false").lower() == "true",
                "push_threshold": int(os.getenv("OPENCTI_PUSH_THRESHOLD", "70")),
            },
        }

        if not STIX_AVAILABLE:
            info["stix_error"] = "STIX export requires 'stix2' Python package"

        if not OPENCTI_AVAILABLE:
            info["opencti_error"] = "OpenCTI integration requires 'pycti' Python package"

        return info

    except Exception as e:
        logger.error(f"Failed to get STIX info: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


# =============================================================================
# OpenCTI Integration Endpoints
# =============================================================================


@router.get("/opencti/health")
async def opencti_health_check(quick: bool = Query(False, description="Quick check (skip connection test)")):
    """
    Check OpenCTI connection health.

    Returns connection status, OpenCTI version, and configuration info.

    Use `?quick=true` for fast response (only checks if configured, doesn't test connection).
    """
    try:
        from services.opencti_client import OPENCTI_AVAILABLE

        result = {
            "available": OPENCTI_AVAILABLE,
            "configured": False,
            "connected": False,
            "version": None,
            "url": None,
            "error": None,
            "quick_check": quick,
        }

        if not OPENCTI_AVAILABLE:
            result["error"] = "pycti library not installed"
            return result

        opencti_url = os.getenv("OPENCTI_URL", config.OPENCTI_URL)
        opencti_key = os.getenv("OPENCTI_API_KEY", config.OPENCTI_API_KEY)

        if not opencti_url or not opencti_key:
            result["error"] = "OpenCTI URL or API key not configured"
            return result

        result["configured"] = True
        result["url"] = opencti_url

        # Quick mode: just return configured status without testing connection
        if quick:
            result["connected"] = None  # Unknown - didn't test
            return result

        # Full mode: test connection using cached client (faster after first call)
        try:
            from services.opencti_client import get_opencti_client

            client = get_opencti_client(
                url=opencti_url,
                api_key=opencti_key,
                ssl_verify=config.OPENCTI_SSL_VERIFY,
            )

            if client:
                # Use cached client's health check (may still be slow on first call)
                health = client.health_check()
                result["connected"] = health.get("healthy", False)
                result["version"] = health.get("version")
                if not result["connected"]:
                    result["error"] = health.get("error")
            else:
                result["error"] = "Failed to initialize OpenCTI client"
        except Exception as e:
            result["error"] = str(e)

        return result

    except Exception as e:
        logger.error(f"OpenCTI health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/opencti/search")
async def opencti_search(
    query: str = Query(..., description="Search query (IP, hash, keyword, etc.)"),
    entity_types: Optional[str] = Query(
        None, description="Comma-separated entity types: Malware,Threat-Actor,Campaign,Indicator"
    ),
):
    """
    Search OpenCTI for threat intelligence.

    Search across various entity types for matching threat data.
    """
    try:
        from services.opencti_client import OPENCTI_AVAILABLE

        if not OPENCTI_AVAILABLE:
            raise HTTPException(status_code=503, detail="OpenCTI client library not available")

        opencti_url = os.getenv("OPENCTI_URL", config.OPENCTI_URL)
        opencti_key = os.getenv("OPENCTI_API_KEY", config.OPENCTI_API_KEY)

        if not opencti_url or not opencti_key:
            raise HTTPException(status_code=503, detail="OpenCTI not configured")

        from services.opencti_client import OpenCTIClientService

        client = OpenCTIClientService(
            url=opencti_url,
            api_key=opencti_key,
            ssl_verify=config.OPENCTI_SSL_VERIFY,
        )

        types_list = None
        if entity_types:
            types_list = [t.strip() for t in entity_types.split(",")]

        result = client.search_threat_intelligence(query, types_list)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OpenCTI search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clusters/{cluster_id}/enrich")
async def enrich_cluster(cluster_id: str):
    """
    Enrich a specific cluster with OpenCTI threat intelligence.

    Queries OpenCTI for related threat actors, campaigns, and malware
    based on the cluster's IOCs.
    """
    try:
        service = get_clustering_service()
        result = service.enrich_cluster_with_opencti(cluster_id)

        if result.get("errors") and not result.get("enriched"):
            if "not configured" in result["errors"][0].lower():
                raise HTTPException(status_code=503, detail=result["errors"][0])

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enrich cluster {cluster_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clusters/enrich")
async def enrich_clusters_bulk(
    min_score: int = Query(50, ge=0, le=100, description="Minimum cluster score to enrich"),
    days: int = Query(7, ge=1, le=365, description="Look back period"),
    limit: int = Query(50, ge=1, le=200, description="Maximum clusters to enrich"),
):
    """
    Bulk enrich clusters with OpenCTI threat intelligence.

    Enriches high-scoring clusters with related threat intelligence data.
    """
    try:
        service = get_clustering_service()
        result = service.enrich_all_clusters(min_score=min_score, days=days, limit=limit)
        return result

    except Exception as e:
        logger.error(f"Failed to bulk enrich clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/opencti/push/{cluster_id}")
async def push_cluster_to_opencti(cluster_id: str):
    """
    Push a cluster's IOCs to OpenCTI.

    Creates STIX objects in OpenCTI for the cluster's indicators.
    """
    try:
        from services.opencti_client import OPENCTI_AVAILABLE

        if not OPENCTI_AVAILABLE:
            raise HTTPException(status_code=503, detail="OpenCTI client library not available")

        opencti_url = os.getenv("OPENCTI_URL", config.OPENCTI_URL)
        opencti_key = os.getenv("OPENCTI_API_KEY", config.OPENCTI_API_KEY)

        if not opencti_url or not opencti_key:
            raise HTTPException(status_code=503, detail="OpenCTI not configured")

        # Get cluster data
        service = get_clustering_service()
        cluster = service.get_cluster_detail(cluster_id)

        if not cluster:
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found")

        # Create STIX bundle
        from services.stix_export import STIX_AVAILABLE, STIXExportService

        if not STIX_AVAILABLE:
            raise HTTPException(status_code=503, detail="STIX export not available")

        stix_service = STIXExportService()
        stix_bundle = stix_service.create_cluster_bundle(cluster)
        stix_dict = stix_service.bundle_to_dict(stix_bundle)

        # Push to OpenCTI
        from services.opencti_client import OpenCTIClientService

        client = OpenCTIClientService(
            url=opencti_url,
            api_key=opencti_key,
            ssl_verify=config.OPENCTI_SSL_VERIFY,
        )

        push_result = client.push_cluster(cluster, stix_dict)

        return {
            "cluster_id": cluster_id,
            "pushed": push_result.get("success", False),
            "entities_created": push_result.get("entities_created", []),
            "entities_updated": push_result.get("entities_updated", []),
            "errors": push_result.get("errors", []),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to push cluster {cluster_id} to OpenCTI: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e
