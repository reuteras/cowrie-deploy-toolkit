"""
OpenCTI Client Service

Handles integration with OpenCTI (Open Cyber Threat Intelligence platform)
for importing and exporting threat intelligence data.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from pycti import OpenCTIApiClient
    from pycti.api.opencti_api_client import File

    OPENCTI_AVAILABLE = True
except ImportError:
    OPENCTI_AVAILABLE = False
    logger.warning("PyCTI library not available. OpenCTI integration will be disabled.")

    # Create dummy class for type hints
    class OpenCTIApiClient:
        pass

    class File:
        pass


logger = logging.getLogger(__name__)

# Global client instance cache
_opencti_client_cache: Optional["OpenCTIClientService"] = None
_opencti_client_config: Optional[tuple] = None


def get_opencti_client(url: str, api_key: str, ssl_verify: bool = True) -> Optional["OpenCTIClientService"]:
    """
    Get or create a cached OpenCTI client instance.

    Reuses existing client if config matches, otherwise creates new one.
    This avoids the overhead of initializing pycti on every request.
    """
    global _opencti_client_cache, _opencti_client_config

    config_key = (url, api_key, ssl_verify)

    if _opencti_client_cache is not None and _opencti_client_config == config_key:
        logger.debug("Using cached OpenCTI client")
        return _opencti_client_cache

    try:
        logger.info(f"Creating new OpenCTI client for {url} (ssl_verify={ssl_verify})")
        client = OpenCTIClientService(url, api_key, ssl_verify, test_connection=False)
        _opencti_client_cache = client
        _opencti_client_config = config_key
        logger.info("OpenCTI client created and cached successfully")
        return client
    except ImportError as e:
        logger.error(f"Failed to create OpenCTI client - missing library: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to create OpenCTI client: {type(e).__name__}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None


class OpenCTIClientService:
    """Service for interacting with OpenCTI platform."""

    def __init__(self, url: str, api_key: str, ssl_verify: bool = True, test_connection: bool = True):
        """
        Initialize OpenCTI client service.

        Args:
            url: OpenCTI instance URL (e.g., https://your-opencti-instance.com)
            api_key: OpenCTI API key with appropriate permissions
            ssl_verify: Whether to verify SSL certificates
            test_connection: Whether to test connection on init (can be slow)
        """
        if not OPENCTI_AVAILABLE:
            raise ImportError("pycti library is required for OpenCTI integration")

        self.url = url.rstrip("/")
        self.api_key = api_key
        self.ssl_verify = ssl_verify
        self._connected = False

        # Initialize client
        try:
            self.client = OpenCTIApiClient(url=self.url, token=self.api_key, ssl_verify=self.ssl_verify)
            logger.info(f"OpenCTI client initialized for {self.url}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenCTI client: {e}")
            raise

        # Test connection (optional - can be slow)
        if test_connection:
            self._test_connection()
            self._connected = True

    def _test_connection(self) -> bool:
        """
        Test connection to OpenCTI instance.

        Returns:
            True if connection successful, raises exception otherwise
        """
        try:
            # Try to get platform information
            query = """
            query {
                about {
                    version
                    dependencies {
                        name
                        version
                    }
                }
            }
            """
            result = self.client.query(query)

            if result and "data" in result and "about" in result["data"]:
                version = result["data"]["about"]["version"]
                logger.info(f"Connected to OpenCTI version {version}")
                return True
            else:
                raise Exception("Invalid response from OpenCTI")

        except Exception as e:
            logger.error(f"OpenCTI connection test failed: {e}")
            raise

    def push_cluster(self, cluster_data: dict, stix_bundle: Optional[dict] = None) -> Dict[str, Any]:
        """
        Push cluster data to OpenCTI.

        Args:
            cluster_data: Cluster dictionary from clustering service
            stix_bundle: Optional STIX bundle for the cluster

        Returns:
            Dictionary with push results and created entity IDs
        """
        try:
            result = {"success": False, "entities_created": [], "entities_updated": [], "errors": []}

            cluster_type = cluster_data.get("cluster_type", "unknown")
            cluster_id = cluster_data.get("cluster_id", "unknown")

            logger.info(f"Pushing cluster {cluster_id} ({cluster_type}) to OpenCTI")

            # Use STIX bundle if provided, otherwise create entities manually
            if stix_bundle:
                push_result = self._push_stix_bundle(stix_bundle)
                result.update(push_result)
            else:
                push_result = self._push_cluster_entities(cluster_data)
                result.update(push_result)

            result["success"] = len(result["errors"]) == 0
            logger.info(f"Cluster {cluster_id} push result: {result['success']}")

            return result

        except Exception as e:
            logger.error(f"Failed to push cluster {cluster_data.get('cluster_id')}: {e}")
            return {"success": False, "entities_created": [], "entities_updated": [], "errors": [str(e)]}

    def _push_stix_bundle(self, stix_bundle: dict) -> Dict[str, Any]:
        """
        Push STIX bundle to OpenCTI.

        Args:
            stix_bundle: STIX 2.1 bundle dictionary

        Returns:
            Push results
        """
        try:
            # Convert dict to JSON string if needed
            if isinstance(stix_bundle, dict):
                bundle_json = json.dumps(stix_bundle)
            else:
                bundle_json = stix_bundle

            # Create a file-like object for the bundle
            import io

            bundle_file = io.BytesIO(bundle_json.encode("utf-8"))

            # Use OpenCTI's file upload and import
            file_info = self.client.file.upload_file(
                file_name="cowrie_cluster_bundle.json", file_content=bundle_file, mime_type="application/json"
            )

            # Import the STIX bundle
            import_result = self.client.stix_core_object.import_stix_content(
                content=bundle_json,
                update=True,  # Update existing entities
            )

            return {
                "entities_created": import_result.get("entitiesCreated", []),
                "entities_updated": import_result.get("entitiesUpdated", []),
                "errors": import_result.get("errors", []),
            }

        except Exception as e:
            logger.error(f"Failed to push STIX bundle: {e}")
            return {"entities_created": [], "entities_updated": [], "errors": [str(e)]}

    def _push_cluster_entities(self, cluster_data: dict) -> Dict[str, Any]:
        """
        Push cluster data as individual OpenCTI entities.

        Args:
            cluster_data: Cluster dictionary

        Returns:
            Push results
        """
        result = {"entities_created": [], "entities_updated": [], "errors": []}

        try:
            cluster_type = cluster_data.get("cluster_type", "unknown")

            if cluster_type == "ttp":
                entity_result = self._create_attack_pattern_from_cluster(cluster_data)
            elif cluster_type == "payload":
                entity_result = self._create_malware_from_cluster(cluster_data)
            else:
                entity_result = self._create_indicator_from_cluster(cluster_data)

            result["entities_created"].extend(entity_result.get("created", []))
            result["entities_updated"].extend(entity_result.get("updated", []))
            result["errors"].extend(entity_result.get("errors", []))

        except Exception as e:
            result["errors"].append(str(e))

        return result

    def _create_attack_pattern_from_cluster(self, cluster_data: dict) -> Dict[str, Any]:
        """Create attack pattern from TTP cluster."""
        try:
            technique_id = cluster_data.get("dominant_technique", "")
            technique_name = cluster_data.get("technique_name", technique_id)

            attack_pattern_data = {
                "name": f"{technique_name} - Honeypot Cluster",
                "description": f"Attack pattern detected in honeypot cluster with {cluster_data.get('size', 0)} unique IPs",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                    }
                ]
                if technique_id.startswith("T")
                else [],
                "confidence": cluster_data.get("score", 50),
                "x_opencti_score": cluster_data.get("score", 50),
            }

            # Create the attack pattern
            attack_pattern = self.client.attack_pattern.create(**attack_pattern_data)

            return {"created": [attack_pattern["id"]], "updated": [], "errors": []}

        except Exception as e:
            logger.error(f"Failed to create attack pattern: {e}")
            return {"created": [], "updated": [], "errors": [str(e)]}

    def _create_malware_from_cluster(self, cluster_data: dict) -> Dict[str, Any]:
        """Create malware entity from payload cluster."""
        try:
            malware_data = {
                "name": f"Honeypot Malware Cluster {cluster_data.get('cluster_id', 'unknown')}",
                "description": f"Malware cluster detected by honeypot with {cluster_data.get('size', 0)} unique IPs",
                "malware_types": ["trojan", "downloader"],
                "is_family": False,
                "confidence": cluster_data.get("score", 50),
                "x_opencti_score": cluster_data.get("score", 50),
            }

            malware = self.client.malware.create(**malware_data)

            return {"created": [malware["id"]], "updated": [], "errors": []}

        except Exception as e:
            logger.error(f"Failed to create malware: {e}")
            return {"created": [], "updated": [], "errors": [str(e)]}

    def _create_indicator_from_cluster(self, cluster_data: dict) -> Dict[str, Any]:
        """Create indicator from IOC cluster."""
        try:
            indicator_data = {
                "name": f"Honeypot {cluster_data.get('cluster_type', 'unknown').title()} Cluster",
                "description": f"Threat cluster detected by honeypot with {cluster_data.get('size', 0)} unique IPs",
                "indicator_types": ["malicious-activity"],
                "confidence": cluster_data.get("score", 50),
                "x_opencti_score": cluster_data.get("score", 50),
                "pattern": f"[x-cowrie:cluster_id = '{cluster_data.get('cluster_id', 'unknown')}']",
                "pattern_type": "stix",
            }

            indicator = self.client.indicator.create(**indicator_data)

            return {"created": [indicator["id"]], "updated": [], "errors": []}

        except Exception as e:
            logger.error(f"Failed to create indicator: {e}")
            return {"created": [], "updated": [], "errors": [str(e)]}

    def pull_related_entities(self, cluster_id: str) -> Dict[str, Any]:
        """
        Pull related threat intelligence from OpenCTI for a cluster.

        Args:
            cluster_id: Local cluster ID

        Returns:
            Dictionary with related entities and enrichment data
        """
        try:
            result = {"campaigns": [], "threat_actors": [], "malware": [], "vulnerabilities": [], "enrichment_data": {}}

            # Query for related entities based on cluster characteristics
            # This is a simplified implementation - in practice, you'd match
            # on observables, attack patterns, etc.

            # For now, return empty result as this requires more complex
            # matching logic based on cluster observables
            logger.info(f"Pulling related entities for cluster {cluster_id} (placeholder implementation)")

            return result

        except Exception as e:
            logger.error(f"Failed to pull related entities for cluster {cluster_id}: {e}")
            return {
                "campaigns": [],
                "threat_actors": [],
                "malware": [],
                "vulnerabilities": [],
                "enrichment_data": {},
                "error": str(e),
            }

    def search_threat_intelligence(self, query: str, entity_types: List[str] = None) -> Dict[str, Any]:
        """
        Search OpenCTI for threat intelligence.

        Args:
            query: Search query string
            entity_types: List of entity types to search (e.g., ['Malware', 'Threat-Actor'])

        Returns:
            Search results
        """
        if entity_types is None:
            entity_types = ["Malware", "Threat-Actor", "Campaign", "Intrusion-Set"]

        try:
            results = {}

            for entity_type in entity_types:
                # Use OpenCTI's search functionality
                search_results = self.client.stix_domain_object.list(
                    types=[entity_type],
                    search=query,
                    first=10,  # Limit results
                )
                results[entity_type.lower()] = search_results

            return {"query": query, "results": results, "success": True}

        except Exception as e:
            logger.error(f"Failed to search OpenCTI: {e}")
            return {"query": query, "results": {}, "success": False, "error": str(e)}

    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get OpenCTI platform information.

        Returns:
            Platform version and capabilities
        """
        try:
            query = """
            query {
                about {
                    version
                    dependencies {
                        name
                        version
                    }
                }
            }
            """
            result = self.client.query(query)
            return result.get("data", {}).get("about", {})

        except Exception as e:
            logger.error(f"Failed to get platform info: {e}")
            return {"error": str(e)}

    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on OpenCTI connection.

        Returns:
            Health check results
        """
        try:
            platform_info = self.get_platform_info()

            return {
                "healthy": "version" in platform_info,
                "version": platform_info.get("version"),
                "url": self.url,
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
                "url": self.url,
                "last_check": datetime.now(timezone.utc).isoformat(),
            }
