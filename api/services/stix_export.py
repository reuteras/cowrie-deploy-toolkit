"""
STIX Export Service

Creates STIX 2.1 bundles from threat intelligence data including clusters,
indicators, attack patterns, and malware objects.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    import stix2
    from stix2 import Bundle, Indicator, AttackPattern, Malware, Relationship, Identity

    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    logger.warning("STIX2 library not available. STIX export functionality will be disabled.")

    # Create dummy classes for type hints when stix2 is not available
    class Bundle:
        pass

    class Indicator:
        pass

    class AttackPattern:
        pass

    class Malware:
        pass

    class Relationship:
        pass

    class Identity:
        pass


logger = logging.getLogger(__name__)


class STIXExportService:
    """Service for creating STIX 2.1 bundles from threat intelligence data."""

    def __init__(self, identity_name: str = "Cowrie Honeypot", identity_id: str = "identity--c0wrie-h0ney"):
        """
        Initialize STIX export service.

        Args:
            identity_name: Name for the identity object representing the honeypot
            identity_id: UUID for the identity object
        """
        if not STIX_AVAILABLE:
            raise ImportError("stix2 library is required for STIX export functionality")

        self.identity_name = identity_name
        self.identity_id = identity_id

        # Create base identity object
        self.identity = Identity(
            id=self.identity_id, name=self.identity_name, identity_class="system", sectors=["technology"]
        )

        logger.info(f"STIX Export Service initialized with identity: {identity_name}")

    def create_cluster_bundle(self, cluster_data: dict, include_ttps: bool = True) -> Bundle:
        """
        Create a STIX bundle for a cluster.

        Args:
            cluster_data: Cluster dictionary from clustering service
            include_ttps: Whether to include TTP information

        Returns:
            STIX Bundle object
        """
        objects = [self.identity]  # Always include our identity

        cluster_type = cluster_data.get("cluster_type", "unknown")
        cluster_id = cluster_data.get("cluster_id", "unknown")

        # Create appropriate STIX objects based on cluster type
        if cluster_type == "command":
            objects.extend(self._create_command_cluster_objects(cluster_data))
        elif cluster_type == "hassh":
            objects.extend(self._create_hassh_cluster_objects(cluster_data))
        elif cluster_type == "payload":
            objects.extend(self._create_payload_cluster_objects(cluster_data))
        elif cluster_type == "ttp":
            objects.extend(self._create_ttp_cluster_objects(cluster_data))
        else:
            # Generic cluster representation
            objects.extend(self._create_generic_cluster_objects(cluster_data))

        # Create relationships
        objects.extend(self._create_cluster_relationships(objects, cluster_data))

        bundle = Bundle(objects=objects)
        logger.info(f"Created STIX bundle for cluster {cluster_id} with {len(objects)} objects")

        return bundle

    def _create_command_cluster_objects(self, cluster_data: dict) -> List[Any]:
        """Create STIX objects for command-based clusters."""
        objects = []

        # Create an indicator for the command pattern
        fingerprint = cluster_data.get("fingerprint", "")
        if fingerprint:
            indicator = Indicator(
                pattern=f"[file:hashes.'SHA-256' = '{fingerprint}']",  # Placeholder pattern
                pattern_type="stix",
                labels=["command-pattern"],
                description=f"Command cluster with {cluster_data.get('size', 0)} unique IPs",
                created_by_ref=self.identity_id,
                confidence=cluster_data.get("score", 50),
            )
            objects.append(indicator)

        return objects

    def _create_hassh_cluster_objects(self, cluster_data: dict) -> List[Any]:
        """Create STIX objects for HASSH-based clusters."""
        objects = []

        # Create an indicator for the HASSH fingerprint
        fingerprint = cluster_data.get("fingerprint", "")
        if fingerprint:
            indicator = Indicator(
                pattern=f"[network-traffic:extensions.'http-request-ext'.x_hassh = '{fingerprint}']",
                pattern_type="stix",
                labels=["ssh-fingerprint"],
                description=f"HASSH cluster with {cluster_data.get('size', 0)} unique IPs",
                created_by_ref=self.identity_id,
                confidence=cluster_data.get("score", 50),
            )
            objects.append(indicator)

        return objects

    def _create_payload_cluster_objects(self, cluster_data: dict) -> List[Any]:
        """Create STIX objects for payload-based clusters."""
        objects = []

        # Create malware object for the payload
        malware = Malware(
            name=f"Malware Cluster {cluster_data.get('cluster_id', 'unknown')}",
            labels=["trojan", "downloader"],  # Would be enriched from VT data
            description=f"Malware downloaded by {cluster_data.get('size', 0)} unique IPs",
            created_by_ref=self.identity_id,
            confidence=cluster_data.get("score", 50),
        )
        objects.append(malware)

        # Create indicators for file hashes
        metadata = cluster_data.get("metadata", {})
        sample_hashes = metadata.get("sample_hashes", [])
        for hash_value in sample_hashes[:5]:  # Limit to 5 samples
            indicator = Indicator(
                pattern=f"[file:hashes.'SHA-256' = '{hash_value}']",
                pattern_type="stix",
                labels=["malicious-file"],
                description="Malware file hash from honeypot captures",
                created_by_ref=self.identity_id,
                confidence=85,  # High confidence for actual file hashes
            )
            objects.append(indicator)

        return objects

    def _create_ttp_cluster_objects(self, cluster_data: dict) -> List[Any]:
        """Create STIX objects for TTP-based clusters."""
        objects = []

        # Create attack pattern for the dominant technique
        dominant_technique = cluster_data.get("dominant_technique", "")
        technique_name = cluster_data.get("technique_name", dominant_technique)

        if dominant_technique:
            attack_pattern = AttackPattern(
                name=technique_name,
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": dominant_technique,
                        "url": f"https://attack.mitre.org/techniques/{dominant_technique}/",
                    }
                ],
                description=f"TTP cluster with {cluster_data.get('size', 0)} unique IPs using {technique_name}",
                created_by_ref=self.identity_id,
                confidence=cluster_data.get("score", 50),
            )
            objects.append(attack_pattern)

        return objects

    def _create_generic_cluster_objects(self, cluster_data: dict) -> List[Any]:
        """Create STIX objects for generic clusters."""
        objects = []

        # Create a basic indicator
        indicator = Indicator(
            pattern=f"[x-cowrie:cluster_id = '{cluster_data.get('cluster_id', 'unknown')}']",
            pattern_type="stix",
            labels=["threat-cluster"],
            description=f"Threat cluster with {cluster_data.get('size', 0)} unique IPs",
            created_by_ref=self.identity_id,
            confidence=cluster_data.get("score", 50),
        )
        objects.append(indicator)

        return objects

    def _create_cluster_relationships(self, objects: List[Any], cluster_data: dict) -> List[Relationship]:
        """Create relationships between STIX objects in the cluster."""
        relationships = []

        # Find the main indicator/attack pattern/malware object
        main_object = None
        for obj in objects:
            if hasattr(obj, "type"):
                if obj.type in ["indicator", "attack-pattern", "malware"]:
                    main_object = obj
                    break

        if main_object:
            # Create relationship to our identity (attributed-to)
            rel = Relationship(
                relationship_type="attributed-to",
                source_ref=main_object.id,
                target_ref=self.identity_id,
                description="Threat intelligence attributed to Cowrie honeypot detections",
                confidence=80,
            )
            relationships.append(rel)

        return relationships

    def create_bulk_bundle(self, clusters: List[dict], bundle_name: str = "Cowrie Threat Intelligence") -> Bundle:
        """
        Create a STIX bundle containing multiple clusters.

        Args:
            clusters: List of cluster dictionaries
            bundle_name: Name for the bundle

        Returns:
            STIX Bundle containing all clusters
        """
        objects = [self.identity]
        cluster_objects = []

        # Create objects for each cluster
        for cluster in clusters:
            cluster_objects.extend(self.create_cluster_bundle(cluster, include_ttps=True).objects)

        # Remove duplicate identity objects and merge
        unique_objects = [self.identity]  # Keep our identity
        seen_ids = {self.identity_id}

        for obj in cluster_objects:
            if hasattr(obj, "id") and obj.id not in seen_ids:
                unique_objects.append(obj)
                seen_ids.add(obj.id)

        bundle = Bundle(objects=unique_objects)
        logger.info(f"Created bulk STIX bundle with {len(unique_objects)} objects from {len(clusters)} clusters")

        return bundle

    def bundle_to_json(self, bundle: Bundle) -> str:
        """
        Convert STIX bundle to JSON string.

        Args:
            bundle: STIX Bundle object

        Returns:
            JSON string representation
        """
        return bundle.serialize(pretty=True)

    def bundle_to_dict(self, bundle: Bundle) -> dict:
        """
        Convert STIX bundle to dictionary.

        Args:
            bundle: STIX Bundle object

        Returns:
            Dictionary representation
        """
        return json.loads(bundle.serialize())

    def validate_bundle(self, bundle: Bundle) -> Dict[str, Any]:
        """
        Validate STIX bundle for correctness.

        Args:
            bundle: STIX Bundle to validate

        Returns:
            Validation results dictionary
        """
        results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "stats": {"total_objects": len(bundle.objects), "object_types": {}, "relationships": 0},
        }

        # Count object types
        for obj in bundle.objects:
            obj_type = getattr(obj, "type", "unknown")
            results["stats"]["object_types"][obj_type] = results["stats"]["object_types"].get(obj_type, 0) + 1

            if obj_type == "relationship":
                results["stats"]["relationships"] += 1

        # Basic validation checks
        if results["stats"]["total_objects"] == 0:
            results["errors"].append("Bundle contains no objects")
            results["valid"] = False

        # Check for required identity
        has_identity = any(getattr(obj, "type", None) == "identity" for obj in bundle.objects)
        if not has_identity:
            results["warnings"].append("Bundle does not contain an identity object")

        return results

    def export_clusters_to_stix(
        self, clusters: List[dict], output_format: str = "json", validate: bool = True
    ) -> Dict[str, Any]:
        """
        Export clusters to STIX format.

        Args:
            clusters: List of cluster dictionaries
            output_format: Output format ("json" or "dict")
            validate: Whether to validate the bundle

        Returns:
            Dictionary with bundle data and metadata
        """
        bundle = self.create_bulk_bundle(clusters)

        result = {
            "bundle": None,
            "validation": None,
            "metadata": {
                "cluster_count": len(clusters),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "format": "STIX 2.1",
            },
        }

        if output_format == "json":
            result["bundle"] = self.bundle_to_json(bundle)
        else:
            result["bundle"] = self.bundle_to_dict(bundle)

        if validate:
            result["validation"] = self.validate_bundle(bundle)

        return result
