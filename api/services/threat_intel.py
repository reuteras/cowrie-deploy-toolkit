"""
Threat Intelligence Service

Integrates with free threat intelligence sources:
- Shodan InternetDB (no API key required)
- ThreatFox (abuse.ch)
- MalwareBazaar (abuse.ch)
- URLhaus (abuse.ch)

Provides caching to respect rate limits and improve performance.
"""

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Default TTLs for different feed types (in hours)
DEFAULT_TTLS = {
    "shodan": 24,
    "threatfox": 12,
    "malwarebazaar": 24,
    "urlhaus": 12,
    "abuseipdb": 24,
}


class ThreatIntelService:
    """Service for querying and caching threat intelligence data."""

    def __init__(self, db_path: str, abuseipdb_key: str = None):
        """
        Initialize threat intelligence service.

        Args:
            db_path: Path to the SQLite database for caching
            abuseipdb_key: Optional AbuseIPDB API key
        """
        self.db_path = db_path
        self.abuseipdb_key = abuseipdb_key
        self._ensure_tables()

        # HTTP session with connection pooling
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Cowrie-Honeypot-Dashboard/1.0"})
        self.timeout = 10

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self):
        """Ensure threat intel tables exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create cache table if not exists
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_feed_cache (
                cache_key TEXT PRIMARY KEY,
                feed_name TEXT NOT NULL,
                query_type TEXT NOT NULL,
                query_value TEXT NOT NULL,
                data TEXT NOT NULL,
                cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_threat_cache_expires
            ON threat_feed_cache(expires_at)
            """
        )

        # Create IP threat intel table if not exists
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_threat_intel (
                ip TEXT PRIMARY KEY,
                shodan_data TEXT,
                threatfox_data TEXT,
                abuseipdb_data TEXT,
                otx_data TEXT,
                malwarebazaar_data TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        conn.commit()
        conn.close()

    def _get_cached(self, feed_name: str, query_type: str, query_value: str) -> Optional[dict]:
        """
        Get cached response if still valid.

        Args:
            feed_name: Name of the feed
            query_type: Type of query (ip, hash, domain)
            query_value: The query value

        Returns:
            Cached data dict or None if not cached/expired
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cache_key = f"{feed_name}:{query_type}:{query_value}"
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            SELECT data FROM threat_feed_cache
            WHERE cache_key = ? AND expires_at > ?
            """,
            (cache_key, now),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            try:
                return json.loads(row["data"])
            except json.JSONDecodeError:
                return None
        return None

    def _set_cached(self, feed_name: str, query_type: str, query_value: str, data: dict, ttl_hours: int = 24):
        """
        Cache a response.

        Args:
            feed_name: Name of the feed
            query_type: Type of query
            query_value: The query value
            data: Data to cache
            ttl_hours: Time to live in hours
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cache_key = f"{feed_name}:{query_type}:{query_value}"
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

        cursor.execute(
            """
            INSERT OR REPLACE INTO threat_feed_cache
            (cache_key, feed_name, query_type, query_value, data, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (cache_key, feed_name, query_type, query_value, json.dumps(data), expires_at),
        )

        conn.commit()
        conn.close()

    def _update_ip_intel(self, ip: str, feed_name: str, data: dict):
        """
        Update the IP threat intel table with data from a specific feed.

        Args:
            ip: IP address
            feed_name: Name of the feed
            data: Data from the feed
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        column_map = {
            "shodan": "shodan_data",
            "threatfox": "threatfox_data",
            "abuseipdb": "abuseipdb_data",
            "otx": "otx_data",
            "malwarebazaar": "malwarebazaar_data",
        }

        column = column_map.get(feed_name)
        if not column:
            conn.close()
            return

        # Check if IP exists
        cursor.execute("SELECT ip FROM ip_threat_intel WHERE ip = ?", (ip,))
        exists = cursor.fetchone()

        if exists:
            cursor.execute(
                f"""
                UPDATE ip_threat_intel
                SET {column} = ?, last_updated = CURRENT_TIMESTAMP
                WHERE ip = ?
                """,
                (json.dumps(data), ip),
            )
        else:
            cursor.execute(
                f"""
                INSERT INTO ip_threat_intel (ip, {column}, last_updated)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (ip, json.dumps(data)),
            )

        conn.commit()
        conn.close()

    # =========================================================================
    # Shodan InternetDB (No API key required)
    # =========================================================================

    def query_shodan_internetdb(self, ip: str, use_cache: bool = True) -> dict:
        """
        Query Shodan InternetDB for IP information.

        InternetDB is free and requires no API key. It provides:
        - Open ports
        - Known vulnerabilities
        - Hostnames
        - Tags (e.g., "vpn", "proxy", "tor")

        Args:
            ip: IP address to query
            use_cache: Whether to use cached results

        Returns:
            Dict with Shodan data or error
        """
        if use_cache:
            cached = self._get_cached("shodan", "ip", ip)
            if cached:
                return cached

        try:
            response = self.session.get(f"https://internetdb.shodan.io/{ip}", timeout=self.timeout)

            if response.status_code == 404:
                # IP not found in Shodan database
                data = {"ip": ip, "found": False, "error": None}
            elif response.status_code == 200:
                data = response.json()
                data["found"] = True
                data["error"] = None
            else:
                data = {"ip": ip, "found": False, "error": f"HTTP {response.status_code}"}

            # Cache the result
            self._set_cached("shodan", "ip", ip, data, DEFAULT_TTLS["shodan"])
            self._update_ip_intel(ip, "shodan", data)

            return data

        except requests.exceptions.Timeout:
            return {"ip": ip, "found": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"Shodan InternetDB query failed for {ip}: {e}")
            return {"ip": ip, "found": False, "error": str(e)}

    # =========================================================================
    # ThreatFox (abuse.ch) - Free, no API key
    # =========================================================================

    def query_threatfox_ip(self, ip: str, use_cache: bool = True) -> dict:
        """
        Query ThreatFox for IP reputation.

        ThreatFox tracks malware, botnets, and C2 servers.

        Args:
            ip: IP address to query
            use_cache: Whether to use cached results

        Returns:
            Dict with ThreatFox data or error
        """
        if use_cache:
            cached = self._get_cached("threatfox", "ip", ip)
            if cached:
                return cached

        try:
            response = self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = response.json()
                data = {
                    "ip": ip,
                    "found": result.get("query_status") == "ok",
                    "data": result.get("data", []),
                    "error": None if result.get("query_status") == "ok" else result.get("query_status"),
                }
            else:
                data = {"ip": ip, "found": False, "data": [], "error": f"HTTP {response.status_code}"}

            self._set_cached("threatfox", "ip", ip, data, DEFAULT_TTLS["threatfox"])
            self._update_ip_intel(ip, "threatfox", data)

            return data

        except requests.exceptions.Timeout:
            return {"ip": ip, "found": False, "data": [], "error": "Timeout"}
        except Exception as e:
            logger.error(f"ThreatFox query failed for {ip}: {e}")
            return {"ip": ip, "found": False, "data": [], "error": str(e)}

    def query_threatfox_hash(self, file_hash: str, use_cache: bool = True) -> dict:
        """
        Query ThreatFox for hash reputation.

        Args:
            file_hash: SHA256, MD5, or SHA1 hash
            use_cache: Whether to use cached results

        Returns:
            Dict with ThreatFox data or error
        """
        if use_cache:
            cached = self._get_cached("threatfox", "hash", file_hash)
            if cached:
                return cached

        try:
            response = self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": file_hash},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = response.json()
                data = {
                    "hash": file_hash,
                    "found": result.get("query_status") == "ok",
                    "data": result.get("data", []),
                    "error": None if result.get("query_status") == "ok" else result.get("query_status"),
                }
            else:
                data = {"hash": file_hash, "found": False, "data": [], "error": f"HTTP {response.status_code}"}

            self._set_cached("threatfox", "hash", file_hash, data, DEFAULT_TTLS["threatfox"])
            return data

        except requests.exceptions.Timeout:
            return {"hash": file_hash, "found": False, "data": [], "error": "Timeout"}
        except Exception as e:
            logger.error(f"ThreatFox hash query failed for {file_hash}: {e}")
            return {"hash": file_hash, "found": False, "data": [], "error": str(e)}

    # =========================================================================
    # MalwareBazaar (abuse.ch) - Free, no API key
    # =========================================================================

    def query_malwarebazaar(self, file_hash: str, use_cache: bool = True) -> dict:
        """
        Query MalwareBazaar for malware sample information.

        Args:
            file_hash: SHA256, MD5, or SHA1 hash
            use_cache: Whether to use cached results

        Returns:
            Dict with MalwareBazaar data or error
        """
        if use_cache:
            cached = self._get_cached("malwarebazaar", "hash", file_hash)
            if cached:
                return cached

        try:
            response = self.session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = response.json()
                data = {
                    "hash": file_hash,
                    "found": result.get("query_status") == "ok",
                    "data": result.get("data", []),
                    "error": None if result.get("query_status") in ["ok", "no_results"] else result.get("query_status"),
                }
            else:
                data = {"hash": file_hash, "found": False, "data": [], "error": f"HTTP {response.status_code}"}

            self._set_cached("malwarebazaar", "hash", file_hash, data, DEFAULT_TTLS["malwarebazaar"])
            return data

        except requests.exceptions.Timeout:
            return {"hash": file_hash, "found": False, "data": [], "error": "Timeout"}
        except Exception as e:
            logger.error(f"MalwareBazaar query failed for {file_hash}: {e}")
            return {"hash": file_hash, "found": False, "data": [], "error": str(e)}

    # =========================================================================
    # URLhaus (abuse.ch) - Free, no API key
    # =========================================================================

    def query_urlhaus_url(self, url: str, use_cache: bool = True) -> dict:
        """
        Query URLhaus for URL reputation.

        Args:
            url: URL to query
            use_cache: Whether to use cached results

        Returns:
            Dict with URLhaus data or error
        """
        if use_cache:
            cached = self._get_cached("urlhaus", "url", url)
            if cached:
                return cached

        try:
            response = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = response.json()
                data = {
                    "url": url,
                    "found": result.get("query_status") == "ok",
                    "data": result,
                    "error": None if result.get("query_status") in ["ok", "no_results"] else result.get("query_status"),
                }
            else:
                data = {"url": url, "found": False, "data": {}, "error": f"HTTP {response.status_code}"}

            self._set_cached("urlhaus", "url", url, data, DEFAULT_TTLS["urlhaus"])
            return data

        except requests.exceptions.Timeout:
            return {"url": url, "found": False, "data": {}, "error": "Timeout"}
        except Exception as e:
            logger.error(f"URLhaus query failed for {url}: {e}")
            return {"url": url, "found": False, "data": {}, "error": str(e)}

    def query_urlhaus_host(self, host: str, use_cache: bool = True) -> dict:
        """
        Query URLhaus for host reputation (IP or domain).

        Args:
            host: IP address or domain
            use_cache: Whether to use cached results

        Returns:
            Dict with URLhaus data or error
        """
        if use_cache:
            cached = self._get_cached("urlhaus", "host", host)
            if cached:
                return cached

        try:
            response = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": host},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = response.json()
                data = {
                    "host": host,
                    "found": result.get("query_status") == "ok",
                    "data": result,
                    "error": None if result.get("query_status") in ["ok", "no_results"] else result.get("query_status"),
                }
            else:
                data = {"host": host, "found": False, "data": {}, "error": f"HTTP {response.status_code}"}

            self._set_cached("urlhaus", "host", host, data, DEFAULT_TTLS["urlhaus"])
            return data

        except requests.exceptions.Timeout:
            return {"host": host, "found": False, "data": {}, "error": "Timeout"}
        except Exception as e:
            logger.error(f"URLhaus host query failed for {host}: {e}")
            return {"host": host, "found": False, "data": {}, "error": str(e)}

    # =========================================================================
    # Aggregated Queries
    # =========================================================================

    def get_ip_intel(self, ip: str, sources: list[str] = None) -> dict:
        """
        Get aggregated threat intelligence for an IP from multiple sources.

        Args:
            ip: IP address
            sources: List of sources to query (default: all free sources)

        Returns:
            Dict with aggregated threat data
        """
        if sources is None:
            sources = ["shodan", "threatfox", "urlhaus"]

        result = {
            "ip": ip,
            "sources": {},
            "summary": {
                "is_known_threat": False,
                "threat_types": [],
                "open_ports": [],
                "vulnerabilities": [],
                "tags": [],
            },
        }

        for source in sources:
            if source == "shodan":
                data = self.query_shodan_internetdb(ip)
                result["sources"]["shodan"] = data
                if data.get("found"):
                    result["summary"]["open_ports"] = data.get("ports", [])
                    result["summary"]["vulnerabilities"] = data.get("vulns", [])
                    result["summary"]["tags"].extend(data.get("tags", []))

            elif source == "threatfox":
                data = self.query_threatfox_ip(ip)
                result["sources"]["threatfox"] = data
                if data.get("found") and data.get("data"):
                    result["summary"]["is_known_threat"] = True
                    for ioc in data.get("data", []):
                        if ioc.get("threat_type"):
                            result["summary"]["threat_types"].append(ioc["threat_type"])
                        if ioc.get("malware"):
                            result["summary"]["tags"].append(ioc["malware"])

            elif source == "urlhaus":
                data = self.query_urlhaus_host(ip)
                result["sources"]["urlhaus"] = data
                if data.get("found") and data.get("data", {}).get("url_count", 0) > 0:
                    result["summary"]["is_known_threat"] = True
                    result["summary"]["tags"].append("malware_distribution")

        # Deduplicate tags
        result["summary"]["tags"] = list(set(result["summary"]["tags"]))
        result["summary"]["threat_types"] = list(set(result["summary"]["threat_types"]))

        return result

    def get_hash_intel(self, file_hash: str, sources: list[str] = None) -> dict:
        """
        Get aggregated threat intelligence for a file hash.

        Args:
            file_hash: SHA256, MD5, or SHA1 hash
            sources: List of sources to query

        Returns:
            Dict with aggregated threat data
        """
        if sources is None:
            sources = ["threatfox", "malwarebazaar"]

        result = {
            "hash": file_hash,
            "sources": {},
            "summary": {
                "is_known_malware": False,
                "malware_families": [],
                "threat_types": [],
                "tags": [],
            },
        }

        for source in sources:
            if source == "threatfox":
                data = self.query_threatfox_hash(file_hash)
                result["sources"]["threatfox"] = data
                if data.get("found") and data.get("data"):
                    result["summary"]["is_known_malware"] = True
                    for ioc in data.get("data", []):
                        if ioc.get("malware"):
                            result["summary"]["malware_families"].append(ioc["malware"])
                        if ioc.get("threat_type"):
                            result["summary"]["threat_types"].append(ioc["threat_type"])

            elif source == "malwarebazaar":
                data = self.query_malwarebazaar(file_hash)
                result["sources"]["malwarebazaar"] = data
                if data.get("found") and data.get("data"):
                    result["summary"]["is_known_malware"] = True
                    for sample in data.get("data", []):
                        if sample.get("signature"):
                            result["summary"]["malware_families"].append(sample["signature"])
                        if sample.get("tags"):
                            result["summary"]["tags"].extend(sample["tags"])

        # Deduplicate
        result["summary"]["malware_families"] = list(set(result["summary"]["malware_families"]))
        result["summary"]["threat_types"] = list(set(result["summary"]["threat_types"]))
        result["summary"]["tags"] = list(set(result["summary"]["tags"]))

        return result

    def cleanup_expired_cache(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("DELETE FROM threat_feed_cache WHERE expires_at < ?", (now,))
        deleted = cursor.rowcount

        conn.commit()
        conn.close()

        logger.info(f"Cleaned up {deleted} expired cache entries")
        return deleted

    def get_cache_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dict with cache stats
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total FROM threat_feed_cache")
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT feed_name, COUNT(*) as count
            FROM threat_feed_cache
            GROUP BY feed_name
            """
        )
        by_feed = {row["feed_name"]: row["count"] for row in cursor.fetchall()}

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "SELECT COUNT(*) as expired FROM threat_feed_cache WHERE expires_at < ?",
            (now,),
        )
        expired = cursor.fetchone()["expired"]

        conn.close()

        return {
            "total_entries": total,
            "by_feed": by_feed,
            "expired_entries": expired,
        }
