"""
Configuration management for Cowrie API
"""

import os
from pathlib import Path


class Config:
    """API Configuration from environment variables"""

    # Cowrie data paths (mounted volumes)
    COWRIE_LOG_PATH: str = os.getenv("COWRIE_LOG_PATH", "/cowrie/cowrie-git/var/log/cowrie/cowrie.json")
    COWRIE_TTY_PATH: str = os.getenv("COWRIE_TTY_PATH", "/cowrie/cowrie-git/var/lib/cowrie/tty")
    COWRIE_DOWNLOADS_PATH: str = os.getenv("COWRIE_DOWNLOADS_PATH", "/cowrie/cowrie-git/var/lib/cowrie/downloads")
    COWRIE_SHARE_PATH: str = os.getenv("COWRIE_SHARE_PATH", "/cowrie-data/share/cowrie")

    # GeoIP databases
    GEOIP_CITY_DB: str = os.getenv("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
    GEOIP_ASN_DB: str = os.getenv("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")

    # Cache databases
    YARA_CACHE_DB: str = os.getenv("YARA_CACHE_DB", "/cowrie/cowrie-git/var/cache/yara-cache.db")
    VT_CACHE_DB: str = os.getenv("VT_CACHE_DB", "/cowrie/cowrie-git/var/cache/vt-cache.db")
    CANARY_WEBHOOKS_DB: str = os.getenv("CANARY_WEBHOOKS_DB", "/opt-cowrie-data/canary-webhooks.db")
    IPLOCK_DB: str = os.getenv("IPLOCK_DB", "/cowrie-data/lib/cowrie/iplock.db")

    # API keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # API settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate_paths(cls) -> list[str]:
        """Validate that required paths exist, return list of missing paths"""
        missing = []

        # Check log file
        if not Path(cls.COWRIE_LOG_PATH).parent.exists():
            missing.append(cls.COWRIE_LOG_PATH)

        # Check directories
        for path in [cls.COWRIE_TTY_PATH, cls.COWRIE_DOWNLOADS_PATH]:
            if not Path(path).exists():
                missing.append(path)

        return missing


# Global config instance
config = Config()
