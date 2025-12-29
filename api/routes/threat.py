"""
Threat intelligence endpoints

Provides GeoIP and other threat intelligence data
"""

from pathlib import Path

from fastapi import APIRouter

router = APIRouter()


@router.get("/threat/ip/{ip}")
async def get_ip_intel(ip: str):
    """
    Get threat intelligence for an IP address

    Returns:
        - GeoIP data (country, city, ASN)
        - AbuseIPDB score (if API key configured)
        - DShield reports
    """
    from config import config

    result = {"ip": ip, "geo": {"country": "-", "city": "-"}, "asn": None, "asn_org": None}

    # GeoIP lookup
    try:
        import geoip2.database

        city_db = Path(config.GEOIP_CITY_DB)
        asn_db = Path(config.GEOIP_ASN_DB)

        if city_db.exists():
            with geoip2.database.Reader(str(city_db)) as reader:
                response = reader.city(ip)
                result["geo"] = {
                    "country": response.country.name or "-",
                    "country_code": response.country.iso_code or "XX",
                    "city": response.city.name or "-",
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }

        if asn_db.exists():
            with geoip2.database.Reader(str(asn_db)) as reader:
                response = reader.asn(ip)
                result["asn"] = response.autonomous_system_number
                result["asn_org"] = response.autonomous_system_organization

    except ImportError:
        result["geo"]["error"] = "GeoIP2 library not available"
    except Exception as e:
        result["geo"]["error"] = str(e)

    return result
