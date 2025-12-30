"""
SQLite-based statistics parser for Cowrie API

Queries Cowrie's SQLite database directly for fast statistics generation.
Falls back to JSON parsing if SQLite is unavailable.
"""

import os
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import geoip2.database
import geoip2.errors

# Database path (container mount path)
DEFAULT_DB_PATH = "/cowrie-data/lib/cowrie/cowrie.db"


class SQLiteStatsParser:
    """Fast statistics parser using SQLite database"""

    def __init__(self, db_path: str = None, geoip_city_db: str = None, geoip_asn_db: str = None):
        """
        Initialize SQLite parser

        Args:
            db_path: Path to cowrie.db (defaults to standard location)
            geoip_city_db: Path to GeoLite2-City.mmdb
            geoip_asn_db: Path to GeoLite2-ASN.mmdb
        """
        self.db_path = db_path or os.getenv("COWRIE_DB_PATH", DEFAULT_DB_PATH)
        self.available = os.path.exists(self.db_path)

        # Initialize GeoIP readers
        self.geoip_city_db = geoip_city_db or os.getenv("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
        self.geoip_asn_db = geoip_asn_db or os.getenv("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")

        self.city_reader = None
        self.asn_reader = None

        if os.path.exists(self.geoip_city_db):
            try:
                self.city_reader = geoip2.database.Reader(self.geoip_city_db)
            except Exception as e:
                print(f"[!] Failed to load GeoIP City database: {e}")

        if os.path.exists(self.geoip_asn_db):
            try:
                self.asn_reader = geoip2.database.Reader(self.geoip_asn_db)
            except Exception as e:
                print(f"[!] Failed to load GeoIP ASN database: {e}")

    def _geoip_lookup(self, ip: str) -> Dict:
        """Lookup GeoIP information for an IP address"""
        result = {
            "country": "-",
            "country_code": "XX",
            "city": "-",
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": "-",
        }

        if not self.city_reader:
            return result

        try:
            response = self.city_reader.city(ip)
            result["country"] = response.country.name or "-"
            result["country_code"] = response.country.iso_code or "XX"
            result["city"] = response.city.name or "-"
            if response.location.latitude and response.location.longitude:
                result["latitude"] = response.location.latitude
                result["longitude"] = response.location.longitude
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[!] GeoIP City lookup error for {ip}: {e}")

        if self.asn_reader:
            try:
                asn_response = self.asn_reader.asn(ip)
                result["asn"] = asn_response.autonomous_system_number
                result["asn_org"] = asn_response.autonomous_system_organization or "-"
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                print(f"[!] GeoIP ASN lookup error for {ip}: {e}")

        return result

    def get_stats_overview(self, days: int = 7) -> Dict:
        """
        Get overview statistics using SQL queries

        Args:
            days: Number of days to include

        Returns:
            Statistics dict with totals, top IPs, credentials, commands
        """
        if not self.available:
            raise FileNotFoundError(f"SQLite database not found at {self.db_path}")

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Total sessions and unique IPs
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total_sessions,
                    COUNT(DISTINCT ip) as unique_ips
                FROM sessions
                WHERE starttime >= ?
                """,
                (cutoff_str,),
            )
            totals = dict(cursor.fetchone())

            # Sessions with commands
            cursor.execute(
                """
                SELECT COUNT(DISTINCT session) as sessions_with_commands
                FROM input
                WHERE timestamp >= ?
                """,
                (cutoff_str,),
            )
            totals["sessions_with_commands"] = cursor.fetchone()["sessions_with_commands"]

            # Total downloads
            cursor.execute(
                """
                SELECT COUNT(*) as downloads
                FROM downloads
                WHERE timestamp >= ?
                """,
                (cutoff_str,),
            )
            totals["downloads"] = cursor.fetchone()["downloads"]

            # Top IPs
            cursor.execute(
                """
                SELECT ip, COUNT(*) as count
                FROM sessions
                WHERE starttime >= ?
                GROUP BY ip
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_ips = [{"ip": row["ip"], "count": row["count"]} for row in cursor.fetchall()]

            # Top credentials
            cursor.execute(
                """
                SELECT username, password, COUNT(*) as count
                FROM auth
                WHERE timestamp >= ?
                GROUP BY username, password
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_credentials = [
                {"username": row["username"], "password": row["password"], "count": row["count"]}
                for row in cursor.fetchall()
            ]

            # Top commands
            cursor.execute(
                """
                SELECT input as command, COUNT(*) as count
                FROM input
                WHERE timestamp >= ? AND success = 1
                GROUP BY input
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_commands = [{"command": row["command"], "count": row["count"]} for row in cursor.fetchall()]

            # Top SSH clients (join with clients table)
            cursor.execute(
                """
                SELECT c.version as client, COUNT(*) as count
                FROM sessions s
                JOIN clients c ON s.client = c.id
                WHERE s.starttime >= ?
                GROUP BY c.version
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff_str,),
            )
            top_clients = [{"client": row["client"], "count": row["count"]} for row in cursor.fetchall()]

            # Get all unique IPs for GeoIP enrichment
            cursor.execute(
                """
                SELECT DISTINCT ip
                FROM sessions
                WHERE starttime >= ?
                """,
                (cutoff_str,),
            )
            unique_ips = [row["ip"] for row in cursor.fetchall()]

            # Enrich with GeoIP data
            country_counter = Counter()
            asn_counter = Counter()
            asn_details = {}
            ip_locations = []

            for ip in unique_ips:
                geo = self._geoip_lookup(ip)

                # Count by country
                if geo["country"] != "-":
                    country_counter[geo["country"]] += 1

                # Count by ASN
                if geo["asn"]:
                    asn_key = f"AS{geo['asn']}"
                    asn_counter[asn_key] += 1
                    asn_details[asn_key] = {
                        "asn": asn_key,
                        "organization": geo["asn_org"],
                    }

                # Add to map locations if has coordinates
                if geo["latitude"] and geo["longitude"]:
                    ip_locations.append({
                        "ip": ip,
                        "lat": geo["latitude"],
                        "lon": geo["longitude"],
                        "city": geo["city"],
                        "country": geo["country"],
                    })

            # Format top countries
            top_countries = [
                {"country": country, "count": count} for country, count in country_counter.most_common(10)
            ]

            # Format top ASNs
            top_asns = []
            for asn, count in asn_counter.most_common(10):
                entry = {"asn": asn, "count": count}
                if asn in asn_details:
                    entry["organization"] = asn_details[asn]["organization"]
                top_asns.append(entry)

            return {
                "time_range": {
                    "start": cutoff.isoformat(),
                    "end": datetime.now(timezone.utc).isoformat(),
                    "days": days,
                },
                "totals": totals,
                "top_ips": top_ips,
                "top_credentials": top_credentials,
                "top_commands": top_commands,
                "top_clients": top_clients,
                "top_countries": top_countries,
                "top_asns": top_asns,
                "ip_locations": ip_locations,
            }

        finally:
            conn.close()


# Global instance
sqlite_parser = SQLiteStatsParser()
