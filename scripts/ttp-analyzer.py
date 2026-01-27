#!/usr/bin/env python3
"""
Cowrie TTP Analyzer - Scheduled Task Script

Analyzes all Cowrie sessions for MITRE ATT&CK TTPs (Tactics, Techniques, and Procedures)
and populates fingerprints for clustering. Run via systemd timer or cron.

Usage:
    # Analyze last 7 days
    uv run scripts/ttp-analyzer.py

    # Analyze last 30 days
    uv run scripts/ttp-analyzer.py --days 30

    # Build clusters after analysis
    uv run scripts/ttp-analyzer.py --build-clusters

    # Just show stats without running analysis
    uv run scripts/ttp-analyzer.py --stats-only
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


def get_db_paths() -> tuple[str, str, str]:
    """Get database paths from environment or defaults."""
    source_db = os.getenv(
        "COWRIE_DB_PATH",
        "/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db",
    )
    clustering_db = os.getenv(
        "CLUSTERING_DB_PATH",
        source_db.replace(".db", "_clustering.db"),
    )
    mitre_db = os.getenv(
        "MITRE_DB_PATH",
        source_db.replace(".db", "_mitre.db"),
    )
    return source_db, clustering_db, mitre_db


def check_database_exists(db_path: str) -> bool:
    """Check if database file exists and is accessible."""
    if not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.close()
        return True
    except sqlite3.Error:
        return False


def get_session_stats(source_db: str, days: int) -> dict:
    """Get statistics about sessions in the time period."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        conn = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total sessions
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE starttime >= ?",
            (cutoff.isoformat(),),
        )
        total_sessions = cursor.fetchone()["cnt"]

        # Sessions with commands
        cursor.execute(
            """
            SELECT COUNT(DISTINCT s.id) as cnt
            FROM sessions s
            INNER JOIN input i ON s.id = i.session
            WHERE s.starttime >= ?
        """,
            (cutoff.isoformat(),),
        )
        sessions_with_commands = cursor.fetchone()["cnt"]

        # Total commands
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM input WHERE timestamp >= ?",
            (cutoff.isoformat(),),
        )
        total_commands = cursor.fetchone()["cnt"]

        conn.close()

        return {
            "total_sessions": total_sessions,
            "sessions_with_commands": sessions_with_commands,
            "total_commands": total_commands,
        }
    except sqlite3.Error as e:
        print(f"Error getting session stats: {e}")
        return {}


def get_fingerprint_stats(clustering_db: str, days: int) -> dict:
    """Get statistics about existing TTP fingerprints."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        conn = sqlite3.connect(clustering_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ttp_fingerprints'")
        if not cursor.fetchone():
            conn.close()
            return {"total_fingerprints": 0, "recent_fingerprints": 0}

        # Total fingerprints
        cursor.execute("SELECT COUNT(*) as cnt FROM ttp_fingerprints")
        total = cursor.fetchone()["cnt"]

        # Recent fingerprints
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM ttp_fingerprints WHERE created_at >= ?",
            (cutoff.isoformat(),),
        )
        recent = cursor.fetchone()["cnt"]

        # Top techniques
        cursor.execute(
            """
            SELECT dominant_techniques, COUNT(*) as cnt
            FROM ttp_fingerprints
            WHERE created_at >= ?
            GROUP BY dominant_techniques
            ORDER BY cnt DESC
            LIMIT 10
        """,
            (cutoff.isoformat(),),
        )
        top_techniques = []
        for row in cursor.fetchall():
            try:
                techniques = json.loads(row["dominant_techniques"])
                if techniques:
                    top_techniques.append({"technique": techniques[0], "count": row["cnt"]})
            except (json.JSONDecodeError, IndexError):
                pass

        conn.close()

        return {
            "total_fingerprints": total,
            "recent_fingerprints": recent,
            "top_techniques": top_techniques,
        }
    except sqlite3.Error as e:
        print(f"Error getting fingerprint stats: {e}")
        return {}


def run_batch_analysis(source_db: str, clustering_db: str, days: int, batch_size: int) -> dict:
    """Run batch TTP analysis."""
    try:
        from services.clustering import ClusteringService

        service = ClusteringService(source_db, clustering_db)
        return service.batch_analyze_ttps(days=days, batch_size=batch_size)
    except ImportError as e:
        print(f"Error importing clustering service: {e}")
        print("Make sure you're running from the project root with: uv run scripts/ttp-analyzer.py")
        return {"error": str(e)}
    except Exception as e:
        print(f"Error during batch analysis: {e}")
        return {"error": str(e)}


def build_clusters(source_db: str, clustering_db: str, days: int, min_size: int) -> dict:
    """Build TTP clusters."""
    try:
        from services.clustering import ClusteringService

        service = ClusteringService(source_db, clustering_db)
        clusters = service.build_ttp_clusters(days=days, min_size=min_size)
        return {"clusters_built": len(clusters), "clusters": clusters}
    except ImportError as e:
        print(f"Error importing clustering service: {e}")
        return {"error": str(e)}
    except Exception as e:
        print(f"Error building clusters: {e}")
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Cowrie sessions for MITRE ATT&CK TTPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run scripts/ttp-analyzer.py                  # Analyze last 7 days
  uv run scripts/ttp-analyzer.py --days 30        # Analyze last 30 days
  uv run scripts/ttp-analyzer.py --build-clusters # Build clusters after analysis
  uv run scripts/ttp-analyzer.py --stats-only     # Show stats only
        """,
    )

    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to analyze (default: 7)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Sessions to process per batch (default: 100)",
    )
    parser.add_argument(
        "--build-clusters",
        action="store_true",
        help="Build TTP clusters after analysis",
    )
    parser.add_argument(
        "--min-cluster-size",
        type=int,
        default=2,
        help="Minimum cluster size for building (default: 2)",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Only show statistics, don't run analysis",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Get database paths
    source_db, clustering_db, mitre_db = get_db_paths()

    # Check database exists
    if not check_database_exists(source_db):
        print(f"Error: Source database not found: {source_db}")
        sys.exit(1)

    # Get current stats
    session_stats = get_session_stats(source_db, args.days)
    fingerprint_stats = get_fingerprint_stats(clustering_db, args.days)

    if args.json:
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "days": args.days,
            "session_stats": session_stats,
            "fingerprint_stats": fingerprint_stats,
        }
    else:
        print(f"=== TTP Analyzer - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        print(f"\nDatabase: {source_db}")
        print(f"Analyzing last {args.days} days\n")

        print("Session Statistics:")
        print(f"  Total sessions: {session_stats.get('total_sessions', 0)}")
        print(f"  Sessions with commands: {session_stats.get('sessions_with_commands', 0)}")
        print(f"  Total commands: {session_stats.get('total_commands', 0)}")

        print("\nFingerprint Statistics:")
        print(f"  Total fingerprints: {fingerprint_stats.get('total_fingerprints', 0)}")
        print(f"  Recent fingerprints: {fingerprint_stats.get('recent_fingerprints', 0)}")

        if fingerprint_stats.get("top_techniques"):
            print("\n  Top Techniques:")
            for t in fingerprint_stats["top_techniques"][:5]:
                print(f"    {t['technique']}: {t['count']} sessions")

    if args.stats_only:
        if args.json:
            print(json.dumps(results, indent=2))
        return

    # Run batch analysis
    if not args.json:
        print("\n--- Running Batch TTP Analysis ---")

    analysis_result = run_batch_analysis(source_db, clustering_db, args.days, args.batch_size)

    if args.json:
        results["analysis"] = analysis_result
    else:
        if "error" in analysis_result:
            print(f"Error: {analysis_result['error']}")
        else:
            print("\nAnalysis Results:")
            print(f"  Total sessions: {analysis_result.get('total_sessions', 0)}")
            print(f"  Already analyzed: {analysis_result.get('already_analyzed', 0)}")
            print(f"  Newly analyzed: {analysis_result.get('analyzed', 0)}")
            print(f"  TTPs found: {analysis_result.get('ttps_found', 0)}")
            print(f"  Skipped (no TTPs): {analysis_result.get('skipped', 0)}")
            print(f"  Failed: {analysis_result.get('failed', 0)}")

            if analysis_result.get("errors"):
                print("\n  First errors:")
                for err in analysis_result["errors"][:3]:
                    print(f"    - {err['session']}: {err['error']}")

    # Build clusters if requested
    if args.build_clusters:
        if not args.json:
            print("\n--- Building TTP Clusters ---")

        cluster_result = build_clusters(source_db, clustering_db, args.days, args.min_cluster_size)

        if args.json:
            results["clusters"] = cluster_result
        else:
            if "error" in cluster_result:
                print(f"Error: {cluster_result['error']}")
            else:
                print(f"\nClusters built: {cluster_result.get('clusters_built', 0)}")

                if cluster_result.get("clusters"):
                    print("\nTop clusters:")
                    for cluster in cluster_result["clusters"][:5]:
                        print(
                            f"  - {cluster.get('technique_name', 'Unknown')} "
                            f"({cluster.get('dominant_technique', '?')}): "
                            f"{cluster.get('session_count', 0)} sessions, "
                            f"{cluster.get('size', 0)} unique IPs"
                        )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n=== Analysis Complete ===")


if __name__ == "__main__":
    main()
