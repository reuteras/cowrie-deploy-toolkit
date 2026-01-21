# ChatGPT Enhancements: Threat Intel + Clustering Recommendations

This document captures additional recommendations for improving threat intel enrichment,
attacker clustering, and how to view the resulting data in this Cowrie deployment toolkit.

## High-Impact Additions

1. **Command-sequence clustering**
   - Normalize commands from the `input` table: lowercase, strip args/paths, keep verb + key flags.
   - Build n-gram or MinHash signatures per session, then cluster by similarity + time window.
   - Store `cluster_id` + feature summary so the dashboard can pivot on clusters.

2. **SSH fingerprint correlation**
   - Use `cowrie.client.fingerprint` from `keyfingerprints` as a high-confidence actor ID.
   - Merge sessions across IP changes; this reduces false splits in cluster graphs.

3. **Download-centric clustering**
   - Link sessions to `downloads` + `virustotal_scans` (hash, threat label).
   - Group by malware family/hash to catch distributed bot clusters even with generic commands.

4. **Infrastructure enrichment**
   - Add passive DNS, WHOIS, and reputation signals for all IPs in a cluster.
   - Store results as events in the `events` table (ex: `cowrie.threatintel.abuseipdb`).

5. **Pivoting and lateral-movement signals**
   - Use `cowrie.direct-tcpip.*` events to flag SSH tunneling and pivot behavior.
   - Track destination IP/port pairs per cluster to identify shared targets.

6. **Multi-sensor correlation**
   - Run clustering centrally and use your multi-source mode to merge clusters by:
     - SSH fingerprints
     - download hashes + VT families
     - ASN/geo/time patterns

## Where This Fits in the Repo

- Enrichment hooks already exist:
  - `web/app.py` `get_threat_intel_for_ip()` (single-source)
  - `web/multisource.py` `get_threat_intel_for_ip()` (multi-source)
- SQLite data you can leverage:
  - `sessions`, `input`, `downloads`, `virustotal_scans`, `keyfingerprints`, `ipforwards`
- Reporting:
  - `scripts/daily-report.py` already enriches GeoIP/ASN, VT, YARA.

## Best Ways to View the Data

1. **Cluster-first dashboard view**
   - Primary table: `cluster_id`, size, top commands, top ASN/org, top hashes, first/last seen.
   - Secondary tabs: session list, IPs, downloads, YARA/VT families, pivot targets.

2. **Pivot graph**
   - Node types: IP, ASN, SSH fingerprint, hash, VT family, domain.
   - Edges: observed-in-session, downloaded-by, resolved-to, shared-fingerprint.
   - Use it for quick anomaly detection and identifying shared infra.

3. **Timeline view**
   - Cluster activity by hour/day, highlight spikes and campaign windows.
   - Show new clusters vs recurring clusters (helps with triage).

4. **IOC explorer**
   - Search by hash, IP, ASN, or SSH fingerprint.
   - One page that lists linked sessions, clusters, downloads, and VT labels.

5. **Map + ASN rollups**
   - Combine GeoIP map with ASN stats to show concentration by hosting provider.
   - Useful for rapid “is this a new campaign?” assessment.

## Suggested Minimal Data Model Additions

- `clusters` table:
  - `cluster_id`, `created_at`, `score`, `primary_fingerprint`, `top_commands`, `top_asns`
- `cluster_sessions` table:
  - `cluster_id`, `session_id`
- `cluster_features` table:
  - `cluster_id`, `feature_type`, `feature_value`, `weight`

## Suggested Workflow (Practical)

1. Add a clustering job (new script) that:
   - Reads `sessions` + `input` + `downloads`
   - Generates command signatures + feature vectors
   - Produces `cluster_id` tables
2. Expose clusters via API and show in the dashboard.
3. Enrich `get_threat_intel_for_ip()` with AbuseIPDB + Shodan + passive DNS.
4. Store enrichment as events so it can be queried in multi-source mode.
