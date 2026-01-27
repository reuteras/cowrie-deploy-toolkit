# Advanced Threat Intelligence & Attacker Clustering Strategy

This document outlines a comprehensive approach to identifying and enriching coordinated attacker clusters observed in Cowrie honeypot data using exclusively free threat intelligence sources.

## Current Capabilities Analysis

The current system has:
- Basic GeoIP enrichment (country, city, ASN)
- VirusTotal integration for file analysis
- Session tracking with command sequences
- Download metadata and malware analysis
- API endpoints for threat intelligence

## Recommended Free Threat Intelligence Sources

### 1. **ThreatFox (abuse.ch)**
**URL:** <https://threatfox.abuse.ch/api/>
**Coverage:** Malware IPs, domains, URLs, hashes
**Rate Limit:** No API key required, reasonable rate limits
**Value:** Malware family attribution, threat types, confidence levels

```python
def query_threatfox(ioc: str, ioc_type: str = "ip:port") -> dict:
    """Query ThreatFox for IOC information."""
    params = {"query": ioc_type, "search": ioc}
    response = requests.get(
        "https://threatfox-api.abuse.ch/api/v1/",
        params=params
    )
    return response.json()
```

### 2. **AlienVault OTX (Open Threat Exchange)**
**URL:** <https://otx.alienvault.com/api>
**Coverage:** Global threat data, pulses, IOCs
**Rate Limit:** Free API key required, generous limits
**Value:** Pulse-based threat sharing, IOC correlation, community intelligence

```python
def query_otx(ip: str, api_key: str) -> dict:
    """Query AlienVault OTX for IP reputation."""
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers
    )
    return response.json()
```

### 3. **AbuseIPDB**
**URL:** <https://www.abuseipdb.com/api>
**Coverage:** IP reputation scoring
**Rate Limit:** Free tier available (1000 requests/day)
**Value:** Abuse confidence scores, report history, ISP information

### 4. **CIRCL Passive DNS**
**URL:** <https://www.circl.lu/services/passive-dns/>
**Coverage:** Historical DNS records
**Rate Limit:** Free access
**Value:** Domain-IP relationships, infrastructure mapping

### 5. **URLScan.io**
**URL:** <https://urlscan.io/api>
**Coverage:** URL analysis, screenshots, network requests
**Rate Limit:** Free tier available
**Value:** Malicious URL detection, infrastructure analysis

### 6. **MISP (Malware Information Sharing Platform)**
**URL:** <https://www.misp-project.org/>
**Coverage:** Threat intelligence sharing
**Rate Limit:** Community-driven, various instances
**Value:** STIX/TAXII feeds, structured threat data

### 7. **DShield/SANS Internet Storm Center**
**URL:** <https://isc.sans.edu/api/>
**Coverage:** Global attack data
**Rate Limit:** Free access
**Value:** Attack trends, IP reputation, global threat landscape

## Attacker Clustering Strategy

### 1. **Command Sequence Fingerprinting**

```python
def create_command_fingerprint(commands: list) -> str:
    """Create a fingerprint from command sequences."""
    # Normalize commands (remove timestamps, normalize paths)
    normalized = [normalize_command(cmd) for cmd in commands]
    # Create n-grams and hash
    ngrams = create_ngrams(normalized, n=3)
    return hashlib.sha256(" ".join(ngrams).encode()).hexdigest()

def cluster_by_commands(sessions: list) -> dict:
    """Cluster sessions by similar command sequences."""
    clusters = defaultdict(list)
    for session in sessions:
        fp = create_command_fingerprint(session.commands)
        clusters[fp].append(session.src_ip)
    return {fp: ips for fp, ips in clusters.items() if len(ips) > 1}
```text

### 2. **HASSH Fingerprint Clustering**

```python
def cluster_by_hassh(sessions: list) -> dict:
    """Cluster by SSH client fingerprints."""
    clusters = defaultdict(list)
    for session in sessions:
        if session.hassh:
            clusters[session.hassh].append(session.src_ip)
    return {hassh: ips for hassh, ips in clusters.items() if len(ips) > 1}
```

### 3. **Malware Payload Clustering**

```python
def cluster_by_payload(downloads: list) -> dict:
    """Cluster by downloaded malware hashes."""
    clusters = defaultdict(list)
    for download in downloads:
        if download.sha256:
            clusters[download.sha256].append(download.src_ip)
    return {sha256: ips for sha256, ips in clusters.items() if len(ips) > 1}
```

### 4. **Temporal Proximity Clustering**

```python
def cluster_by_timing(sessions: list, window_minutes: int = 30) -> dict:
    """Cluster sessions that occur within close time windows."""
    # Group sessions by time windows
    time_clusters = {}
    for session in sorted(sessions, key=lambda s: s.timestamp):
        found_cluster = False
        for cluster_id, cluster in time_clusters.items():
            time_diff = abs((session.timestamp - cluster['last_time']).total_seconds() / 60)
            if time_diff <= window_minutes:
                cluster['sessions'].append(session)
                cluster['last_time'] = session.timestamp
                found_cluster = True
                break
        if not found_cluster:
            time_clusters[session.timestamp] = {
                'sessions': [session],
                'last_time': session.timestamp
            }
    
    # Convert to IP clusters
    ip_clusters = {}
    for cluster_id, cluster_data in time_clusters.items():
        ips = set(session.src_ip for session in cluster_data['sessions'])
        if len(ips) > 1:
            ip_clusters[cluster_id] = ips
    
    return ip_clusters
```

### 5. **Graph-Based Cluster Analysis**

```python
def build_cluster_graph(sessions: list, downloads: list) -> nx.Graph:
    """Build a graph connecting IPs based on shared attributes."""
    G = nx.Graph()
    
    # Add nodes (IP addresses)
    all_ips = set(session.src_ip for session in sessions)
    G.add_nodes_from(all_ips)
    
    # Add edges based on shared command fingerprints
    command_clusters = cluster_by_commands(sessions)
    for fp, ips in command_clusters.items():
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i+1:]:
                if G.has_edge(ip1, ip2):
                    G[ip1][ip2]['weight'] += 1
                    G[ip1][ip2]['reasons'].append(f"command_fp:{fp}")
                else:
                    G.add_edge(ip1, ip2, weight=1, reasons=[f"command_fp:{fp}"])
    
    # Add edges based on shared HASSH
    hassh_clusters = cluster_by_hassh(sessions)
    for hassh, ips in hassh_clusters.items():
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i+1:]:
                if G.has_edge(ip1, ip2):
                    G[ip1][ip2]['weight'] += 1
                    G[ip1][ip2]['reasons'].append(f"hassh:{hassh}")
                else:
                    G.add_edge(ip1, ip2, weight=1, reasons=[f"hassh:{hassh}"])
    
    # Add edges based on shared malware downloads
    payload_clusters = cluster_by_payload(downloads)
    for sha256, ips in payload_clusters.items():
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i+1:]:
                if G.has_edge(ip1, ip2):
                    G[ip1][ip2]['weight'] += 1
                    G[ip1][ip2]['reasons'].append(f"payload:{sha256}")
                else:
                    G.add_edge(ip1, ip2, weight=1, reasons=[f"payload:{sha256}"])
    
    return G

def find_clusters(G: nx.Graph) -> list[set]:
    """Find connected components (clusters)."""
    return list(nx.connected_components(G))
```

## Implementation Roadmap

### Phase 1: Core Clustering (Immediate)
1. **Enhance command sequence analysis**
   - Extract and normalize command sequences
   - Implement n-gram fingerprinting
   - Store cluster IDs in database

2. **Add HASSH extraction and clustering**
   - Parse SSH client fingerprints from Cowrie logs
   - Cluster by identical HASSH values

3. **Store clusters in SQLite table:**
```sql
CREATE TABLE attack_clusters (
    cluster_id TEXT PRIMARY KEY,
    cluster_type TEXT NOT NULL,  -- 'command', 'hassh', 'payload', 'graph'
    fingerprint TEXT,           -- Original fingerprint/hash
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    size INTEGER NOT NULL,       -- Number of unique IPs
    score INTEGER DEFAULT 0,     -- Confidence score
    metadata TEXT                -- JSON with additional info
);

CREATE TABLE cluster_members (
    cluster_id TEXT,
    src_ip TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    session_count INTEGER,
    PRIMARY KEY (cluster_id, src_ip),
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id)
);
```

### Phase 2: Threat Intelligence Enrichment
1. **Integrate free threat feeds:**
   - ThreatFox for malware attribution
   - AlienVault OTX for IP reputation
   - CIRCL Passive DNS for infrastructure mapping

2. **Enrich cluster data:**
   - Query threat intelligence for each IP in cluster
   - Aggregate threat scores and labels
   - Identify common threat families

3. **Add enrichment tables:**
```sql
CREATE TABLE cluster_enrichment (
    cluster_id TEXT PRIMARY KEY,
    threat_families TEXT,       -- JSON array
    top_asns TEXT,              -- JSON array
    countries TEXT,             -- JSON array
    threat_score INTEGER,       -- Aggregated score
    first_enriched DATETIME,
    last_enriched DATETIME,
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id)
);

CREATE TABLE ip_threat_intel (
    ip TEXT PRIMARY KEY,
    threatfox_data TEXT,        -- JSON
    otx_data TEXT,              -- JSON
    abuseipdb_data TEXT,        -- JSON
    last_updated DATETIME
);
```

### Phase 3: Dashboard Integration
1. **Add cluster view to web dashboard**
   - Cluster list with size, threat score, and timeline
   - Cluster detail page with member IPs and enrichment

2. **Show cluster timeline visualization**
   - Activity heatmap by cluster
   - Cluster emergence and evolution

3. **Display enrichment data per cluster**
   - Threat family breakdown
   - Geographic distribution
   - ASN/organization analysis

4. **Add cluster alerting**
   - New cluster with >N IPs
   - Cluster with high threat score
   - Rapidly growing clusters

### Phase 4: Data Sharing & Automation
1. **Automated enrichment jobs:**
   - Daily cluster analysis
   - Weekly threat intelligence updates
   - Monthly reporting

2. **Data sharing integration:**
   - **MISP** - Push clusters as events with STIX format
   - **AlienVault OTX** - Create pulses from cluster analysis
   - **DShield** - Share cluster data with SANS

3. **Automated reporting:**
   - Cluster summary reports
   - Threat intelligence digests
   - Emerging threat alerts

## Database Schema Extensions

```sql
-- Cluster tracking
CREATE TABLE attack_clusters (
    cluster_id TEXT PRIMARY KEY,
    cluster_type TEXT NOT NULL,
    fingerprint TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    size INTEGER NOT NULL,
    score INTEGER DEFAULT 0,
    metadata TEXT
);

CREATE TABLE cluster_members (
    cluster_id TEXT,
    src_ip TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    session_count INTEGER,
    PRIMARY KEY (cluster_id, src_ip),
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id)
);

-- Threat intelligence cache
CREATE TABLE ip_threat_intel (
    ip TEXT PRIMARY KEY,
    threatfox_data TEXT,
    otx_data TEXT,
    abuseipdb_data TEXT,
    circl_pdns_data TEXT,
    last_updated DATETIME
);

-- Cluster enrichment
CREATE TABLE cluster_enrichment (
    cluster_id TEXT PRIMARY KEY,
    threat_families TEXT,
    top_asns TEXT,
    countries TEXT,
    threat_score INTEGER,
    first_enriched DATETIME,
    last_enriched DATETIME,
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id)
);

-- Cluster relationships
CREATE TABLE cluster_relationships (
    cluster_id1 TEXT,
    cluster_id2 TEXT,
    relationship_type TEXT,  -- 'overlapping_ips', 'similar_commands', etc.
    strength REAL,
    details TEXT,
    PRIMARY KEY (cluster_id1, cluster_id2),
    FOREIGN KEY (cluster_id1) REFERENCES attack_clusters(cluster_id),
    FOREIGN KEY (cluster_id2) REFERENCES attack_clusters(cluster_id)
);
```

## API Endpoints

```text
GET /api/v1/clusters
- List all clusters with summary information
- Parameters: min_size, min_score, cluster_type, time_range

GET /api/v1/clusters/{cluster_id}
- Get detailed cluster information
- Includes member IPs, enrichment data, timeline

GET /api/v1/clusters/{cluster_id}/members
- List all IPs in a cluster
- Includes per-IP threat intelligence

GET /api/v1/ip/{ip}/clusters
- Get all clusters containing a specific IP
- Useful for IP investigation

POST /api/v1/clusters/analyze
- Trigger manual cluster analysis
- Parameters: time_range, cluster_types

GET /api/v1/threat/sources
- List available threat intelligence sources
- Show status and last update times
```

## Clustering Algorithm Recommendations

### 1. **Multi-Feature Clustering**
Combine multiple clustering methods with weighted scoring:
- Command sequence similarity (weight: 0.4)
- HASSH fingerprint match (weight: 0.3)
- Malware payload sharing (weight: 0.2)
- Temporal proximity (weight: 0.1)

### 2. **Dynamic Thresholding**
Adjust cluster formation thresholds based on:
- Time of day (more aggressive during peak attack hours)
- Attack volume (more conservative during high-volume periods)
- Threat intelligence scores (lower thresholds for high-risk IPs)

### 3. **Cluster Merging**
Merge clusters that share significant overlap:
- Jaccard similarity > 0.7
- Common threat families
- Shared infrastructure (ASN, /24 networks)

### 4. **Temporal Analysis**
Track cluster evolution over time:
- Cluster lifespan and activity patterns
- Command sequence evolution
- Infrastructure changes

## Threat Intelligence Enrichment Strategy

### 1. **Prioritized Enrichment**
Focus enrichment efforts on:
- Large clusters (>5 IPs)
- High-activity clusters
- Clusters with malware downloads
- Clusters with high threat scores

### 2. **Caching Strategy**
- Cache threat intelligence for 24-48 hours
- Implement rate limiting per source
- Use bulk queries where possible
- Fallback to cached data when rate limited

### 3. **Data Correlation**
Correlate threat intelligence across sources:
- Identify common threat actors
- Map infrastructure relationships
- Detect campaign patterns

### 4. **Automated Tagging**
Apply tags based on enrichment:
- `botnet:{family}` - Identified botnet families
- `campaign:{name}` - Known attack campaigns
- `threat:{type}` - Threat types (APT, ransomware, etc.)
- `infrastructure:{asn}` - Shared infrastructure

## Monitoring and Alerting

### 1. **Cluster Alerts**
- New cluster detected with >10 IPs
- Cluster with threat score > 80
- Rapid cluster growth (>5 new IPs in 1 hour)
- Cluster with known malware families

### 2. **Threat Intelligence Alerts**
- IP with high abuse confidence score
- Known malicious infrastructure detected
- New malware families observed
- Emerging threat campaigns

### 3. **Dashboard Widgets**
- Cluster activity timeline
- Top threat families
- Geographic heatmap
- ASN/organization breakdown

## Implementation Considerations

### Performance Optimization
- Use database indexing for cluster queries
- Implement pagination for large clusters
- Cache cluster computations
- Use background jobs for enrichment

### Privacy Considerations
- Anonymize sensitive data in shared reports
- Comply with data protection regulations
- Implement data retention policies

### Scalability
- Design for multi-honeypot deployments
- Support distributed cluster analysis
- Implement incremental updates

## Comparison with Other Approaches

This strategy improves upon existing recommendations by:

1. **Comprehensive Free Sources:** Uses a broader range of free threat intelligence feeds
2. **Multi-Modal Clustering:** Combines command, fingerprint, payload, and temporal analysis
3. **Graph-Based Analysis:** Identifies complex relationships between attackers
4. **Prioritized Enrichment:** Focuses resources on high-value clusters
5. **Automated Workflow:** End-to-end from detection to sharing
6. **Scalable Architecture:** Designed for growth and multi-honeypot deployments

The approach avoids reliance on paid services like GreyNoise while providing comparable or better results through intelligent combination of free sources and advanced clustering techniques.
