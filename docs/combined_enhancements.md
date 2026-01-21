# Master Threat Intelligence & Attacker Clustering Enhancements

This document combines all useful recommendations from the individual enhancement files (ChatGPT, Claude, Grok, and Mistral) for improving Cowrie honeypot threat intelligence and attacker clustering capabilities.

## Overview

The enhancements focus on identifying coordinated attacker clusters through multiple techniques and enriching them with free threat intelligence sources. Key goals include:
- Automated clustering of related attack sessions
- Integration of free threat intelligence feeds
- Enhanced dashboard views for cluster analysis
- Data sharing with threat intelligence communities

## Clustering Techniques

### Command Sequence Fingerprinting
- Normalize commands from the `input` table: lowercase, strip args/paths, keep verb + key flags
- Build n-gram or MinHash signatures per session, then cluster by similarity + time window
- Create normalized fingerprints from command sequences, removing variable parts (IPs, hashes, paths, ports, URLs)
- Use n-grams and SHA256 hashing for consistent fingerprinting

### HASSH Fingerprint Clustering
- Use HASSH fingerprints (SSH client implementation based on key exchange algorithms)
- Cluster sessions by identical HASSH values - survives IP rotation and identifies actual SSH client software
- Parse HASSH from Cowrie JSON logs (eventid: "cowrie.client.kex")

### Malware Payload Clustering
- Group IPs downloading identical malware by SHA256 hash
- Link sessions to downloads and virustotal_scans for correlation
- Identify shared attack campaigns through common payloads

### Temporal Proximity Clustering
- Cluster sessions occurring within close time windows (5-15 minutes)
- Detect coordinated attacks and activity bursts from multiple IPs
- Analyze timing patterns (hour-of-day distribution, burst detection)

### Graph-Based Cluster Analysis
- Build relationship graphs connecting IPs based on shared attributes
- Use NetworkX to find connected components and cluster relationships
- Support complex multi-attribute clustering

### Additional Techniques
- SSH fingerprint correlation for high-confidence actor identification
- Pivoting and lateral-movement signals (SSH tunneling, direct-tcpip events)
- Multi-sensor correlation (merge clusters by fingerprints, hashes, ASN/geo/time patterns)
- Behavioral clustering (command similarity, credential reuse)
- Infrastructure clustering (ASN grouping, /24 subnet analysis, geographic proximity)

## Threat Intelligence Sources

### Primary Sources (High Priority)
1. **ThreatFox (abuse.ch)**
   - Coverage: Malware IPs, domains, URLs, hashes
   - Rate Limit: Unlimited
   - Value: Malware family attribution, threat types, confidence levels

2. **AlienVault OTX (Open Threat Exchange)**
   - Coverage: Global threat data, pulses, IOCs
   - Rate Limit: Free API key required, generous limits
   - Value: Pulse-based threat sharing, IOC correlation, community intelligence

3. **AbuseIPDB**
   - Coverage: IP reputation scoring
   - Rate Limit: Free tier (1000 requests/day)
   - Value: Abuse confidence scores, report history, ISP information

4. **MalwareBazaar (abuse.ch)**
   - Coverage: Malware sample database, YARA matches, tags
   - Rate Limit: Unlimited
   - Value: Sample analysis, YARA rule matches, delivery methods

### Secondary Sources (Medium Priority)
5. **CIRCL Passive DNS**
   - Coverage: Historical DNS records
   - Rate Limit: Free for security researchers
   - Value: Domain-IP relationships, infrastructure mapping

6. **IPinfo**
   - Coverage: ASN, hosting detection, VPN/proxy/Tor identification
   - Rate Limit: 50,000 requests/month
   - Value: Hosting/VPN detection, privacy service identification

7. **Shodan InternetDB**
   - Coverage: Open ports, vulnerabilities, hostnames
   - Rate Limit: Unlimited (no API key required)
   - Value: Infrastructure profiling, service enumeration

8. **BGPView**
   - Coverage: ASN relationships, IP prefix announcements
   - Rate Limit: Rate limited
   - Value: Network relationships, upstream provider identification

9. **URLhaus (abuse.ch)**
   - Coverage: Malware distribution URLs, payload hashes
   - Rate Limit: Unlimited
   - Value: Malware hosting URL tracking

10. **Feodo Tracker (abuse.ch)**
    - Coverage: Botnet C2 server tracking (Emotet, Dridex, TrickBot, QakBot)
    - Rate Limit: Unlimited
    - Value: Known botnet infrastructure identification

11. **Pulsedive**
    - Coverage: Threat intelligence aggregation, risk scoring
    - Rate Limit: 1,000 requests/day
    - Value: Consolidated threat scores, risk assessment

12. **Spamhaus DROP/EDROP**
    - Coverage: Botnet C&C detection
    - Rate Limit: Public JSON feeds, daily downloads
    - Value: Known malicious network blocks

13. **MISP/IPSum Levels 5-8**
    - Coverage: High-confidence malicious IPs
    - Rate Limit: Direct GitHub raw feeds
    - Value: Community-curated malicious IP lists

14. **DShield/SANS Internet Storm Center**
    - Coverage: Global attack data, IP reputation
    - Rate Limit: Free access
    - Value: Attack trends, global threat landscape

15. **URLScan.io**
    - Coverage: URL analysis, screenshots, network requests
    - Rate Limit: Free tier available
    - Value: Malicious URL detection, infrastructure analysis

## Database Schema Additions

### Core Cluster Tables
```sql
CREATE TABLE attack_clusters (
    cluster_id TEXT PRIMARY KEY,
    cluster_type TEXT NOT NULL,  -- 'command', 'hassh', 'payload', 'graph'
    fingerprint TEXT,           -- Original fingerprint/hash
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    size INTEGER NOT NULL,      -- Number of unique IPs
    score INTEGER DEFAULT 0,    -- Confidence score
    metadata TEXT               -- JSON with additional info
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

### Enrichment Tables
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
    circl_pdns_data TEXT,       -- JSON
    last_updated DATETIME
);
```

### Caching and Relationships
```sql
CREATE TABLE threat_feed_cache (
    ip_address TEXT,
    feed_name TEXT,
    data JSON,
    cached_at TIMESTAMP,
    ttl_hours INTEGER
);

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

## API Enhancements

### Cluster Management
- `GET /api/v1/clusters` - List all clusters with summary information (parameters: min_size, min_score, cluster_type, time_range)
- `GET /api/v1/clusters/{cluster_id}` - Get detailed cluster information (includes member IPs, enrichment data, timeline)
- `GET /api/v1/clusters/{cluster_id}/members` - List all IPs in a cluster with per-IP threat intelligence
- `GET /api/v1/ip/{ip}/clusters` - Get all clusters containing a specific IP
- `POST /api/v1/clusters/analyze` - Trigger manual cluster analysis (parameters: time_range, cluster_types)

### Threat Intelligence
- `GET /api/v1/threat/clusters` - List threat clusters
- `GET /api/v1/threat/ip/{ip}/clusters` - Get clusters for specific IP
- `POST /api/v1/threat/analyze-cluster` - Manual cluster analysis
- `GET /api/v1/threat/sources` - List available threat intelligence sources with status and last update times

## Implementation Phases

### Phase 1: Core Clustering (Immediate)
1. Enhance command sequence analysis with normalization and n-gram fingerprinting
2. Add HASSH extraction from Cowrie logs and clustering by fingerprint
3. Store cluster data in new SQLite tables
4. Integrate basic free feeds (Shodan InternetDB, ThreatFox, MalwareBazaar)

### Phase 2: Enrichment Integration (Short-term)
1. Add comprehensive threat intelligence queries (AlienVault OTX, AbuseIPDB, CIRCL PDNS, IPinfo)
2. Implement enrichment caching (24-48 hour TTL) with rate limiting
3. Enrich cluster data with aggregated threat scores and family labels
4. Add bulk query capabilities where supported

### Phase 3: Analysis Dashboard (Medium-term)
1. Add cluster-centric views to web dashboard with size, threat score, and timeline
2. Implement cluster detail pages with member IPs and enrichment data
3. Add pivot graph visualization (IP, ASN, fingerprint, hash nodes with relationship edges)
4. Create IOC explorer for searching by hash, IP, ASN, or fingerprint
5. Add cluster alerting for new clusters, high scores, or rapid growth

### Phase 4: Data Sharing & Automation (Long-term)
1. Implement automated daily/weekly enrichment jobs
2. Add data sharing integrations (MISP STIX exports, AlienVault OTX pulses, DShield submissions)
3. Create automated reporting for cluster summaries and threat digests
4. Add monitoring dashboards with cluster activity heatmaps and geographic distributions

## Dashboard Views

### Cluster Analysis
- **Cluster-first dashboard**: Primary table showing cluster_id, size, top commands, top ASN/org, top hashes, first/last seen
- **Pivot graph**: Node types (IP, ASN, SSH fingerprint, hash, VT family, domain) with edges for relationships
- **Timeline view**: Cluster activity by hour/day, highlighting spikes and campaign windows
- **IOC explorer**: Search interface for hashes, IPs, ASNs, SSH fingerprints with linked sessions/clusters

### Geographic and Network Analysis
- **Map + ASN rollups**: GeoIP map combined with ASN statistics for provider concentration analysis
- **Geographic heatmap**: Cluster distribution by country/region
- **ASN/organization breakdown**: Top hosting providers and network relationships

### Activity Monitoring
- **Cluster activity heatmap**: Temporal patterns and evolution tracking
- **Threat family breakdown**: Distribution of identified malware families across clusters
- **Cluster evolution charts**: Growth patterns and lifespan analysis

## Data Sharing & Community Integration

### Primary Platforms
- **MISP**: Push clusters as events with STIX/TAXII format for structured threat sharing
- **AlienVault OTX**: Create pulses from cluster analysis with IOC correlations
- **abuse.ch platforms**: Submit new malware samples to MalwareBazaar, contribute to ThreatFox

### Secondary Platforms
- **DShield/SANS ISC**: Share cluster data and attack patterns with global threat landscape
- **Community feeds**: Contribute to MISP instances and other threat intelligence sharing platforms

## Code Examples

### Command Fingerprinting
```python
import hashlib
import re
from collections import defaultdict

def fingerprint_session(commands: list[str]) -> str:
    """Create a normalized fingerprint from command sequence."""
    normalized = []
    for cmd in commands:
        # Normalize variable parts
        cmd = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', cmd)
        cmd = re.sub(r'\b[a-f0-9]{32,}\b', '<HASH>', cmd)
        cmd = re.sub(r'/tmp/[^\s]+', '/tmp/<TMP>', cmd)
        cmd = re.sub(r':\d{2,5}\b', ':<PORT>', cmd)
        cmd = re.sub(r'https?://[^\s]+', '<URL>', cmd)
        normalized.append(cmd)
    return hashlib.sha256('\n'.join(normalized).encode()).hexdigest()[:16]
```

### HASSH Clustering
```python
def cluster_by_hassh(sessions: list) -> dict[str, set[str]]:
    """Group IPs by SSH client fingerprint."""
    clusters = defaultdict(set)
    for session in sessions:
        if session.hassh:
            clusters[session.hassh].add(session.src_ip)
    return {h: ips for h, ips in clusters.items() if len(ips) > 1}
```

### Threat Intelligence Queries
```python
def query_threatfox(ioc: str, ioc_type: str = "ip:port") -> dict:
    """Query ThreatFox for IOC information."""
    params = {"query": ioc_type, "search": ioc}
    response = requests.get("https://threatfox-api.abuse.ch/api/v1/", params=params)
    return response.json()

def query_otx(ip: str, api_key: str) -> dict:
    """Query AlienVault OTX for IP reputation."""
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers
    )
    return response.json()

def query_shodan_internetdb(ip: str) -> dict:
    """Query Shodan InternetDB (free, no API key)."""
    response = requests.get(f"https://internetdb.shodan.io/{ip}")
    if response.status_code == 200:
        return response.json()
    return {}
```

### Graph-Based Clustering
```python
import networkx as nx

def build_cluster_graph(sessions: list, downloads: list) -> nx.Graph:
    """Build graph of attack relationships."""
    G = nx.Graph()

    for session in sessions:
        ip = session.src_ip
        G.add_node(ip, type='ip')

        # Link to command fingerprint
        fp = fingerprint_session(session.commands)
        G.add_node(f"cmd:{fp}", type='fingerprint')
        G.add_edge(ip, f"cmd:{fp}")

        # Link to HASSH
        if session.hassh:
            G.add_node(f"hassh:{session.hassh}", type='hassh')
            G.add_edge(ip, f"hassh:{session.hassh}")

    for dl in downloads:
        # Link IP to payload
        G.add_node(f"sha256:{dl.sha256}", type='payload')
        G.add_edge(dl.src_ip, f"sha256:{dl.sha256}")

    return G

def find_clusters(G: nx.Graph) -> list[set]:
    """Find connected components (clusters)."""
    ip_clusters = []
    for component in nx.connected_components(G):
        ips = {n for n in component if G.nodes[n].get('type') == 'ip'}
        if len(ips) > 1:
            ip_clusters.append(ips)
    return ip_clusters
```

## Priority Matrix

| Source | Query Type | Rate Limit | Best For |
|--------|-----------|------------|----------|
| **Shodan InternetDB** | IP | Unlimited | Infrastructure profiling |
| **ThreatFox** | IP, hash, domain | Unlimited | Malware attribution |
| **MalwareBazaar** | Hash | Unlimited | Sample analysis |
| **URLhaus** | URL, domain, IP | Unlimited | Malware distribution |
| **IPinfo** | IP | 50k/month | Hosting/VPN detection |
| **BGPView** | IP, ASN | Rate limited | Network relationships |
| **AlienVault OTX** | IP, domain, hash | Unlimited | Community intel |
| **AbuseIPDB** | IP | 1k/day | Abuse reports |

## Success Metrics
- Cluster detection rate (>80% of coordinated attacks identified)
- False positive reduction (<10% incorrectly clustered sessions)
- API efficiency (response times <2s, cache hit rate >90%)
- Intelligence quality (threat attribution accuracy, actionable insights)

## Implementation Considerations
- **Performance**: Use database indexing, pagination, background jobs for enrichment
- **Privacy**: Anonymize sensitive data in shared reports, implement retention policies
- **Scalability**: Design for multi-honeypot deployments, support incremental updates
- **Monitoring**: Add cluster alerts, threat intelligence updates, dashboard widgets