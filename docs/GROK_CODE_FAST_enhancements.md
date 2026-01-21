# GROK CODE FAST Threat Intelligence Enhancements

## Overview
Enhanced attacker clustering and threat intelligence gathering from Cowrie honeypot data using exclusively free services.

## Current State
- Basic threat intel: GeoIP, VirusTotal
- Missing: IP clustering, advanced correlation, comprehensive enrichment
- Individual IP analysis only

## Free Threat Intelligence Sources

### Primary (High Priority)
1. **Spamhaus DROP/EDROP**
   - Botnet C&C detection
   - Public JSON feeds, no auth
   - Daily downloads recommended

2. **AbuseIPDB** 
   - IP reputation scoring (1,000 free/day)
   - Attack categories, confidence scores
   - 24-hour cache strategy

3. **AlienVault OTX**
   - Threat pulse sharing
   - Free API access
   - Correlation with other intel

### Secondary (Medium Priority)
4. **MISP/IPSum Levels 5-8**
   - High-confidence malicious IPs
   - Direct GitHub raw feeds

5. **DShield ISC**
   - Attack data sharing
   - Public XML feeds

## Clustering Implementation

### Algorithms
- **Behavioral**: Command sequence similarity, temporal windows (5-15min), credential reuse
- **Infrastructure**: ASN grouping, /24 subnet clustering, geographic proximity

### Database Extensions
```sql
CREATE TABLE ip_clusters (
    cluster_id TEXT PRIMARY KEY,
    cluster_type TEXT,
    confidence_score REAL,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    description TEXT
);

CREATE TABLE cluster_members (
    cluster_id TEXT,
    ip_address TEXT,
    joined_at TIMESTAMP,
    confidence REAL,
    FOREIGN KEY (cluster_id) REFERENCES ip_clusters(cluster_id)
);

CREATE TABLE threat_feed_cache (
    ip_address TEXT,
    feed_name TEXT,
    data JSON,
    cached_at TIMESTAMP,
    ttl_hours INTEGER
);
```

### API Enhancements
- `GET /api/v1/threat/clusters` - List clusters
- `GET /api/v1/threat/clusters/{id}` - Cluster details
- `GET /api/v1/threat/ip/{ip}/clusters` - IP clusters
- `POST /api/v1/threat/analyze-cluster` - Manual analysis

### Processing Pipeline
1. Real-time enrichment during sessions
2. Daily batch clustering
3. Cross-source correlation

## Implementation Phases

### Phase 1: Core Feeds
1. Spamhaus + AbuseIPDB integration
2. Feed caching system
3. Basic IP enrichment

### Phase 2: Clustering Engine
1. Clustering algorithms
2. Database schema updates
3. Cluster API endpoints
4. Batch processing scripts

### Phase 3: Advanced Features
1. Multi-source correlation
2. Temporal analysis
3. Dashboard visualization

## Success Metrics
- Cluster detection rate
- False positive reduction
- API efficiency
- Intelligence quality