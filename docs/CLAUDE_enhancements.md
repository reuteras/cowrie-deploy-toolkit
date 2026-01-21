# Threat Intelligence Enhancements for Attacker Cluster Analysis

This document outlines techniques for identifying and enriching coordinated attacker clusters observed in Cowrie honeypot data.

## Problem Statement

Multiple IP addresses frequently execute identical or near-identical command sequences, indicating:
- Botnet activity
- Automated scanning tools
- Coordinated attack campaigns
- Shared attack scripts/playbooks

Identifying these clusters and enriching them with threat intelligence provides attribution and context.

## Cluster Identification Techniques

### 1. Command Sequence Fingerprinting

Create normalized fingerprints from command sequences to group related sessions:

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
        cmd = re.sub(r':\d{2,5}\b', ':<PORT>', cmd)  # Ports
        cmd = re.sub(r'https?://[^\s]+', '<URL>', cmd)
        normalized.append(cmd)
    return hashlib.sha256('\n'.join(normalized).encode()).hexdigest()[:16]

def cluster_sessions(sessions: list) -> dict[str, set[str]]:
    """Group IPs by command fingerprint."""
    clusters = defaultdict(set)
    for session in sessions:
        fp = fingerprint_session(session.commands)
        clusters[fp].add(session.src_ip)
    return {fp: ips for fp, ips in clusters.items() if len(ips) > 1}
```

**What makes a strong fingerprint:**
- Command sequence order
- Command structure (arguments, flags)
- Download URLs (normalized)
- Target paths

### 2. HASSH Fingerprinting

HASSH fingerprints the SSH client implementation based on key exchange algorithms. It survives IP rotation and identifies the actual SSH client software.

Cowrie already logs HASSH in JSON output:
```json
{
  "eventid": "cowrie.client.kex",
  "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
  "hasshAlgorithms": "curve25519-sha256,..."
}
```

**Cluster on HASSH:**
```python
def cluster_by_hassh(sessions: list) -> dict[str, set[str]]:
    """Group IPs by SSH client fingerprint."""
    clusters = defaultdict(set)
    for session in sessions:
        if session.hassh:
            clusters[session.hassh].add(session.src_ip)
    return {h: ips for h, ips in clusters.items() if len(ips) > 1}
```

HASSH database for lookup: https://github.com/salesforce/hassh

### 3. Payload Hash Correlation

IPs downloading the same malware are likely part of the same campaign:

```python
def cluster_by_payload(downloads: list) -> dict[str, set[str]]:
    """Group IPs by downloaded file hash."""
    clusters = defaultdict(set)
    for dl in downloads:
        clusters[dl.sha256].add(dl.src_ip)
    return {h: ips for h, ips in clusters.items() if len(ips) > 1}
```

### 4. Timing Pattern Analysis

Coordinated attacks often show temporal patterns:

```python
from datetime import datetime, timedelta
from collections import Counter

def analyze_timing_patterns(sessions: list) -> dict:
    """Identify timing-based clusters."""
    # Hour-of-day distribution (UTC)
    hours = Counter(s.timestamp.hour for s in sessions)

    # Burst detection (multiple IPs in short window)
    sessions_sorted = sorted(sessions, key=lambda s: s.timestamp)
    bursts = []
    window = timedelta(minutes=5)

    i = 0
    while i < len(sessions_sorted):
        burst_ips = {sessions_sorted[i].src_ip}
        j = i + 1
        while j < len(sessions_sorted):
            if sessions_sorted[j].timestamp - sessions_sorted[i].timestamp <= window:
                burst_ips.add(sessions_sorted[j].src_ip)
                j += 1
            else:
                break
        if len(burst_ips) > 3:  # Threshold for "burst"
            bursts.append({
                'start': sessions_sorted[i].timestamp,
                'ips': burst_ips,
                'count': j - i
            })
        i = j if j > i + 1 else i + 1

    return {'hour_distribution': hours, 'bursts': bursts}
```

### 5. C2 Extraction from Payloads

Extract callback IPs/domains from downloaded scripts:

```python
import re

def extract_c2_indicators(payload_content: str) -> set[str]:
    """Extract potential C2 indicators from malware."""
    indicators = set()

    # IP addresses
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload_content)
    indicators.update(ips)

    # URLs
    urls = re.findall(r'https?://[^\s\'"<>]+', payload_content)
    indicators.update(urls)

    # Domains (simple pattern)
    domains = re.findall(r'\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b', payload_content, re.I)
    indicators.update(domains)

    return indicators
```

IPs/domains appearing in multiple payloads indicate shared infrastructure.

---

## Free Enrichment Sources

All sources below have free tiers suitable for honeypot research.

### 1. ThreatFox (abuse.ch)

**URL:** https://threatfox.abuse.ch/api/

**Value:** IOC database with malware family attribution, C2 indicators

**Free tier:** Unlimited API access

**Integration:**
```python
import requests

def query_threatfox(ioc: str, ioc_type: str = "ip:port") -> dict:
    """Query ThreatFox for IOC information."""
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "search_ioc", "search_term": ioc}
    )
    return response.json()
```

**Returns:** Malware family, threat type, first/last seen, confidence level

### 2. URLhaus (abuse.ch)

**URL:** https://urlhaus.abuse.ch/api/

**Value:** Malware distribution URLs, payload hashes

**Free tier:** Unlimited

**Integration:**
```python
def query_urlhaus_host(host: str) -> dict:
    """Query URLhaus for host reputation."""
    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data={"host": host}
    )
    return response.json()
```

### 3. Feodo Tracker (abuse.ch)

**URL:** https://feodotracker.abuse.ch/

**Value:** Botnet C2 server tracking (Emotet, Dridex, TrickBot, QakBot)

**Free tier:** Unlimited

**Integration:**
```python
def query_feodo(ip: str) -> dict:
    """Check if IP is known botnet C2."""
    response = requests.get(
        f"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    )
    blocklist = response.json()
    return {"is_c2": ip in [entry["ip_address"] for entry in blocklist]}
```

### 4. MalwareBazaar (abuse.ch)

**URL:** https://bazaar.abuse.ch/api/

**Value:** Malware sample database, YARA matches, tags

**Free tier:** Unlimited

**Integration:**
```python
def query_malwarebazaar(sha256: str) -> dict:
    """Query MalwareBazaar for sample info."""
    response = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": sha256}
    )
    return response.json()
```

**Returns:** Malware family, tags, YARA matches, first seen, delivery method

### 5. IPinfo.io

**URL:** https://ipinfo.io/

**Value:** ASN, hosting detection, VPN/proxy/Tor identification

**Free tier:** 50,000 requests/month

**Integration:**
```python
def query_ipinfo(ip: str, token: str = None) -> dict:
    """Get IP metadata from IPinfo."""
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    response = requests.get(url)
    return response.json()
```

**Key fields:** `hosting` (boolean), `privacy.vpn`, `privacy.proxy`, `privacy.tor`

### 6. BGPView

**URL:** https://bgpview.io/

**Value:** ASN relationships, IP prefix announcements, peer networks

**Free tier:** Unlimited (rate limited)

**Integration:**
```python
def query_bgpview_ip(ip: str) -> dict:
    """Get BGP information for IP."""
    response = requests.get(f"https://api.bgpview.io/ip/{ip}")
    return response.json()

def query_bgpview_asn(asn: int) -> dict:
    """Get ASN details and peers."""
    response = requests.get(f"https://api.bgpview.io/asn/{asn}")
    return response.json()
```

**Use case:** Identify if multiple attacking IPs share ASN or upstream provider

### 7. Shodan (InternetDB)

**URL:** https://internetdb.shodan.io/

**Value:** Open ports, vulnerabilities, hostnames - NO API KEY REQUIRED

**Free tier:** Unlimited (InternetDB endpoint)

**Integration:**
```python
def query_shodan_internetdb(ip: str) -> dict:
    """Query Shodan InternetDB (free, no API key)."""
    response = requests.get(f"https://internetdb.shodan.io/{ip}")
    if response.status_code == 200:
        return response.json()
    return {}
```

**Returns:** `ports`, `hostnames`, `cpes`, `vulns`, `tags`

### 8. CIRCL Passive DNS

**URL:** https://www.circl.lu/services/passive-dns/

**Value:** Historical DNS resolutions

**Free tier:** Free for security researchers (registration required)

**Use case:** Track domain history for C2 infrastructure

### 9. AlienVault OTX

**URL:** https://otx.alienvault.com/api

**Value:** Pulses (threat reports), IOC correlation, community intelligence

**Free tier:** Unlimited with registration

**Integration:**
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

### 10. Pulsedive

**URL:** https://pulsedive.com/api/

**Value:** Threat intelligence aggregation, risk scoring

**Free tier:** 1,000 requests/day

**Integration:**
```python
def query_pulsedive(indicator: str, api_key: str) -> dict:
    """Query Pulsedive for indicator info."""
    response = requests.get(
        "https://pulsedive.com/api/info.php",
        params={"indicator": indicator, "key": api_key}
    )
    return response.json()
```

---

## Enrichment Priority Matrix

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

---

## Graph-Based Cluster Analysis

Build a relationship graph for deeper analysis:

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

**Visualization:** Export to Gephi, Maltego, or use `pyvis` for interactive HTML graphs.

---

## Implementation Recommendations

### Phase 1: Core Clustering (Immediate)

1. Add command fingerprinting to daily report
2. Add HASSH extraction and clustering
3. Store clusters in SQLite table:

```sql
CREATE TABLE attack_clusters (
    cluster_id TEXT PRIMARY KEY,
    fingerprint_type TEXT,  -- 'command', 'hassh', 'payload'
    fingerprint_value TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    ip_count INTEGER
);

CREATE TABLE cluster_members (
    cluster_id TEXT,
    src_ip TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    session_count INTEGER,
    PRIMARY KEY (cluster_id, src_ip)
);
```

### Phase 2: Enrichment Integration (Short-term)

1. Add Shodan InternetDB queries (no API key needed)
2. Add ThreatFox/MalwareBazaar for payload attribution
3. Add IPinfo for hosting/VPN detection
4. Cache enrichment results (24h TTL)

### Phase 3: Analysis Dashboard (Medium-term)

1. Add cluster view to web dashboard
2. Show cluster timeline visualization
3. Display enrichment data per cluster
4. Add cluster alerting (new cluster with >N IPs)

---

## Data Sharing

Consider contributing findings to:

- **MISP** - Push clusters as events with STIX format
- **AlienVault OTX** - Create pulses from cluster analysis
- **abuse.ch** - Submit new malware samples to MalwareBazaar

---

*Document created: 2026-01-20*
*Based on operational honeypot observations*
