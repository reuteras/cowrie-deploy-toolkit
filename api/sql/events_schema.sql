-- Events table for fast event lookups
-- Stores parsed Cowrie JSON log events for quick querying

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    eventid TEXT NOT NULL,
    src_ip TEXT,
    data TEXT NOT NULL,  -- Full JSON event data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

-- Metadata table to track indexing progress
CREATE TABLE IF NOT EXISTS events_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Track last processed position in each log file
CREATE TABLE IF NOT EXISTS log_files (
    filepath TEXT PRIMARY KEY,
    last_position INTEGER DEFAULT 0,
    last_inode INTEGER,
    last_processed DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Download metadata for file type detection and caching
-- Stores pre-computed file metadata to avoid on-demand detection
CREATE TABLE IF NOT EXISTS download_meta (
    shasum TEXT PRIMARY KEY,
    file_size INTEGER,
    file_type TEXT,
    file_category TEXT,
    is_previewable BOOLEAN DEFAULT 0,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast metadata lookups
CREATE INDEX IF NOT EXISTS idx_download_meta_category ON download_meta(file_category);

-- VirusTotal scan results (replaces unreliable Cowrie VT plugin output)
-- Stores VT scan results from event-indexer's own scanning
CREATE TABLE IF NOT EXISTS virustotal_scans (
    shasum TEXT PRIMARY KEY,
    positives INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    scan_date INTEGER,  -- Unix timestamp from VT
    threat_label TEXT,
    threat_categories TEXT,  -- JSON array
    family_labels TEXT,  -- JSON array
    permalink TEXT,
    is_new BOOLEAN DEFAULT 0,  -- True if file was new to VT
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Pending VT scans for files that were new to VT and need retry
-- Persists across daemon restarts
CREATE TABLE IF NOT EXISTS virustotal_pending (
    shasum TEXT PRIMARY KEY,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    next_retry_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    session TEXT,  -- Original session for context
    src_ip TEXT    -- Original source IP for context
);

-- Index for efficient pending scan queries
CREATE INDEX IF NOT EXISTS idx_vt_pending_retry ON virustotal_pending(next_retry_at);

-- ============================================================================
-- Attack Clustering Tables
-- ============================================================================

-- Core cluster definitions
CREATE TABLE IF NOT EXISTS attack_clusters (
    cluster_id TEXT PRIMARY KEY,
    cluster_type TEXT NOT NULL,  -- 'command', 'hassh', 'payload', 'temporal', 'graph'
    fingerprint TEXT,           -- Original fingerprint/hash that defined this cluster
    name TEXT,                  -- Human-readable cluster name
    description TEXT,           -- Auto-generated description
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,      -- Number of unique IPs
    session_count INTEGER NOT NULL DEFAULT 0,  -- Total sessions
    score INTEGER DEFAULT 0,    -- Confidence/threat score (0-100)
    metadata TEXT,              -- JSON with additional cluster info
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_clusters_type ON attack_clusters(cluster_type);
CREATE INDEX IF NOT EXISTS idx_clusters_fingerprint ON attack_clusters(fingerprint);
CREATE INDEX IF NOT EXISTS idx_clusters_score ON attack_clusters(score DESC);
CREATE INDEX IF NOT EXISTS idx_clusters_size ON attack_clusters(size DESC);
CREATE INDEX IF NOT EXISTS idx_clusters_last_seen ON attack_clusters(last_seen DESC);

-- Cluster membership (IPs belonging to clusters)
CREATE TABLE IF NOT EXISTS cluster_members (
    cluster_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    session_count INTEGER DEFAULT 1,
    metadata TEXT,  -- JSON with per-IP info (commands, credentials used, etc.)
    PRIMARY KEY (cluster_id, src_ip),
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cluster_members_ip ON cluster_members(src_ip);
CREATE INDEX IF NOT EXISTS idx_cluster_members_cluster ON cluster_members(cluster_id);

-- Cluster threat enrichment from external sources
CREATE TABLE IF NOT EXISTS cluster_enrichment (
    cluster_id TEXT PRIMARY KEY,
    threat_families TEXT,       -- JSON array of malware families
    top_asns TEXT,              -- JSON array of {asn, org, count}
    countries TEXT,             -- JSON array of {country, code, count}
    threat_score INTEGER,       -- Aggregated threat score
    total_reports INTEGER DEFAULT 0,  -- Sum of abuse reports
    tags TEXT,                  -- JSON array of tags
    first_enriched DATETIME,
    last_enriched DATETIME,
    FOREIGN KEY (cluster_id) REFERENCES attack_clusters(cluster_id) ON DELETE CASCADE
);

-- IP-level threat intelligence cache
CREATE TABLE IF NOT EXISTS ip_threat_intel (
    ip TEXT PRIMARY KEY,
    shodan_data TEXT,           -- JSON from Shodan InternetDB
    threatfox_data TEXT,        -- JSON from ThreatFox
    abuseipdb_data TEXT,        -- JSON from AbuseIPDB
    otx_data TEXT,              -- JSON from AlienVault OTX
    malwarebazaar_data TEXT,    -- JSON from MalwareBazaar
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_intel_updated ON ip_threat_intel(last_updated);

-- Threat feed cache with TTL support
CREATE TABLE IF NOT EXISTS threat_feed_cache (
    cache_key TEXT PRIMARY KEY,  -- feed_name:query_type:query_value
    feed_name TEXT NOT NULL,
    query_type TEXT NOT NULL,    -- 'ip', 'hash', 'domain', 'url'
    query_value TEXT NOT NULL,
    data TEXT NOT NULL,          -- JSON response
    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_cache_expires ON threat_feed_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_threat_cache_feed ON threat_feed_cache(feed_name, query_type);

-- Cluster relationships for graph analysis
CREATE TABLE IF NOT EXISTS cluster_relationships (
    cluster_id1 TEXT NOT NULL,
    cluster_id2 TEXT NOT NULL,
    relationship_type TEXT NOT NULL,  -- 'overlapping_ips', 'similar_commands', 'shared_payload', 'temporal'
    strength REAL NOT NULL DEFAULT 0.0,  -- 0.0 to 1.0
    shared_count INTEGER DEFAULT 0,  -- Number of shared elements
    details TEXT,                -- JSON with relationship details
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cluster_id1, cluster_id2, relationship_type),
    FOREIGN KEY (cluster_id1) REFERENCES attack_clusters(cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id2) REFERENCES attack_clusters(cluster_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cluster_rel_type ON cluster_relationships(relationship_type);

-- Command fingerprints for session clustering
CREATE TABLE IF NOT EXISTS command_fingerprints (
    session TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    normalized_commands TEXT,   -- JSON array of normalized commands
    command_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cmd_fingerprint ON command_fingerprints(fingerprint);

-- HASSH fingerprints from SSH key exchange
CREATE TABLE IF NOT EXISTS hassh_fingerprints (
    session TEXT PRIMARY KEY,
    hassh TEXT NOT NULL,
    hassh_server TEXT,          -- Server HASSH if available
    kex_algorithms TEXT,        -- JSON array
    encryption_algorithms TEXT, -- JSON array
    mac_algorithms TEXT,        -- JSON array
    src_ip TEXT,
    timestamp DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hassh ON hassh_fingerprints(hassh);
CREATE INDEX IF NOT EXISTS idx_hassh_ip ON hassh_fingerprints(src_ip);
