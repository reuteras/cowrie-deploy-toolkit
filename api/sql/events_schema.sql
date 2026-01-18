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
