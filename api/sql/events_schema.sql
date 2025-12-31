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
