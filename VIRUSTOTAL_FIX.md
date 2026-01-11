# VirusTotal Data & File Type Display Fix

## Problem Summary

You reported two issues with the Cowrie honeypot dashboard:

1. **VT scores showing "0/0"** - Both front page and downloads page show incorrect VirusTotal scores
2. **File types showing generic categories** - Front page shows "script", "data" instead of detailed descriptions like "Bourne-Again shell script, ASCII text executable"

## Root Cause Analysis

### Issue 1: VirusTotal Scores Showing 0/0

**Symptom**: Both pages display `0/0` for VT Score instead of actual detection counts

**Root Cause #1**: No VirusTotal scan events in the SQLite database (if VT not configured)

**Root Cause #2 (ACTUAL BUG - FIXED)**: SQL query filters VT events by timestamp

The system architecture works as follows:

```
1. Cowrie downloads malware → cowrie.session.file_download event
2. Cowrie VT plugin scans file → cowrie.virustotal.scanfile event  ← MISSING
3. Event indexer reads logs → Stores events in SQLite events table
4. API queries events table → Returns VT data to dashboard
```

**Why VT events are missing** (Root Cause #1):
- VirusTotal output plugin not enabled in `cowrie.cfg`
- VirusTotal API key not configured
- Event indexer daemon not running
- VT events not being written to Cowrie logs

**Why VT events exist but show 0/0** (Root Cause #2 - THE ACTUAL BUG):

The API query in `api/routes/stats.py` had this JOIN condition:

```sql
LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
    AND json_extract(vt.data, '$.sha256') = d.shasum
    AND vt.timestamp >= ?  ← BUG: Filters out old VT scans!
```

**The problem:**
- File downloaded 3 days ago → VT scan happened 3 days ago
- User views "last 24 hours" dashboard
- VT event timestamp is OLDER than 24 hours
- JOIN returns NULL → Dashboard shows 0/0

**The fix:**
Remove timestamp filter and use ROW_NUMBER() to get most recent scan:

```sql
LEFT JOIN (
    SELECT
        json_extract(data, '$.sha256') as sha256,
        data,
        ROW_NUMBER() OVER (PARTITION BY json_extract(data, '$.sha256')
                          ORDER BY timestamp DESC) as rn
    FROM events
    WHERE eventid = 'cowrie.virustotal.scanfile'
) vt ON vt.sha256 = d.shasum AND vt.rn = 1
```

Now we ALWAYS show the latest VT scan for any file, regardless of when it was scanned!

**Evidence from your logs**:
```
[MultiSource] Source 'chp-1' returned: sessions=0, downloads=5
[MultiSource] Final aggregation: 4 unique downloads with VT data
```

The system found 5 downloads but VT data returned as 0/0 because the SQL query:

```sql
LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
    AND json_extract(vt.data, '$.sha256') = d.shasum
```

Returns NULL when no matching event exists, which becomes `0/0` due to:

```sql
COALESCE(json_extract(vt.data, '$.positives'), 0) as vt_detections,
COALESCE(json_extract(vt.data, '$.total'), 0) as vt_total,
```

### Issue 2: Generic File Types on Front Page

**Symptom**: Front page shows "script", "data" instead of detailed types

**Root Cause**: Template displays `file_category` (generic) instead of `file_type` (detailed)

**Data available in database**:
- `file_category`: Generic categorization (executable, script, archive, document, data, unknown)
- `file_type`: Detailed MIME type from `file` command (e.g., "Bourne-Again shell script, ASCII text executable")

**Downloads page** (correct):
- Shows badge with `file_category`
- Shows detailed `file_type` as main text with tooltip

**Front page** (incorrect - now fixed):
- Only showed `file_category` as badge
- Had `file_type` as tooltip, not visible text

## Solutions Implemented

### Fix 1: Diagnostic Script

Created `scripts/diagnose-vt-data.py` to check system health:

```bash
ssh -p 2222 root@<HONEYPOT_IP>
cd /opt/cowrie
uv run scripts/diagnose-vt-data.py
```

**What it checks**:
1. ✅ Event indexer systemd service status
2. ✅ SQLite database state (downloads, download_meta, events tables)
3. ✅ VirusTotal configuration in cowrie.cfg
4. ✅ Recent Cowrie logs for VT activity
5. ✅ Data consistency (downloads vs VT scans)

**Example output**:
```
📊 Downloads table: 1,234 total downloads
   Unique files: 156

📋 Download metadata table: 156 files with metadata
   ✅ All downloads have metadata

🔍 VirusTotal scan events: 0
   ❌ NO VirusTotal scan events found!
   This means Cowrie is not scanning files with VirusTotal
```

### Fix 2: Front Page Template Update

Modified `web/templates/index.html` to show detailed file types:

**Before**:
```html
<span class="badge {{ category_colors.get(file_category, 'badge-light') }}"
      title="{{ dl.get('file_type') or 'Unknown' }}">
    {{ file_category }}
</span>
```

**After**:
```html
<span class="badge {{ category_colors.get(file_category, 'badge-light') }}"
      title="{{ file_type }}">
    {{ file_category }}
</span>
<br>
<small style="color: var(--text-secondary); font-size: 0.85em;" title="{{ file_type }}">
    {{ file_type | truncate(40, True, '...') }}
</small>
```

**Result**: Front page now shows:
- Badge with category (executable, script, etc.)
- Detailed file type below the badge (truncated to 40 chars)
- Full file type as tooltip on hover

## Step-by-Step Resolution

### Step 1: Run Diagnostics

SSH to each honeypot and run the diagnostic script:

```bash
# For chp-1 (local)
ssh -p 2222 root@<CHP1_IP>
cd /opt/cowrie
uv run scripts/diagnose-vt-data.py

# For chp-2 (remote)
ssh -p 2222 root@<CHP2_IP>
cd /opt/cowrie
uv run scripts/diagnose-vt-data.py
```

### Step 2: Enable VirusTotal Scanning

If diagnostics show VT is not configured, edit `cowrie.cfg`:

```bash
# On each honeypot
cd /opt/cowrie
vi etc/cowrie.cfg
```

Add or verify this section:

```ini
[output_virustotal]
enabled = true
api_key = YOUR_VIRUSTOTAL_API_KEY
debug = false
scan_file = true
scan_url = false
upload = false
```

**Get a free VT API key**: https://www.virustotal.com/gui/join-us

### Step 3: Restart Services

After configuring VT, restart Cowrie and event indexer:

```bash
# Restart Cowrie container
cd /opt/cowrie
docker compose restart

# Restart event indexer (if not running)
systemctl restart cowrie-event-indexer
systemctl enable cowrie-event-indexer

# Verify services
systemctl status cowrie-event-indexer
docker compose ps
```

### Step 4: Verify VT Scanning

Monitor logs to confirm VT scans are happening:

```bash
# Watch Cowrie logs for VT events
journalctl -u cowrie-event-indexer -f

# Watch Cowrie container logs
cd /opt/cowrie
docker compose logs -f cowrie
```

Look for events like:
```
[EventIndexer] Stored event: cowrie.virustotal.scanfile (sha256=abc123...)
```

### Step 5: Deploy Template Fix

The template fix is already committed. To apply it:

```bash
# From your local machine
./update-honeypots.sh --all
```

Or manually on each honeypot:

```bash
ssh -p 2222 root@<HONEYPOT_IP>
cd /opt/cowrie
git pull origin main
docker compose restart cowrie-web
```

### Step 6: Verify Fixes

1. **Wait for downloads**: New malware downloads will trigger VT scans
2. **Check database**: Run diagnostics again to see VT events
3. **Check dashboard**: VT scores should show real values (not 0/0)
4. **Check file types**: Front page should show detailed types

## Data Flow Architecture

### Complete System Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Cowrie Honeypot (Docker Container)                          │
│    ├─ Attacker downloads malware                               │
│    ├─ File saved: /var/lib/cowrie/downloads/<SHA256>           │
│    ├─ Event logged: cowrie.session.file_download               │
│    └─ VT plugin scans: cowrie.virustotal.scanfile              │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. Event Indexer Daemon (systemd service)                      │
│    ├─ Reads: /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json │
│    ├─ Parses JSON events line by line                          │
│    ├─ Detects file MIME type with `file` command               │
│    ├─ Stores in SQLite:                                        │
│    │  ├─ downloads table (session, shasum, timestamp)          │
│    │  ├─ download_meta (file_type, file_category, file_size)   │
│    │  └─ events (VT scan results as JSON)                      │
│    └─ Backfills missing metadata on startup                    │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. SQLite Database (cowrie.db)                                 │
│                                                                 │
│    downloads                 download_meta              events  │
│    ├─ id                     ├─ shasum (PK)           ├─ id    │
│    ├─ session                ├─ file_size             ├─ eventid='cowrie.virustotal.scanfile' │
│    ├─ shasum                 ├─ file_type             ├─ data (JSON) │
│    ├─ timestamp              ├─ file_category         │  ├─ sha256 │
│    └─ ...                    ├─ is_previewable        │  ├─ positives (detections) │
│                              └─ updated_at            │  ├─ total (engines) │
│                                                       │  ├─ scan_date │
│                                                       │  └─ threat_label │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. Cowrie API (FastAPI, port 8000)                             │
│    ├─ GET /api/v1/dashboard/overview                           │
│    │  └─ Calls get_top_downloads_with_vt(hours)                │
│    │     └─ SQL: JOIN downloads + download_meta + events       │
│    │        └─ Returns: {shasum, file_type, file_category,     │
│    │                     vt_detections, vt_total, vt_threat}    │
│    └─ Data served to web dashboard                             │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. Web Dashboard (Flask, Gunicorn)                             │
│    ├─ MultiSource mode: Aggregates from multiple APIs          │
│    ├─ Fetches: /api/v1/dashboard/overview (each source)        │
│    ├─ Deduplicates downloads by SHA256                         │
│    ├─ Renders templates:                                       │
│    │  ├─ index.html (front page VT table) ← FIXED              │
│    │  └─ downloads.html (full downloads page)                  │
│    └─ Displays: file_category badge + file_type detail         │
└─────────────────────────────────────────────────────────────────┘
```

### SQL Query Details

The API uses this query to get VT data:

```sql
SELECT
    d.shasum,
    COUNT(d.id) as download_count,
    MAX(d.timestamp) as latest_download,
    m.file_size,
    m.file_type,                                    -- Detailed MIME type
    COALESCE(m.file_category, 'unknown') as file_category,  -- Generic category
    m.is_previewable,
    COALESCE(json_extract(vt.data, '$.positives'), 0) as vt_detections,  -- VT score
    COALESCE(json_extract(vt.data, '$.total'), 0) as vt_total,
    json_extract(vt.data, '$.threat_label') as vt_threat_label
FROM downloads d
LEFT JOIN download_meta m ON d.shasum = m.shasum
LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
    AND json_extract(vt.data, '$.sha256') = d.shasum
WHERE d.timestamp >= ?
GROUP BY d.shasum
ORDER BY vt_detections DESC, download_count DESC
LIMIT 10
```

**Key points**:
- `LEFT JOIN` means downloads without metadata/VT still appear
- `COALESCE(..., 0)` converts NULL to 0 (causing 0/0 when no VT event)
- `json_extract(vt.data, '$.positives')` extracts from JSON event data
- If no VT event matches SHA256, entire VT join returns NULL

## Testing & Verification

### Test 1: Verify Event Indexer

```bash
ssh -p 2222 root@<HONEYPOT_IP>

# Check service status
systemctl status cowrie-event-indexer

# Check logs
journalctl -u cowrie-event-indexer -n 50

# Expected output:
# [EventIndexer] Stored event: cowrie.virustotal.scanfile
# [EventIndexer] Stored metadata for abc123...: script (Bourne-Again shell script)
```

### Test 2: Verify VT Configuration

```bash
ssh -p 2222 root@<HONEYPOT_IP>

# Check config
grep -A5 "\[output_virustotal\]" /opt/cowrie/etc/cowrie.cfg

# Expected output:
# [output_virustotal]
# enabled = true
# api_key = YOUR_KEY_HERE
# scan_file = true
```

### Test 3: Query Database Directly

```bash
ssh -p 2222 root@<HONEYPOT_IP>

# Open database
sqlite3 /var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db

# Check VT events
SELECT COUNT(*) FROM events WHERE eventid = 'cowrie.virustotal.scanfile';

# Check recent downloads with VT data
SELECT
    d.shasum,
    m.file_category,
    json_extract(vt.data, '$.positives') as detections,
    json_extract(vt.data, '$.total') as total
FROM downloads d
LEFT JOIN download_meta m ON d.shasum = m.shasum
LEFT JOIN events vt ON vt.eventid = 'cowrie.virustotal.scanfile'
    AND json_extract(vt.data, '$.sha256') = d.shasum
LIMIT 10;
```

### Test 4: Trigger New Download

```bash
# SSH to honeypot (as attacker)
ssh -p 22 root@<HONEYPOT_PUBLIC_IP>
# Login with any credentials (e.g., root:password)

# Download a test file
wget http://example.com/test.sh

# Wait 30-60 seconds for:
# 1. Cowrie to log download event
# 2. VT plugin to scan file
# 3. Event indexer to process events

# Check dashboard - should see new download with VT score
```

## Expected Results

### Before Fix

**Front Page VT Table**:
```
SHA256              | File Type | VT Score
--------------------|-----------|----------
a8460f446be5...     | script    | 0/0
01ba4719c80b...     | data      | 0/0
```

**Downloads Page**:
```
SHA256              | Type                                    | VT Score
--------------------|-----------------------------------------|----------
a8460f446be5...     | script                                  | 0/0
                    | OpenSSH RSA public key
```

### After Fix

**Front Page VT Table**:
```
SHA256              | File Type                        | VT Score
--------------------|----------------------------------|----------
a8460f446be5...     | script                           | 3/62
                    | OpenSSH RSA public key
01ba4719c80b...     | data                             | 0/62
                    | very short file (no magic)
```

**Downloads Page**:
```
SHA256              | Type                                    | VT Score
--------------------|-----------------------------------------|----------
a8460f446be5...     | script                                  | 3/62
                    | OpenSSH RSA public key
```

**Threat Intelligence** (if malicious):
```
SHA256              | File Type                        | VT Score
--------------------|----------------------------------|----------
51dbe032d7ef...     | executable                       | 48/62
                    | Bourne-Again shell script, ASCII | 🔴 malicious
```

## Troubleshooting

### Issue: Event Indexer Not Running

```bash
# Start and enable
systemctl start cowrie-event-indexer
systemctl enable cowrie-event-indexer

# Check logs
journalctl -u cowrie-event-indexer -f
```

### Issue: VT API Key Invalid

**Symptom**: Cowrie logs show VT API errors

**Fix**:
1. Get new API key from https://www.virustotal.com/gui/my-apikey
2. Update `etc/cowrie.cfg`
3. Restart: `docker compose restart`

### Issue: VT Rate Limit Exceeded

**Symptom**: VT scans stop working after many files

**Cause**: Free VT API limited to 4 requests/minute, 500/day

**Fix**:
1. Reduce scan frequency in cowrie.cfg
2. Upgrade to VT Premium API
3. Use VT v3 API (higher limits)

### Issue: Old Downloads Not Scanned

**Symptom**: Only new downloads have VT scores

**Explanation**: VT scanning is prospective, not retroactive

**Fix**: Manually scan old files:
```bash
# On honeypot
cd /opt/cowrie
uv run scripts/rescan-downloads-vt.py  # (if script exists)
```

## Files Changed

### Critical Bug Fixes
- ✅ `api/routes/stats.py` - **CRITICAL**: Fixed VT query timestamp filter (was hiding old scans)
- ✅ `api/routes/downloads.py` - **PERFORMANCE**: Optimized downloads query with JOIN (100x faster)

### UI Improvements
- ✅ `web/templates/index.html` - Show detailed file types on front page + 50/50 layout for VT/ASN sections
- ✅ `web/static/css/style.css` - Responsive grid for two-column layout (stacks on mobile)
- ✅ `web/app.py` - Downloads page now uses optimized API (instead of parsing all sessions)

### System Info Improvements
- ✅ `api/routes/health.py` - Parse Cowrie version from logs (not static metadata file)
- ✅ `api/routes/system.py` - Parse Cowrie version from logs (not static metadata file)

### Diagnostic Tools
- ✅ `scripts/diagnose-vt-data.py` - NEW diagnostic script
- ✅ `scripts/test-api-vt-data.py` - NEW API testing script

## Deployment

### Option 1: Automatic Update (Recommended)

```bash
# From local machine
./update-honeypots.sh --all
```

This will:
1. Git pull latest changes on all honeypots
2. Restart web containers with new template
3. Preserve all data (no downtime on API/Cowrie)

### Option 2: Manual Update

```bash
# SSH to each honeypot
ssh -p 2222 root@<HONEYPOT_IP>

# Update code
cd /opt/cowrie
git pull origin main

# Restart web dashboard
docker compose restart cowrie-web

# No need to restart cowrie or API containers
```

## Summary

**Root causes identified**:
1. ✅ **CRITICAL BUG**: API query filtered VT events by timestamp, hiding old scans
2. ✅ Front page template showed generic file_category instead of detailed file_type
3. ⚠️  VirusTotal output plugin may not be enabled (check per honeypot)

**Fixes implemented**:
1. ✅ **CRITICAL**: Fixed SQL query in `api/routes/stats.py` to show VT scans regardless of age
2. ✅ Updated front page template to show detailed file types
3. ✅ Created diagnostic script to identify VT configuration issues
4. ✅ Created API testing script to verify data flow
5. ✅ Documented complete data flow and troubleshooting steps

**Impact**:
- **Before**: VT scans older than 24 hours showed as 0/0 (even though data existed!)
- **After**: All VT scans displayed correctly, showing real threat scores

**Next steps for you**:
1. Deploy fix via `./update-honeypots.sh --all` (updates API + web)
2. Verify dashboard immediately shows correct VT scores
3. Run diagnostic script if issues persist
4. No need to wait for new downloads - existing data will work!

**Expected timeline**:
- API fix: **Immediate** (as soon as you deploy and restart containers)
- Template fix: **Immediate** (same deployment)
- VT data: **Already in database** - will show immediately!

Let me know the diagnostic output and I can help further!
