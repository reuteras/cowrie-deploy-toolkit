#!/usr/bin/env python3
"""
Cowrie SSH Session Playback Web Service

Provides a web interface for viewing and replaying SSH sessions captured by Cowrie.
"""

import json
import os
import sqlite3
import struct
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request
import requests

try:
    import geoip2.database
except ImportError:
    geoip2 = None

app = Flask(__name__)

# Configuration from environment variables
CONFIG = {
    'log_path': os.getenv('COWRIE_LOG_PATH', '/cowrie-data/log/cowrie/cowrie.json'),
    'tty_path': os.getenv('COWRIE_TTY_PATH', '/cowrie-data/lib/cowrie/tty'),
    'download_path': os.getenv('COWRIE_DOWNLOAD_PATH', '/cowrie-data/lib/cowrie/downloads'),
    'geoip_db_path': os.getenv('GEOIP_DB_PATH', '/cowrie-data/geoip/GeoLite2-City.mmdb'),
    'base_url': os.getenv('BASE_URL', ''),
    'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'cache_db_path': os.getenv('CACHE_DB_PATH', '/tmp/vt-cache.db'),
    'yara_cache_db_path': os.getenv('YARA_CACHE_DB_PATH', '/cowrie-data/var/yara-cache.db'),
}


class GeoIPLookup:
    """Simple GeoIP lookup wrapper."""

    def __init__(self, db_path: str):
        self.reader = None
        if geoip2 and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                pass

    def lookup(self, ip: str) -> dict:
        """Lookup IP and return geo data."""
        result = {'country': 'Unknown', 'country_code': 'XX', 'city': 'Unknown'}
        if not self.reader:
            return result
        try:
            response = self.reader.city(ip)
            result['country'] = response.country.name or 'Unknown'
            result['country_code'] = response.country.iso_code or 'XX'
            result['city'] = response.city.name or 'Unknown'
            result['latitude'] = response.location.latitude
            result['longitude'] = response.location.longitude
        except Exception:
            pass
        return result


class CacheDB:
    """Simple SQLite cache for VirusTotal results."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result TEXT,
                timestamp INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    def get_vt_result(self, sha256: str) -> Optional[dict]:
        """Get cached VT result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            'SELECT result FROM vt_cache WHERE sha256 = ?',
            (sha256,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def set_vt_result(self, sha256: str, result: dict):
        """Cache VT result."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'INSERT OR REPLACE INTO vt_cache (sha256, result, timestamp) VALUES (?, ?, ?)',
            (sha256, json.dumps(result), int(time.time()))
        )
        conn.commit()
        conn.close()


class YARACache:
    """SQLite cache for YARA scan results (read-only for web app)."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_result(self, sha256: str) -> Optional[dict]:
        """Get cached YARA scan result."""
        if not os.path.exists(self.db_path):
            return None

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                'SELECT matches, scan_timestamp FROM yara_cache WHERE sha256 = ?',
                (sha256,)
            )
            row = cursor.fetchone()
            conn.close()

            if row:
                return {
                    'sha256': sha256,
                    'matches': json.loads(row[0]),
                    'scan_timestamp': row[1]
                }
        except Exception:
            pass
        return None


class VirusTotalScanner:
    """Scan files using VirusTotal API."""

    def __init__(self, api_key: str, cache: CacheDB):
        self.api_key = api_key
        self.cache = cache
        self.base_url = 'https://www.virustotal.com/api/v3'

    def scan_file(self, sha256: str) -> Optional[dict]:
        """Scan file and return results."""
        if not self.api_key:
            return None

        # Check cache first
        cached = self.cache.get_vt_result(sha256)
        if cached:
            return cached

        # Query VirusTotal
        headers = {'x-apikey': self.api_key}

        try:
            response = requests.get(
                f'{self.base_url}/files/{sha256}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']

                result = {
                    'sha256': sha256,
                    'detections': attributes['last_analysis_stats']['malicious'],
                    'total_engines': sum(attributes['last_analysis_stats'].values()),
                    'link': f"https://www.virustotal.com/gui/file/{sha256}"
                }

                # Extract threat label if available
                threat_class = attributes.get('popular_threat_classification', {})
                if threat_class and 'suggested_threat_label' in threat_class:
                    result['threat_label'] = threat_class['suggested_threat_label']

                # Cache result
                self.cache.set_vt_result(sha256, result)
                return result

            elif response.status_code == 404:
                return None

        except Exception as e:
            print(f"[!] VirusTotal API error: {e}")

        return None


class SessionParser:
    """Parse Cowrie JSON logs and extract session data."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.sessions = {}
        self.geoip = GeoIPLookup(CONFIG['geoip_db_path'])

    def parse_all(self, hours: int = 168) -> dict:
        """Parse all sessions from logs within the specified hours."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        sessions = defaultdict(lambda: {
            'id': None,
            'src_ip': None,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'username': None,
            'password': None,
            'commands': [],
            'downloads': [],
            'tty_log': None,
            'client_version': None,
            'geo': {},
            'login_success': False,
        })

        if not os.path.exists(self.log_path):
            return {}

        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))

                    if timestamp < cutoff_time:
                        continue

                    session_id = entry.get('session')
                    if not session_id:
                        continue

                    event_id = entry.get('eventid', '')
                    session = sessions[session_id]
                    session['id'] = session_id

                    if event_id == 'cowrie.session.connect':
                        session['src_ip'] = entry.get('src_ip')
                        session['start_time'] = entry['timestamp']
                        session['client_version'] = entry.get('version')
                        if session['src_ip']:
                            session['geo'] = self.geoip.lookup(session['src_ip'])

                    elif event_id == 'cowrie.login.success':
                        session['username'] = entry.get('username')
                        session['password'] = entry.get('password')
                        session['login_success'] = True

                    elif event_id == 'cowrie.login.failed':
                        if not session['username']:
                            session['username'] = entry.get('username')
                            session['password'] = entry.get('password')

                    elif event_id == 'cowrie.command.input':
                        session['commands'].append({
                            'command': entry.get('input', ''),
                            'timestamp': entry['timestamp']
                        })

                    elif event_id == 'cowrie.session.file_download':
                        session['downloads'].append({
                            'url': entry.get('url', ''),
                            'shasum': entry.get('shasum', ''),
                            'timestamp': entry['timestamp']
                        })

                    elif event_id == 'cowrie.log.closed':
                        tty_log = entry.get('ttylog')
                        if tty_log:
                            session['tty_log'] = tty_log

                    elif event_id == 'cowrie.session.closed':
                        session['end_time'] = entry['timestamp']
                        if session['start_time']:
                            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                            end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
                            session['duration'] = (end - start).total_seconds()

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        return dict(sessions)

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a specific session by ID."""
        sessions = self.parse_all(hours=720)  # Look back 30 days
        return sessions.get(session_id)

    def get_stats(self, hours: int = 24) -> dict:
        """Get statistics for the dashboard."""
        sessions = self.parse_all(hours=hours)

        if not sessions:
            return {
                'total_sessions': 0,
                'unique_ips': 0,
                'sessions_with_commands': 0,
                'total_downloads': 0,
                'top_countries': [],
                'top_credentials': [],
                'top_commands': [],
                'hourly_activity': [],
            }

        # Calculate stats
        ips = set()
        ip_details = defaultdict(lambda: {
            'count': 0,
            'geo': None,
            'last_seen': None,
            'successful_logins': 0,
            'failed_logins': 0
        })
        country_counter = Counter()
        credential_counter = Counter()
        successful_credentials = set()
        command_counter = Counter()
        sessions_with_cmds = 0
        total_downloads = 0
        unique_downloads = set()
        hourly_activity = defaultdict(int)
        ip_locations = []  # For map

        for session in sessions.values():
            if session['src_ip']:
                ips.add(session['src_ip'])
                ip = session['src_ip']
                ip_details[ip]['count'] += 1
                ip_details[ip]['geo'] = session.get('geo', {})
                ip_details[ip]['last_seen'] = session['start_time']

                # Track login attempts for this IP
                if session.get('login_success'):
                    ip_details[ip]['successful_logins'] += 1
                elif session.get('username'):  # Had login attempt but not successful
                    ip_details[ip]['failed_logins'] += 1

                # Collect IP locations for map
                geo = session.get('geo', {})
                if geo and 'latitude' in geo and 'longitude' in geo:
                    ip_locations.append({
                        'ip': ip,
                        'lat': geo['latitude'],
                        'lon': geo['longitude'],
                        'country': geo.get('country', 'Unknown'),
                        'city': geo.get('city', 'Unknown')
                    })

                country = session.get('geo', {}).get('country', 'Unknown')
                country_counter[country] += 1

            if session['username'] and session['password']:
                cred = f"{session['username']}:{session['password']}"
                credential_counter[cred] += 1
                # Track successful logins
                if session.get('login_success'):
                    successful_credentials.add(cred)

            if session['commands']:
                sessions_with_cmds += 1
                for cmd in session['commands']:
                    command_counter[cmd['command']] += 1

            # Track downloads
            for download in session['downloads']:
                total_downloads += 1
                if download['shasum']:
                    unique_downloads.add(download['shasum'])

            if session['start_time']:
                try:
                    hour = datetime.fromisoformat(
                        session['start_time'].replace('Z', '+00:00')
                    ).strftime('%Y-%m-%d %H:00')
                    hourly_activity[hour] += 1
                except Exception:
                    pass

        # Sort hourly activity
        sorted_hours = sorted(hourly_activity.items())

        # Sort IP details by session count
        sorted_ips = sorted(
            [{'ip': ip, **details} for ip, details in ip_details.items()],
            key=lambda x: x['count'],
            reverse=True
        )

        return {
            'total_sessions': len(sessions),
            'unique_ips': len(ips),
            'sessions_with_commands': sessions_with_cmds,
            'total_downloads': total_downloads,
            'unique_downloads': len(unique_downloads),
            'ip_list': sorted_ips,
            'ip_locations': ip_locations,
            'top_countries': country_counter.most_common(10),
            'top_credentials': credential_counter.most_common(10),
            'successful_credentials': successful_credentials,
            'top_commands': command_counter.most_common(20),
            'hourly_activity': sorted_hours[-48:],  # Last 48 hours
        }

    def get_all_commands(self, hours: int = 168) -> list:
        """Get a flat list of all commands from all sessions."""
        sessions = self.parse_all(hours=hours)
        all_commands = []
        for session in sessions.values():
            if session['commands']:
                for cmd in session['commands']:
                    all_commands.append({
                        'timestamp': cmd['timestamp'],
                        'command': cmd['command'],
                        'src_ip': session['src_ip'],
                        'session_id': session['id']
                    })
        
        # Sort by timestamp, most recent first
        return sorted(all_commands, key=lambda x: x['timestamp'], reverse=True)


class TTYLogParser:
    """Parse Cowrie TTY log files and convert to asciicast format."""

    # Cowrie TTY log opcodes
    OP_OPEN = 1
    OP_CLOSE = 2
    OP_WRITE = 3
    OP_EXEC = 4

    # Cowrie TTY stream types
    TYPE_INPUT = 1
    TYPE_OUTPUT = 2
    TYPE_INTERACT = 3

    def __init__(self, tty_path: str):
        self.tty_path = tty_path

    def find_tty_file(self, tty_log_name: str) -> Optional[str]:
        """Find a TTY log file by name."""
        if not tty_log_name:
            return None

        original_tty_log_name = tty_log_name
        # Strip common Cowrie path prefixes if present
        # Sessions may store paths like "var/lib/cowrie/tty/HASH"
        for prefix in ['var/lib/cowrie/tty/', 'lib/cowrie/tty/', 'tty/']:
            if tty_log_name.startswith(prefix):
                tty_log_name = tty_log_name[len(prefix):]
                break

        # Try direct path (just the hash/filename)
        direct_path = os.path.join(self.tty_path, tty_log_name)
        if os.path.exists(direct_path):
            return direct_path

        # Try with various date-based subdirectories
        for root, dirs, files in os.walk(self.tty_path):
            if tty_log_name in files:
                return os.path.join(root, tty_log_name)

        print(f"[!] TTY file lookup failed. Searched for '{tty_log_name}' (from '{original_tty_log_name}') in '{self.tty_path}' but it was not found.")
        return None

    def parse_tty_log(self, tty_log_name: str) -> Optional[dict]:
        """Parse a Cowrie TTY log file and return asciicast v1 format."""
        file_path = self.find_tty_file(tty_log_name)
        if not file_path:
            # Error is logged in find_tty_file
            return None

        stdout = []
        width = 80
        height = 24
        duration = 0.0
        currtty = 0
        prevtime = 0
        prefdir = 0  # Preferred direction (first stream seen)

        # Cowrie ttylog format: <iLiiLL = op, tty, length, direction, sec, usec
        record_size = struct.calcsize("<iLiiLL")

        try:
            with open(file_path, 'rb') as f:
                while True:
                    # Read record header
                    record_data = f.read(record_size)
                    if not record_data:
                        break  # End of file

                    if len(record_data) < record_size:
                        print(f"[!] Incomplete record in TTY log, stopping parse: {file_path}")
                        break

                    try:
                        op, tty, length, direction, sec, usec = struct.unpack('<iLiiLL', record_data)
                    except struct.error as e:
                        print(f"[!] Corrupt record in TTY log, stopping parse: {file_path} - {e}")
                        break

                    if length > 10 * 1024 * 1024:  # 10MB limit
                        print(f"[!] Unreasonable TTY record size ({length} bytes), stopping parse: {file_path}")
                        break

                    # Read data payload
                    data = f.read(length)
                    if len(data) < length:
                        print(f"[!] Truncated data record in TTY log (expected {length}, got {len(data)}), stopping parse: {file_path}")
                        break

                    # Track the first TTY we see
                    if currtty == 0:
                        currtty = tty

                    # Only process events for the primary TTY
                    if tty == currtty:
                        if op == self.OP_OPEN:
                            # Try to extract terminal dimensions
                            try:
                                if len(data) >= 8:
                                    width, height = struct.unpack('<II', data[:8])
                            except struct.error:
                                # Ignore if terminal size parsing fails
                                pass

                        elif op == self.OP_WRITE:
                            # The first stream seen is considered 'output' (prefdir)
                            if prefdir == 0:
                                prefdir = direction

                            # Only include events matching the preferred direction
                            if direction == prefdir:
                                # Calculate timestamp
                                curtime = float(sec) + float(usec) / 1000000.0
                                if prevtime != 0:
                                    sleeptime = curtime - prevtime
                                else:
                                    sleeptime = 0.0
                                prevtime = curtime

                                # Convert newlines to carriage return + newline
                                # This prevents upload mangling in asciinema
                                data = data.replace(b"\n", b"\r\n")

                                try:
                                    text = data.decode('utf-8', errors='replace')
                                except Exception:
                                    text = data.decode('latin-1', errors='replace')

                                # Add to stdout (v1 format uses [time, data])
                                stdout.append([sleeptime, text])
                                duration += sleeptime

                        elif op == self.OP_CLOSE:
                            break

        except (IOError, OSError) as e:
            print(f"[!] I/O error reading TTY log '{file_path}': {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected exception in parse_tty_log for '{file_path}': {e}")
            return None

        # Return asciicast v1 format (matches Cowrie's asciinema.py)
        return {
            'version': 1,
            'width': min(width, 200),
            'height': min(height, 50),
            'duration': duration,
            'command': '/bin/bash',
            'title': 'Cowrie Recording',
            'env': {'SHELL': '/bin/bash', 'TERM': 'xterm256-color'},
            'stdout': stdout
        }


# Initialize parsers
session_parser = SessionParser(CONFIG['log_path'])
tty_parser = TTYLogParser(CONFIG['tty_path'])

# Initialize VirusTotal scanner if API key is provided
vt_scanner = None
if CONFIG['virustotal_api_key']:
    cache_db = CacheDB(CONFIG['cache_db_path'])
    vt_scanner = VirusTotalScanner(CONFIG['virustotal_api_key'], cache_db)

# Initialize YARA cache (reads results from yara-scanner-daemon)
yara_cache = YARACache(CONFIG['yara_cache_db_path'])


@app.route('/')
def index():
    """Dashboard page."""
    hours = request.args.get('hours', 24, type=int)
    stats = session_parser.get_stats(hours=hours)
    return render_template('index.html', stats=stats, hours=hours, config=CONFIG)


@app.route('/sessions')
def sessions():
    """Session listing page."""
    hours = request.args.get('hours', 168, type=int)
    page = request.args.get('page', 1, type=int)
    per_page = 50

    all_sessions = session_parser.parse_all(hours=hours)

    # Sort by start time (most recent first)
    sorted_sessions = sorted(
        all_sessions.values(),
        key=lambda x: x['start_time'] or '',
        reverse=True
    )

    # Filter options
    ip_filter = request.args.get('ip', '')
    has_commands = request.args.get('has_commands', '')
    has_tty = request.args.get('has_tty', '')

    if ip_filter:
        sorted_sessions = [s for s in sorted_sessions if s['src_ip'] == ip_filter]
    if has_commands == '1':
        sorted_sessions = [s for s in sorted_sessions if s['commands']]
    if has_tty == '1':
        sorted_sessions = [s for s in sorted_sessions if s['tty_log']]

    # Paginate
    total = len(sorted_sessions)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = sorted_sessions[start:end]

    return render_template(
        'sessions.html',
        sessions=paginated,
        page=page,
        per_page=per_page,
        total=total,
        hours=hours,
        ip_filter=ip_filter,
        has_commands=has_commands,
        has_tty=has_tty,
        config=CONFIG
    )


@app.route('/session/<session_id>')
def session_detail(session_id: str):
    """Session detail page."""
    session = session_parser.get_session(session_id)
    if not session:
        return render_template('404.html', message='Session not found'), 404

    # Check if TTY log exists
    has_tty = False
    if session['tty_log']:
        tty_file = tty_parser.find_tty_file(session['tty_log'])
        has_tty = tty_file is not None

    return render_template('session_detail.html', session=session, has_tty=has_tty, config=CONFIG)


@app.route('/session/<session_id>/playback')
def session_playback(session_id: str):
    """Session playback page with asciinema player."""
    session = session_parser.get_session(session_id)
    if not session:
        return render_template('404.html', message='Session not found'), 404

    if not session['tty_log']:
        return render_template('404.html', message='No TTY recording for this session'), 404

    # Parse TTY log for width and height
    asciicast = tty_parser.parse_tty_log(session['tty_log'])
    if not asciicast:
        print(f"[!] Failed to parse TTY log for playback: {session['tty_log']}")
        return render_template('404.html', message='Failed to parse TTY log for playback'), 404

    return render_template('playback.html', session=session, asciicast=asciicast, config=CONFIG)


@app.route('/api/session/<session_id>/asciicast')
def session_asciicast(session_id: str):
    """Return asciicast data for a session."""
    session = session_parser.get_session(session_id)
    if not session or not session['tty_log']:
        print(f"[!] No TTY recording for session {session_id}")
        return jsonify({'error': 'No TTY recording'}), 404

    # Check if TTY file exists
    tty_file = tty_parser.find_tty_file(session['tty_log'])
    if not tty_file:
        print(f"[!] TTY file not found: {session['tty_log']}")
        return jsonify({'error': 'TTY recording file not found'}), 404

    asciicast = tty_parser.parse_tty_log(session['tty_log'])
    if not asciicast:
        print(f"[!] Failed to parse TTY log: {session['tty_log']}")
        return jsonify({'error': 'Failed to parse TTY log'}), 404

    return jsonify(asciicast)


@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard stats."""
    hours = request.args.get('hours', 24, type=int)
    stats = session_parser.get_stats(hours=hours)
    return jsonify(stats)


@app.route('/api/sessions')
def api_sessions():
    """API endpoint for sessions list."""
    hours = request.args.get('hours', 168, type=int)
    limit = request.args.get('limit', 100, type=int)

    all_sessions = session_parser.parse_all(hours=hours)
    sorted_sessions = sorted(
        all_sessions.values(),
        key=lambda x: x['start_time'] or '',
        reverse=True
    )[:limit]

    return jsonify(sorted_sessions)


@app.route('/downloads')
def downloads():
    """Downloaded files listing page."""
    hours = request.args.get('hours', 168, type=int)
    all_sessions = session_parser.parse_all(hours=hours)

    # Collect all downloads
    all_downloads = []
    for session in all_sessions.values():
        for download in session['downloads']:
            download['session_id'] = session['id']
            download['src_ip'] = session['src_ip']
            all_downloads.append(download)

    # Deduplicate by shasum
    unique_downloads = {}
    for dl in all_downloads:
        shasum = dl['shasum']
        if shasum not in unique_downloads:
            unique_downloads[shasum] = dl
            unique_downloads[shasum]['count'] = 1
        else:
            unique_downloads[shasum]['count'] += 1

    # Check which files exist on disk and get VT/YARA scores
    download_path = CONFIG['download_path']
    for shasum, dl in unique_downloads.items():
        file_path = os.path.join(download_path, shasum)
        dl['exists'] = os.path.exists(file_path)
        if dl['exists']:
            dl['size'] = os.path.getsize(file_path)
        else:
            dl['size'] = 0

        # Get YARA matches from cache
        yara_result = yara_cache.get_result(shasum)
        if yara_result and yara_result['matches']:
            dl['yara_matches'] = yara_result['matches']

        # Get VirusTotal score if scanner is available
        if vt_scanner and shasum:
            vt_result = vt_scanner.scan_file(shasum)
            if vt_result:
                dl['vt_detections'] = vt_result['detections']
                dl['vt_total'] = vt_result['total_engines']
                dl['vt_link'] = vt_result['link']
                dl['vt_threat_label'] = vt_result.get('threat_label', '')

    downloads_list = sorted(unique_downloads.values(), key=lambda x: x['timestamp'], reverse=True)

    return render_template('downloads.html', downloads=downloads_list, hours=hours, config=CONFIG)


@app.route('/commands')
def commands():
    """Commands listing page."""
    hours = request.args.get('hours', 168, type=int)
    all_commands = session_parser.get_all_commands(hours=hours)
    return render_template('commands.html', commands=all_commands, hours=hours, config=CONFIG)


@app.route('/ips')
def ip_list():
    """IP address listing page."""
    hours = request.args.get('hours', 168, type=int)
    stats = session_parser.get_stats(hours=hours)

    return render_template('ips.html', ips=stats['ip_list'], hours=hours, config=CONFIG)


@app.template_filter('format_duration')
def format_duration(seconds):
    """Format duration in seconds to human readable string."""
    if not seconds:
        return 'N/A'
    if seconds < 60:
        return f'{int(seconds)}s'
    elif seconds < 3600:
        return f'{int(seconds // 60)}m {int(seconds % 60)}s'
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f'{hours}h {minutes}m'


@app.template_filter('format_timestamp')
def format_timestamp(ts_str):
    """Format ISO timestamp to readable string."""
    if not ts_str:
        return 'N/A'
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return ts_str


@app.template_filter('truncate_hash')
def truncate_hash(hash_str, length=16):
    """Truncate a hash for display."""
    if not hash_str:
        return 'N/A'
    if len(hash_str) <= length:
        return hash_str
    return hash_str[:length] + '...'


if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
