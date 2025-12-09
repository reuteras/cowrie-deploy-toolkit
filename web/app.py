#!/usr/bin/env python3
"""
Cowrie SSH Session Playback Web Service

Provides a web interface for viewing and replaying SSH sessions captured by Cowrie.
"""

import json
import os
import struct
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request

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
        except Exception:
            pass
        return result


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
        country_counter = Counter()
        credential_counter = Counter()
        successful_credentials = set()
        command_counter = Counter()
        sessions_with_cmds = 0
        total_downloads = 0
        hourly_activity = defaultdict(int)

        for session in sessions.values():
            if session['src_ip']:
                ips.add(session['src_ip'])
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

            total_downloads += len(session['downloads'])

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

        return {
            'total_sessions': len(sessions),
            'unique_ips': len(ips),
            'sessions_with_commands': sessions_with_cmds,
            'total_downloads': total_downloads,
            'top_countries': country_counter.most_common(10),
            'top_credentials': credential_counter.most_common(10),
            'successful_credentials': successful_credentials,
            'top_commands': command_counter.most_common(20),
            'hourly_activity': sorted_hours[-48:],  # Last 48 hours
        }


class TTYLogParser:
    """Parse Cowrie TTY log files and convert to asciicast format."""

    # Cowrie TTY log opcodes
    OP_OPEN = 1
    OP_CLOSE = 2
    OP_WRITE = 3
    OP_EXEC = 4

    def __init__(self, tty_path: str):
        self.tty_path = tty_path

    def find_tty_file(self, tty_log_name: str) -> Optional[str]:
        """Find a TTY log file by name."""
        if not tty_log_name:
            return None

        # Try direct path
        direct_path = os.path.join(self.tty_path, tty_log_name)
        if os.path.exists(direct_path):
            return direct_path

        # Try with various date-based subdirectories
        for root, dirs, files in os.walk(self.tty_path):
            if tty_log_name in files:
                return os.path.join(root, tty_log_name)

        return None

    def parse_tty_log(self, tty_log_name: str) -> Optional[dict]:
        """Parse a Cowrie TTY log file and return asciicast v2 format."""
        file_path = self.find_tty_file(tty_log_name)
        if not file_path:
            return None

        events = []
        start_time = None
        width = 80
        height = 24

        try:
            with open(file_path, 'rb') as f:
                while True:
                    # Read header: opcode (4 bytes), time (4 bytes), size (4 bytes)
                    header = f.read(12)
                    if len(header) < 12:
                        break

                    opcode, ts, size = struct.unpack('<III', header)
                    data = f.read(size)

                    if opcode == self.OP_OPEN:
                        start_time = ts / 1000000.0  # Convert to seconds
                        # Try to parse terminal size from data
                        try:
                            if len(data) >= 8:
                                width, height = struct.unpack('<II', data[:8])
                        except Exception:
                            pass

                    elif opcode == self.OP_WRITE:
                        if start_time is not None:
                            relative_time = (ts / 1000000.0) - start_time
                            # Decode data, replacing invalid bytes
                            try:
                                text = data.decode('utf-8', errors='replace')
                            except Exception:
                                text = data.decode('latin-1', errors='replace')
                            events.append([relative_time, 'o', text])

                    elif opcode == self.OP_CLOSE:
                        break

        except Exception as e:
            return None

        if not events:
            return None

        # Return asciicast v2 format
        return {
            'version': 2,
            'width': min(width, 200),
            'height': min(height, 50),
            'timestamp': int(start_time) if start_time else int(time.time()),
            'env': {'SHELL': '/bin/bash', 'TERM': 'xterm-256color'},
            'events': events
        }

    def get_asciicast_ndjson(self, tty_log_name: str) -> Optional[str]:
        """Get TTY log as asciicast v2 NDJSON format."""
        data = self.parse_tty_log(tty_log_name)
        if not data:
            return None

        lines = []
        # Header line
        header = {
            'version': data['version'],
            'width': data['width'],
            'height': data['height'],
            'timestamp': data['timestamp'],
            'env': data['env']
        }
        lines.append(json.dumps(header))

        # Event lines
        for event in data['events']:
            lines.append(json.dumps(event))

        return '\n'.join(lines)


# Initialize parsers
session_parser = SessionParser(CONFIG['log_path'])
tty_parser = TTYLogParser(CONFIG['tty_path'])


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

    return render_template('playback.html', session=session, config=CONFIG)


@app.route('/api/session/<session_id>/asciicast')
def session_asciicast(session_id: str):
    """Return asciicast data for a session."""
    session = session_parser.get_session(session_id)
    if not session or not session['tty_log']:
        return jsonify({'error': 'No TTY recording'}), 404

    asciicast = tty_parser.get_asciicast_ndjson(session['tty_log'])
    if not asciicast:
        return jsonify({'error': 'Failed to parse TTY log'}), 500

    return Response(asciicast, mimetype='application/x-asciicast')


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

    # Check which files exist on disk
    download_path = CONFIG['download_path']
    for shasum, dl in unique_downloads.items():
        file_path = os.path.join(download_path, shasum)
        dl['exists'] = os.path.exists(file_path)
        if dl['exists']:
            dl['size'] = os.path.getsize(file_path)
        else:
            dl['size'] = 0

    downloads_list = sorted(unique_downloads.values(), key=lambda x: x['timestamp'], reverse=True)

    return render_template('downloads.html', downloads=downloads_list, hours=hours, config=CONFIG)


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
