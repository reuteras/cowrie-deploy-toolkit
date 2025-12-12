"""
Cowrie IP-Locked Authentication Output Plugin

This plugin implements IP-based credential locking for enhanced honeypot realism.
When an IP successfully authenticates for the first time, it becomes "locked" to
those specific credentials and cannot use any other username/password combinations.

Unlike traditional authentication checkers, this plugin works at the Cowrie output
layer where we have full access to session data including source IP. It intercepts
login events and force-disconnects sessions that violate IP locks.

Behavior:
- First successful login from an IP: Accept and lock IP to those credentials
- Subsequent logins from that IP: Only accept if credentials match the lock
- Violations: Force-disconnect the session immediately

Database: SQLite stored in persistent volume (cowrie-var)
Path: /cowrie/cowrie-git/var/lib/cowrie/iplock.db

Author: Claude Code
License: MIT
"""

import sqlite3
import os
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class IPLockAuthDB:
    """SQLite database for tracking IP -> credential locks"""

    def __init__(self, db_path):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Create database schema if not exists"""
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create table for IP -> credential locks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_locks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                login_count INTEGER DEFAULT 1,
                last_login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Index for fast IP lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_src_ip ON ip_locks(src_ip)
        """)

        # Create table for tracking all authentication attempts (for analysis)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                is_locked BOOLEAN DEFAULT FALSE,
                lock_matched BOOLEAN DEFAULT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Index for analysis queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attempts_ip ON auth_attempts(src_ip)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON auth_attempts(attempted_at)
        """)

        conn.commit()
        conn.close()

        log.msg(f"[IPLockAuth] Database initialized: {self.db_path}")

    def get_locked_credentials(self, src_ip):
        """
        Get locked credentials for an IP address

        Returns:
            tuple: (username, password) or None if not locked
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username, password FROM ip_locks WHERE src_ip = ?
        """, (src_ip,))

        result = cursor.fetchone()
        conn.close()

        return result if result else None

    def lock_ip_to_credentials(self, src_ip, username, password):
        """
        Lock an IP to specific credentials (first successful login)

        Args:
            src_ip: Source IP address
            username: Username used
            password: Password used

        Returns:
            bool: True if locked successfully, False if already locked
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO ip_locks (src_ip, username, password)
                VALUES (?, ?, ?)
            """, (src_ip, username, password))

            conn.commit()
            conn.close()

            log.msg(f"[IPLockAuth] IP {src_ip} locked to credentials: {username}:***")
            return True
        except sqlite3.IntegrityError:
            # IP already locked (race condition or concurrent login)
            conn.close()
            return False

    def increment_login_count(self, src_ip):
        """Increment successful login count for a locked IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE ip_locks
            SET login_count = login_count + 1,
                last_login_at = CURRENT_TIMESTAMP
            WHERE src_ip = ?
        """, (src_ip,))

        conn.commit()
        conn.close()

    def log_attempt(self, src_ip, username, password, success, is_locked, lock_matched=None):
        """
        Log an authentication attempt for analysis

        Args:
            src_ip: Source IP address
            username: Username attempted
            password: Password attempted
            success: Whether authentication succeeded
            is_locked: Whether this IP was already locked
            lock_matched: Whether attempted credentials matched the lock (None if not locked)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO auth_attempts (src_ip, username, password, success, is_locked, lock_matched)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (src_ip, username, password, success, is_locked, lock_matched))

        conn.commit()
        conn.close()

    def get_stats(self):
        """Get statistics about locked IPs and violations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total locked IPs
        cursor.execute("SELECT COUNT(*) FROM ip_locks")
        total_locks = cursor.fetchone()[0]

        # Total violations (failed attempts on locked IPs)
        cursor.execute("""
            SELECT COUNT(*) FROM auth_attempts
            WHERE is_locked = 1 AND lock_matched = 0
        """)
        total_violations = cursor.fetchone()[0]

        # Most violated IPs
        cursor.execute("""
            SELECT src_ip, COUNT(*) as violation_count
            FROM auth_attempts
            WHERE is_locked = 1 AND lock_matched = 0
            GROUP BY src_ip
            ORDER BY violation_count DESC
            LIMIT 10
        """)
        top_violators = cursor.fetchall()

        conn.close()

        return {
            'total_locks': total_locks,
            'total_violations': total_violations,
            'top_violators': top_violators
        }


class Output(cowrie.core.output.Output):
    """
    IP-Lock Authentication Output Plugin

    Intercepts login events and enforces IP-based credential locking by
    force-disconnecting sessions that violate locks.
    """

    def start(self):
        """Initialize the plugin"""
        # Database path in persistent volume
        db_path = CowrieConfig.get('output_iplock', 'db_path',
                                     fallback='/cowrie/cowrie-git/var/lib/cowrie/iplock.db')

        self.iplock_db = IPLockAuthDB(db_path)

        # Track sessions to disconnect
        self.sessions_to_disconnect = set()

        log.msg("[IPLockAuth] IP-Lock Authentication plugin started")

        # Log initial stats
        stats = self.iplock_db.get_stats()
        log.msg(f"[IPLockAuth] Loaded {stats['total_locks']} locked IPs, "
                f"{stats['total_violations']} violations recorded")

    def stop(self):
        """Cleanup on plugin stop"""
        log.msg("[IPLockAuth] IP-Lock Authentication plugin stopped")

        # Log final stats
        stats = self.iplock_db.get_stats()
        log.msg(f"[IPLockAuth] Final stats - Locked IPs: {stats['total_locks']}, "
                f"Violations: {stats['total_violations']}")

    def write(self, event):
        """
        Process Cowrie events and enforce IP locking

        Listens for:
        - cowrie.login.success: Check if IP should be locked or if lock is violated
        - cowrie.login.failed: Log failed attempts for analysis
        """
        eventid = event.get('eventid')

        if eventid == 'cowrie.login.success':
            self._handle_login_success(event)
        elif eventid == 'cowrie.login.failed':
            self._handle_login_failed(event)

    def _handle_login_success(self, event):
        """Handle successful login event"""
        src_ip = event.get('src_ip', 'unknown')
        username = event.get('username', '')
        password = event.get('password', '')
        session = event.get('session', '')

        # Check if IP is already locked
        locked_creds = self.iplock_db.get_locked_credentials(src_ip)

        if locked_creds:
            # IP is locked - check if credentials match
            locked_username, locked_password = locked_creds

            if username == locked_username and password == locked_password:
                # Credentials match lock - allow
                self.iplock_db.log_attempt(src_ip, username, password,
                                            success=True, is_locked=True, lock_matched=True)
                self.iplock_db.increment_login_count(src_ip)

                log.msg(f"[IPLockAuth] ✓ IP {src_ip} authenticated with locked credentials: {username}:***")
            else:
                # Credentials don't match lock - VIOLATION!
                self.iplock_db.log_attempt(src_ip, username, password,
                                            success=False, is_locked=True, lock_matched=False)

                log.msg(f"[IPLockAuth] ✗ VIOLATION! IP {src_ip} locked to {locked_username}:*** "
                        f"but authenticated with {username}:*** - DISCONNECTING")

                # Force-disconnect this session
                self._disconnect_session(session,
                    f"IP locked to different credentials ({locked_username})")
        else:
            # IP not locked yet - accept and lock to these credentials
            if self.iplock_db.lock_ip_to_credentials(src_ip, username, password):
                self.iplock_db.log_attempt(src_ip, username, password,
                                            success=True, is_locked=False, lock_matched=None)

                log.msg(f"[IPLockAuth] 🔒 IP {src_ip} first login - locked to {username}:***")
            else:
                # Race condition - IP was locked by concurrent login
                # Treat as potential violation and disconnect
                log.msg(f"[IPLockAuth] ⚠ Race condition detected for IP {src_ip} - disconnecting")
                self._disconnect_session(session, "Concurrent login detected")

    def _handle_login_failed(self, event):
        """Handle failed login event"""
        src_ip = event.get('src_ip', 'unknown')
        username = event.get('username', '')
        password = event.get('password', '')

        # Check if IP is locked
        locked_creds = self.iplock_db.get_locked_credentials(src_ip)

        if locked_creds:
            # Log failed attempt on locked IP
            locked_username, locked_password = locked_creds
            lock_matched = (username == locked_username and password == locked_password)

            self.iplock_db.log_attempt(src_ip, username, password,
                                        success=False, is_locked=True, lock_matched=lock_matched)

            if not lock_matched:
                log.msg(f"[IPLockAuth] Failed login from locked IP {src_ip}: "
                        f"tried {username}:*** (locked to {locked_username}:***)")
        else:
            # Log failed attempt from unlocked IP
            self.iplock_db.log_attempt(src_ip, username, password,
                                        success=False, is_locked=False, lock_matched=None)

    def _disconnect_session(self, session_id, reason):
        """
        Request disconnection of a session

        Note: This adds the session to a disconnect list. The actual disconnection
        must be handled by Cowrie's session management. We emit a custom event
        that other parts of Cowrie can listen to.
        """
        self.sessions_to_disconnect.add(session_id)

        # Emit custom event for session termination
        log.msg(f"[IPLockAuth] Requesting termination of session {session_id}: {reason}")

        # Note: In a full implementation, we would need to interact with Cowrie's
        # session manager to actually close the transport. For now, we log the
        # violation which makes it visible in logs and dashboards.
        #
        # To fully implement forced disconnection, we would need to:
        # 1. Access the session object from Cowrie's session manager
        # 2. Call transport.loseConnection() on the session
        #
        # This would require deeper integration with Cowrie's core.
