# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains authentication code
"""

from __future__ import annotations

import configparser
import re
import sqlite3
from collections import OrderedDict
from pathlib import Path
from re import Pattern

from cowrie.core.config import CowrieConfig
from twisted.python import log

_USERDB_DEFAULTS: list[str] = [
    "root:x:!root",
    "root:x:!123456",
    "root:x:!/honeypot/i",
    "root:x:*",
]


class IPUserDB:
    """
    By Walter de Jong <walter@sara.nl>
    Extended with IP support by Peter Reuterås <peter@reuteras.net>
    """

    def __init__(self) -> None:
        self.userdb: dict[tuple[Pattern[bytes] | bytes, Pattern[bytes] | bytes], bool] = OrderedDict()
        self.load()
        self.db_path = CowrieConfig.get("honeypot", "userdb_path")
        self.min_len = int(CowrieConfig.get("honeypot", "minimum_password_len"))
        self._init_database()

    def load(self) -> None:
        """
        load the user db
        """

        dblines: list[str]
        try:
            with open(
                "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path")),
                encoding="ascii",
            ) as db:
                dblines = db.readlines()
        except (OSError, configparser.Error):
            log.msg("Could not read etc/userdb.txt, default database activated")
            dblines = _USERDB_DEFAULTS

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.adduser(login, password)

    def _init_database(self):
        """Create database schema if not exists"""

        if Path(self.db_path).is_file():
            return

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

    def increment_login_count(self, src_ip):
        """Increment successful login count for a locked IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE ip_locks
            SET login_count = login_count + 1,
                last_login_at = CURRENT_TIMESTAMP
            WHERE src_ip = ?
        """,
            (src_ip,),
        )

        conn.commit()
        conn.close()

    def get_locked_credentials(self, src_ip):
        """
        Get locked credentials for an IP address

        Returns:
            tuple: (username, password) or None if not locked
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT username, password FROM ip_locks WHERE src_ip = ?
        """,
            (src_ip,),
        )

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
            cursor.execute(
                """
                INSERT INTO ip_locks (src_ip, username, password)
                VALUES (?, ?, ?)
            """,
                (src_ip, username, password),
            )

            conn.commit()
            conn.close()

            log.msg(f"[IPLockAuth] IP {src_ip} locked to credentials: {username}:{password}")
            return True
        except sqlite3.IntegrityError:
            # IP already locked (race condition or concurrent login)
            conn.close()
            return False

    def checklogin(self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0") -> bool:
        if len(thepasswd) <= self.min_len:
            log.msg("[IPLockAuth] Password too short")
            self.log_attempt(src_ip, thelogin, thepasswd, False, False)
            return False

        locked = self.get_locked_credentials(src_ip)

        if locked:
            if locked != (thelogin, thepasswd):
                log.msg(f"[IPLockAuth] IP {src_ip} locked to different credentials, rejecting")
                self.log_attempt(src_ip, thelogin, thepasswd, False, True, lock_matched=False)
                return False

        for credentials, policy in self.userdb.items():
            login: bytes | Pattern[bytes]
            passwd: bytes | Pattern[bytes]
            login, passwd = credentials

            if self.match_rule(login, thelogin):
                if self.match_rule(passwd, thepasswd):
                    if policy and not locked:
                        # First successful login - lock IP to these credentials
                        self.lock_ip_to_credentials(src_ip, thelogin, thepasswd)
                        self.log_attempt(src_ip, thelogin, thepasswd, True, False)
                    elif locked:
                        # Subsequent successful login with locked credentials
                        self.increment_login_count(src_ip)
                        self.log_attempt(src_ip, thelogin, thepasswd, True, True, lock_matched=True)
                    return policy

        self.log_attempt(src_ip, thelogin, thepasswd, False, bool(locked), lock_matched=None)
        return False

    def match_rule(self, rule: bytes | Pattern[bytes], data: bytes) -> bool | bytes:
        if isinstance(rule, bytes):
            return rule in [b"*", data]
        return bool(rule.search(data))

    def re_or_bytes(self, rule: bytes) -> Pattern[bytes] | bytes:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is

        @param login: rule
        @type login: bytes
        """
        res = re.match(rb"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule

    def adduser(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes

        @param login: user id
        @type login: bytes
        @param passwd: password
        @type passwd: bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.userdb[(user, p)] = policy

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

        cursor.execute(
            """
            INSERT INTO auth_attempts (src_ip, username, password, success, is_locked, lock_matched)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (src_ip, username, password, success, is_locked, lock_matched),
        )

        conn.commit()
        conn.close()
