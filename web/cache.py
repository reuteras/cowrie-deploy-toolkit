#!/usr/bin/env python3
"""
Response Cache for Multi-Source Dashboard

Provides TTL-based caching to reduce API calls and prevent resource exhaustion.
"""

import time
from threading import Lock
from typing import Any, Optional


class ResponseCache:
    """Thread-safe cache with TTL support."""

    def __init__(self, default_ttl: int = 30):
        """
        Initialize cache.

        Args:
            default_ttl: Default time-to-live in seconds
        """
        self.default_ttl = default_ttl
        self.cache = {}
        self.lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if expired/missing
        """
        with self.lock:
            if key not in self.cache:
                return None

            value, expiry = self.cache[key]
            if time.time() > expiry:
                # Expired, remove from cache
                del self.cache[key]
                return None

            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.default_ttl

        expiry = time.time() + ttl

        with self.lock:
            self.cache[key] = (value, expiry)

    def clear(self):
        """Clear all cached entries."""
        with self.lock:
            self.cache.clear()

    def cleanup_expired(self):
        """Remove expired entries from cache."""
        now = time.time()
        with self.lock:
            expired_keys = [key for key, (_, expiry) in self.cache.items() if now > expiry]
            for key in expired_keys:
                del self.cache[key]


class ExponentialBackoff:
    """Exponential backoff for failed connections."""

    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, max_failures: int = 5):
        """
        Initialize backoff tracker.

        Args:
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            max_failures: Max consecutive failures before giving up
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_failures = max_failures
        self.failures = {}  # source_name -> (failure_count, last_attempt_time)
        self.lock = Lock()

    def should_retry(self, source_name: str) -> bool:
        """
        Check if we should attempt to connect to this source.

        Args:
            source_name: Source identifier

        Returns:
            True if we should attempt connection
        """
        with self.lock:
            if source_name not in self.failures:
                return True

            failure_count, last_attempt = self.failures[source_name]

            # If max failures reached, wait for max_delay before trying again
            if failure_count >= self.max_failures:
                if time.time() - last_attempt < self.max_delay:
                    return False
                # Reset after max_delay has passed
                del self.failures[source_name]
                return True

            # Calculate delay based on failure count
            delay = min(self.base_delay * (2**failure_count), self.max_delay)

            if time.time() - last_attempt < delay:
                return False

            return True

    def record_failure(self, source_name: str):
        """
        Record a failed connection attempt.

        Args:
            source_name: Source identifier
        """
        with self.lock:
            if source_name in self.failures:
                failure_count, _ = self.failures[source_name]
                self.failures[source_name] = (failure_count + 1, time.time())
            else:
                self.failures[source_name] = (1, time.time())

    def record_success(self, source_name: str):
        """
        Record a successful connection (resets failure count).

        Args:
            source_name: Source identifier
        """
        with self.lock:
            if source_name in self.failures:
                del self.failures[source_name]

    def get_status(self, source_name: str) -> dict:
        """
        Get backoff status for a source.

        Args:
            source_name: Source identifier

        Returns:
            Dict with failure count and next retry time
        """
        with self.lock:
            if source_name not in self.failures:
                return {"failures": 0, "available": True}

            failure_count, last_attempt = self.failures[source_name]
            delay = min(self.base_delay * (2**failure_count), self.max_delay)
            next_retry = last_attempt + delay

            return {
                "failures": failure_count,
                "available": self.should_retry(source_name),
                "next_retry": next_retry,
                "retry_in_seconds": max(0, next_retry - time.time()),
            }
