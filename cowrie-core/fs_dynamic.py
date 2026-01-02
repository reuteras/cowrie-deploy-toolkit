# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
Dynamic filesystem with real-time /proc/uptime
"""

from __future__ import annotations

import time

from cowrie.shell.fs import HoneyPotFilesystem


class DynamicHoneyPotFilesystem(HoneyPotFilesystem):
    """
    HoneyPotFilesystem with dynamic /proc/uptime that changes based on container runtime
    """

    def __init__(self, arch: str, home: str) -> None:
        super().__init__(arch, home)
        # Track when the container/honeypot started
        self.start_time = time.time()

    def file_contents(self, target: str):
        """
        Override file_contents to provide dynamic /proc/uptime
        """
        if target == "/proc/uptime":
            # Return dynamic uptime: seconds since container start, plus some idle time
            uptime_seconds = time.time() - self.start_time
            idle_seconds = uptime_seconds * 0.95  # Simulate some idle time
            content = f"{uptime_seconds:.2f} {idle_seconds:.2f}\n"
            return content.encode("utf-8")

        # For all other files, use the parent implementation
        return super().file_contents(target)


# Monkey patch the original HoneyPotFilesystem to use our dynamic version
# This allows us to override the filesystem behavior without changing core Cowrie code
import cowrie.shell.fs

cowrie.shell.fs.HoneyPotFilesystem = DynamicHoneyPotFilesystem
