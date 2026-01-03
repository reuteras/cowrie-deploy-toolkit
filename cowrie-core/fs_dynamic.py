# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
Dynamic filesystem with real-time /proc/uptime
"""

from __future__ import annotations

import time

# Monkey patch the original HoneyPotFilesystem to use our dynamic version
# This allows us to override the filesystem behavior without changing core Cowrie code
import cowrie.shell.fs
from cowrie.shell.fs import HoneyPotFilesystem


class DynamicHoneyPotFilesystem(HoneyPotFilesystem):
    """
    HoneyPotFilesystem with dynamic /proc/uptime that changes based on container runtime
    """

    # Class variable to store start time across instances
    _start_time = None

    def __init__(self, arch: str, home: str) -> None:
        super().__init__(arch, home)
        # Track when the container/honeypot started
        if DynamicHoneyPotFilesystem._start_time is None:
            DynamicHoneyPotFilesystem._start_time = time.time()
        self.start_time = DynamicHoneyPotFilesystem._start_time

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


# Apply the monkey patch to replace the filesystem class
print("Dynamic filesystem: Installing monkey patch for /proc/uptime")
cowrie.shell.fs.HoneyPotFilesystem = DynamicHoneyPotFilesystem

# Also patch the module's direct reference if it exists
import sys

if hasattr(sys.modules.get("cowrie.shell.fs"), "HoneyPotFilesystem"):
    sys.modules["cowrie.shell.fs"].HoneyPotFilesystem = DynamicHoneyPotFilesystem
