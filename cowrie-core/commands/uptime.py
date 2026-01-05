# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
Uptime command that matches dynamic /proc/uptime output
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cowrie.shell.command import HoneyPotCommand

# Monkey patch to access the filesystem start time
import cowrie.shell.fs
from cowrie.shell.command import HoneyPotCommand

commands = {}


class command_uptime(HoneyPotCommand):
    """
    uptime command that shows consistent output with /proc/uptime
    """

    def call(self) -> None:
        """
        Show system uptime information with randomized load averages
        """
        import random

        # Try to get start time from dynamic filesystem if available
        start_time = None
        if hasattr(cowrie.shell.fs, "HoneyPotFilesystem"):
            fs_class = cowrie.shell.fs.HoneyPotFilesystem
            start_time = getattr(fs_class, "_start_time", None)

        if start_time is None:
            # Fallback to current time if no start time available
            start_time = time.time() - 3600  # Assume 1 hour uptime as fallback

        uptime_seconds = time.time() - start_time
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        # Generate realistic randomized load averages
        # Typical ranges: 0.00-2.00 for normal systems, occasional spikes higher
        base_load = random.uniform(0.00, 1.50)

        # 1-minute average (highest, most current)
        load_1min = round(base_load + random.uniform(0.00, 0.50), 2)

        # 5-minute average (middle)
        load_5min = round(base_load + random.uniform(0.00, 0.30), 2)

        # 15-minute average (lowest, most stable)
        load_15min = round(base_load + random.uniform(0.00, 0.20), 2)

        # Ensure realistic relationships (15min <= 5min <= 1min, with some variation)
        load_15min = min(load_15min, load_5min, load_1min)
        load_5min = min(load_5min, load_1min)

        load_avg = f"{load_1min:.2f}, {load_5min:.2f}, {load_15min:.2f}"

        self.write(f" {time.strftime('%H:%M:%S')} up {hours:2d}:{minutes:02d},  1 user,  load average: {load_avg}\n")


commands["/usr/bin/uptime"] = command_uptime
commands["uptime"] = command_uptime
