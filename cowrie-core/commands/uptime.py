# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
uptime command that matches /proc/uptime output
"""

from __future__ import annotations

import time

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_uptime(HoneyPotCommand):
    """
    uptime command
    """

    def call(self) -> None:
        # Get uptime from the filesystem's start time (same as /proc/uptime)
        uptime_seconds = self.protocol.fs.start_time
        if hasattr(self.protocol.fs, "start_time") and uptime_seconds:
            total_seconds = time.time() - uptime_seconds

            # Format like standard uptime output
            days = int(total_seconds // 86400)
            hours = int((total_seconds % 86400) // 3600)
            minutes = int((total_seconds % 3600) // 60)

            if days > 0:
                uptime_str = f"{days} day{'s' if days != 1 else ''}, {hours:2d}:{minutes:02d}"
            else:
                uptime_str = f"{hours:2d}:{minutes:02d}"

            # Get current time
            import datetime

            now = datetime.datetime.now()
            time_str = now.strftime("%H:%M:%S")

            self.write(f" {time_str} up {uptime_str},  1 user,  load average: 0.00, 0.01, 0.05\n")
        else:
            # Fallback to simple uptime display
            self.write(" 10:30:45 up 1 day,  2:35,  1 user,  load average: 0.00, 0.01, 0.05\n")


commands["/usr/bin/uptime"] = Command_uptime
commands["uptime"] = Command_uptime
