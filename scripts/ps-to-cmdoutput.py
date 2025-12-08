#!/usr/bin/env python3
"""
Convert ps aux output to Cowrie cmdoutput.json format.

Reads ps.txt (output from 'ps aux') and generates a cmdoutput.json file
compatible with Cowrie's command output system.
"""

import json
import re
import sys
from pathlib import Path


def parse_ps_line(line: str) -> dict | None:
    """
    Parse a line from 'ps aux' output.

    Format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    Example: root 1 0.0 0.1 169656 11404 ? Ss Dec07 0:01 /sbin/init
    """
    # Split on whitespace, but preserve the command (everything after 10 fields)
    parts = line.split(None, 10)

    if len(parts) < 11:
        return None

    try:
        return {
            "USER": parts[0],
            "PID": int(parts[1]),
            "CPU": float(parts[2]),
            "MEM": float(parts[3]),
            "VSZ": int(parts[4]) * 1024,  # Convert KB to bytes
            "RSS": int(parts[5]) * 1024,  # Convert KB to bytes
            "TTY": parts[6],
            "STAT": parts[7],
            "START": parts[8],
            "TIME": parse_time(parts[9]),
            "COMMAND": parts[10].strip()
        }
    except (ValueError, IndexError):
        return None


def parse_time(time_str: str) -> float:
    """
    Convert TIME field (MM:SS or HH:MM:SS) to seconds.

    Examples: "0:01" -> 1.0, "1:23:45" -> 5025.0
    """
    parts = time_str.split(":")

    try:
        if len(parts) == 2:  # MM:SS
            return int(parts[0]) * 60 + int(parts[1])
        elif len(parts) == 3:  # HH:MM:SS
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        else:
            return 0.0
    except ValueError:
        return 0.0


def convert_ps_to_cmdoutput(ps_file: Path) -> dict:
    """Convert ps.txt file to cmdoutput.json structure."""
    processes = []

    with open(ps_file, 'r') as f:
        lines = f.readlines()

    # Skip header line (first line of ps aux output)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        process = parse_ps_line(line)
        if process:
            processes.append(process)

    return {
        "command": {
            "ps": processes
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: ps-to-cmdoutput.py <ps.txt> [output.json]")
        print("  ps.txt: Input file containing 'ps aux' output")
        print("  output.json: Optional output file (default: cmdoutput.json)")
        sys.exit(1)

    ps_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("cmdoutput.json")

    if not ps_file.exists():
        print(f"Error: Input file not found: {ps_file}", file=sys.stderr)
        sys.exit(1)

    # Convert ps output to cmdoutput.json structure
    cmdoutput = convert_ps_to_cmdoutput(ps_file)

    # Write JSON output
    with open(output_file, 'w') as f:
        json.dump(cmdoutput, f, indent=2)

    process_count = len(cmdoutput["command"]["ps"])
    print(f"[*] Converted {process_count} processes to {output_file}", file=sys.stderr)


if __name__ == '__main__':
    main()
