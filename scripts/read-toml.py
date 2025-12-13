#!/usr/bin/env python3
"""
TOML Configuration Reader for Cowrie Deployment Scripts

This script provides a safe way to read TOML configuration values
from bash scripts, replacing fragile sed/grep parsing.

Usage:
    python3 scripts/read-toml.py <toml_file> <key_path>

Examples:
    python3 scripts/read-toml.py master-config.toml "deployment.server_type"
    python3 scripts/read-toml.py master-config.toml "deployment.ssh_keys"
    python3 scripts/read-toml.py master-config.toml "honeypot.enable_reporting"

Key paths use dot notation: section.key
For arrays, returns JSON array format
For booleans, returns "true" or "false"
"""

import sys
import tomllib
from pathlib import Path


def get_nested_value(data: dict, key_path: str):
    """
    Get nested value from dictionary using dot notation.

    Args:
        data: Dictionary to search
        key_path: Dot-separated path (e.g., "deployment.server_type")

    Returns:
        Value at the key path, or None if not found
    """
    keys = key_path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    return current


def format_value(value):
    """
    Format value for bash consumption.

    Args:
        value: Python value to format

    Returns:
        String representation suitable for bash
    """
    if value is None:
        return ""
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, list):
        # Return as newline-separated string for bash arrays
        # Each item on its own line, properly handles items with spaces
        return "\n".join(str(item) for item in value)
    elif isinstance(value, (int, float)):
        return str(value)
    else:
        # String - return as-is (caller should quote in bash)
        return str(value)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 read-toml.py <toml_file> <key_path>", file=sys.stderr)
        print("", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print('  python3 read-toml.py config.toml "deployment.server_type"', file=sys.stderr)
        print('  python3 read-toml.py config.toml "deployment.ssh_keys"', file=sys.stderr)
        sys.exit(1)

    toml_file = Path(sys.argv[1])
    key_path = sys.argv[2]

    # Check if file exists
    if not toml_file.exists():
        print(f"Error: TOML file not found: {toml_file}", file=sys.stderr)
        sys.exit(1)

    # Read and parse TOML file
    try:
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        print(f"Error parsing TOML file: {e}", file=sys.stderr)
        sys.exit(1)

    # Get value at key path
    value = get_nested_value(data, key_path)

    if value is None:
        # Key not found - return empty string (bash can check for empty)
        print("", end="")
        sys.exit(0)

    # Format and print value
    formatted = format_value(value)
    # For arrays, ensure trailing newline so bash can read all items
    if isinstance(value, list) and formatted:
        print(formatted)  # print() adds newline automatically
    else:
        print(formatted, end="")
    sys.exit(0)


if __name__ == "__main__":
    main()
