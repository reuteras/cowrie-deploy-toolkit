#!/usr/bin/env python3
"""
Honeypot Configuration Helper for Multi-Honeypot Deployments

This script handles reading and merging honeypot configurations from master-config.toml.

Usage:
    # List all honeypot names
    python3 scripts/get-honeypot-config.py master-config.toml --list

    # Get specific honeypot's merged config as JSON
    python3 scripts/get-honeypot-config.py master-config.toml --name cowrie-hp-1

    # Get shared configuration as JSON
    python3 scripts/get-honeypot-config.py master-config.toml --shared

    # Check if honeypots array exists
    python3 scripts/get-honeypot-config.py master-config.toml --has-array

    # Get count of honeypots
    python3 scripts/get-honeypot-config.py master-config.toml --count
"""

import sys
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import tomllib


def merge_configs(shared: Dict[str, Any], honeypot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge shared configuration with honeypot-specific configuration.

    Honeypot-specific values override shared values.

    Args:
        shared: Shared configuration from [shared.*] sections
        honeypot: Honeypot-specific configuration from [[honeypots]]

    Returns:
        Merged configuration dictionary
    """
    merged = {}

    # Start with flattened shared config
    for section, values in shared.items():
        if isinstance(values, dict):
            for key, value in values.items():
                merged[key] = value
        else:
            merged[section] = values

    # Override with honeypot-specific config
    for key, value in honeypot.items():
        merged[key] = value

    return merged


def get_honeypots(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get list of honeypot configurations."""
    return data.get("honeypots", [])


def has_honeypots_array(data: Dict[str, Any]) -> bool:
    """Check if [[honeypots]] array exists and has items."""
    honeypots = data.get("honeypots", [])
    return isinstance(honeypots, list) and len(honeypots) > 0


def get_shared_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract shared configuration from [shared.*] sections."""
    return data.get("shared", {})


def get_honeypot_by_name(
    data: Dict[str, Any], name: str
) -> Optional[Dict[str, Any]]:
    """
    Get specific honeypot configuration by name, merged with shared config.

    Args:
        data: Parsed TOML data
        name: Honeypot name to find

    Returns:
        Merged configuration dictionary or None if not found
    """
    honeypots = get_honeypots(data)
    shared = get_shared_config(data)

    for honeypot in honeypots:
        if honeypot.get("name") == name:
            return merge_configs(shared, honeypot)

    return None


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 get-honeypot-config.py <toml_file> <--list|--name NAME|--has-array|--count|--shared>", file=sys.stderr)
        sys.exit(1)

    toml_file = Path(sys.argv[1])
    operation = sys.argv[2]

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

    # Handle operations
    if operation == "--list":
        # List all honeypot names
        honeypots = get_honeypots(data)
        names = [h.get("name", "") for h in honeypots if h.get("name")]
        for name in names:
            print(name)

    elif operation == "--count":
        # Count honeypots
        honeypots = get_honeypots(data)
        print(len(honeypots))

    elif operation == "--has-array":
        # Check if honeypots array exists
        print("true" if has_honeypots_array(data) else "false")

    elif operation == "--name":
        # Get specific honeypot's merged config
        if len(sys.argv) < 4:
            print("Error: --name requires a honeypot name", file=sys.stderr)
            sys.exit(1)

        name = sys.argv[3]
        config = get_honeypot_by_name(data, name)

        if config is None:
            print(f"Error: Honeypot '{name}' not found", file=sys.stderr)
            sys.exit(1)

        # Output as JSON for easy parsing in bash
        print(json.dumps(config, indent=2))

    elif operation == "--shared":
        # Get shared configuration (flattened from [shared.*] sections)
        shared = get_shared_config(data)

        # Flatten the shared config
        flattened = {}
        for section, values in shared.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    flattened[key] = value
            else:
                flattened[section] = values

        # Output as JSON
        print(json.dumps(flattened, indent=2))

    else:
        print(f"Error: Unknown operation: {operation}", file=sys.stderr)
        print("Valid operations: --list, --name NAME, --has-array, --count, --shared", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
