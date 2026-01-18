#!/usr/bin/env python3
"""
Process master-config.toml and execute commands to fetch secrets.

Reads master-config.toml, executes any shell commands in values
(like "op read op://..."), and outputs a server-ready config.
"""

import shlex
import subprocess
import sys
from pathlib import Path

import tomllib


def execute_command(value: str) -> str:
    """
    If value looks like a command, execute it and return output.
    Otherwise return the value as-is.

    Detects commands like:
    - "op read op://Personal/Item/field"
    - Any string starting with known command prefixes

    SECURITY: Uses array-based execution (shell=False) to prevent command injection.
    """
    value = value.strip()

    # List of allowed secret management CLIs (executable names only)
    allowed_commands = {
        "op": ["read"],  # 1Password CLI: op read <ref>
        "pass": [],  # Unix password manager: pass <entry>
        "vault": ["read"],  # HashiCorp Vault: vault read <path>
        "aws": ["secretsmanager"],  # AWS Secrets Manager: aws secretsmanager get-secret-value ...
    }

    # Parse command into array (prevents shell injection)
    try:
        command_array = shlex.split(value)
    except ValueError:
        # Invalid shell syntax - not a valid command
        return value

    if not command_array:
        return value

    # Check if first token is an allowed command
    cmd = command_array[0]
    if cmd not in allowed_commands:
        return value

    # Additional validation for specific commands
    allowed_subcommands = allowed_commands[cmd]
    if allowed_subcommands:
        # Verify subcommand is allowed (e.g., "op read" not "op delete")
        if len(command_array) < 2 or command_array[1] not in allowed_subcommands:
            print(f"Warning: Subcommand not allowed: {value}", file=sys.stderr)
            return value

    # Execute command with array (shell=False) - SAFE from command injection
    try:
        result = subprocess.run(
            command_array,  # Array, not string - prevents shell injection
            shell=False,  # CRITICAL: shell=False prevents command injection
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"Warning: Command failed: {value}", file=sys.stderr)
            print(f"Error: {result.stderr}", file=sys.stderr)
            return value  # Return original value as fallback

    except subprocess.TimeoutExpired:
        print(f"Warning: Command timed out: {value}", file=sys.stderr)
        return value
    except Exception as e:
        print(f"Warning: Command execution failed: {value}: {e}", file=sys.stderr)
        return value


def process_config(config_path: str) -> dict:
    """Process config file and execute any commands."""
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    # Recursively process all string values
    def process_value(val):
        if isinstance(val, str):
            return execute_command(val)
        elif isinstance(val, dict):
            return {k: process_value(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [process_value(v) for v in val]
        else:
            return val

    return process_value(config)


def generate_env_file(config: dict) -> str:
    """Generate environment variable file for server."""
    lines = ["#!/bin/bash", "# Cowrie Daily Report Configuration", "# Generated from master-config.toml", ""]

    # Handle both direct config and shared.* prefixed config
    # The config structure is: config["shared"]["reporting"], config["shared"]["email"], etc.
    shared = config.get("shared", {})
    reporting = shared.get("reporting", config.get("reporting", {}))
    email = shared.get("email", config.get("email", {}))
    advanced = shared.get("advanced", config.get("advanced", {}))

    # Paths
    if advanced:
        lines.append("# Paths")
        for key, value in advanced.items():
            env_var = key.upper()
            lines.append(f'export {env_var}="{value}"')
        lines.append("")

    # VirusTotal
    if reporting and "virustotal_api_key" in reporting:
        lines.append("# VirusTotal")
        lines.append(f'export VT_API_KEY="{reporting["virustotal_api_key"]}"')
        lines.append('export VT_ENABLED="true"')
        lines.append("")

    # Email settings
    if reporting:
        lines.append("# Email Configuration")
        if "email_from" in reporting:
            lines.append(f'export EMAIL_FROM="{reporting["email_from"]}"')
        if "email_to" in reporting:
            lines.append(f'export EMAIL_TO="{reporting["email_to"]}"')
        if "email_subject_prefix" in reporting:
            lines.append(f'export EMAIL_SUBJECT_PREFIX="{reporting["email_subject_prefix"]}"')
        if "max_commands_per_session" in reporting:
            lines.append(f'export MAX_COMMANDS_PER_SESSION="{reporting["max_commands_per_session"]}"')
        lines.append("")

    # SMTP settings
    if email:
        lines.append("# SMTP Settings")
        if "smtp_host" in email:
            lines.append(f'export SMTP_HOST="{email["smtp_host"]}"')
        if "smtp_port" in email:
            lines.append(f'export SMTP_PORT="{email["smtp_port"]}"')
        if "smtp_user" in email:
            lines.append(f'export SMTP_USER="{email["smtp_user"]}"')
        if "smtp_password" in email:
            lines.append(f'export SMTP_PASSWORD="{email["smtp_password"]}"')
        if "smtp_tls" in email:
            lines.append(f'export SMTP_TLS="{"true" if email["smtp_tls"] else "false"}"')

        lines.append("")

    # Report settings
    if advanced and "report_hours" in advanced:
        lines.append("# Report Settings")
        lines.append(f'export REPORT_HOURS="{advanced["report_hours"]}"')

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: process-config.py <master-config.toml> [--output env|json]")
        sys.exit(1)

    config_path = sys.argv[1]
    output_format = "env"

    if len(sys.argv) > 3 and sys.argv[2] == "--output":
        output_format = sys.argv[3]

    if not Path(config_path).exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Process config
    print(f"[*] Processing config: {config_path}", file=sys.stderr)
    config = process_config(config_path)

    # Output in requested format
    if output_format == "env":
        print(generate_env_file(config))
    elif output_format == "json":
        import json

        print(json.dumps(config, indent=2))
    else:
        print(f"Error: Unknown output format: {output_format}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
