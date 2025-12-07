#!/usr/bin/env python3
"""
Process master-config.toml and execute commands to fetch secrets.

Reads master-config.toml, executes any shell commands in values
(like "op read op://..."), and outputs a server-ready config.
"""

import sys
import subprocess
import re
import tomllib
from pathlib import Path


def execute_command(value: str) -> str:
    """
    If value looks like a command, execute it and return output.
    Otherwise return the value as-is.

    Detects commands like:
    - "op read op://Personal/Item/field"
    - Any string starting with known command prefixes
    """
    value = value.strip()

    # List of known secret management CLIs
    command_prefixes = ['op read', 'pass', 'vault', 'aws secretsmanager']

    # Check if this looks like a command
    is_command = any(value.startswith(prefix) for prefix in command_prefixes)

    if not is_command:
        return value

    # Execute command and return output
    try:
        result = subprocess.run(
            value,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
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
    with open(config_path, 'rb') as f:
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
    lines = [
        "#!/bin/bash",
        "# Cowrie Daily Report Configuration",
        "# Generated from master-config.toml",
        ""
    ]

    # Paths
    if 'advanced' in config:
        lines.append("# Paths")
        for key, value in config['advanced'].items():
            env_var = key.upper()
            lines.append(f'export {env_var}="{value}"')
        lines.append("")

    # VirusTotal
    if 'reporting' in config and 'virustotal_api_key' in config['reporting']:
        lines.append("# VirusTotal")
        lines.append(f'export VT_API_KEY="{config["reporting"]["virustotal_api_key"]}"')
        lines.append('export VT_ENABLED="true"')
        lines.append("")

    # Email settings
    if 'reporting' in config:
        lines.append("# Email Configuration")
        r = config['reporting']
        if 'email_from' in r:
            lines.append(f'export EMAIL_FROM="{r["email_from"]}"')
        if 'email_to' in r:
            lines.append(f'export EMAIL_TO="{r["email_to"]}"')
        if 'email_subject_prefix' in r:
            lines.append(f'export EMAIL_SUBJECT_PREFIX="{r["email_subject_prefix"]}"')
        if 'max_commands_per_session' in r:
            lines.append(f'export MAX_COMMANDS_PER_SESSION="{r["max_commands_per_session"]}"')
        lines.append("")

    # SMTP settings
    if 'email' in config:
        lines.append("# SMTP Settings")
        e = config['email']
        if 'smtp_host' in e:
            lines.append(f'export SMTP_HOST="{e["smtp_host"]}"')
        if 'smtp_port' in e:
            lines.append(f'export SMTP_PORT="{e["smtp_port"]}"')
        if 'smtp_user' in e:
            lines.append(f'export SMTP_USER="{e["smtp_user"]}"')
        if 'smtp_password' in e:
            lines.append(f'export SMTP_PASSWORD="{e["smtp_password"]}"')
        if 'smtp_tls' in e:
            lines.append(f'export SMTP_TLS="{"true" if e["smtp_tls"] else "false"}"')
        if 'sendgrid_api_key' in e:
            lines.append(f'export SENDGRID_API_KEY="{e["sendgrid_api_key"]}"')
        if 'mailgun_api_key' in e:
            lines.append(f'export MAILGUN_API_KEY="{e["mailgun_api_key"]}"')
        if 'mailgun_domain' in e:
            lines.append(f'export MAILGUN_DOMAIN="{e["mailgun_domain"]}"')
        lines.append("")

    # Webhooks
    if 'alerts' in config:
        lines.append("# Webhook Alerts")
        a = config['alerts']
        if 'slack_webhook' in a:
            lines.append(f'export SLACK_WEBHOOK="{a["slack_webhook"]}"')
        if 'discord_webhook' in a:
            lines.append(f'export DISCORD_WEBHOOK="{a["discord_webhook"]}"')
        if 'teams_webhook' in a:
            lines.append(f'export TEAMS_WEBHOOK="{a["teams_webhook"]}"')
        if 'alert_threshold_connections' in a:
            lines.append(f'export ALERT_THRESHOLD_CONNECTIONS="{a["alert_threshold_connections"]}"')
        if 'alert_on_malware' in a:
            lines.append(f'export ALERT_ON_MALWARE="{"true" if a["alert_on_malware"] else "false"}"')
        lines.append("")

    # Report settings
    if 'advanced' in config and 'report_hours' in config['advanced']:
        lines.append("# Report Settings")
        lines.append(f'export REPORT_HOURS="{config["advanced"]["report_hours"]}"')

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: process-config.py <master-config.toml> [--output env|json]")
        sys.exit(1)

    config_path = sys.argv[1]
    output_format = 'env'

    if len(sys.argv) > 3 and sys.argv[2] == '--output':
        output_format = sys.argv[3]

    if not Path(config_path).exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Process config
    print(f"[*] Processing config: {config_path}", file=sys.stderr)
    config = process_config(config_path)

    # Output in requested format
    if output_format == 'env':
        print(generate_env_file(config))
    elif output_format == 'json':
        import json
        print(json.dumps(config, indent=2))
    else:
        print(f"Error: Unknown output format: {output_format}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
