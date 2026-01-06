# Cowrie Deploy Toolkit - Improvement Opportunities

This document outlines potential simplifications and robustness improvements identified through comprehensive code analysis.

## Table of Contents

- [Code Simplification Opportunities](#code-simplification-opportunities)
- [Robustness Improvements](#robustness-improvements)
- [Configuration & Validation](#configuration--validation)
- [Testing & CI/CD](#testing--cicd)
- [Documentation Gaps](#documentation-gaps)

---

## Code Simplification Opportunities

### 1. Modularize Deploy Script (2140 lines → ~500 lines per module)

**Current State:**
- Single monolithic `deploy_cowrie_honeypot.sh` (2140 lines)
- Difficult to test individual components
- High cognitive load when making changes

**Proposed Structure:**
```bash
deploy/
├── 00-init.sh           # Parse args, validate config, set globals
├── 10-server.sh         # Hetzner server creation, SSH wait
├── 20-base.sh           # Docker, Tailscale, base packages
├── 30-cowrie.sh         # Cowrie container deployment
├── 40-reporting.sh      # MaxMind, Postfix, reporting setup
├── 50-dashboard.sh      # Web dashboard deployment
├── 60-api.sh            # API deployment
├── 70-finalize.sh       # VERSION.json, cleanup
└── common.sh            # Shared functions

# Main script becomes:
for module in deploy/*.sh; do
    source "$module" || handle_rollback
done
```

**Benefits:**
- Easier testing (can test each module independently)
- Clearer separation of concerns
- Reusable components (e.g., `40-reporting.sh` could be standalone)
- Faster development (smaller files to navigate)

**Effort:** Medium (2-3 days refactoring)

---

### 2. Replace sed Placeholders with Template Engine

**Current State:**
```bash
cat > /opt/cowrie/docker-compose.yml << 'DOCKEREOF'
...
environment:
  - BASE_URL=WEB_BASE_URL_PLACEHOLDER
  - VT_API_KEY=VT_API_KEY_PLACEHOLDER
DOCKEREOF

sed -i "s|WEB_BASE_URL_PLACEHOLDER|$WEB_BASE_URL|g" /opt/cowrie/docker-compose.yml
sed -i "s|VT_API_KEY_PLACEHOLDER|$VT_API_KEY|g" /opt/cowrie/docker-compose.yml
```

**Problems:**
- Fragile (string replacement can break on special chars)
- Verbose (14 separate `sed -i` calls)
- Hard to debug (template and substitution separated)

**Proposed Solution:** Use `envsubst` or Jinja2

**Option A: envsubst (simple, bash-native)**
```bash
export WEB_BASE_URL VT_API_KEY SERVER_IP  # etc.
envsubst < templates/docker-compose.yml.tmpl > /opt/cowrie/docker-compose.yml
```

**Option B: Jinja2 (more powerful)**
```python
# scripts/render-template.py
from jinja2 import Template
template = Template(open('templates/docker-compose.yml.j2').read())
output = template.render(
    web_base_url=os.getenv('WEB_BASE_URL'),
    vt_api_key=os.getenv('VT_API_KEY'),
    # ...
)
```

**Benefits:**
- More reliable (proper escaping)
- Easier to maintain (single template file)
- Better error messages

**Effort:** Low (1 day)

---

### 3. Simplify Dashboard Mode Naming

**Current Confusion:**
- "Local mode" doesn't mean "local file access" (it means "local API")
- Documentation inconsistency (README says "direct files", code uses API)

**Proposed Renaming:**
```toml
[web_dashboard]
mode = "internal-api"  # Was "local" - clarifies it uses local API
mode = "remote-api"    # Was "remote" - explicit about API access
mode = "multi-api"     # Was "multi" - clear it aggregates via APIs
```

**Or Alternative:**
```toml
[web_dashboard]
data_source = "local"    # Local API endpoint
data_source = "remote"   # Single remote API
data_source = "multi"    # Multiple remote APIs

# Implementation detail (always API):
api_mode = true  # Never false in v2.1
```

**Benefits:**
- Clearer intent
- Reduced confusion for users
- Better documentation alignment

**Effort:** Low (1 day - rename + update docs)

---

### 4. Abstract SSH Connection Logic

**Current State:**
```bash
# Duplicated in update-honeypots.sh, deploy script, etc.
if [ "$USE_TAILSCALE_SSH" = "true" ]; then
    ssh root@$TAILSCALE_NAME "command"
else
    ssh -p 2222 root@$SERVER_IP "command"
fi
```

**Proposed: Common Function**
```bash
# scripts/common.sh
ssh_connect() {
    local server_id="$1"
    shift  # remaining args are the command

    local use_tailscale=$(get_config_value "$server_id" "use_tailscale_ssh")
    local tailscale_name=$(get_config_value "$server_id" "tailscale_name")
    local server_ip=$(get_config_value "$server_id" "server_ip")

    if [ "$use_tailscale" = "true" ]; then
        ssh root@"$tailscale_name" "$@"
    else
        ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR root@"$server_ip" "$@"
    fi
}

# Usage:
ssh_connect cowrie-hp-1 "cd /opt/cowrie && git pull"
```

**Benefits:**
- DRY (Don't Repeat Yourself)
- Centralized connection logic
- Easier to add features (e.g., SSH key selection)

**Effort:** Low (4 hours)

---

### 5. Consolidate Configuration Processing

**Current Chain:**
```text
master-config.toml
  → get-honeypot-config.py (Python)
  → JSON
  → bash eval
  → process-config.py (Python)
  → report.env
```

**Proposed: Single-Pass Processing**
```python
# scripts/process-all-config.py
import toml
import json
import subprocess

config = toml.load('master-config.toml')

# Execute "op read" commands
for key, value in config.items():
    if isinstance(value, str) and value.startswith('op read'):
        config[key] = subprocess.check_output(value.split(), text=True).strip()

# Output formats
json.dump(config, open('/tmp/config.json', 'w'))  # For bash consumption
write_env_file(config, '/tmp/report.env')  # For reporting
write_cowrie_cfg(config, '/tmp/cowrie.cfg')  # For Cowrie
```

**Benefits:**
- Single source of truth
- Fewer intermediate steps
- Easier debugging (one script to check)

**Effort:** Medium (2 days)

---

## Robustness Improvements

### 1. Add Configuration Schema Validation

**Current Problem:**
- Missing required fields caught late (during deployment)
- Typos in field names silently ignored
- No type checking (e.g., port as string instead of int)

**Proposed: JSON Schema**
```python
# scripts/validate-config.py
import jsonschema
import toml

schema = {
    "type": "object",
    "required": ["shared"],
    "properties": {
        "shared": {
            "type": "object",
            "required": ["tailscale"],
            "properties": {
                "tailscale": {
                    "type": "object",
                    "required": ["authkey", "tailscale_domain"],
                    "properties": {
                        "authkey": {"type": "string", "pattern": "^tskey-auth-"},
                        "tailscale_domain": {"type": "string", "pattern": "\\.ts\\.net$"}
                    }
                }
            }
        },
        "honeypots": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "hostname"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[a-z0-9-]+$"},
                    "api_enabled": {"type": "boolean"}
                }
            }
        }
    }
}

config = toml.load('master-config.toml')
jsonschema.validate(config, schema)
```

**Benefits:**
- Fail fast with clear error messages
- Self-documenting (schema defines valid config)
- Type safety (catches string vs int errors)

**Effort:** Medium (2 days to write schema + integrate)

---

### 2. Add Network Retry Logic

**Current Problem:**
- Docker pulls, git clones, SCP uploads fail on transient network errors
- No retry logic (deployment fails completely)

**Proposed:**
```bash
# scripts/common.sh
retry_with_backoff() {
    local max_attempts=3
    local timeout=1
    local attempt=1
    local exitCode=0

    while [ $attempt -le $max_attempts ]; do
        if "$@"; then
            return 0
        else
            exitCode=$?
        fi

        if [ $attempt -lt $max_attempts ]; then
            echo "Attempt $attempt failed. Retrying in ${timeout}s..." >&2
            sleep $timeout
            timeout=$((timeout * 2))  # Exponential backoff
        fi

        attempt=$((attempt + 1))
    done

    echo "All $max_attempts attempts failed." >&2
    return $exitCode
}

# Usage:
retry_with_backoff git clone https://github.com/...
retry_with_backoff docker compose pull
retry_with_backoff scp -P 2222 file.txt root@server:/tmp/
```

**Benefits:**
- More reliable deployments
- Handles transient network issues
- Reduced manual intervention

**Effort:** Low (4 hours)

---

*Last updated: 2026-01-05*
*Based on comprehensive code analysis of v2.1*
