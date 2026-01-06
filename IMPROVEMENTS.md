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
```
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

### 1. Add Dry-Run Mode

**Current Problem:**
- Errors discovered mid-deployment (can fail after server created)
- No way to validate configuration before spending money/time

**Proposed:**
```bash
./deploy_cowrie_honeypot.sh ./output_dir --dry-run

# Output:
✓ Configuration valid
✓ Output directory exists and contains required files
✓ Hetzner API accessible
✓ Tailscale authkey valid
✓ SSH keys found in Hetzner account
⚠ MaxMind license key not set (reporting will be disabled)
✗ SMTP credentials missing (deployment would fail at step 16)

Estimated cost: €5.83/month (cx22 server in hel1)
Estimated deployment time: 8-12 minutes
```

**Implementation:**
```bash
DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
fi

# In each step:
if [ "$DRY_RUN" = "true" ]; then
    echo "[DRY-RUN] Would create server..."
    return 0
fi
hcloud server create ...
```

**Benefits:**
- Fail fast (before creating resources)
- Cost estimation
- Configuration validation

**Effort:** Medium (2-3 days)

---

### 2. Add Configuration Schema Validation

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

### 3. Add Network Retry Logic

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

### 4. Add Resource Pre-Flight Checks

**Current Problem:**
- No disk space checks before downloading/uploading
- No memory checks before starting containers
- Can fail mid-deployment with cryptic errors

**Proposed:**
```bash
preflight_checks() {
    echo "Running pre-flight checks..."

    # Check disk space (need ~5GB for images + logs)
    local available_gb=$(df /opt --output=avail | tail -1 | awk '{print int($1/1024/1024)}')
    if [ $available_gb -lt 5 ]; then
        echo "ERROR: Insufficient disk space ($available_gb GB available, need 5 GB)"
        return 1
    fi

    # Check memory (need ~2GB for containers)
    local available_mb=$(free -m | awk '/^Mem:/{print $7}')
    if [ $available_mb -lt 2048 ]; then
        echo "WARNING: Low available memory ($available_mb MB)"
    fi

    # Check connectivity
    if ! curl -s --max-time 5 https://ghcr.io > /dev/null; then
        echo "ERROR: Cannot reach ghcr.io (needed for Docker images)"
        return 1
    fi

    echo "✓ Pre-flight checks passed"
}
```

**Benefits:**
- Fail fast with clear errors
- Prevents partial deployments
- Better user experience

**Effort:** Low (1 day)

---

### 5. Add Deployment Locking for Concurrent Deployments

**Current Problem:**
- `--all` deploys honeypots sequentially, but user could run multiple scripts
- Could conflict on Hetzner API rate limits, Tailscale device creation

**Proposed:**
```bash
LOCK_FILE="/tmp/cowrie-deploy.lock"

acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "ERROR: Another deployment is running (lock file: $LOCK_FILE)"
        echo "Wait for it to complete or run: rm $LOCK_FILE"
        exit 1
    fi
    trap "flock -u 200" EXIT
}

# In main script:
acquire_lock
# ... deployment logic ...
```

**Benefits:**
- Prevents conflicts
- Clear error message
- Automatic cleanup on exit

**Effort:** Low (2 hours)

---

### 6. Improve Rollback to Include Volume Snapshots

**Current Problem:**
- Rollback only restores git state + VERSION.json
- Docker volumes (`cowrie-var`, `cowrie-etc`) not included
- Database schema migrations could break

**Proposed:**
```bash
create_snapshot() {
    local snapshot_dir="/opt/cowrie/.rollback/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$snapshot_dir"

    # Git state
    git rev-parse HEAD > "$snapshot_dir/git-commit.txt"

    # Docker images
    docker compose images --format json > "$snapshot_dir/docker-images.json"

    # Volume backups (NEW)
    docker run --rm -v cowrie-etc:/source -v "$snapshot_dir":/backup \
        alpine tar czf /backup/cowrie-etc.tar.gz -C /source .

    docker run --rm -v cowrie-var:/source -v "$snapshot_dir":/backup \
        alpine tar czf /backup/cowrie-var.tar.gz -C /source .

    # VERSION.json
    cp VERSION.json "$snapshot_dir/"
}

rollback() {
    local snapshot_dir="$1"

    # Restore git
    git reset --hard "$(cat "$snapshot_dir/git-commit.txt")"

    # Restore volumes (NEW)
    docker run --rm -v cowrie-etc:/dest -v "$snapshot_dir":/backup \
        alpine tar xzf /backup/cowrie-etc.tar.gz -C /dest

    docker run --rm -v cowrie-var:/dest -v "$snapshot_dir":/backup \
        alpine tar xzf /backup/cowrie-var.tar.gz -C /dest

    # Restart containers
    docker compose restart
}
```

**Benefits:**
- Complete rollback (including data)
- Safer updates (can undo database changes)
- Better disaster recovery

**Tradeoffs:**
- Larger snapshots (volumes can be GBs)
- Slower snapshot creation (~30s)
- Disk space requirements

**Effort:** Medium (2 days)

---

## Configuration & Validation

### 1. Add 1Password Integration Validation

**Current Problem:**
- `op read` commands not validated (silent failures)
- Empty values accepted
- No feedback if `op` CLI not installed

**Proposed:**
```bash
validate_1password_integration() {
    # Check if op CLI is installed
    if ! command -v op &> /dev/null; then
        echo "WARNING: 'op' CLI not found. 1Password integration disabled."
        echo "Install: https://1password.com/downloads/command-line/"
        return 1
    fi

    # Check if user is signed in
    if ! op account list &> /dev/null; then
        echo "WARNING: Not signed in to 1Password"
        echo "Run: eval \$(op signin)"
        return 1
    fi

    # Test a read command
    if ! op read "op://Personal/Test/field" &> /dev/null; then
        echo "WARNING: Failed to read test value from 1Password"
        echo "Ensure you have a Test item in the Personal vault"
        return 1
    fi

    echo "✓ 1Password integration validated"
}
```

**Benefits:**
- Clear error messages
- Early validation (before deployment)
- Better onboarding experience

**Effort:** Low (4 hours)

---

### 2. Maintain OS Compatibility Matrix

**Current Problem:**
- Warns if version gap >2, but no tested combinations documented
- No automated testing of compatibility

**Proposed:**
```markdown
# os-compatibility.md

## Tested Combinations

| Source OS | Deployment OS | Status | Notes |
|-----------|---------------|--------|-------|
| debian-11 | debian-11     | ✅ Pass | Reference configuration |
| debian-11 | debian-12     | ✅ Pass | Recommended (newer host) |
| debian-11 | debian-13     | ✅ Pass | Recommended (newest host) |
| debian-12 | debian-11     | ⚠️ Warning | Older host, not recommended |
| debian-11 | debian-14     | ❌ Fail | fs.pickle incompatible |

## Test Results

Last updated: 2026-01-05

Each combination tested with:
- Filesystem generation (WordPress, MySQL, canary tokens)
- Honeypot deployment
- 24-hour runtime test
- Attack simulation (login, commands, file download)
- Dashboard access verification
```

**Benefits:**
- Clear guidance for users
- Basis for automated testing
- Informs warning thresholds

**Effort:** Medium (1 day testing + documentation)

---

### 3. Add Secret Validation

**Current Problem:**
- Secrets in `master-config.toml` not validated
- API keys could be invalid, discovered only during deployment
- No feedback on which secrets are missing

**Proposed:**
```bash
validate_secrets() {
    local errors=0

    # Check MaxMind credentials
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then
        echo "Validating MaxMind credentials..."
        if ! curl -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" \
            "https://download.maxmind.com/geoip/databases/GeoLite2-City/download" \
            --head -f &> /dev/null; then
            echo "❌ MaxMind credentials invalid"
            ((errors++))
        else
            echo "✅ MaxMind credentials valid"
        fi
    fi

    # Check VirusTotal API key
    if [ -n "$VT_API_KEY" ]; then
        echo "Validating VirusTotal API key..."
        local vt_response=$(curl -s "https://www.virustotal.com/api/v3/users/$VT_API_KEY/overall_quotas" \
            -H "x-apikey: $VT_API_KEY")
        if echo "$vt_response" | grep -q '"error"'; then
            echo "❌ VirusTotal API key invalid"
            ((errors++))
        else
            echo "✅ VirusTotal API key valid"
        fi
    fi

    # Check Tailscale authkey
    if [ -n "$TAILSCALE_AUTHKEY" ]; then
        if ! echo "$TAILSCALE_AUTHKEY" | grep -q '^tskey-auth-'; then
            echo "❌ Tailscale authkey format invalid (should start with 'tskey-auth-')"
            ((errors++))
        else
            echo "✅ Tailscale authkey format valid"
        fi
    fi

    return $errors
}
```

**Benefits:**
- Early detection of invalid credentials
- Better error messages
- Saves deployment time (no partial deployments)

**Effort:** Medium (1-2 days for all integrations)

---

## Testing & CI/CD

### 1. Add Integration Tests

**Current State:**
- No automated testing
- Manual testing required after changes
- High risk of regressions

**Proposed:**
```bash
# tests/integration/test-deployment.sh
#!/bin/bash

test_single_honeypot_deployment() {
    # Create test config
    cat > test-config.toml <<EOF
[shared.tailscale]
authkey = "$TEST_TAILSCALE_AUTHKEY"
tailscale_domain = "test.ts.net"
...
EOF

    # Generate filesystem
    ./generate_cowrie_fs_from_hetzner.sh

    # Deploy honeypot
    ./deploy_cowrie_honeypot.sh ./output_*/

    # Validate deployment
    assert_container_running "cowrie"
    assert_port_open "22"
    assert_ssh_accessible

    # Test attack
    simulate_ssh_attack
    assert_attack_logged

    # Cleanup
    cleanup_test_honeypot
}

test_multi_honeypot_deployment() {
    # Deploy 2 honeypots + dashboard
    ...
    assert_dashboard_shows_both_sources
}

# Run tests
test_single_honeypot_deployment
test_multi_honeypot_deployment
```

**Benefits:**
- Catch regressions early
- Confidence in changes
- Documentation via tests

**Effort:** High (1-2 weeks initial setup)

---

### 2. Add GitHub Actions Pre-Deployment Validation

**Proposed:**
```yaml
# .github/workflows/validate-deployment.yml
name: Validate Deployment Scripts
on: [push, pull_request]

jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ShellCheck
        run: |
          shellcheck *.sh
          shellcheck scripts/*.sh

  config-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate example config
        run: |
          python3 scripts/validate-config.py example-config.toml

  dry-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dry-run deployment
        env:
          HCLOUD_TOKEN: ${{ secrets.HCLOUD_TOKEN }}
        run: |
          ./deploy_cowrie_honeypot.sh ./test-output --dry-run
```

**Benefits:**
- Automated validation on every commit
- Prevents broken deployments
- Enforces code quality

**Effort:** Low (1 day)

---

## Documentation Gaps

### 1. Missing: Event Indexer Service Documentation

**Current State:**
- `scripts/event-indexer.py` exists but not documented
- Mentioned in `update-agent.sh` but nowhere else

**Needed:**
```markdown
# YARA_AND_INDEXING.md

## Event Indexer Service

Background daemon for fast event queries.

**Purpose:**
- Creates indexed views of SQLite events
- Improves dashboard query performance
- Enables complex filtering without full table scans

**How it works:**
- Monitors `/var/lib/docker/volumes/cowrie-var/_data/lib/cowrie/cowrie.db`
- Creates materialized views for common queries
- Refreshes views on insert/update

**Commands:**
```bash
# View status
systemctl status event-indexer

# View logs
journalctl -u event-indexer -f

# Restart
systemctl restart event-indexer
```
```

**Effort:** Low (2 hours)

---

### 2. Missing: Tailscale Serve Configuration Details

**Current State:**
- Tailscale Serve configured automatically
- No documentation on how it works or how to customize

**Needed:**
```markdown
# TAILSCALE_SERVE.md

## How Tailscale Serve Works

Tailscale Serve provides HTTPS access to local services without exposing them publicly.

**Configuration:**
- API: `https://cowrie-hp-1.tail9e5e41.ts.net/api/` → `http://localhost:8000`
- Dashboard: `https://cowrie-hp-1.tail9e5e41.ts.net/` → `http://localhost:5000`

**View current config:**
```bash
ssh root@cowrie-hp-1 'tailscale serve status'
```

**Customize paths:**
```bash
# Add custom path
tailscale serve https:443 / http://localhost:5000
tailscale serve https:443 /api http://localhost:8000
tailscale serve https:443 /metrics http://localhost:9090
```
```

**Effort:** Low (1 hour)

---

## Priority Recommendations

### Quick Wins (< 1 day, high impact)
1. ✅ **Network retry logic** - Immediate reliability improvement
2. ✅ **Resource pre-flight checks** - Prevents cryptic failures
3. ✅ **Deployment locking** - Prevents conflicts
4. ✅ **SSH connection abstraction** - Code cleanup

### Medium Priority (1-3 days, medium-high impact)
1. ⚠️ **Dry-run mode** - Major UX improvement
2. ⚠️ **Configuration schema validation** - Better error messages
3. ⚠️ **Template engine** - More maintainable
4. ⚠️ **Secret validation** - Early failure detection

### Long-Term (1-2 weeks, strategic value)
1. 🔮 **Modularize deploy script** - Maintainability
2. 🔮 **Integration tests** - Quality assurance
3. 🔮 **Volume snapshot rollback** - Better disaster recovery
4. 🔮 **OS compatibility matrix** - User guidance

### Documentation (< 1 day, clarifies existing features)
1. 📚 Event indexer service
2. 📚 Tailscale Serve configuration
3. 📚 Dashboard mode naming clarification
4. 📚 Update rollback limitations

---

## Implementation Notes

- All improvements should maintain backward compatibility
- Existing deployments should continue working without changes
- New features should be opt-in where possible
- Breaking changes should be clearly communicated in CHANGELOG.md

## Contributing

If you'd like to contribute an improvement:
1. Open an issue discussing the proposal
2. Reference this document and the specific improvement
3. Submit a PR with tests (if applicable)
4. Update documentation

---

*Last updated: 2026-01-05*
*Based on comprehensive code analysis of v2.1*
