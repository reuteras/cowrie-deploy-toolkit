#checkov:skip=CKV_DOCKER_2: HEALTHCHECK in cowrie/cowrie
#checkov:skip=CKV_DOCKER_7: We like the latest for this work
# hadolint ignore=DL3007
FROM cowrie/cowrie:latest

# Switch to root to install plugins and generate metadata
USER root

# Copy custom plugins directory (may be empty)
COPY cowrie-plugins /tmp/cowrie-plugins

# Copy custom core directory (may be empty)
COPY cowrie-core /tmp/cowrie-core

# Copy plugins if they exist (exec form - no shell at all)
# hadolint ignore=SC1088
RUN ["python3", "-c", "import shutil; from pathlib import Path; src = Path('/tmp/cowrie-plugins'); dest = Path('/cowrie/cowrie-git/src/cowrie/output'); files = list(src.glob('*.py')); [shutil.copy2(f, dest / f.name) for f in files]; print(f'Installed {len(files)} custom plugin(s)' if files else 'No custom plugins, using defaults'); shutil.rmtree(src)"]

# Copy core files (excluding commands) if they exist (exec form - no shell at all)
# hadolint ignore=SC1088
RUN ["python3", "-c", "import shutil; from pathlib import Path; src = Path('/tmp/cowrie-core'); dest = Path('/cowrie/cowrie-git/src/cowrie/core'); files = [f for f in src.glob('*.py') if f.name != 'commands']; [shutil.copy2(f, dest / f.name) for f in files]; print(f'Installed {len(files)} custom file(s) for core' if files else 'No custom files for core, using defaults')"]

# Copy command files if they exist (exec form - no shell at all)
# hadolint ignore=SC1088
RUN ["python3", "-c", "import shutil; from pathlib import Path; src = Path('/tmp/cowrie-core/commands'); dest = Path('/cowrie/cowrie-git/src/cowrie/commands'); files = list(src.glob('*.py')); [shutil.copy2(f, dest / f.name) for f in files]; print(f'Installed {len(files)} custom command(s)' if files else 'No custom commands, using defaults'); shutil.rmtree('/tmp/cowrie-core')"]

# Generate build metadata JSON file (exec form - no shell at all)
# hadolint ignore=SC1088
RUN ["python3", "-c", "import json; import os; from datetime import datetime, timezone; import cowrie._version; metadata = {'build_date': datetime.now(timezone.utc).isoformat(), 'build_timestamp': int(datetime.now(timezone.utc).timestamp()), 'cowrie_version': cowrie._version.__version__}; open('/cowrie/cowrie-git/metadata.json', 'w').write(json.dumps(metadata, indent=2)); print('Build metadata generated')"]

# Ensure correct permissions (exec form - no shell at all)
# hadolint ignore=SC1088
RUN ["python3", "-c", "import os; import pwd; import grp; uid = pwd.getpwnam('cowrie').pw_uid; gid = grp.getgrnam('cowrie').gr_gid; [os.chown(os.path.join(r, f), uid, gid) for r, d, files in os.walk('/cowrie/cowrie-git/src/cowrie/output') for f in files + d]; os.chown('/cowrie/cowrie-git/metadata.json', uid, gid)"]

# Switch back to cowrie user
USER cowrie

# Add label with build info
LABEL maintainer="Cowrie Deploy Toolkit"
LABEL description="Custom Cowrie honeypot with additional output plugins"
