set shell := ["zsh", "-cu"]

# Update uv.lock only (no upgrades)
lock:
    uv lock

# Upgrade all deps, update uv.lock, then regenerate requirements files
deps-update:
    uv lock --upgrade
    uv export --frozen --group api -o api/requirements.txt
    uv export --frozen --group web -o web/requirements.txt

# Regenerate requirements files from existing uv.lock
deps:
    uv export --frozen --group api -o api/requirements.txt
    uv export --frozen --group web -o web/requirements.txt
