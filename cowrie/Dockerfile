#checkov:skip=CKV_DOCKER_2: HEALTHCHECK in cowrie/cowrie
#checkov:skip=CKV_DOCKER_7: We need specific base images for compatibility

# This Dockerfile extends the official Cowrie multi-stage build
# Builder stage clones Cowrie and installs custom plugins/core files
# Runtime stage uses distroless for minimal attack surface

ARG SOURCE_DATE_EPOCH
ARG COWRIE_VERSION=main
FROM debian:bookworm-slim AS builder

WORKDIR /

ENV COWRIE_GROUP=cowrie \
    COWRIE_USER=cowrie \
    COWRIE_HOME=/cowrie

# Set locale to UTF-8, otherwise upstream libraries have bytes/string conversion issues
ENV LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

RUN groupadd -r ${COWRIE_GROUP} && \
    useradd -r -d ${COWRIE_HOME} -m -g ${COWRIE_GROUP} ${COWRIE_USER}

# Set up Debian prereqs (including git for cloning Cowrie)
# hadolint ignore=DL3008
RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get -qq update && \
    apt-get -qq install -y \
        -o APT::Install-Suggests=false \
        -o APT::Install-Recommends=false \
        -o Dpkg::Use-Pty="0" \
      build-essential \
      ca-certificates \
      cargo \
      git \
      libffi-dev \
      libsnappy-dev \
      libssl-dev \
      locales \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      rustc && \
    sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

USER ${COWRIE_USER}
WORKDIR ${COWRIE_HOME}

# Clone official Cowrie repository
ARG COWRIE_VERSION
# hadolint ignore=DL3003
RUN git clone --branch ${COWRIE_VERSION} https://github.com/cowrie/cowrie.git cowrie-git && \
    cd cowrie-git && \
    git fetch --tags && \
    echo "Cloned Cowrie version: $(git describe --tags --always)"

# Install Python dependencies and Cowrie itself
# hadolint ignore=DL3013
RUN python3 -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    pip install -q --no-cache-dir --upgrade pip setuptools wheel && \
    pip install -q --no-cache-dir --upgrade cffi && \
    pip install -q --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements.txt && \
    pip install -q --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements-output.txt && \
    pip install -q --no-cache-dir -e ${COWRIE_HOME}/cowrie-git

# === CUSTOM MODIFICATIONS START ===

# Switch to root for custom file installation
USER root

# Copy custom files from build context (repo root)
COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} cowrie-plugins ${COWRIE_HOME}/custom-plugins
COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} cowrie-core ${COWRIE_HOME}/custom-core

# Set shell options for subsequent RUN commands
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install custom plugins (if any exist)
RUN if [ -d "${COWRIE_HOME}/custom-plugins" ] && [ -n "$(find ${COWRIE_HOME}/custom-plugins -maxdepth 1 -name '*.py' -print -quit 2>/dev/null)" ]; then \
        cp -v ${COWRIE_HOME}/custom-plugins/*.py ${COWRIE_HOME}/cowrie-git/src/cowrie/output/ && \
        echo "Installed custom plugins: $(find ${COWRIE_HOME}/custom-plugins -name '*.py' | wc -l)" && \
        rm -rf ${COWRIE_HOME}/custom-plugins; \
    else \
        echo "No custom plugins found, using defaults" && \
        rm -rf ${COWRIE_HOME}/custom-plugins; \
    fi

# Install custom core files (excluding special directories)
# hadolint ignore=SC2231
RUN if [ -d "${COWRIE_HOME}/custom-core" ]; then \
        for file in "${COWRIE_HOME}"/custom-core/*.py; do \
            [ -f "$file" ] || continue; \
            basename=$(basename "$file" .py); \
            case "$basename" in \
                commands|fs_dynamic|server_dynamic|__init__) \
                    echo "Skipping excluded file: $basename.py" ;; \
                *) \
                    cp -v "$file" ${COWRIE_HOME}/cowrie-git/src/cowrie/core/ && \
                    echo "Installed core file: $basename.py" ;; \
            esac; \
        done; \
    fi

# Install dynamic filesystem file if it exists
RUN if [ -f "${COWRIE_HOME}/custom-core/fs_dynamic.py" ]; then \
        cp -v ${COWRIE_HOME}/custom-core/fs_dynamic.py ${COWRIE_HOME}/cowrie-git/src/cowrie/shell/ && \
        echo "Installed dynamic filesystem"; \
    else \
        echo "No dynamic filesystem, using standard filesystem"; \
    fi

# Install custom commands (if directory exists)
RUN if [ -d "${COWRIE_HOME}/custom-core/commands" ] && [ -n "$(find ${COWRIE_HOME}/custom-core/commands -maxdepth 1 -name '*.py' -print -quit 2>/dev/null)" ]; then \
        cp -v ${COWRIE_HOME}/custom-core/commands/*.py ${COWRIE_HOME}/cowrie-git/src/cowrie/commands/ && \
        echo "Installed custom commands: $(find ${COWRIE_HOME}/custom-core/commands -name '*.py' | wc -l)"; \
    else \
        echo "No custom commands, using defaults"; \
    fi

# Clean up custom core directory
RUN rm -rf ${COWRIE_HOME}/custom-core

# Generate build metadata JSON file
# hadolint ignore=DL3003
RUN git config --global --add safe.directory ${COWRIE_HOME}/cowrie-git && \
    version=$(cd ${COWRIE_HOME}/cowrie-git && git describe --tags --always 2>&1) && \
    python3 -c "import json; from datetime import datetime, timezone; \
metadata = { \
    'build_date': datetime.now(timezone.utc).isoformat(), \
    'build_timestamp': int(datetime.now(timezone.utc).timestamp()), \
    'cowrie_version': '$version' \
}; \
print(json.dumps(metadata, indent=2), file=open('${COWRIE_HOME}/cowrie-git/metadata.json', 'w')); \
print('Build metadata generated with version: $version')"

# Ensure correct ownership
RUN chown -R ${COWRIE_USER}:${COWRIE_GROUP} \
    ${COWRIE_HOME}/cowrie-git/src/cowrie/output \
    ${COWRIE_HOME}/cowrie-git/src/cowrie/core \
    ${COWRIE_HOME}/cowrie-git/src/cowrie/shell \
    ${COWRIE_HOME}/cowrie-git/src/cowrie/commands \
    ${COWRIE_HOME}/cowrie-git/metadata.json

# Switch back to cowrie user
USER ${COWRIE_USER}

# === CUSTOM MODIFICATIONS END ===

# hadolint ignore=DL3007
FROM gcr.io/distroless/python3-debian12:latest AS runtime

LABEL org.opencontainers.image.authors="Michel Oosterhof <michel@oosterhof.net>"
LABEL org.opencontainers.image.url="https://cowrie.org/"
LABEL org.opencontainers.image.documentation="https://docs.cowrie.org"
LABEL org.opencontainers.image.source="https://github.com/cowrie/cowrie"
LABEL org.opencontainers.image.revision="Source control revision identifier for the packaged software."
LABEL org.opencontainers.image.vendor="Cowrie"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.title="Cowrie SSH/Telnet Honeypot"
LABEL org.opencontainers.image.description="Cowrie SSH/Telnet Honeypot with custom plugins"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/python3-debian12"
LABEL maintainer="Cowrie Deploy Toolkit"

ENV COWRIE_GROUP=cowrie \
    COWRIE_USER=cowrie \
    COWRIE_HOME=/cowrie

COPY --from=builder --chown=0:0 /etc/passwd /etc/group /etc/

COPY --from=builder --chown=${COWRIE_USER}:${COWRIE_GROUP} ${COWRIE_HOME} ${COWRIE_HOME}

RUN [ "python3", "-m", "compileall", "-q", "/cowrie/cowrie-git/src", "/cowrie/cowrie-env/", "/usr/lib/python3.11"]

VOLUME [ "/cowrie/cowrie-git/var", "/cowrie/cowrie-git/etc" ]

USER ${COWRIE_USER}
WORKDIR ${COWRIE_HOME}/cowrie-git

ENV PATH=${COWRIE_HOME}/cowrie-env/bin:${PATH}
ENV PYTHONPATH=${COWRIE_HOME}/cowrie-git/src
ENV PYTHONUNBUFFERED=1

RUN [ "python3", "/cowrie/cowrie-git/bin/regen-dropin.cache" ]

ENTRYPOINT [ "/cowrie/cowrie-env/bin/python3" ]
CMD [ "/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie" ]

EXPOSE 2222
