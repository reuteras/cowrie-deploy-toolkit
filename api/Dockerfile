FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libmaxminddb0 \
    libmaxminddb-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
# Install VCS dependencies separately (pip --require-hashes can't hash VCS repos).
# setuptools is excluded from the hashed install because pycti 6.x pins an old
# vulnerable version (~=71.1.0) that we override here with the patched release.
RUN pip install --no-cache-dir "cowrie @ git+https://github.com/cowrie/cowrie@fb38e08c729a8d6f0aae2ed1f9eba6730a34718d" && \
    grep -v "^cowrie @\|^setuptools==" requirements.txt > /tmp/requirements-hashed.txt && \
    pip install --no-cache-dir --require-hashes -r /tmp/requirements-hashed.txt && \
    pip install --no-cache-dir "setuptools>=78.1.1"

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 apiuser && \
    chown -R apiuser:apiuser /app

# Switch to non-root user
USER apiuser

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run FastAPI with uvicorn as non-root user
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
