# Cowrie SSH Session Playback Web Service
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set work directory
WORKDIR /app

# Copy application code
COPY . .

# Install system dependencies
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl && \
    pip install --no-cache-dir -r requirements.txt && \
    mkdir -p /app/static /app/templates /geoip /identity && \
    groupadd -r cowrie && useradd -r -g cowrie cowrie && \
    chown -R cowrie:cowrie /app && \
    rm -rf /var/lib/apt/lists/*

# Switch to non-root user
USER cowrie

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Run with gunicorn for production
# Single worker with multiple threads to share in-memory queue across all SSE connections
# This ensures canary token events reach all connected browsers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--worker-class", "gthread", "--threads", "8", "--timeout", "120", "app:app"]
