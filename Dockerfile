# =============================================================================
# INNTRIS CORE - PRODUCTION DOCKERFILE
# =============================================================================
# Multi-stage build for minimal production image
# Targets: Core API, MCP Server, Anchor Worker
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM python:3.12.13-slim-bookworm AS builder

# Set build environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Production Base
# -----------------------------------------------------------------------------
FROM python:3.12.13-slim-bookworm AS production-base

# Set production environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Application settings
    ENVIRONMENT=production \
    PORT=8000

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r inntris && useradd -r -g inntris inntris

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=inntris:inntris api/ ./api/
COPY --chown=inntris:inntris mcp_server/ ./mcp_server/
COPY --chown=inntris:inntris workers/ ./workers/
COPY --chown=inntris:inntris alembic/ ./alembic/
COPY --chown=inntris:inntris database/ ./database/
COPY --chown=inntris:inntris alembic.ini ./alembic.ini
COPY --chown=inntris:inntris scripts/configure_runtime_role.py ./scripts/configure_runtime_role.py

# -----------------------------------------------------------------------------
# Stage 3: Database migrations and runtime role provisioning
# -----------------------------------------------------------------------------
FROM production-base AS migrate

USER inntris

# The privileged migration DSN is confined to this one-shot container.  The
# script then provisions inntris_worker from a separate runtime credential.
CMD ["sh", "-c", "alembic upgrade head && python /app/scripts/configure_runtime_role.py"]

# -----------------------------------------------------------------------------
# Stage 4: Core API Service
# -----------------------------------------------------------------------------
FROM production-base AS api

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER inntris

# Run the API
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# -----------------------------------------------------------------------------
# Stage 5: MCP Server
# -----------------------------------------------------------------------------
FROM production-base AS mcp-server

# MCP Server runs via stdio, no port needed
USER inntris

# Run the MCP server
CMD ["python", "-m", "mcp_server.server"]

# -----------------------------------------------------------------------------
# Stage 6: Anchor Worker
# -----------------------------------------------------------------------------
FROM production-base AS anchor-worker

# Prometheus heartbeat and proof backlog metrics
EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${ANCHOR_METRICS_PORT:-9100}/metrics || exit 1

USER inntris

# Run the anchor worker
CMD ["python", "-m", "workers.anchor_worker"]

# -----------------------------------------------------------------------------
# Default target: API
# -----------------------------------------------------------------------------
FROM api AS default
