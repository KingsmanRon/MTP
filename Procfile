# =============================================================================
# MACHINE TRUST PROTOCOL - PROCFILE
# =============================================================================
# For deployment on Railway, Render, Heroku, and similar platforms
# =============================================================================

# Core API - The main web service
web: uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}

# Anchor Worker - Background blockchain anchoring
worker: python -m workers.anchor_worker

# MCP Server - Run alongside agent (typically not deployed separately)
mcp: python -m mcp_server.server
