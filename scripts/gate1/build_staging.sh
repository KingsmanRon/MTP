#!/usr/bin/env bash
# Gate 1: build a production-SHAPED staging database at the DEPLOYED revision.
#
# The cardinality in seed_staging.sql is SYNTHETIC. It is sized to expose the
# index and constraint lock cost of the migrations that touch populated
# tables; it is NOT measured production volume and must not be reported as
# such.
#
# Requires ALEMBIC_DATABASE_URL (privileged) and DATABASE_URL (runtime role),
# plus RUNTIME_DATABASE_PASSWORD. Idempotent: drops and recreates, so every
# rehearsal starts from identical state.
set -euo pipefail

: "${ALEMBIC_DATABASE_URL:?set ALEMBIC_DATABASE_URL}"
: "${GATE1_DATABASE:=inntris_stage}"
: "${GATE1_DEPLOYED_REVISION:=0018_merkle_anchor_visibility}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PYTHON="${GATE1_PYTHON:-$REPO/.venv/bin/python}"

cd "$REPO"
sudo -u postgres psql -q -c "DROP DATABASE IF EXISTS ${GATE1_DATABASE};" >/dev/null 2>&1 || true
sudo -u postgres psql -q -c "CREATE DATABASE ${GATE1_DATABASE} OWNER postgres;"
"$PYTHON" -m alembic upgrade "$GATE1_DEPLOYED_REVISION" >/dev/null
"$PYTHON" scripts/configure_runtime_role.py >/dev/null
psql "$ALEMBIC_DATABASE_URL" -q -v ON_ERROR_STOP=1 -f "$HERE/seed_staging.sql"
echo "staging built at $("$PYTHON" -m alembic current 2>&1 | tail -1)"
