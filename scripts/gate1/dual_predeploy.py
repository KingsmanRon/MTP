"""Gate 1: both Railway services run `alembic upgrade head`. Prove it is safe.

`railway.json` (API) and `railway.worker.json` (worker) both declare the same
pre-deploy command, and they can reach the database at the same time. This
runs exactly that against a populated database at the deployed revision and
records which invocation migrated, which waited, and where both ended up.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import asyncpg

MIGRATOR_URL = os.environ["ALEMBIC_DATABASE_URL"]
HEAD = "0027_authority_config_mgmt"


async def run(label: str) -> dict:
    began = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head",
        cwd=str(Path(__file__).resolve().parents[2]),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    text = (out or b"").decode()
    return {
        "service": label,
        "returncode": proc.returncode,
        "seconds": round(time.perf_counter() - began, 3),
        "applied_migrations": "Running upgrade" in text,
        "revisions_applied": text.count("Running upgrade"),
        "deadlock": "deadlock detected" in text,
    }


async def main() -> int:
    conn = await asyncpg.connect(MIGRATOR_URL)
    start = await conn.fetchval("SELECT version_num FROM alembic_version")

    api, worker = await asyncio.gather(run("railway web (API)"),
                                       run("railway worker"))

    end = await conn.fetchval("SELECT version_num FROM alembic_version")
    version_rows = await conn.fetchval("SELECT count(*) FROM alembic_version")
    await conn.close(timeout=5)

    migrators = [r for r in (api, worker) if r["applied_migrations"]]
    result = {
        "start_revision": start,
        "end_revision": end,
        "alembic_version_rows": version_rows,
        "invocations": [api, worker],
        "exactly_one_migrated": len(migrators) == 1,
        "both_exited_cleanly": api["returncode"] == 0 and worker["returncode"] == 0,
        "deadlock": api["deadlock"] or worker["deadlock"],
    }
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2))

    for entry in (api, worker):
        role = ("MIGRATED " + str(entry["revisions_applied"]) + " revisions"
                if entry["applied_migrations"] else "waited, then no-op at head")
        print(f"  {entry['service']:<20} exit={entry['returncode']} "
              f"{entry['seconds']:>6.3f}s  {role}")
    print(f"  {start} -> {end}; alembic_version rows = {version_rows}")
    ok = (result["exactly_one_migrated"] and result["both_exited_cleanly"]
          and end == HEAD and version_rows == 1 and not result["deadlock"])
    print("  DUAL PRE-DEPLOY SAFE" if ok else "  DUAL PRE-DEPLOY UNSAFE")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
