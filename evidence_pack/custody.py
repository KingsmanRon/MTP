"""Chain-of-custody records for evidence source files.

Custody is checked at every hop, not asserted once at ingest:

* ``ingest_file`` hashes the source artifact when it enters custody and
  records the SHA-256, size, and ingest time.
* ``reverify_at_retrieval`` re-reads the artifact when the pack is assembled,
  recomputes the hash, and **hard-fails** (``CustodyIntegrityError``) if it no
  longer matches the ingest-time value. Anything that corrupts or swaps the
  file while it sits in storage — a bug, a migration, tampering — is caught
  here instead of shipping next to a stale hash claim.
* Every re-verification (pass or fail) is logged as its own custody event and
  the pack's ``custody_log.json`` carries the full event sequence, so the
  verifier can see that the check happened, not just trust that it did.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("inntris.evidence_pack.custody")

_HASH_CHUNK_BYTES = 1024 * 1024


class CustodyIntegrityError(RuntimeError):
    """A stored evidence file no longer matches its ingest-time SHA-256."""


@dataclass(frozen=True)
class EvidenceRecord:
    """Ingest-time custody record for one source artifact."""

    arcname: str
    source_path: str
    sha256: str
    size_bytes: int
    ingested_at: str  # ISO 8601 UTC with Z suffix

    def to_dict(self) -> dict[str, Any]:
        return {
            "arcname": self.arcname,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "ingested_at": self.ingested_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        return cls(
            arcname=data["arcname"],
            source_path=data["source_path"],
            sha256=data["sha256"],
            size_bytes=int(data["size_bytes"]),
            ingested_at=data["ingested_at"],
        )


def canonical_utc(moment: datetime) -> str:
    """ISO 8601 UTC with the ``Z`` suffix (matches the receipt contract)."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: str | Path) -> tuple[str, int]:
    """Stream a file through SHA-256; returns (hex digest, size in bytes)."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def ingest_file(
    source_path: str | Path,
    arcname: str,
    ingested_at: datetime | None = None,
) -> EvidenceRecord:
    """Hash a source artifact as it enters custody."""
    sha256, size = sha256_file(source_path)
    record = EvidenceRecord(
        arcname=arcname,
        source_path=str(source_path),
        sha256=sha256,
        size_bytes=size,
        ingested_at=canonical_utc(ingested_at or datetime.now(UTC)),
    )
    logger.info(
        "custody ingest: %s sha256=%s size=%d", record.arcname, record.sha256, record.size_bytes
    )
    return record


def reverify_at_retrieval(
    record: EvidenceRecord,
    verified_at: datetime,
    source_path: str | Path | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Re-hash a stored artifact against its ingest record; hard-fail on drift.

    Returns the verified file bytes plus the custody event describing the
    re-verification. Raises :class:`CustodyIntegrityError` on any mismatch —
    a pack must never be assembled around a file whose current content does
    not match the hash recorded when it entered custody.
    """
    path = Path(source_path or record.source_path)
    content = path.read_bytes()
    retrieved_sha256 = hashlib.sha256(content).hexdigest()

    event: dict[str, Any] = {
        "event": "hash_reverified_at_retrieval",
        "arcname": record.arcname,
        "ingest_sha256": record.sha256,
        "retrieval_sha256": retrieved_sha256,
        "size_bytes": len(content),
        "verified_at": canonical_utc(verified_at),
    }

    if retrieved_sha256 != record.sha256:
        event["result"] = "mismatch"
        logger.error(
            "custody FAILURE: %s changed between ingest and retrieval "
            "(ingest sha256=%s, retrieval sha256=%s)",
            record.arcname,
            record.sha256,
            retrieved_sha256,
        )
        raise CustodyIntegrityError(
            f"evidence file {record.arcname!r} failed retrieval re-verification: "
            f"ingest sha256 {record.sha256} != retrieval sha256 {retrieved_sha256}. "
            "The file was corrupted or replaced while in storage; refusing to build."
        )

    event["result"] = "match"
    logger.info("custody re-verification passed: %s sha256=%s", record.arcname, record.sha256)
    return content, event
