"""Evidence pack assembly.

Pulls the pieces together in the order the guarantees require:

1. every evidence file is custody re-verified at retrieval (hard fail on
   drift) and the re-verification logged as its own event;
2. all pack JSON is written as JCS canonical bytes;
3. the signed manifest of per-file SHA-256 leaves is the attested object;
4. the standalone verifier and methodology doc are embedded in the pack;
5. the container is written as a deterministic ZIP.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from api.jcs import canonicalize
from evidence_pack.custody import EvidenceRecord, canonical_utc, reverify_at_retrieval
from evidence_pack.deterministic_zip import (
    DeterministicZipError,
    validate_arcname,
    write_deterministic_zip,
)
from evidence_pack.manifest import (
    MANIFEST_ARCNAME,
    SIGNATURE_ARCNAME,
    build_manifest,
    manifest_bytes,
    sign_manifest,
)

logger = logging.getLogger("inntris.evidence_pack.builder")

_PACK_CONTENTS_DIR = Path(__file__).parent / "pack_contents"
_RESERVED_ARCNAMES = {MANIFEST_ARCNAME, SIGNATURE_ARCNAME, "custody_log.json"}


@dataclass(frozen=True)
class BuildResult:
    zip_path: Path
    manifest_sha256: str
    zip_sha256: str
    file_count: int
    custody_event_count: int


class EvidencePackBuilder:
    """Collects receipts, proofs, and custody-verified evidence into a pack."""

    def __init__(
        self,
        pack_name: str,
        snapshot_time: datetime,
        inntris_commit: str | None = None,
        anchor: dict[str, Any] | None = None,
        notes: str | None = None,
    ) -> None:
        self.pack_name = pack_name
        self.snapshot_time = snapshot_time
        self.inntris_commit = inntris_commit
        self.anchor = anchor
        self.notes = notes
        self._entries: dict[str, bytes] = {}
        self._custody_events: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Content collection
    # ------------------------------------------------------------------

    def add_evidence(self, record: EvidenceRecord, source_path: str | Path | None = None) -> None:
        """Add a source artifact, re-verifying its ingest hash at retrieval.

        Raises :class:`~evidence_pack.custody.CustodyIntegrityError` if the
        file's current bytes no longer match the hash recorded at ingest —
        the pack must not be built around silently corrupted evidence.
        """
        arcname = f"evidence/{record.arcname}"
        content, reverify_event = reverify_at_retrieval(
            record, verified_at=self.snapshot_time, source_path=source_path
        )
        self._add_entry(arcname, content)
        self._custody_events.append(
            {
                "event": "ingested",
                "arcname": arcname,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "ingested_at": record.ingested_at,
            }
        )
        reverify_event["arcname"] = arcname
        self._custody_events.append(reverify_event)

    def add_receipt(self, receipt: dict[str, Any], proof: dict[str, Any] | None = None) -> None:
        """Add a public verification receipt and (optionally) its Merkle proof."""
        audit_id = receipt.get("audit_id")
        if not audit_id:
            raise ValueError("receipt is missing audit_id")
        self._add_entry(f"receipts/{audit_id}.json", canonicalize(receipt))
        if proof is not None:
            self._add_entry(f"proofs/{audit_id}.json", canonicalize(proof))

    def add_document(self, arcname: str, content: bytes | str) -> None:
        """Add a freeform document (scope description, policy export, ...)."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        self._add_entry(arcname, content)

    def _add_entry(self, arcname: str, content: bytes) -> None:
        validate_arcname(arcname)
        if arcname in _RESERVED_ARCNAMES:
            raise DeterministicZipError(f"arcname {arcname!r} is reserved for the builder")
        if arcname in self._entries:
            raise DeterministicZipError(f"duplicate arcname: {arcname!r}")
        self._entries[arcname] = content

    # ------------------------------------------------------------------
    # Assembly
    # ------------------------------------------------------------------

    def build(self, zip_path: str | Path, signing_key: SigningKey) -> BuildResult:
        """Write the deterministic, manifest-signed archive."""
        entries = dict(self._entries)

        # Embedded verifier + methodology: shipped in every pack so a
        # verifier needs nothing from Inntris.
        entries["verify_pack.py"] = (_PACK_CONTENTS_DIR / "verify_pack.py").read_bytes()
        entries["METHODOLOGY.md"] = (_PACK_CONTENTS_DIR / "METHODOLOGY.md").read_bytes()

        custody_log = {
            "pack_name": self.pack_name,
            "snapshot_time": canonical_utc(self.snapshot_time),
            "events": sorted(
                self._custody_events,
                key=lambda event: (event["arcname"], event["event"]),
            ),
        }
        entries["custody_log.json"] = canonicalize(custody_log)

        manifest = build_manifest(
            pack_name=self.pack_name,
            snapshot_time_utc=canonical_utc(self.snapshot_time),
            files=entries,
            custody_events=custody_log["events"],
            inntris_commit=self.inntris_commit,
            anchor=self.anchor,
            notes=self.notes,
        )
        manifest_raw = manifest_bytes(manifest)
        signature_body = sign_manifest(manifest, signing_key)

        archive = dict(entries)
        archive[MANIFEST_ARCNAME] = manifest_raw
        archive[SIGNATURE_ARCNAME] = canonicalize(signature_body)

        zip_path = Path(zip_path)
        write_deterministic_zip(zip_path, archive, snapshot_time=self.snapshot_time)

        zip_sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        result = BuildResult(
            zip_path=zip_path,
            manifest_sha256=signature_body["manifest_sha256"],
            zip_sha256=zip_sha256,
            file_count=len(archive),
            custody_event_count=len(custody_log["events"]),
        )
        logger.info(
            "evidence pack built: %s manifest_sha256=%s zip_sha256=%s files=%d",
            zip_path,
            result.manifest_sha256,
            result.zip_sha256,
            result.file_count,
        )
        return result
