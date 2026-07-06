"""Inntris evidence packs: deterministic, custody-checked, independently verifiable.

This package builds the buyer/auditor evidence pack described in
``docs/pilot/PILOT_EVIDENCE_PACK_TEMPLATE.md`` as a portable archive with
three hard guarantees:

1. **Deterministic bytes** — identical inputs produce a byte-identical ZIP
   (sorted entries, fixed timestamps via the SOURCE_DATE_EPOCH convention,
   pinned compression). The attested object is a signed manifest of per-file
   SHA-256 hashes, not the container bytes, so the ZIP is mere packaging.
2. **Chain of custody at every hop** — files are hashed at ingest and
   re-hashed when the pack is assembled; a mismatch hard-fails the build and
   every re-verification is recorded as its own custody event.
3. **Standalone verification** — every pack embeds ``verify_pack.py`` (a
   zero-dependency offline verifier) and ``METHODOLOGY.md`` (the exact
   canonicalization, hash-scheme, and anchor-semantics contract), so an
   auditor can verify with no Inntris tooling or endpoints.
"""

from evidence_pack.builder import BuildResult, EvidencePackBuilder
from evidence_pack.custody import (
    CustodyIntegrityError,
    EvidenceRecord,
    ingest_file,
    reverify_at_retrieval,
)
from evidence_pack.deterministic_zip import DeterministicZipError, write_deterministic_zip
from evidence_pack.manifest import build_manifest, sign_manifest

__all__ = [
    "BuildResult",
    "CustodyIntegrityError",
    "DeterministicZipError",
    "EvidencePackBuilder",
    "EvidenceRecord",
    "build_manifest",
    "ingest_file",
    "reverify_at_retrieval",
    "sign_manifest",
    "write_deterministic_zip",
]
