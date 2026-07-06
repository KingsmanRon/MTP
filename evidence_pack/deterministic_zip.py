"""Canonical (byte-reproducible) ZIP construction.

A naive ``zipfile.ZipFile`` embeds file mtimes, host OS metadata, and
insertion order, so building the same evidence pack twice yields different
bytes — and a different SHA-256 — even for identical inputs. That breaks
reproducibility: a verifier recreating the pack from the same inputs gets a
hash that does not match what was anchored or claimed.

This module pins every source of nondeterminism:

* **Entry order** — entries are written sorted by arcname (bytewise UTF-8).
* **Timestamps** — every entry uses one fixed timestamp, taken from the
  ``SOURCE_DATE_EPOCH`` environment variable (the reproducible-builds
  convention) when set, otherwise from the caller-supplied snapshot time,
  clamped to the ZIP format's 1980-01-01 minimum.
* **Compression** — DEFLATE at a pinned level for every entry.
* **Metadata** — fixed create_system/external_attr, no extra fields, no
  directory entries, UTF-8 arcnames only.

The resulting invariant, verified by ``tests/test_evidence_pack.py``:
identical (arcname, bytes) inputs and the same effective timestamp produce a
byte-identical archive regardless of wall clock, filesystem mtimes, or the
order entries were added.
"""

from __future__ import annotations

import os
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

# ZIP local-header timestamps are DOS-format and cannot represent anything
# before 1980-01-01; clamp rather than let zipfile raise or wrap.
_ZIP_EPOCH_MIN = datetime(1980, 1, 1, tzinfo=UTC)

# Pinned for reproducibility. zlib's DEFLATE output is deterministic for a
# given (level, strategy) across platforms; changing this constant changes
# every pack hash, so treat it as part of the pack format version.
PINNED_COMPRESSION = zipfile.ZIP_DEFLATED
PINNED_COMPRESSLEVEL = 9

# Fixed entry metadata: 3 = Unix creator, regular file with 0644 permissions.
_CREATE_SYSTEM_UNIX = 3
_EXTERNAL_ATTR_0644 = (0o100644 << 16)


class DeterministicZipError(ValueError):
    """Raised for arcname collisions or unsafe/non-canonical arcnames."""


def canonical_timestamp(snapshot_time: datetime | None = None) -> datetime:
    """Resolve the single timestamp used for every archive entry.

    Precedence follows the reproducible-builds convention:
    ``SOURCE_DATE_EPOCH`` (seconds since the Unix epoch) if set, else the
    caller's ``snapshot_time``, else the ZIP epoch minimum. The result is
    clamped to 1980-01-01 because DOS timestamps cannot go earlier.
    """
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if sde is not None:
        try:
            resolved = datetime.fromtimestamp(int(sde), tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise DeterministicZipError(f"invalid SOURCE_DATE_EPOCH {sde!r}: {exc}")
    elif snapshot_time is not None:
        if snapshot_time.tzinfo is None:
            raise DeterministicZipError("snapshot_time must be timezone-aware")
        resolved = snapshot_time.astimezone(UTC)
    else:
        resolved = _ZIP_EPOCH_MIN
    return max(resolved, _ZIP_EPOCH_MIN)


def validate_arcname(arcname: str) -> str:
    """Reject arcnames that are unsafe or would not round-trip canonically."""
    if not arcname:
        raise DeterministicZipError("empty arcname")
    if "\\" in arcname:
        raise DeterministicZipError(f"arcname must use '/' separators: {arcname!r}")
    if arcname.startswith("/"):
        raise DeterministicZipError(f"absolute arcname not allowed: {arcname!r}")
    if arcname.endswith("/"):
        raise DeterministicZipError(f"directory entries not allowed: {arcname!r}")
    parts = arcname.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise DeterministicZipError(f"non-canonical arcname: {arcname!r}")
    return arcname


def write_deterministic_zip(
    zip_path: str | Path,
    entries: dict[str, bytes] | Iterable[tuple[str, bytes]],
    snapshot_time: datetime | None = None,
) -> None:
    """Write ``entries`` (arcname -> content bytes) as a canonical ZIP.

    The same entries and effective timestamp always produce the same bytes,
    independent of dict/iteration order, wall clock, or platform.
    """
    pairs = list(entries.items()) if isinstance(entries, dict) else list(entries)
    items: dict[str, bytes] = {}
    for arcname, content in pairs:
        validate_arcname(arcname)
        if arcname in items:
            raise DeterministicZipError(f"duplicate arcname: {arcname!r}")
        items[arcname] = content

    stamp = canonical_timestamp(snapshot_time)
    date_time = (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)

    zip_path = Path(zip_path)
    with zipfile.ZipFile(zip_path, "w") as zf:
        for arcname in sorted(items, key=lambda name: name.encode("utf-8")):
            info = zipfile.ZipInfo(filename=arcname, date_time=date_time)
            info.create_system = _CREATE_SYSTEM_UNIX
            info.external_attr = _EXTERNAL_ATTR_0644
            info.compress_type = PINNED_COMPRESSION
            zf.writestr(info, items[arcname], compresslevel=PINNED_COMPRESSLEVEL)
