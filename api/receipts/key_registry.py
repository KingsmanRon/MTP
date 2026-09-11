"""Which authority-evidence keys the public can verify against.

Phase 7A, Gate 4. A signature is only evidence if somebody else can check
it, and they can only check it if they can obtain the public key from a
place they trust. So this module has two jobs:

**Publication.** It reads the published key mirror
(``frontend/public/.well-known/inntris-keys.txt``) — the same file CI pins
against ``verify_publication.lock`` and the same file mirrored at
``github.com/Inntris/inntris-verify``. There is deliberately no second
source of truth: a registry the code believed and the public could not see
would be worse than none.

**The gate.** In production, Core refuses to sign authority evidence with a
key whose fingerprint is not published as ``active``. That is the
mechanical form of "do not emit publicly advertised v3 receipts until the
verifier publication gate passes": it is not a process everybody has to
remember, it is a refusal.

Historical retention
--------------------
A retired key stays in the registry forever. Evidence it signed while
active was legitimate and must stay verifiable — a verifier handed a
two-year-old chain has to be able to find the key it was signed with. So
``retired`` means "may not sign anything new", never "delete".

Key separation
--------------
The authority-evidence key must not be any of: an agent request-signing
key, the offline evidence-pack manifest seed, or the anchor wallet. Each
asserts a different thing, and a key that can assert two things can be
misread as asserting the wrong one. :func:`assert_key_separation` enforces
that against the other key material this process can see, rather than
leaving it as a claim in a document.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

#: The published mirror, relative to the repository root.
PUBLISHED_KEYS_PATH: Final[Path] = Path("frontend/public/.well-known/inntris-keys.txt")

#: Key-id prefix for authority-evidence signing keys. Deliberately distinct
#: from ``ipk-`` (evidence-pack manifest keys) so a reader can never mistake
#: one kind of assertion for the other.
AUTHORITY_EVIDENCE_KEY_PREFIX: Final[str] = "iae-"

#: Override for the mirror location. Used by tests and by any deployment
#: that ships the mirror somewhere other than the repository layout.
PUBLISHED_KEYS_PATH_ENV: Final[str] = "INNTRIS_PUBLISHED_KEYS_PATH"

_KEY_ENTRY = re.compile(
    r"^(?P<key_id>(?:ipk|iae)-\d{4}-\d{2}) "
    r"(?P<public_key>[0-9a-f]{64}) "
    r"sha256 (?P<fingerprint>[0-9a-f]{64}) "
    r"(?P<status>active|retired) "
    r"(?P<effective_date>\d{4}-\d{2}-\d{2})$"
)

_NON_PRODUCTION: Final[frozenset[str]] = frozenset({"development", "test", "ci"})


class KeyPublicationError(RuntimeError):
    """The key registry is unusable, or a key is not publishable."""


class PublishedKeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class PublishedKey:
    """One key the public can verify against."""

    key_id: str
    public_key: bytes
    fingerprint: str
    status: PublishedKeyStatus
    effective_date: date

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")

    @property
    def is_authority_evidence(self) -> bool:
        return self.key_id.startswith(AUTHORITY_EVIDENCE_KEY_PREFIX)


@dataclass(frozen=True, slots=True)
class PublishedKeyRegistry:
    """Every key in the published mirror, of both kinds."""

    keys: tuple[PublishedKey, ...] = ()

    def authority_evidence_keys(self) -> tuple[PublishedKey, ...]:
        return tuple(key for key in self.keys if key.is_authority_evidence)

    def by_fingerprint(self, fingerprint: str) -> PublishedKey | None:
        for key in self.keys:
            if key.fingerprint == fingerprint:
                return key
        return None

    def active_authority_evidence_key(self) -> PublishedKey | None:
        """The one key permitted to sign new authority evidence.

        More than one active key is refused rather than resolved: two
        active signing keys means a reader cannot tell which one *should*
        have signed a given event, and neither can an operator responding
        to a compromise.
        """
        active = [
            key for key in self.authority_evidence_keys() if key.status is PublishedKeyStatus.ACTIVE
        ]
        if len(active) > 1:
            raise KeyPublicationError(
                "more than one active authority-evidence key is published: "
                + ", ".join(key.key_id for key in active)
            )
        return active[0] if active else None

    def as_discovery_document(self) -> dict[str, object]:
        """The public discovery form, served over HTTP.

        Retired keys are included, because a verifier holding an old chain
        needs the key it was signed with. ``status`` says which may sign
        something new.
        """
        return {
            "format": "inntris-authority-evidence-keys-v1",
            "keys": [
                {
                    "key_id": key.key_id,
                    "algorithm": "ed25519",
                    "public_key_hex": key.public_key.hex(),
                    "public_key_b64": key.public_key_b64,
                    "fingerprint_sha256": key.fingerprint,
                    "status": key.status.value,
                    "effective_date": key.effective_date.isoformat(),
                }
                for key in self.authority_evidence_keys()
            ],
            "mirror": (
                "https://github.com/Inntris/inntris-verify — this document "
                "mirrors the published KEYS file; a verifier should compare "
                "the two rather than trust either alone"
            ),
        }


def _mirror_path(root: Path | None = None) -> Path:
    override = (os.getenv(PUBLISHED_KEYS_PATH_ENV) or "").strip()
    if override:
        return Path(override)
    base = root if root is not None else Path(__file__).resolve().parents[2]
    return base / PUBLISHED_KEYS_PATH


def load_published_keys(root: Path | None = None) -> PublishedKeyRegistry:
    """Parse the published mirror.

    A missing mirror is an empty registry, not an error: a deployment that
    has not published anything yet is a valid state, and the signing gate
    below is what stops it emitting evidence nobody can verify.
    """
    path = _mirror_path(root)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.warning(
            "no published key mirror at %s; authority evidence cannot be "
            "signed in production until one exists",
            path,
        )
        return PublishedKeyRegistry()

    keys: list[PublishedKey] = []
    seen_ids: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _KEY_ENTRY.fullmatch(stripped)
        if match is None:
            # Hash lines for verify_pack.py and METHODOLOGY.md live in the
            # same file and are not keys. Anything else unrecognised is
            # left to scripts/check_verify_publication.py, which is the
            # authority on the file's full shape.
            continue
        key_id = match.group("key_id")
        if key_id in seen_ids:
            raise KeyPublicationError(f"duplicate key id in the mirror: {key_id}")
        seen_ids.add(key_id)

        public_key = bytes.fromhex(match.group("public_key"))
        computed = hashlib.sha256(public_key).hexdigest()
        if computed != match.group("fingerprint"):
            raise KeyPublicationError(f"published fingerprint for {key_id} does not match its key")
        keys.append(
            PublishedKey(
                key_id=key_id,
                public_key=public_key,
                fingerprint=computed,
                status=PublishedKeyStatus(match.group("status")),
                effective_date=date.fromisoformat(match.group("effective_date")),
            )
        )
    return PublishedKeyRegistry(keys=tuple(keys))


# ---------------------------------------------------------------------------
# Key separation
# ---------------------------------------------------------------------------

#: The other key material this process may be configured with. Each asserts
#: something different; none may be the authority-evidence key.
_OTHER_KEY_ENVIRONMENT: Final[tuple[tuple[str, str], ...]] = (
    ("INNTRIS_PRIVATE_KEY_B64", "the agent request-signing key"),
    ("BLOCKCHAIN_PRIVATE_KEY", "the anchor wallet"),
    ("EVIDENCE_PACK_SIGNING_SEED", "the offline evidence-pack manifest seed"),
)


def _candidate_bytes(raw: str) -> set[bytes]:
    """Every plausible decoding of a configured secret, for comparison.

    A collision matters whatever encoding the two happened to be written
    in, so both are compared as raw bytes under every encoding either could
    have used, plus the literal text.
    """
    text = raw.strip()
    found: set[bytes] = {text.encode()}
    stripped = text[2:] if text.lower().startswith("0x") else text
    with contextlib.suppress(ValueError, binascii.Error):
        found.add(bytes.fromhex(stripped))
    with contextlib.suppress(ValueError, binascii.Error):
        found.add(base64.b64decode(text, validate=True))
    return found


def assert_key_separation(seed: bytes, *, environ: dict[str, str] | None = None) -> None:
    """Refuse an authority-evidence seed that is some other key.

    Enforced rather than documented. A key that signs both "Core decided
    this" and "this agent requested that" lets one assertion be read as the
    other, and no amount of prose prevents somebody pasting the same secret
    into two variables.
    """
    env = environ if environ is not None else dict(os.environ)
    for variable, description in _OTHER_KEY_ENVIRONMENT:
        raw = (env.get(variable) or "").strip()
        if not raw:
            continue
        if seed in _candidate_bytes(raw):
            raise KeyPublicationError(
                f"the authority-evidence signing key is also {description} "
                f"({variable}). These assert different things and must be "
                "different keys; rotate one of them."
            )


def assert_key_is_published(
    fingerprint: str,
    *,
    environment: str | None = None,
    registry: PublishedKeyRegistry | None = None,
) -> PublishedKey | None:
    """Refuse to sign with a key the public cannot obtain.

    This is the publication gate. Outside production an unpublished key is
    permitted so tests and local runs work; in production evidence signed
    by a key nobody can look up verifies against nothing, which is worse
    than no evidence because it reads as authenticated.

    Returns the published key when there is one, so a caller can use its
    stable published ``key_id`` rather than a locally derived one.
    """
    env = (environment or os.getenv("ENVIRONMENT", "development")).strip().lower()
    published = (registry if registry is not None else load_published_keys()).by_fingerprint(
        fingerprint
    )

    if published is None:
        if env in _NON_PRODUCTION:
            logger.warning(
                "authority-evidence key %s is not published; evidence signed "
                "with it cannot be verified by anyone outside this process",
                fingerprint[:16],
            )
            return None
        raise KeyPublicationError(
            f"authority-evidence key {fingerprint} is not in the published key "
            "mirror. Publish it (and the inntris-verify mirror, and the "
            "publication lock) before emitting v3 evidence: a signature "
            "nobody can check is not evidence."
        )

    if published.status is not PublishedKeyStatus.ACTIVE:
        raise KeyPublicationError(
            f"authority-evidence key {published.key_id} is published as "
            f"{published.status.value} and must not sign new evidence. What it "
            "signed while active stays verifiable; rotate to the active key."
        )
    return published


__all__ = [
    "AUTHORITY_EVIDENCE_KEY_PREFIX",
    "KeyPublicationError",
    "PUBLISHED_KEYS_PATH",
    "PUBLISHED_KEYS_PATH_ENV",
    "PublishedKey",
    "PublishedKeyRegistry",
    "PublishedKeyStatus",
    "assert_key_is_published",
    "assert_key_separation",
    "load_published_keys",
]
