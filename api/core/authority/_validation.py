"""Shared validation helpers for the core authority boundary.

Private to the package. These enforce the identifier, digest and
timestamp rules that the documented hash format depends on, so that two
callers describing the same act cannot produce two different canonical
forms.
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime

from api.core.authority.errors import CoreAuthorityError

# Identifiers are bounded so a hostile caller cannot push megabytes through
# canonicalization. 512 characters is far above any real principal,
# organisation, domain, action type or reference id.
MAX_IDENTIFIER_LENGTH = 512

# Every digest exchanged across this boundary is a SHA-256 hex digest.
DIGEST_LENGTH = 64
_HEX_ALPHABET = frozenset("0123456789abcdef")


def require_identifier(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> str:
    """Validate a single-line, NFC-normalised, non-empty identifier.

    Rules, in the order they are checked:

    * must be a ``str`` (never ``None``, never a number coerced to text);
    * must be non-empty and carry no leading/trailing whitespace;
    * must contain no C0 control characters and no ``DEL``;
    * must be already NFC-normalised.

    The NFC rule matters because this boundary does **not** normalise
    strings before hashing. Two visually identical principals in NFC and
    NFD would otherwise canonicalize to different bytes and therefore to
    different execution action hashes. Rejecting non-NFC input at the
    edge keeps one act mapped to one hash without silently rewriting
    caller-supplied identity.
    """
    if not isinstance(value, str):
        raise error(f"{field} must be a string, got {type(value).__name__}")
    if not value:
        raise error(f"{field} must not be empty")
    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise error(
            f"{field} exceeds the maximum identifier length of "
            f"{MAX_IDENTIFIER_LENGTH} characters"
        )
    if value.strip() != value:
        raise error(f"{field} must not have leading or trailing whitespace")
    for char in value:
        code_point = ord(char)
        if code_point < 0x20 or code_point == 0x7F:
            raise error(f"{field} must not contain control characters")
    if unicodedata.normalize("NFC", value) != value:
        raise error(
            f"{field} must be Unicode NFC-normalised; this boundary never "
            "normalises identifiers on the caller's behalf"
        )
    return value


def require_optional_identifier(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> str | None:
    """Validate an identifier that may be omitted entirely (``None``)."""
    if value is None:
        return None
    return require_identifier(value, field, error=error)


def require_digest(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> str:
    """Validate a lowercase 64-character SHA-256 hex digest."""
    if not isinstance(value, str):
        raise error(f"{field} must be a string, got {type(value).__name__}")
    if len(value) != DIGEST_LENGTH or not _HEX_ALPHABET.issuperset(value):
        raise error(f"{field} must be a lowercase {DIGEST_LENGTH}-character SHA-256 hex digest")
    return value


def require_optional_digest(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> str | None:
    """Validate a digest that may be omitted entirely (``None``)."""
    if value is None:
        return None
    return require_digest(value, field, error=error)


def require_utc(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> datetime:
    """Normalise a timezone-aware datetime to UTC.

    Naive datetimes are rejected rather than assumed to be UTC. The
    legacy signing path in ``api.crypto`` tolerates naive input with a
    warning for backwards compatibility with deployed SDKs; this
    boundary is new, so it fails closed instead of guessing an offset.
    """
    if not isinstance(value, datetime):
        raise error(f"{field} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise error(f"{field} must be timezone-aware; naive datetimes are rejected")
    return value.astimezone(UTC)


def require_optional_utc(
    value: object,
    field: str,
    *,
    error: type[CoreAuthorityError],
) -> datetime | None:
    """Normalise an optional timezone-aware datetime to UTC."""
    if value is None:
        return None
    return require_utc(value, field, error=error)
