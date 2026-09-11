"""The published producer schema for receipt v3 authority evidence.

Phase 7A, Gate 4. A third party who receives a v3 chain needs to know what
shape it is before they can check it, and they must be able to obtain that
description without asking Inntris what it means at the time.

This is the *structural* contract only. It says which fields exist and what
type they are; it says nothing about whether a particular chain verifies.
Verification is the signature, the parent links and the continuity rules in
``api/receipts/v3.py`` and in the published ``verify_pack.py``. A chain can
satisfy every constraint here and be a forgery, which is exactly why the
schema is not the check.

v1 and v2 are elsewhere and frozen. Nothing here is reachable from their
path.
"""

from __future__ import annotations

from typing import Any, Final

from api.receipts.v3 import (
    EVIDENCE_PAYLOAD_FORMAT,
    RECEIPT_SCHEMA_V3,
)

_EVENT_TYPES: Final[tuple[str, ...]] = ("decision", "consumption", "outcome")

_SIGNED_EVENT: Final[dict[str, Any]] = {
    "type": "object",
    "description": (
        "One immutable, authenticated link. The payload is the signed truth; "
        "every field duplicated outside it is convenience for readers and MUST "
        "equal its signed original, or the event is refused."
    ),
    "required": [
        "event_id",
        "event_type",
        "schema_version",
        "recorded_at",
        "payload",
        "evidence_payload_hash",
        "signature_b64",
        "signing_key_id",
        "signing_key_fingerprint",
    ],
    "properties": {
        "event_id": {"type": "string", "format": "uuid"},
        "event_type": {"type": "string", "enum": list(_EVENT_TYPES)},
        "schema_version": {"type": "string", "const": RECEIPT_SCHEMA_V3},
        "recorded_at": {
            "type": "string",
            "format": "date-time",
            "description": "RFC 3339 with an explicit UTC offset.",
        },
        "parent_event_id": {
            "type": ["string", "null"],
            "description": (
                "The event this one follows. Inside the signature, so an event "
                "cannot be re-parented without invalidating it."
            ),
        },
        "parent_payload_hash": {
            "type": ["string", "null"],
            "pattern": "^[a-f0-9]{64}$",
            "description": (
                "The parent's evidence_payload_hash. Editing any ancestor "
                "breaks every descendant."
            ),
        },
        "payload": {
            "type": "object",
            "required": [
                "format",
                "event_id",
                "event_type",
                "schema_version",
                "recorded_at",
                "body",
                "signing_key_id",
                "signing_key_fingerprint",
            ],
            "properties": {
                "format": {"type": "string", "const": EVIDENCE_PAYLOAD_FORMAT},
                "body": {
                    "type": "object",
                    "description": (
                        "The event's own facts. Its fields differ by event_type; "
                        "see METHODOLOGY.md for the per-type contract."
                    ),
                },
                "signing_key_fingerprint": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$",
                    "description": (
                        "SHA-256 of the raw Ed25519 public key. Inside the "
                        "signature, so substituting a key and rewriting the "
                        "metadata to match it cannot pass."
                    ),
                },
            },
        },
        "evidence_payload_hash": {
            "type": "string",
            "pattern": "^[a-f0-9]{64}$",
            "description": (
                "SHA-256 over the RFC 8785 canonical form of payload. NOT "
                "anchored on-chain: v3 events are authenticated by their "
                "signature and their parent links, and that is the whole of "
                "their assurance."
            ),
        },
        "signature_b64": {
            "type": "string",
            "description": (
                "Ed25519 over the 32 raw bytes of evidence_payload_hash, NOT " "over its hex text."
            ),
        },
        "signing_key_id": {
            "type": "string",
            "description": (
                "The published key id, e.g. iae-2026-01. Look it up at "
                "https://inntris.com/.well-known/inntris-keys.txt."
            ),
        },
    },
}

RECEIPT_SCHEMA_V3_DOCUMENT: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "/schema/receipt/v3.json",
    "title": "Inntris Authority Evidence Chain v3",
    "description": (
        "A decision and everything that followed from it, as a chain of "
        "immutable signed events. A decision receipt is never rewritten once "
        "consumption happens; each event commits to its own facts and to its "
        "parent. Structure only -- satisfying this schema is not verification."
    ),
    "type": "object",
    "required": ["decision"],
    "properties": {
        "decision": _SIGNED_EVENT,
        "consumption": {
            **_SIGNED_EVENT,
            "description": (
                "Present when the authority was spent. Only an ALLOW can be "
                "followed by one: authority that was refused cannot have been "
                "spent."
            ),
        },
        "outcome": {
            **_SIGNED_EVENT,
            "description": (
                "Present when the downstream result was recorded. An outcome "
                "without a consumption is refused."
            ),
        },
    },
    "additionalProperties": True,
    "x-verification": {
        "canonicalisation": "RFC 8785 (JCS) over payload",
        "signature": "Ed25519 over the raw bytes of evidence_payload_hash",
        "key_discovery": "/.well-known/inntris-authority-keys.json",
        "key_mirror": "https://github.com/Inntris/inntris-verify",
        "offline_verifier": "verify_pack.py, shipped inside every evidence pack",
        "not_anchored": (
            "The evidence_payload_hash is not itself committed on Base. The "
            "underlying audit decision row participates in the existing Merkle "
            "anchoring pipeline; the v3 event commitment does not."
        ),
        "what_a_verified_chain_proves": (
            "That Inntris Core recorded these decisions and consumptions, and "
            "that nobody has altered them since. It does not prove that money "
            "settled: the executor's own outcome evidence is a linked boundary."
        ),
    },
}


__all__ = ["RECEIPT_SCHEMA_V3_DOCUMENT"]
