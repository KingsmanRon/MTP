# Receipt Canonicalization Contract

This document defines the exact serialization contract used to compute
`receipt_fingerprint` in Inntris verification receipts. Any consumer
(Python SDK, Node.js SDK, Go SDK, browser) that recomputes the fingerprint
**must** follow this contract byte-for-byte or every receipt will fail its
integrity check.

---

## Field Set and Sort Order

The fingerprint is computed over exactly these seven fields (in this order
after `sort_keys=True`):

| Field          | Type              | Notes                                    |
|----------------|-------------------|------------------------------------------|
| `action_hash`  | string (hex64)    | SHA-256 of the action signing payload    |
| `action_type`  | string            | e.g. `"tool_call"`, `"promptfoo_eval"`  |
| `agent_id`     | string (UUID)     | `str(uuid)` — hyphenated lowercase       |
| `audit_id`     | string (UUID)     | `str(uuid)` — hyphenated lowercase       |
| `policy_hash`  | string or `null`  | `null` for v1 receipts                  |
| `timestamp`    | string (ISO 8601) | **Must use `Z` suffix, not `+00:00`**   |
| `verdict`      | string            | e.g. `"approved"`, `"blocked"`          |

The `signature` field is **excluded** from the canonical payload.

---

## Serialization Algorithm

```python
import hashlib, json

canonical = json.dumps(
    fingerprint_payload,       # dict with the 7 fields above
    sort_keys=True,            # lexicographic key order
    separators=(",", ":"),     # no spaces: {"a":"b","c":"d"}
)
receipt_fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

- `sort_keys=True` — keys sorted **lexicographically** (ASCII order).
- `separators=(",", ":")` — no whitespace anywhere in the output.
- `ensure_ascii=False` is **not** set for the fingerprint payload; all
  values in the fingerprint set are ASCII-safe.
- UTF-8 encoding for the `sha256` input.

---

## Timestamp Format

Timestamps **must** use the `Z` suffix for UTC, not `+00:00`.

| Correct                    | Incorrect                        |
|----------------------------|----------------------------------|
| `"2026-04-07T22:22:25Z"`  | `"2026-04-07T22:22:25+00:00"`   |

Pydantic v2 emits `Z` on the JSON wire. The backend helper
`canonical_wire_timestamp(dt)` normalises `+00:00` → `Z`.
If your language's ISO formatter emits `+00:00`, strip and replace.

---

## v1 vs v2 Distinction

| Version | Guarantee                                                       |
|---------|-----------------------------------------------------------------|
| `v1`    | `policy_hash` may be `null`; no policy binding asserted        |
| `v2`    | `policy_hash` is non-null and bound to the decision            |

The **field set is identical** for v1 and v2. What changes is the
semantic guarantee: a v2 receipt asserts that a specific policy file
was evaluated and its hash is locked into the fingerprint.

---

## Reference Vectors

See `tests/fixtures/canonicalization/vectors.json` for known-input /
known-output test vectors. Run:

```bash
# Python
python tests/fixtures/canonicalization/verify_python.py

# Node.js
node tests/fixtures/canonicalization/verify_node.js
```

Both must exit 0.
