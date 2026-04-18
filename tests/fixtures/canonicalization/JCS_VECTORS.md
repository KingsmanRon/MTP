# JCS Canonicalization Vectors — Cross-Language Contract

Phase 1B.1. These vectors are the authoritative contract that every
Inntris agent SDK — Python, Node, Go, Rust, anything — must satisfy if
it wants its signatures to verify under `sig_version=3`.

## Files

| File | Purpose |
| --- | --- |
| `jcs_vectors.json` | 12 input / canonical-bytes / SHA-256 vectors |
| `verify_jcs_node.js` | Node reference implementation + runner |
| [`api/jcs.py`](../../../api/jcs.py) | Python reference implementation |
| [`tests/test_jcs_canonicalization.py`](../../test_jcs_canonicalization.py) | pytest that re-runs every vector |

## Running the verifiers

```bash
# Python
PYTHONPATH=. pytest tests/test_jcs_canonicalization.py -v

# Node
node tests/fixtures/canonicalization/verify_jcs_node.js
```

Both MUST print 12 `OK` lines and exit 0. If your own SDK fails any
vector, that SDK cannot produce valid `sig_version=3` signatures.

## The contract

Each vector in `jcs_vectors.json` has four fields an SDK author cares
about:

```json
{
  "name": "integer_valued_float_becomes_int",
  "description": "1.0 and 100.0 drop the trailing '.0' per ECMA-262 ToString",
  "input": { "whole": 1.0, "hundred": 100.0, "negative": -42.0 },
  "canonical": "{\"hundred\":100,\"negative\":-42,\"whole\":1}",
  "sha256": "319fcb60f1f2444acca2135644ac55ffe253f499beb81ce11663c26262eabe2e"
}
```

Your SDK must:

1. Produce **byte-for-byte** the `canonical` string when JCS-encoding
   `input` and UTF-8-encoding the result.
2. Produce **exactly** the `sha256` hex digest when taking SHA-256 over
   those UTF-8 bytes.

No transformation, no whitespace, no Unicode normalization beyond what
RFC 8785 prescribes. If your output differs in any byte, fix your SDK.

## The rules that most SDKs get wrong

JCS is RFC 8785. In practice, the spots where a naive implementation
diverges from the vectors are:

| Rule | What naive code does | What JCS requires |
| --- | --- | --- |
| `1.0` | `"1.0"` (Python `json`, Go `encoding/json`) | `"1"` |
| `100.0` | `"100.0"` | `"100"` |
| `-0.0` | `"-0"` or `"-0.0"` | `"0"` |
| `NaN`, `Infinity` | emitted or silently `null` | **reject** |
| Key order | insertion order or locale-sensitive sort | UTF-16 code-unit sort |
| `1e-7` | `"1e-07"` (Python `repr`) | `"1e-7"` |
| Unicode | `ensure_ascii=True` escapes | pass-through UTF-8 |

For ASCII-only, BMP-only payloads, the only hard rule is the number
serialization. That's why `verify_jcs_node.js` is **six lines of actual
JCS logic** — JavaScript's `String(number)` matches ECMA-262 ToString
natively, so JS gets this for free.

## Integrating with `sig_version=3`

The `/verify` request body is unchanged except for the `sig_version`
field:

```json
{
  "agent_id": "4f0e4fd5-5e2f-4e95-a2d5-78b0a7b0d66a",
  "action_type": "financial_transaction",
  "payload": { "amount": 49.99, "currency": "USD" },
  "nonce": "...",
  "timestamp": "2026-04-17T12:00:00Z",
  "signature": "<base64>",
  "sig_version": 3
}
```

The client-side hash that your SDK signs is computed by:

1. `payload_hash = JCS_SHA256(payload)`
2. Build the envelope
   `{"agent_id": ..., "action_type": ..., "payload_hash": ...,
    "nonce": ..., "timestamp": canonicalize_timestamp(timestamp)}`
3. `action_hash = JCS_SHA256(envelope)`
4. `signature = Ed25519(private_key, bytes.fromhex(action_hash))`

`canonicalize_timestamp` is the same as Phase 0.3 — convert to UTC and
emit `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.

## Adding a new vector

1. Edit the `specs` list in
   [`tests/test_jcs_canonicalization.py`](../../test_jcs_canonicalization.py)
   if you need a regression on actual Python behavior, OR
2. Regenerate `jcs_vectors.json`:
   ```bash
   PYTHONPATH=. python -c 'from api.jcs import canonicalize, sha256_hex; \
   import json; \
   obj = {"your": "payload"}; \
   print(canonicalize(obj).decode("utf-8")); \
   print(sha256_hex(obj))'
   ```
3. Add the vector to `jcs_vectors.json` and re-run both verifiers.
4. The Node verifier (and any other SDK verifier you maintain) must
   continue to pass.

If a new vector only passes in Python, **the vector is wrong**, not
the Node runner — JCS is defined by ECMA-262 number formatting, which
JavaScript implements natively. Python is the SDK most likely to
diverge because its `json` module is not JCS-compliant.
