# Signing a `POST /verify` request

This is the contract for producing the Ed25519 signature that `POST /verify`
checks. If you use the Python client (`api/agent_client.py`) or the MCP server,
this is already handled for you — read this only if you are building your own
client in another language.

> **The #1 mistake:** you sign **`bytes.fromhex(action_hash)`** (the 32 raw bytes
> of the SHA-256 digest), **not** the 64-character hex string and **not** the
> JSON. Get this wrong and every signature fails.

## The fastest way to get it right

Don't guess. Two zero-risk tools tell you exactly what the server expects:

1. **`POST /verify/debug`** — same body as `/verify`, but **no side effects**
   (no audit row, no nonce consumed, no policy evaluation, no trust-score
   change, no security alert). It returns:
   ```json
   {
     "expected_action_hash": "…64 hex chars…",
     "canonical_timestamp": "2026-06-16T12:00:00Z",
     "sig_version": 2,
     "signature_valid": true,
     "agent_found": true
   }
   ```
   Iterate against this until `signature_valid` is `true`, then switch to
   `/verify`. (Doing this against `/verify` instead would drop the agent's trust
   score by 20 per failure and trip signature-failure monitoring.)

2. **The `401` from `/verify`** echoes the same `expected_action_hash`,
   `canonical_timestamp`, and `sig_version`. Diff your locally computed
   `action_hash` against `expected_action_hash`: if they differ, your
   canonicalization differs (almost always the timestamp or the JSON
   serialization).

## The algorithm (sig_version 2 — the default)

Given `agent_id`, `action_type`, `payload` (a JSON object), `nonce`, and
`timestamp`:

1. **Canonicalize the timestamp** to UTC ISO-8601 with a `Z` suffix:
   `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. Parse any offset, convert to UTC, and
   render with `Z` (not `+00:00`). Send this exact string on the wire as
   `timestamp`.

2. **Hash the payload.** Serialize `payload` as canonical JSON and SHA-256 it:
   - keys sorted lexicographically, recursively
   - separators `,` and `:` with **no whitespace**
   - UTF-8, Unicode preserved (Python: `ensure_ascii=False`)
   ```
   payload_hash = sha256_hex(canonical_json(payload))
   ```

3. **Build the signing envelope** and hash it the same way:
   ```json
   {"action_type": "...", "agent_id": "...", "nonce": "...",
    "payload_hash": "...", "timestamp": "...Z"}
   ```
   ```
   action_hash = sha256_hex(canonical_json(envelope))
   ```
   (`timestamp` here is the canonical `Z` form from step 1.)

4. **Sign the digest bytes** with the agent's Ed25519 private key and base64 the
   64-byte signature:
   ```
   signature = base64( ed25519_sign( private_key, bytes.fromhex(action_hash) ) )
   ```

5. **POST** to `/verify`:
   ```json
   {
     "agent_id": "…uuid…",
     "action_type": "tool_call",
     "payload": { ... the same object you hashed ... },
     "nonce": "…unique, ≤64 chars…",
     "timestamp": "2026-06-16T12:00:00Z",
     "signature": "…base64 64-byte Ed25519 signature…",
     "sig_version": 2,
     "policy_hash": null
   }
   ```

### Python reference (≈15 lines, stdlib + pynacl)

```python
import base64, hashlib, json
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

def canon(obj):  # matches the server's compute_payload_hash
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sign_verify_request(agent_id, sk: SigningKey, action_type, payload, nonce, ts_z):
    payload_hash = hashlib.sha256(canon(payload).encode()).hexdigest()
    envelope = {"agent_id": str(agent_id), "action_type": action_type,
                "payload_hash": payload_hash, "nonce": nonce, "timestamp": ts_z}
    action_hash = hashlib.sha256(canon(envelope).encode()).hexdigest()
    sig = sk.sign(bytes.fromhex(action_hash)).signature
    return {"agent_id": str(agent_id), "action_type": action_type, "payload": payload,
            "nonce": nonce, "timestamp": ts_z,
            "signature": base64.b64encode(sig).decode(), "sig_version": 2}
```

## sig_version 3 — RFC 8785 JCS (for non-Python SDKs)

`sig_version` 2 uses Python's `json.dumps(sort_keys=True)`. For ASCII payloads
with string values this is easy to match in any language. But Python's number
and Unicode serialization has edge cases other languages won't reproduce
byte-for-byte. **If your payloads contain non-ASCII strings or non-integer
numbers, use `sig_version: 3`**, which canonicalizes both the payload hash and
the envelope with [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785). The
server accepts versions 1, 2, and 3; pin the one you signed with.

Cross-language test vectors and ready-to-run verifiers live in
`tests/fixtures/canonicalization/`:

| File | Purpose |
|---|---|
| `vectors.json` | sig_version 2 action-hash vectors |
| `jcs_vectors.json` | RFC 8785 JCS vectors |
| `verify_node.js`, `verify_jcs_node.js` | Node reference verifiers |
| `verify_python.py` | Python reference verifier |

These are the authoritative byte-level contract — run your implementation
against them in CI.

## Gotchas that cause a silent 401

- **Signing the hex string or the JSON** instead of `bytes.fromhex(action_hash)`.
- **Timestamp drift:** the wire `timestamp` must canonicalize to the same value
  you hashed. Send the `Z` form. The server also enforces a **5-minute** clock
  skew (`policy.py: MAX_CLOCK_SKEW`), so sign close to real UTC.
- **JSON whitespace / key order:** any space in separators, or unsorted keys,
  changes the hash. Floats: prefer integers or strings, or use sig_version 3.
- **`action_type`** is lower-cased and must be `[a-z0-9_]+`.
- **`nonce`** must be unique per request (≤64 chars); a repeat inside 10 minutes
  is rejected as a replay (`401 "Nonce already used"`), which is a *different*
  failure from a bad signature.

## Canonical source of truth

- Server: [`api/crypto.py`](../api/crypto.py) — `compute_action_hash`,
  `canonicalize_timestamp`, `verify_ed25519_signature`.
- Client: [`api/agent_client.py`](../api/agent_client.py) —
  `build_signed_verify_request`.
- Receipt-side canonicalization (verifying a returned receipt) is documented
  separately in [`RECEIPT_CANONICALIZATION.md`](RECEIPT_CANONICALIZATION.md).
