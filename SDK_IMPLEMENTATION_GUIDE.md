# Inntris SDK Implementation Guide (Cross-Language)

**CRITICAL: For Building Inntris Clients in Node.js, Go, Rust, Java, etc.**

This document specifies the EXACT requirements for implementing Inntris signature verification in languages other than Python. Even small deviations will cause signature verification failures.

---

## 📋 JSON Canonicalization Requirements

### **CRITICAL: Payload Hashing**

When computing the payload hash, you MUST use this EXACT JSON serialization:

```javascript
// Node.js Example
const crypto = require('crypto');

function computePayloadHash(payload) {
    // CRITICAL: Use these EXACT settings
    const canonical = JSON.stringify(payload, Object.keys(payload).sort(), null);
    // Remove all whitespace (JSON.stringify with null creates compact form)
    // Sort keys alphabetically

    return crypto.createHash('sha256')
        .update(canonical, 'utf8')
        .digest('hex');
}
```

### **Required Settings:**

1. **Key Sorting**: MUST be lexicographic/alphabetical
2. **Separators**:
   - Key-value: `:` (colon, no spaces)
   - Items: `,` (comma, no spaces)
3. **Whitespace**: NONE (no spaces, newlines, or tabs)
4. **Encoding**: UTF-8
5. **Unicode**: Preserve non-ASCII characters (do NOT escape to `\uXXXX`)
6. **Floating Point**: 17 significant digits (IEEE 754 double precision)

### **Test Vectors**

Use these to validate your implementation:

```json
// Input 1: Simple payload
{
    "amount": 50.00,
    "currency": "USD",
    "description": "Test transaction"
}

// Expected canonical form:
{"amount":50.0,"currency":"USD","description":"Test transaction"}

// Expected hash (SHA-256):
// Compute and compare with Python reference implementation
```

```json
// Input 2: Unicode characters
{
    "description": "Payment for café ☕",
    "amount": 10.50
}

// Expected canonical form (Unicode preserved):
{"amount":10.5,"description":"Payment for café ☕"}

// WRONG (escaped Unicode):
{"amount":10.5,"description":"Payment for caf\u00e9 \u2615"}
```

```json
// Input 3: Nested objects
{
    "metadata": {
        "user_id": "123",
        "session": "abc"
    },
    "amount": 100
}

// Expected canonical form (keys sorted at ALL levels):
{"amount":100,"metadata":{"session":"abc","user_id":"123"}}
```

---

## 🔐 Signature Computation Flow

### **Step 1: Compute Payload Hash**

```python
# Python Reference Implementation
import json
import hashlib

payload_canonical = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
)
payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()
```

### **Step 2: Compute Action Hash**

```python
signing_data = {
    "agent_id": "your-uuid-here",
    "action_type": "financial_transaction",
    "payload_hash": payload_hash,  # From Step 1
    "nonce": "random-32-byte-urlsafe-string",
    "timestamp": "2026-01-15T10:30:00.123456Z",  # ISO 8601 with microseconds
}

signing_canonical = json.dumps(
    signing_data,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
)
action_hash = hashlib.sha256(signing_canonical.encode("utf-8")).hexdigest()
```

**CRITICAL**: The `timestamp` format MUST be:
- ISO 8601 format
- UTC timezone (Z suffix)
- Microseconds included (6 decimal places)
- Example: `2026-01-15T10:30:00.123456Z`

### **Step 3: Sign Action Hash**

```python
# Using Ed25519 (NaCl/libsodium)
from nacl.signing import SigningKey
import base64

# Your 32-byte private key
private_key_bytes = base64.b64decode(private_key_b64)
signing_key = SigningKey(private_key_bytes)

# Convert hex hash to bytes
message_bytes = bytes.fromhex(action_hash)

# Sign (deterministic, no randomness)
signed = signing_key.sign(message_bytes)
signature = base64.b64encode(signed.signature).decode('utf-8')
```

**CRITICAL**:
- Sign the **bytes** of the action hash (not the hex string)
- Use **only the signature** (64 bytes), not the entire signed message
- Encode signature as **Base64** (standard, not URL-safe)

---

## 📦 Language-Specific Implementations

### **Node.js / TypeScript**

```typescript
import crypto from 'crypto';
import nacl from 'tweetnacl';
import { Buffer } from 'buffer';

function computePayloadHash(payload: any): string {
    // Sort keys recursively
    const sortedPayload = sortKeys(payload);
    const canonical = JSON.stringify(sortedPayload);
    return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function sortKeys(obj: any): any {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(sortKeys);

    return Object.keys(obj)
        .sort()
        .reduce((result, key) => {
            result[key] = sortKeys(obj[key]);
            return result;
        }, {} as any);
}

function signAction(
    agentId: string,
    actionType: string,
    payload: any,
    nonce: string,
    timestamp: string,
    privateKeyBase64: string
): string {
    const payloadHash = computePayloadHash(payload);

    const signingData = {
        agent_id: agentId,
        action_type: actionType,
        payload_hash: payloadHash,
        nonce: nonce,
        timestamp: timestamp,
    };

    const actionHash = computePayloadHash(signingData);

    // Sign with Ed25519
    const privateKey = Buffer.from(privateKeyBase64, 'base64');
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);

    const messageBytes = Buffer.from(actionHash, 'hex');
    const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

    return Buffer.from(signature).toString('base64');
}
```

**Required Packages:**
```bash
npm install tweetnacl buffer
```

### **Go**

```go
package inntris

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "sort"
    "time"
)

func ComputePayloadHash(payload map[string]interface{}) (string, error) {
    // Marshal with sorted keys
    canonical, err := json.Marshal(sortKeys(payload))
    if err != nil {
        return "", err
    }

    hash := sha256.Sum256(canonical)
    return hex.EncodeToString(hash[:]), nil
}

func sortKeys(m map[string]interface{}) map[string]interface{} {
    // Go's json.Marshal automatically sorts keys
    return m
}

func SignAction(
    agentID string,
    actionType string,
    payload map[string]interface{},
    nonce string,
    timestamp time.Time,
    privateKey ed25519.PrivateKey,
) (string, error) {
    payloadHash, _ := ComputePayloadHash(payload)

    signingData := map[string]interface{}{
        "agent_id":     agentID,
        "action_type":  actionType,
        "payload_hash": payloadHash,
        "nonce":        nonce,
        "timestamp":    timestamp.Format(time.RFC3339Nano),
    }

    actionHash, _ := ComputePayloadHash(signingData)
    messageBytes, _ := hex.DecodeString(actionHash)

    signature := ed25519.Sign(privateKey, messageBytes)
    return base64.StdEncoding.EncodeToString(signature), nil
}
```

### **Rust**

```rust
use ed25519_dalek::{Keypair, Signature, Signer};
use serde_json::{json, Value};
use sha2::{Sha256, Digest};
use base64;

fn compute_payload_hash(payload: &Value) -> String {
    // serde_json automatically sorts keys
    let canonical = serde_json::to_string(payload).unwrap();
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

fn sign_action(
    agent_id: &str,
    action_type: &str,
    payload: &Value,
    nonce: &str,
    timestamp: &str,
    keypair: &Keypair,
) -> String {
    let payload_hash = compute_payload_hash(payload);

    let signing_data = json!({
        "agent_id": agent_id,
        "action_type": action_type,
        "payload_hash": payload_hash,
        "nonce": nonce,
        "timestamp": timestamp,
    });

    let action_hash = compute_payload_hash(&signing_data);
    let message_bytes = hex::decode(action_hash).unwrap();

    let signature = keypair.sign(&message_bytes);
    base64::encode(signature.to_bytes())
}
```

---

## ✅ Testing Your Implementation

### **Step 1: Reference Test**

Use the Python reference implementation to generate a test case:

```python
# Python reference - run this first
import json
import hashlib
from nacl.signing import SigningKey
import base64

# Generate keypair
signing_key = SigningKey.generate()
private_key_b64 = base64.b64encode(signing_key._signing_key).decode()
public_key_b64 = base64.b64encode(signing_key.verify_key._key).decode()

print(f"Private Key: {private_key_b64}")
print(f"Public Key: {public_key_b64}")

# Test payload
payload = {"amount": 100.50, "currency": "USD", "description": "Test"}
nonce = "test-nonce-12345678901234567890123456789012"
timestamp = "2026-01-15T10:30:00.000000Z"

# Compute hashes
payload_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()

signing_data = {
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "action_type": "financial_transaction",
    "payload_hash": payload_hash,
    "nonce": nonce,
    "timestamp": timestamp,
}

signing_canonical = json.dumps(signing_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
action_hash = hashlib.sha256(signing_canonical.encode("utf-8")).hexdigest()

# Sign
message_bytes = bytes.fromhex(action_hash)
signed = signing_key.sign(message_bytes)
signature_b64 = base64.b64encode(signed.signature).decode()

print(f"\nPayload Hash: {payload_hash}")
print(f"Action Hash: {action_hash}")
print(f"Signature: {signature_b64}")
```

### **Step 2: Compare Outputs**

Run your implementation with the SAME inputs and verify:
1. ✅ Payload hash matches exactly
2. ✅ Action hash matches exactly
3. ✅ Signature format is correct (88 characters Base64)
4. ✅ Server accepts your signature (send to `/verify` endpoint)

### **Step 3: Edge Cases**

Test these challenging cases:

1. **Unicode characters**: `{"text": "Café ☕ 日本語"}`
2. **Floating point precision**: `{"amount": 123.456789012345678}`
3. **Empty objects**: `{"metadata": {}}`
4. **Null values**: `{"optional_field": null}`
5. **Boolean values**: `{"is_test": true}`
6. **Nested arrays**: `{"items": [{"id": 1}, {"id": 2}]}`

---

## 🚨 Common Mistakes

### ❌ **Mistake 1: Escaping Unicode**
```json
// WRONG
{"text":"Caf\u00e9"}

// CORRECT
{"text":"Café"}
```

### ❌ **Mistake 2: Adding Spaces**
```json
// WRONG
{"amount": 100, "currency": "USD"}

// CORRECT
{"amount":100,"currency":"USD"}
```

### ❌ **Mistake 3: Inconsistent Key Sorting**
```json
// WRONG (unsorted)
{"currency":"USD","amount":100}

// CORRECT (alphabetical)
{"amount":100,"currency":"USD"}
```

### ❌ **Mistake 4: Signing Hex String Instead of Bytes**
```javascript
// WRONG
const signature = sign(actionHash);  // Signing the hex string

// CORRECT
const messageBytes = Buffer.from(actionHash, 'hex');
const signature = sign(messageBytes);  // Signing the bytes
```

### ❌ **Mistake 5: Wrong Timestamp Format**
```
// WRONG
2026-01-15 10:30:00
2026-01-15T10:30:00
2026-01-15T10:30:00.123Z (only 3 decimals)

// CORRECT
2026-01-15T10:30:00.000000Z (6 decimals, microseconds)
```

---

## 📚 Future: Upgrade to RFC 8785 (JCS)

For maximum cross-language compatibility, consider upgrading to **JSON Canonicalization Scheme (RFC 8785)**:

- **Spec**: https://www.rfc-editor.org/rfc/rfc8785
- **Python**: `pip install canonicaljson-rs`
- **Node.js**: `npm install canonicaljson`
- **Go**: `go get github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer`

This provides **strict determinism** across all languages, platforms, and JSON implementations.

---

## 🆘 Debugging

If signatures are failing:

1. **Compare payload hashes**: Print your payload hash and compare with Python reference
2. **Compare action hashes**: Print your action hash and compare
3. **Check timestamp format**: Must include microseconds
4. **Verify key encoding**: Private key should be 32 bytes, public key 32 bytes
5. **Use test vectors**: Start with the reference test case above

**Enable debug logging:**
```bash
curl -X POST https://your-api.com/verify \
  -H "Content-Type: application/json" \
  -d @test-request.json \
  --verbose
```

Check server logs for:
- `SECURITY: Signature verification failed`
- `Computed action hash: <hash>`
- Compare your computed hash with server's hash

---

**Last Updated**: 2026-01-15
**Version**: 1.0.0
**Maintained By**: Inntris Core Team
